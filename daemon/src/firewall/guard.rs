//! Dead-man's-switch auto-revert for firewall changes.
//!
//! [`apply_with_revert`] snapshots the current ruleset, applies a new one, then starts
//! a background timer. Unless [`FirewallGuard::confirm`] is called before the timer
//! fires, the previous ruleset is automatically restored — preventing operator lockout
//! on remote/headless hosts.

use std::time::Duration;

use tokio::sync::oneshot;

use super::{apply_with, FwBackend, FwError, ManagedRuleset};

// ──────────────────────────────────────────────────────────────────────────────
// Snapshot path helper
// ──────────────────────────────────────────────────────────────────────────────

fn snapshot_path() -> std::path::PathBuf {
    let mut p = dirs_snapshot();
    p.push("fw_snapshot.json");
    p
}

/// Returns the Belay data directory (creating it if necessary).
fn dirs_snapshot() -> std::path::PathBuf {
    let dir = crate::paths::data_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// ──────────────────────────────────────────────────────────────────────────────
// Snapshot persistence
// ──────────────────────────────────────────────────────────────────────────────

/// Atomically persist `bytes` to the snapshot file (write to temp, then rename).
fn persist_snapshot(bytes: &[u8]) -> Result<(), FwError> {
    let dir = dirs_snapshot();
    let tmp = tempfile::NamedTempFile::new_in(&dir).map_err(FwError::SnapshotIo)?;
    std::fs::write(tmp.path(), bytes).map_err(FwError::SnapshotIo)?;
    tmp.persist(snapshot_path())
        .map_err(|e| FwError::SnapshotIo(e.error))?;
    Ok(())
}

/// Remove the snapshot file (called after a confirmed apply).
pub fn remove_snapshot() {
    let _ = std::fs::remove_file(snapshot_path());
}

/// On daemon start: if a snapshot exists, restore it immediately (fail-soft).
///
/// For [`RustablesBackend`](super::RustablesBackend) this means the `belay`
/// table is deleted, returning the host to its pre-Belay firewall state.
/// Any error from `load` is logged but does not abort startup.
pub fn restore_on_start<B: FwBackend>(backend: &mut B) {
    let path = snapshot_path();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return, // no snapshot — normal startup
    };
    if let Err(e) = backend.load(&bytes) {
        eprintln!("firewall: restore_on_start load failed: {e}");
    }
    let _ = std::fs::remove_file(&path);
}

// ──────────────────────────────────────────────────────────────────────────────
// FirewallGuard
// ──────────────────────────────────────────────────────────────────────────────

/// A guard that keeps a pending firewall change alive.
///
/// Call [`confirm`](FirewallGuard::confirm) to commit the change.
/// Dropping the guard without confirming does NOT revert — the background task
/// handles the revert; dropping just releases the confirm channel (revert fires
/// when the timer expires).
///
/// Call [`wait_for_revert`](FirewallGuard::wait_for_revert) in one-shot CLI
/// contexts to block until the background revert task completes, preventing
/// the runtime from being dropped mid-revert (SSH lockout risk).
pub struct FirewallGuard {
    /// Signals the dead-man's-switch task. `true` = keep (confirm), `false` =
    /// revert immediately. If the sender is dropped without sending, the task
    /// honours the original deadline (fail-safe revert).
    confirm_tx: Option<oneshot::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl FirewallGuard {
    /// Confirm the pending ruleset change, preventing auto-revert.
    ///
    /// Sends the keep signal; the background task will exit without
    /// reverting.  The task handle is dropped (it will finish on its own).
    pub fn confirm(mut self) {
        if let Some(tx) = self.confirm_tx.take() {
            let _ = tx.send(true);
        }
        // Drop the handle — the task saw the keep signal and exits promptly.
        drop(self.task.take());
    }

    /// Revert the pending ruleset change **immediately** (do not wait for the
    /// deadline), then block until the background task has finished restoring.
    ///
    /// Use this for an explicit operator "revert now" action (GUI button / IPC
    /// `firewall_revert`). Awaiting the task guarantees `backend.load()` has
    /// completed before this returns, so the caller's runtime is not dropped
    /// mid-restore (SSH lockout risk).
    pub async fn revert_now(mut self) {
        // Send the revert signal; if the receiver is already gone the task is
        // finishing on its own path, which still reverts.
        if let Some(tx) = self.confirm_tx.take() {
            let _ = tx.send(false);
        }
        if let Some(handle) = self.task.take() {
            let _ = handle.await;
        }
    }

    /// Block until the background revert task finishes.
    ///
    /// Use this in one-shot CLI paths (timeout / non-CONFIRM input branches) so
    /// the `#[tokio::main]` runtime is not dropped while `backend.load()` is
    /// still in flight.  Dropping `confirm_tx` first makes the task honour the
    /// original deadline. If there is no task (already consumed), returns
    /// immediately.
    pub async fn wait_for_revert(mut self) {
        // Drop the sender so the task takes its deadline-honouring branch.
        drop(self.confirm_tx.take());
        if let Some(handle) = self.task.take() {
            // Ignore JoinError (task panicked or was aborted) — the important
            // invariant is that we waited.
            let _ = handle.await;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// apply_with_revert
// ──────────────────────────────────────────────────────────────────────────────

/// Apply `rs` via `backend`, and schedule an automatic revert after `revert_after`.
///
/// 1. Dumps + persists the current snapshot **before** applying the new ruleset.
/// 2. Applies the new ruleset.  If apply fails, returns `Err` immediately — the
///    dead-man's-switch timer is **not** armed (no partial state to revert).
/// 3. Spawns a timer task: waits for either a confirm signal or the timeout.
///    On timeout → `backend.load(&snapshot)` (errors from load are logged).
///
/// Returns a [`FirewallGuard`]; call `.confirm()` to keep the new ruleset.
pub async fn apply_with_revert<B: FwBackend>(
    rs: &ManagedRuleset,
    revert_after: Duration,
    mut backend: B,
) -> Result<FirewallGuard, FwError> {
    // 1. Snapshot current state BEFORE applying anything.
    let snapshot = backend.dump();
    persist_snapshot(&snapshot)?;

    // 2. Apply the new ruleset.  Return Err BEFORE arming the timer if this fails.
    if let Err(e) = apply_with(&mut backend, rs) {
        // Remove the snapshot we just wrote — there's nothing to revert.
        remove_snapshot();
        return Err(e);
    }

    // 3. Arm the dead-man's-switch.
    let (confirm_tx, confirm_rx) = oneshot::channel::<bool>();

    // Record the deadline NOW (before any await), so that even if the guard is dropped
    // before the spawned task runs, `sleep_until(deadline)` will resolve immediately
    // once the virtual clock has been advanced past the deadline.
    let deadline = tokio::time::Instant::now() + revert_after;

    let task = tokio::spawn(async move {
        tokio::select! {
            result = confirm_rx => {
                match result {
                    // Explicitly confirmed (keep) — drop the snapshot, leave rules in place.
                    Ok(true) => {
                        remove_snapshot();
                    }
                    // Explicit "revert now" — restore the previous ruleset immediately.
                    Ok(false) => {
                        if let Err(e) = backend.load(&snapshot) {
                            eprintln!("firewall: revert (explicit) load failed: {e}");
                        }
                        remove_snapshot();
                    }
                    // Sender dropped without signalling — honour the original deadline.
                    Err(_) => {
                        tokio::time::sleep_until(deadline).await;
                        if let Err(e) = backend.load(&snapshot) {
                            eprintln!("firewall: revert (drop) load failed: {e}");
                        }
                        remove_snapshot();
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                // Timer fired before any signal — restore the previous ruleset.
                if let Err(e) = backend.load(&snapshot) {
                    eprintln!("firewall: revert (timer) load failed: {e}");
                }
                remove_snapshot();
            }
        }
    });

    Ok(FirewallGuard {
        confirm_tx: Some(confirm_tx),
        task: Some(task),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::firewall::{FwBackend, FwError, ManagedRuleset, NftProgram};

    // ── SharedMock: a cloneable, Arc<Mutex<MockBackend>> ───────────────────────

    #[derive(Default)]
    struct Inner {
        pub applied: Option<NftProgram>,
        pub restored: bool,
    }

    #[derive(Clone, Default)]
    struct SharedMock(Arc<Mutex<Inner>>);

    impl SharedMock {
        fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
            self.0.lock().unwrap()
        }
    }

    impl FwBackend for SharedMock {
        fn apply(&mut self, prog: &NftProgram) -> Result<(), FwError> {
            self.lock().applied = Some(prog.clone());
            Ok(())
        }

        fn dump(&mut self) -> Vec<u8> {
            serde_json::to_vec(&self.lock().applied).unwrap_or_default()
        }

        fn load(&mut self, _bytes: &[u8]) -> Result<(), FwError> {
            self.lock().restored = true;
            Ok(())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn auto_reverts_when_not_confirmed() {
        let backend = SharedMock::default();
        let rs = ManagedRuleset {
            allow_ports: vec![],
            ssh_source: None,
            default_drop: true,
        };
        let _guard = apply_with_revert(&rs, Duration::from_secs(60), backend.clone())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(backend.lock().restored, "ruleset must auto-revert");
    }

    #[tokio::test(start_paused = true)]
    async fn confirm_prevents_revert() {
        let backend = SharedMock::default();
        let rs = ManagedRuleset {
            allow_ports: vec![443],
            ssh_source: None,
            default_drop: true,
        };
        let guard = apply_with_revert(&rs, Duration::from_secs(60), backend.clone())
            .await
            .unwrap();
        guard.confirm();
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(!backend.lock().restored, "confirmed ruleset must persist");
    }

    #[tokio::test(start_paused = true)]
    async fn revert_now_restores_before_deadline() {
        let backend = SharedMock::default();
        let rs = ManagedRuleset {
            allow_ports: vec![443],
            ssh_source: None,
            default_drop: true,
        };
        let guard = apply_with_revert(&rs, Duration::from_secs(600), backend.clone())
            .await
            .unwrap();
        // Explicit revert WITHOUT advancing the clock — must restore immediately
        // and the awaited task guarantees load() completed before returning.
        guard.revert_now().await;
        assert!(
            backend.lock().restored,
            "explicit revert_now must restore without waiting for the deadline"
        );
    }
}
