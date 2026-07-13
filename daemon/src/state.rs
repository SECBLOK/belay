//! Long-lived, shared daemon state for the stateful host/EDR IPC commands
//! (piece 2 of the daemon IPC wiring).
//!
//! The single hard problem this module solves: a GUI firewall change is applied
//! in one IPC request (`firewall_apply`) and confirmed/reverted in a *separate*
//! later request. The dead-man's-switch [`FirewallGuard`] owns a background
//! tokio task that must stay alive across those requests. So [`DaemonState`]
//! owns a dedicated multi-thread runtime (kept alive for the daemon's lifetime)
//! and the guard, both behind `Arc`, shared across every connection thread.
//!
//! The remaining state — the operator-curated egress allowlist, the egress
//! mode, the inline-egress toggle and the SSH ban list — is in-memory only
//! (not persisted across daemon restarts). That is an intentional piece-2
//! limitation; persistence is a follow-up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(fw)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(fw)]
use serde_json::Value;

#[cfg(fw)]
use crate::firewall::guard::{apply_with_revert, FirewallGuard};
#[cfg(fw)]
use crate::firewall::{FwBackend, FwError, ManagedRuleset};
use crate::host_api::{BanDto, EgressRuleDto, FirewallStatusDto};

/// Auto-revert window for a GUI-driven firewall apply. The dead-man's-switch
/// restores the previous ruleset after this many seconds unless the operator
/// confirms — the primary anti-lockout safeguard for the GUI path (the CLI path
/// uses its own `--confirm-within`).
#[cfg(fw)]
pub const FIREWALL_REVERT_WINDOW_SECS: u64 = 120;

/// Monotonic-ish suffix so two applies in the same millisecond get distinct
/// handles. Wraps harmlessly; only uniqueness within a daemon lifetime matters.
static HANDLE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(fw)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Lock a `Mutex`, recovering the inner value if a previous holder panicked.
/// Daemon state must never become permanently unusable due to one poisoned lock.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether a stored firewall entry is still pending or confirmed-active.
///
/// The auto-revert timer lives inside the [`FirewallGuard`] task and cannot
/// reach back to clear this slot when it fires, so a stored entry can outlive
/// the kernel ruleset it describes. We treat a `Some(deadline)` whose deadline
/// has passed as STALE (the timer has already restored the previous ruleset),
/// i.e. not active. `None` means the operator confirmed (permanent).
#[cfg(fw)]
fn is_pending(live: &FirewallLive) -> bool {
    match live.revert_deadline {
        None => true,               // confirmed → permanently active
        Some(d) => now_secs() <= d, // pending iff before the auto-revert deadline
    }
}

/// A firewall ruleset currently applied to the kernel, tracked across the
/// separate apply / confirm / revert IPC requests.
#[cfg(fw)]
pub struct FirewallLive {
    /// Opaque handle returned to the GUI on apply; confirm/revert must match it.
    pub handle: String,
    /// Unix seconds when the dead-man's-switch auto-reverts. `None` once the
    /// operator has confirmed (the change is then permanent).
    pub revert_deadline: Option<u64>,
    /// Number of rules in the applied ruleset (for `FirewallStatusDto.rule_count`).
    pub rule_count: usize,
    /// The dead-man's-switch guard. Consumed (taken) on confirm/revert; `None`
    /// afterwards (a confirmed ruleset stays applied with no pending timer).
    pub guard: Option<FirewallGuard>,
}

/// Shared daemon state. Cloning is cheap (`Arc`) and shares the same state.
#[derive(Clone)]
pub struct DaemonState {
    /// Dedicated multi-thread runtime that HOSTS the dead-man's-switch task.
    /// Owned via `Arc` so the timer task is never cancelled by a runtime drop
    /// while the daemon is alive. `block_on` is only ever called from the
    /// per-connection std threads (never a runtime worker), so it cannot panic
    /// with "cannot block within a runtime".
    #[cfg(fw)]
    rt: Arc<tokio::runtime::Runtime>,
    #[cfg(fw)]
    firewall: Arc<Mutex<Option<FirewallLive>>>,
    egress: Arc<Mutex<Vec<EgressRuleDto>>>,
    egress_mode: Arc<Mutex<String>>,
    inline_egress: Arc<Mutex<bool>>,
    bans: Arc<Mutex<Vec<BanDto>>>,
}

impl DaemonState {
    /// Build fresh daemon state, including the dedicated firewall runtime.
    ///
    /// Panics only if the OS refuses to create the runtime threads — a fatal,
    /// fail-closed condition for a daemon that exists to enforce a firewall.
    pub fn new() -> Self {
        Self {
            #[cfg(fw)]
            rt: Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("daemon: failed to build firewall runtime"),
            ),
            #[cfg(fw)]
            firewall: Arc::new(Mutex::new(None)),
            egress: Arc::new(Mutex::new(Vec::new())),
            egress_mode: Arc::new(Mutex::new("off".to_string())),
            inline_egress: Arc::new(Mutex::new(false)),
            bans: Arc::new(Mutex::new(Vec::new())),
        }
    }

    // ── Firewall (dead-man's-switch) ──────────────────────────────────────────

    /// Apply `managed` via `backend` with a dead-man's-switch, store the guard,
    /// and return `(handle, revert_deadline_secs)`.
    ///
    /// Generic over the backend so unit tests can inject a mock; the IPC arm
    /// passes the real `RustablesBackend`.
    ///
    /// Rejects a second apply while a change is still pending (a single pending
    /// change at a time). This is held atomically: the `firewall` lock is taken
    /// BEFORE the pending check and kept across the kernel apply, so two
    /// concurrent applies can never both pass the check and orphan each other's
    /// auto-revert guard (which would leave the kernel and the daemon's view of
    /// it divergent). The lock is a `std::sync::Mutex` held across `block_on` —
    /// safe here because this is a *synchronous* fn (no `.await`), the lock is
    /// never re-entered by the awaited future (`apply_with_revert` touches only
    /// the backend and snapshot files, never `DaemonState`), and the hold is
    /// brief (the arm returns as soon as the timer task is spawned).
    #[cfg(fw)]
    pub fn firewall_apply_with<B: FwBackend>(
        &self,
        managed: &ManagedRuleset,
        window: Duration,
        backend: B,
    ) -> Result<(String, u64), FwError> {
        let mut slot = lock(&self.firewall);

        // Reject if a change is still pending (or confirmed-active). A stale
        // entry whose deadline has passed (the auto-revert timer already fired)
        // is NOT pending and is overwritten below.
        if slot.as_ref().is_some_and(is_pending) {
            return Err(FwError::Apply(
                "a firewall ruleset is already active or pending — confirm or revert it first"
                    .to_string(),
            ));
        }

        let rule_count = managed.allow_ports.len()
            + usize::from(managed.ssh_source.is_some())
            + usize::from(managed.default_drop);

        // Apply + arm on the owned runtime. Returns Err BEFORE arming if the
        // kernel rejected the ruleset, leaving any prior `slot` value untouched.
        let guard = self
            .rt
            .block_on(apply_with_revert(managed, window, backend))?;

        let handle = format!(
            "fw-{}-{}",
            now_ms(),
            HANDLE_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let deadline = now_secs() + window.as_secs();

        // Replaces any stale (already auto-reverted) entry; that entry's guard
        // task has finished, so dropping it here is harmless.
        *slot = Some(FirewallLive {
            handle: handle.clone(),
            revert_deadline: Some(deadline),
            rule_count,
            guard: Some(guard),
        });
        Ok((handle, deadline))
    }

    /// Confirm the applied firewall identified by `handle` (keep it, cancel the
    /// auto-revert). Returns `false` if no live firewall matches `handle` (and
    /// always `false` in builds without the `firewall` feature).
    pub fn firewall_confirm(&self, handle: &str) -> bool {
        #[cfg(fw)]
        {
            let mut slot = lock(&self.firewall);
            match slot.as_mut() {
                // Only confirm a still-pending change. Confirming a stale entry
                // (deadline already passed → kernel auto-reverted) would falsely
                // mark a reverted ruleset as permanently active.
                Some(live) if live.handle == handle && is_pending(live) => {
                    if let Some(guard) = live.guard.take() {
                        guard.confirm(); // sync: signals "keep"
                    }
                    live.revert_deadline = None; // confirmed → no pending revert
                    true
                }
                _ => false,
            }
        }
        #[cfg(not(fw))]
        {
            let _ = handle;
            false
        }
    }

    /// Revert the applied firewall identified by `handle` **immediately** and
    /// block until the kernel restore has completed. Returns `false` if no live
    /// firewall matches `handle` (and always `false` in builds without the
    /// `firewall` feature).
    pub fn firewall_revert(&self, handle: &str) -> bool {
        #[cfg(fw)]
        {
            // Take the live entry out from under the lock FIRST, then drive the
            // async revert OUTSIDE the lock (never hold a std Mutex across block_on).
            let live = {
                let mut slot = lock(&self.firewall);
                match slot.as_ref() {
                    Some(l) if l.handle == handle => slot.take(),
                    _ => None,
                }
            };
            match live {
                Some(mut l) => {
                    if let Some(guard) = l.guard.take() {
                        self.rt.block_on(guard.revert_now());
                    }
                    true
                }
                None => false,
            }
        }
        #[cfg(not(fw))]
        {
            let _ = handle;
            false
        }
    }

    /// Current firewall status DTO (live state, or the "off" default).
    ///
    /// A stored entry whose auto-revert deadline has already passed is reported
    /// as inactive (the dead-man's-switch has restored the previous ruleset).
    pub fn firewall_status(&self) -> FirewallStatusDto {
        #[cfg(fw)]
        {
            let slot = lock(&self.firewall);
            if let Some(live) = slot.as_ref() {
                if is_pending(live) {
                    return FirewallStatusDto {
                        active: true,
                        mode: "enforce",
                        handle: Some(live.handle.clone()),
                        revert_deadline: live.revert_deadline,
                        rule_count: live.rule_count,
                    };
                }
            }
        }
        crate::host_api::build_firewall_status()
    }

    // ── Egress allowlist ──────────────────────────────────────────────────────

    /// Snapshot of the operator-curated egress allowlist.
    pub fn egress_list(&self) -> Vec<EgressRuleDto> {
        lock(&self.egress).clone()
    }

    /// Add an egress rule, assigning a fresh id, and return the stored rule.
    pub fn egress_add(
        &self,
        host: String,
        port: Option<u16>,
        proto: &str,
        action: &str,
        comment: Option<String>,
    ) -> EgressRuleDto {
        let rule = EgressRuleDto {
            id: format!(
                "egr-{}-{}",
                now_ms(),
                HANDLE_SEQ.fetch_add(1, Ordering::Relaxed)
            ),
            host,
            port,
            proto: normalize_proto(proto),
            action: normalize_action(action),
            comment,
        };
        lock(&self.egress).push(rule.clone());
        rule
    }

    /// Remove the egress rule with `id`. Returns `true` if one was removed.
    pub fn egress_remove(&self, id: &str) -> bool {
        let mut rules = lock(&self.egress);
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() != before
    }

    /// Current egress mode ("off" | "monitor" | "enforce").
    pub fn egress_mode(&self) -> String {
        lock(&self.egress_mode).clone()
    }

    /// Set the egress mode. Unknown values are coerced to "off" (fail-safe).
    pub fn set_egress_mode(&self, mode: &str) -> &'static str {
        let normalized = match mode {
            "monitor" => "monitor",
            "enforce" => "enforce",
            _ => "off",
        };
        *lock(&self.egress_mode) = normalized.to_string();
        normalized
    }

    /// Whether inline NFQUEUE egress is enabled.
    pub fn inline_egress(&self) -> bool {
        *lock(&self.inline_egress)
    }

    /// Toggle inline NFQUEUE egress.
    pub fn set_inline_egress(&self, enabled: bool) {
        *lock(&self.inline_egress) = enabled;
    }

    // ── SSH bans ──────────────────────────────────────────────────────────────

    /// Snapshot of the current SSH ban list.
    pub fn bans_list(&self) -> Vec<BanDto> {
        lock(&self.bans).clone()
    }

    /// Record a ban (used by the brute-force tailer wiring).
    pub fn ban_add(&self, ban: BanDto) {
        lock(&self.bans).push(ban);
    }

    /// Remove the ban with `id`. Returns `true` if one was removed.
    ///
    /// NOTE: this clears the daemon's in-memory record. The kernel `sshd_bans`
    /// set element is not removed here (rustables 0.8 limitation, see
    /// `sshguard`); kernel bans clear on `belay` table flush.
    pub fn unban(&self, id: &str) -> bool {
        let mut bans = lock(&self.bans);
        let before = bans.len();
        bans.retain(|b| b.id != id);
        bans.len() != before
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a dynamic protocol string to one of the static contract values.
fn normalize_proto(p: &str) -> &'static str {
    match p {
        "udp" => "udp",
        "any" => "any",
        _ => "tcp",
    }
}

/// Map a dynamic action string to one of the static contract values.
/// Unknown values become "deny" (fail-safe).
fn normalize_action(a: &str) -> &'static str {
    if a == "allow" {
        "allow"
    } else {
        "deny"
    }
}

/// Convert a GUI ruleset value (matching `ProposedRulesetDto`) into the
/// kernel-facing [`ManagedRuleset`]. Best-effort: anti-lockout (the SSH pin) is
/// already encoded by the proposal; here we just project it back.
///
/// - `action == "deny"` on `0.0.0.0/0` or `::/0` ⇒ `default_drop`.
/// - `action == "allow"` on port 22 with a concrete IP host ⇒ `ssh_source`.
/// - other `action == "allow"` rules with a port ⇒ `allow_ports`.
#[cfg(fw)]
pub fn managed_from_ruleset_value(ruleset: &Value) -> ManagedRuleset {
    let rules = ruleset
        .get("rules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut allow_ports = Vec::new();
    let mut ssh_source = None;
    let mut default_drop = false;

    for r in &rules {
        let action = r.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let host = r.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let port = r
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok());

        if action == "deny" && (host == "0.0.0.0/0" || host == "::/0") {
            default_drop = true;
        } else if action == "allow" {
            if let Some(p) = port {
                if p == 22 {
                    match host.parse() {
                        Ok(ip) => ssh_source = Some(ip),
                        Err(_) => allow_ports.push(p), // port 22 open to all
                    }
                } else {
                    allow_ports.push(p);
                }
            }
        }
    }

    ManagedRuleset {
        allow_ports,
        ssh_source,
        default_drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Firewall tests (need the kernel-backend trait + mock) ─────────────────
    #[cfg(fw)]
    use crate::firewall::NftProgram;
    #[cfg(fw)]
    use std::sync::{Arc, Mutex};

    // Shared mock backend mirroring guard.rs's test double.
    #[cfg(fw)]
    #[derive(Default)]
    struct Inner {
        applied: Option<NftProgram>,
        restored: bool,
    }
    #[cfg(fw)]
    #[derive(Clone, Default)]
    struct SharedMock(Arc<Mutex<Inner>>);
    #[cfg(fw)]
    impl SharedMock {
        fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
            self.0.lock().unwrap()
        }
    }
    #[cfg(fw)]
    impl FwBackend for SharedMock {
        fn apply(&mut self, prog: &NftProgram) -> Result<(), FwError> {
            self.inner().applied = Some(prog.clone());
            Ok(())
        }
        fn dump(&mut self) -> Vec<u8> {
            serde_json::to_vec(&self.inner().applied).unwrap_or_default()
        }
        fn load(&mut self, _bytes: &[u8]) -> Result<(), FwError> {
            self.inner().restored = true;
            Ok(())
        }
    }

    #[cfg(fw)]
    fn sample_managed() -> ManagedRuleset {
        ManagedRuleset {
            allow_ports: vec![443, 80],
            ssh_source: None,
            default_drop: true,
        }
    }

    // NOTE: plain #[test] (NOT #[tokio::test]) so the state's internal
    // `rt.block_on` runs on a non-runtime thread. A long window means we always
    // confirm/revert well before the deadline — auto-revert timing is covered by
    // guard.rs's paused-clock tests.

    #[cfg(fw)]
    #[test]
    fn apply_then_status_is_active_with_deadline() {
        let state = DaemonState::new();
        let backend = SharedMock::default();
        let (handle, deadline) = state
            .firewall_apply_with(&sample_managed(), Duration::from_secs(600), backend.clone())
            .unwrap();
        assert!(backend.inner().applied.is_some(), "backend received apply");

        let status = state.firewall_status();
        assert!(status.active);
        assert_eq!(status.mode, "enforce");
        assert_eq!(status.handle.as_deref(), Some(handle.as_str()));
        assert_eq!(status.revert_deadline, Some(deadline));
        assert_eq!(status.rule_count, 3); // 2 allow ports + default drop
    }

    #[cfg(fw)]
    #[test]
    fn confirm_clears_deadline_keeps_active() {
        let state = DaemonState::new();
        let (handle, _) = state
            .firewall_apply_with(
                &sample_managed(),
                Duration::from_secs(600),
                SharedMock::default(),
            )
            .unwrap();
        assert!(state.firewall_confirm(&handle));
        let status = state.firewall_status();
        assert!(status.active, "confirmed firewall stays active");
        assert_eq!(
            status.revert_deadline, None,
            "confirmed → no pending revert"
        );
    }

    #[cfg(fw)]
    #[test]
    fn confirm_wrong_handle_is_rejected() {
        let state = DaemonState::new();
        state
            .firewall_apply_with(
                &sample_managed(),
                Duration::from_secs(600),
                SharedMock::default(),
            )
            .unwrap();
        assert!(!state.firewall_confirm("fw-does-not-exist"));
    }

    #[cfg(fw)]
    #[test]
    fn revert_restores_and_clears_status() {
        let state = DaemonState::new();
        let backend = SharedMock::default();
        let (handle, _) = state
            .firewall_apply_with(&sample_managed(), Duration::from_secs(600), backend.clone())
            .unwrap();
        assert!(state.firewall_revert(&handle));
        assert!(backend.inner().restored, "revert restored the snapshot");
        let status = state.firewall_status();
        assert!(!status.active, "reverted firewall is inactive");
        assert_eq!(status.mode, "off");
    }

    #[cfg(fw)]
    #[test]
    fn second_apply_while_pending_is_rejected() {
        let state = DaemonState::new();
        state
            .firewall_apply_with(
                &sample_managed(),
                Duration::from_secs(600),
                SharedMock::default(),
            )
            .unwrap();
        // A second apply while the first is still pending must be rejected
        // (single pending change at a time — prevents an orphaned guard).
        let err = state.firewall_apply_with(
            &sample_managed(),
            Duration::from_secs(600),
            SharedMock::default(),
        );
        assert!(err.is_err(), "second apply while pending must be rejected");
    }

    #[cfg(fw)]
    #[test]
    fn stale_entry_past_deadline_reports_inactive() {
        let state = DaemonState::new();
        // Simulate the state after the auto-revert TIMER fired: the slot still
        // holds an entry (the guard task could not clear it) but its deadline is
        // in the past and the guard is consumed.
        *lock(&state.firewall) = Some(FirewallLive {
            handle: "fw-stale".to_string(),
            revert_deadline: Some(0), // epoch — long past
            rule_count: 2,
            guard: None,
        });
        let status = state.firewall_status();
        assert!(
            !status.active,
            "stale (auto-reverted) entry must read inactive"
        );
        assert_eq!(status.mode, "off");
        // Confirming a stale entry must NOT resurrect it as active.
        assert!(!state.firewall_confirm("fw-stale"));
        // And a fresh apply is allowed (the stale entry is overwritten).
        assert!(state
            .firewall_apply_with(
                &sample_managed(),
                Duration::from_secs(600),
                SharedMock::default()
            )
            .is_ok());
    }

    #[test]
    fn egress_add_list_remove_roundtrip() {
        let state = DaemonState::new();
        assert!(state.egress_list().is_empty());
        let r = state.egress_add(
            "api.example.com".to_string(),
            Some(443),
            "tcp",
            "allow",
            None,
        );
        assert_eq!(state.egress_list().len(), 1);
        assert!(state.egress_remove(&r.id));
        assert!(state.egress_list().is_empty());
        assert!(!state.egress_remove(&r.id), "second remove is a no-op");
    }

    #[test]
    fn egress_mode_normalizes_unknown_to_off() {
        let state = DaemonState::new();
        assert_eq!(state.egress_mode(), "off");
        assert_eq!(state.set_egress_mode("enforce"), "enforce");
        assert_eq!(state.egress_mode(), "enforce");
        assert_eq!(state.set_egress_mode("bogus"), "off");
        assert_eq!(state.egress_mode(), "off");
    }

    #[cfg(fw)]
    #[test]
    fn managed_from_ruleset_projects_ssh_pin_and_drop() {
        let ruleset = serde_json::json!({
            "rules": [
                {"id": "auto-0", "host": "0.0.0.0", "port": 443, "proto": "tcp", "action": "allow"},
                {"id": "ssh-pinned", "host": "198.51.100.7", "port": 22, "proto": "tcp", "action": "allow"},
                {"id": "default-drop", "host": "0.0.0.0/0", "proto": "any", "action": "deny"}
            ]
        });
        let m = managed_from_ruleset_value(&ruleset);
        assert_eq!(m.allow_ports, vec![443]);
        assert_eq!(m.ssh_source, Some("198.51.100.7".parse().unwrap()));
        assert!(m.default_drop);
    }
}
