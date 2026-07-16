//! Phase-1 Windows honeytoken canary watcher (Tier 1 — no admin, no ETW/WFP, no
//! driver). This is the FIRST real detection signal on the CLOSED desktop apps
//! (Claude Desktop, ChatGPT/Codex desktop): the target app reads a planted decoy
//! itself, so no hook, cooperation, or privilege is required.
//!
//! Mechanism: poll each canary file's `LastAccessTime` every ~1–2 s. A forward
//! move since the last poll means "something read it" → emit
//! `ObservedEvent { pid: 0, kind: Open, detail: <path> }`, which the existing
//! [`crate::honeypot::Honeypot::classify_access`] escalates to a CRITICAL verdict.
//!
//! HONEST LIMITS (surfaced in the UI and the report, never hidden):
//! - **Detection, never prevention** — the decoy is already read by the time we
//!   see the timestamp move. We record it; we do not (and cannot) stop it here.
//! - **No reader attribution** — a last-access poll cannot say WHICH process read
//!   the file, so `pid` is always `0`.
//! - **Suppressible/racy** — NTFS last-access can be disabled system-wide
//!   (`fsutil behavior set DisableLastAccess 1`); polling has latency. Verified
//!   ENABLED + sub-second on the dev box, but it is best-effort, not a guarantee.
//!
//! Why a purpose-built reactor instead of `Reflex::react`: Reflex's row asserts a
//! SIGKILL/`deny` ("reflex_kill", `tool:"ebpf"`) — accurate for the eBPF tier that
//! has a real pid to kill, but a lie here (pid 0, nothing prevented). The honesty
//! bar the handoff sets ("never imply it was stopped") wins: this writes an honest
//! `verdict:"detected"` / `prevented:false` row through the SAME hash-chained
//! `AuditWriter` the hook path uses, so it lands in `audit.ndjson` and the Live
//! Feed. Reflex remains the model for Phase 2/3, where a real pid enables kill-after.

use crate::observe::{EventKind, ObservedEvent};
use serde_json::json;
use std::time::SystemTime;

/// Read a path's last-access time WITHOUT updating it. `std::fs::metadata` issues
/// a metadata-only query (attribute read), which — verified empirically on the box
/// — does NOT bump the file's own last-access time, so the poller never self-trips.
fn read_atime_fs(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.accessed().ok()
}

struct Entry {
    /// Original canary path string — must match `Honeypot::canary_paths` exactly
    /// so `classify_access` recognizes the emitted event's `detail`.
    path: String,
    /// Last-observed access time; `None` if the file was unreadable at capture.
    last: Option<SystemTime>,
}

/// Change-detection state over a fixed canary set. The detection logic is a pure
/// function of (previous atime, current atime), so it is unit-testable with an
/// injected reader — no reliance on real filesystem timing in tests.
pub struct CanaryWatcher {
    entries: Vec<Entry>,
}

impl CanaryWatcher {
    /// Capture the baseline access time for each canary path (real filesystem).
    pub fn new(paths: &[String]) -> Self {
        Self::with_reader(paths, read_atime_fs)
    }

    /// Baseline capture with an injectable reader (tests supply a fake clock).
    fn with_reader(paths: &[String], read: impl Fn(&str) -> Option<SystemTime>) -> Self {
        let entries = paths
            .iter()
            .map(|p| Entry {
                path: p.clone(),
                last: read(p),
            })
            .collect();
        CanaryWatcher { entries }
    }

    /// Poll every canary once against the real filesystem; emit an `Open` event
    /// for each whose last-access time advanced since the previous poll.
    pub fn poll(&mut self) -> Vec<ObservedEvent> {
        self.poll_with(read_atime_fs)
    }

    /// Core change-detection, reader injected. Emits `Open{pid:0}` on a strictly
    /// forward atime move from a KNOWN baseline. A path that was unreadable at
    /// baseline is adopted silently once it becomes readable (no false trip).
    fn poll_with(&mut self, read: impl Fn(&str) -> Option<SystemTime>) -> Vec<ObservedEvent> {
        let mut out = Vec::new();
        for e in &mut self.entries {
            let cur = read(&e.path);
            if let (Some(prev), Some(now)) = (e.last, cur) {
                if now > prev {
                    out.push(ObservedEvent {
                        pid: 0,
                        kind: EventKind::Open,
                        detail: e.path.clone(),
                    });
                }
            }
            // Advance the baseline whenever we got a reading (so one read yields
            // exactly one event, and a transient unreadable poll doesn't reset it).
            if cur.is_some() {
                e.last = cur;
            }
        }
        out
    }
}

/// Append an HONEST, hash-chained canary-trip row to the real audit log
/// (`paths::audit_path()`), the same chain the hook path writes — so the trip is
/// durable proof and renders in the Live Feed. Detection-only: `verdict:"detected"`
/// (NOT `deny` — nothing was blocked) and `prevented:false`, never implying a stop.
///
/// `verdict.reason` carries the classifier's canary-read reason; we prepend the
/// honest framing so the Live Feed's `describeAction` shows "read, not prevented".
pub fn record_canary_trip(ev: &ObservedEvent, verdict: &crate::engine::types::Verdict) {
    let reason = format!(
        "canary tripped - a decoy secret was READ ({}); Belay detected it post-hoc but did NOT prevent the read (Tier-1 detection-only)",
        ev.detail
    );
    let row = json!({
        "ts": now_rfc3339(),
        "event": "canary/tripped",
        "session": "canary_win",
        "tool": "canary",
        // Distinct from allow/ask/deny: the Live Feed renders this WITHOUT the red
        // "Blocked" styling and does NOT count it as a deny (honest — see dash.tsx).
        "verdict": "detected",
        "reason": reason,
        "rules": verdict.rules,
        "input": {
            "path": ev.detail,
            "pid": ev.pid,            // always 0 — last-access polling can't attribute
            "prevented": false,        // detection-only; never blocked
        },
        "severity": "critical",
        "category": "honeypot",
        "explain": {
            "summary": "A decoy credential file was read. Belay saw it but could not prevent it.",
            "what": "A planted honeytoken (.env with fake credentials) had its last-access time move, meaning some process opened and read it.",
            "why_risky": "A real agent reading decoy secrets means it is scanning for credentials; the same scan would hit your real secrets. On the closed desktop apps this is the only signal Belay can produce today.",
            "normal_use": "Nothing legitimately reads these decoys - they exist only to catch credential-scanning.",
            "suggested_action": "Investigate what read it. This is DETECTION only - the read already happened and was not blocked (Tier-1, no admin/driver). Prevention needs the Phase 2/3 OS-level tiers.",
        },
    });

    let path = crate::paths::audit_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match crate::audit::AuditWriter::open(&path.to_string_lossy()) {
        Ok(mut w) => {
            if let Err(e) = w.append(row) {
                eprintln!("[belayd] canary audit append failed ({}): {e}", path.display());
            } else {
                eprintln!("[belayd] canary tripped (detection-only): {}", ev.detail);
            }
        }
        Err(e) => eprintln!("[belayd] canary audit open failed ({}): {e}", path.display()),
    }
}

fn now_rfc3339() -> String {
    use std::time::UNIX_EPOCH;
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::host_config::rfc3339_utc(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::Duration;

    // A fake, deterministic atime source so change-detection is tested without
    // relying on real filesystem last-access timing (which varies by OS/config).
    struct FakeClock {
        atimes: RefCell<HashMap<String, Option<SystemTime>>>,
    }
    impl FakeClock {
        fn new() -> Self {
            FakeClock {
                atimes: RefCell::new(HashMap::new()),
            }
        }
        fn set(&self, path: &str, t: Option<SystemTime>) {
            self.atimes.borrow_mut().insert(path.to_string(), t);
        }
        fn reader(&self) -> impl Fn(&str) -> Option<SystemTime> + '_ {
            move |p: &str| self.atimes.borrow().get(p).copied().flatten()
        }
    }

    fn t(base: SystemTime, secs: u64) -> SystemTime {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn emits_open_when_atime_advances() {
        let base = SystemTime::UNIX_EPOCH;
        let clock = FakeClock::new();
        let p = r"C:\decoy\.env".to_string();
        clock.set(&p, Some(t(base, 100)));

        let mut w = CanaryWatcher::with_reader(std::slice::from_ref(&p), clock.reader());
        // No change yet → no event.
        assert!(w.poll_with(clock.reader()).is_empty());

        // Simulate a read: atime moves forward.
        clock.set(&p, Some(t(base, 105)));
        let evs = w.poll_with(clock.reader());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::Open);
        assert_eq!(evs[0].pid, 0);
        assert_eq!(evs[0].detail, p);

        // Same atime on the next poll → no duplicate event.
        assert!(w.poll_with(clock.reader()).is_empty());
    }

    #[test]
    fn no_event_without_a_read() {
        let base = SystemTime::UNIX_EPOCH;
        let clock = FakeClock::new();
        let p = r"C:\decoy\aws_credentials".to_string();
        clock.set(&p, Some(t(base, 50)));
        let mut w = CanaryWatcher::with_reader(std::slice::from_ref(&p), clock.reader());
        for _ in 0..5 {
            assert!(w.poll_with(clock.reader()).is_empty());
        }
    }

    #[test]
    fn unreadable_baseline_then_readable_does_not_false_trip() {
        let base = SystemTime::UNIX_EPOCH;
        let clock = FakeClock::new();
        let p = r"C:\decoy\.env".to_string();
        // Baseline unreadable (None).
        clock.set(&p, None);
        let mut w = CanaryWatcher::with_reader(std::slice::from_ref(&p), clock.reader());
        // Becomes readable — adopt as baseline, DON'T emit (we never saw a prior value).
        clock.set(&p, Some(t(base, 10)));
        assert!(w.poll_with(clock.reader()).is_empty());
        // A subsequent real read now trips.
        clock.set(&p, Some(t(base, 11)));
        assert_eq!(w.poll_with(clock.reader()).len(), 1);
    }

    #[test]
    fn multiple_canaries_report_independently() {
        let base = SystemTime::UNIX_EPOCH;
        let clock = FakeClock::new();
        let a = r"C:\decoy\.env".to_string();
        let b = r"C:\decoy\aws_credentials".to_string();
        clock.set(&a, Some(t(base, 1)));
        clock.set(&b, Some(t(base, 1)));
        let paths = vec![a.clone(), b.clone()];
        let mut w = CanaryWatcher::with_reader(&paths, clock.reader());
        // Only `a` is read.
        clock.set(&a, Some(t(base, 2)));
        let evs = w.poll_with(clock.reader());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].detail, a);
    }

    // Integration: a REAL planted canary, read by an external process, is
    // detected by the real-filesystem poll AND classified CRITICAL Deny.
    #[test]
    fn real_read_of_planted_canary_detected_and_classified_critical() {
        use crate::engine::types::{Decision, Severity};
        use crate::honeypot::Honeypot;

        let tmp = tempfile::tempdir().unwrap();
        let hp = Honeypot::plant(tmp.path()).unwrap();
        let mut w = CanaryWatcher::new(&hp.canary_paths);

        // Read one canary's DATA (bumps last-access on a last-access-enabled vol).
        let target = hp.canary_paths[0].clone();
        let _ = std::fs::read(&target).unwrap();

        // Poll until detected (real atime updates can lag a beat); bounded so the
        // test fails fast rather than hanging if last-access is disabled on CI.
        let mut hit = None;
        for _ in 0..40 {
            let evs = w.poll();
            if let Some(ev) = evs.into_iter().find(|e| e.detail == target) {
                hit = Some(ev);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // If last-access is disabled on the test host, skip rather than false-fail
        // (the pure-logic tests above already prove the detection algorithm).
        let Some(ev) = hit else {
            eprintln!(
                "SKIP: last-access did not update on this host (NtfsDisableLastAccessUpdate?) — \
                 change-detection logic is covered by the fake-clock tests"
            );
            return;
        };

        assert_eq!(ev.kind, EventKind::Open);
        let verdict = hp
            .classify_access(&ev)
            .expect("a canary read must classify as a finding");
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.severity, Severity::Critical);
        assert!(verdict.rules.iter().any(|r| r == "honeypot.canary_read"));
    }
}
