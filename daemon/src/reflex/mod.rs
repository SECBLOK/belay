//! Reflex: on a critical hook-bypass verdict, SIGKILL the offending pid,
//! escalate (pending_approval / alert), and write a hash-chained audit row.
use crate::engine::types::{Decision, Severity, Verdict};
use crate::observe::ObservedEvent;
use serde_json::json;

pub trait Killer {
    fn kill(&mut self, pid: u32) -> std::io::Result<()>;
}

pub trait Sink {
    fn escalate(&mut self, row: serde_json::Value);
    fn audit(&mut self, row: serde_json::Value);
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReflexAction {
    pub killed: bool,
    pub escalated: bool,
    pub audited: bool,
}

pub struct Reflex<K: Killer, S: Sink> {
    pub killer: K,
    pub sink: S,
    prev_hash: String,
}

impl<K: Killer, S: Sink> Reflex<K, S> {
    pub fn new(killer: K, sink: S) -> Self {
        Reflex {
            killer,
            sink,
            prev_hash: "genesis".to_string(),
        }
    }

    pub fn react(&mut self, ev: &ObservedEvent, verdict: &Verdict, session: &str) -> ReflexAction {
        let critical = verdict.decision == Decision::Deny && verdict.severity == Severity::Critical;
        if !critical {
            return ReflexAction::default();
        }

        // 1) SIGKILL — but never let a failed kill skip escalation/audit.
        let killed = self.killer.kill(ev.pid).is_ok();

        // 2) Escalate (UDS pending_approval / alert).
        self.sink.escalate(json!({
            "type": "pending_approval",
            "session": session,
            "pid": ev.pid,
            "reason": verdict.reason,
            "rules": verdict.rules,
            "severity": "critical",
            "source": "ebpf_reflex",
        }));

        // 3) Hash-chained audit row (Phase 6 schema).
        let row = self.audit_row(ev, verdict, session, killed);
        self.sink.audit(row);

        ReflexAction {
            killed,
            escalated: true,
            audited: true,
        }
    }

    fn audit_row(
        &mut self,
        ev: &ObservedEvent,
        verdict: &Verdict,
        session: &str,
        killed: bool,
    ) -> serde_json::Value {
        let ts = chrono_now();
        let core = json!({
            "ts": ts,
            "event": "reflex_kill",
            "session": session,
            "tool": "ebpf",
            "input": { "pid": ev.pid, "detail": ev.detail, "killed": killed },
            "verdict": "deny",
            "reason": verdict.reason,
            "rules": verdict.rules,
            "prev_hash": self.prev_hash,
        });
        let hash = sha256_hex(&format!("{}{}", self.prev_hash, core));
        self.prev_hash = hash.clone();
        let mut row = core;
        row["hash"] = json!(hash);
        row
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Production SIGKILL implementation (Linux/Unix).
#[cfg(unix)]
pub struct SignalKiller;
#[cfg(unix)]
impl Killer for SignalKiller {
    fn kill(&mut self, pid: u32) -> std::io::Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
}

/// Production process-termination implementation (Windows).
///
/// Uses `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` via the
/// `windows-sys` crate.  The handle is always closed before returning.
/// On failure the fn returns `Err(last_os_error())`; the `Killer` trait
/// contract in `Reflex::react` continues to escalate+audit even when
/// `kill()` returns `Err` (fail-safe — see `escalates_and_audits_even_if_kill_fails`).
#[cfg(windows)]
pub struct WinKiller;

#[cfg(windows)]
impl Killer for WinKiller {
    fn kill(&mut self, pid: u32) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        // SAFETY: all three FFI functions are well-defined for valid inputs.
        // OpenProcess returns 0 (NULL) on error; we check before using the handle.
        // CloseHandle is called unconditionally once we own a valid handle.
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if h.is_null() {
                // NULL handle — process not found or access denied; fail-safe.
                return Err(std::io::Error::last_os_error());
            }
            let ok = TerminateProcess(h, 1);
            CloseHandle(h);
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{Decision, Severity, Verdict};
    use crate::observe::{EventKind, ObservedEvent};

    #[derive(Default)]
    struct MockKiller {
        killed: Vec<u32>,
    }
    impl Killer for MockKiller {
        fn kill(&mut self, pid: u32) -> std::io::Result<()> {
            self.killed.push(pid);
            Ok(())
        }
    }
    #[derive(Default)]
    struct MockSink {
        escalations: Vec<serde_json::Value>,
        audits: Vec<serde_json::Value>,
    }
    impl Sink for MockSink {
        fn escalate(&mut self, row: serde_json::Value) {
            self.escalations.push(row);
        }
        fn audit(&mut self, row: serde_json::Value) {
            self.audits.push(row);
        }
    }

    fn crit() -> Verdict {
        Verdict {
            decision: Decision::Deny,
            reason: "x".into(),
            rules: vec!["bypass.proc_environ".into()],
            severity: Severity::Critical,
            primary_rule: None,
            category: None,
            owasp: None,
            atlas: None,
            explain: None,
        }
    }
    fn benign() -> Verdict {
        Verdict {
            decision: Decision::Allow,
            reason: String::new(),
            rules: vec![],
            severity: Severity::Info,
            primary_rule: None,
            category: None,
            owasp: None,
            atlas: None,
            explain: None,
        }
    }
    fn ev() -> ObservedEvent {
        ObservedEvent {
            pid: 4242,
            kind: EventKind::Open,
            detail: "/proc/1/environ".into(),
        }
    }

    #[test]
    fn kills_and_escalates_and_audits_on_critical() {
        let mut r = Reflex::new(MockKiller::default(), MockSink::default());
        let act = r.react(&ev(), &crit(), "sess-1");
        assert!(act.killed && act.escalated && act.audited);
        assert_eq!(r.killer.killed, vec![4242]);
        assert_eq!(r.sink.escalations.len(), 1);
        assert_eq!(r.sink.audits.len(), 1);
        // audit row carries the verdict + a hash chain field.
        let row = &r.sink.audits[0];
        assert_eq!(row["verdict"], "deny");
        assert!(row.get("hash").is_some());
    }

    #[test]
    fn noop_on_benign() {
        let mut r = Reflex::new(MockKiller::default(), MockSink::default());
        let act = r.react(&ev(), &benign(), "sess-1");
        assert!(!act.killed && !act.escalated && !act.audited);
        assert!(r.killer.killed.is_empty());
    }

    #[test]
    fn escalates_and_audits_even_if_kill_fails() {
        struct FailKiller;
        impl Killer for FailKiller {
            fn kill(&mut self, _: u32) -> std::io::Result<()> {
                Err(std::io::Error::from_raw_os_error(3)) // ESRCH: process gone
            }
        }
        let mut r = Reflex::new(FailKiller, MockSink::default());
        let act = r.react(&ev(), &crit(), "sess-1");
        assert!(!act.killed); // kill failed
        assert!(act.escalated && act.audited); // but we still escalated + audited
    }

    // Windows-only tests for WinKiller.  These are cfg-gated and do NOT run on
    // Linux/macOS CI — but they MUST compile when targeting x86_64-pc-windows-gnu.
    #[cfg(windows)]
    mod winkiller_tests {
        use super::super::*;

        /// Spawn a real child (`cmd /c pause`), kill it via WinKiller, assert it exits.
        #[test]
        fn kills_live_process() {
            let mut child = std::process::Command::new("cmd")
                .args(["/c", "pause"])
                .spawn()
                .expect("failed to spawn cmd /c pause");
            let pid = child.id();
            let mut killer = WinKiller;
            killer
                .kill(pid)
                .expect("WinKiller.kill should succeed for live process");
            // wait() must return without hanging — TerminateProcess forces exit.
            let _status = child.wait().expect("wait() failed after kill");
        }

        /// A bogus (non-existent) PID must return Err (OpenProcess returns NULL).
        #[test]
        fn bogus_pid_returns_err() {
            let mut killer = WinKiller;
            // 0xFFFF_FFFE is never a valid Windows process id.
            let result = killer.kill(0xFFFF_FFFE);
            assert!(result.is_err(), "expected Err for non-existent pid");
        }
    }
}
