#[cfg(test)]
mod tests {
    use crate::engine::{evaluate_event, types::*};
    use crate::observe::{EventKind, ObservedEvent};

    fn ev(kind: EventKind, detail: &str) -> ObservedEvent {
        ObservedEvent {
            pid: 7,
            kind,
            detail: detail.into(),
        }
    }

    #[test]
    fn proc_environ_read_is_critical_deny() {
        let mut st = SessionState::new("s");
        let v = evaluate_event(&ev(EventKind::Open, "/proc/1234/environ"), &mut st);
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.rules.iter().any(|r| r == "bypass.proc_environ"));
    }

    #[test]
    fn new_connect_destination_is_high_deny_then_remembered() {
        let mut st = SessionState::new("s");
        let v1 = evaluate_event(&ev(EventKind::Connect, "203.0.113.9:443"), &mut st);
        assert_eq!(v1.decision, Decision::Deny);
        assert_eq!(v1.severity, Severity::High);
        // Same dest again is now known -> allowed.
        let v2 = evaluate_event(&ev(EventKind::Connect, "203.0.113.9:443"), &mut st);
        assert_eq!(v2.decision, Decision::Allow);
    }

    #[test]
    fn secret_bytes_over_tls_is_critical_deny() {
        let mut st = SessionState::new("s");
        let v = evaluate_event(
            &ev(EventKind::TlsWrite, "POST /x AKIAIOSFODNN7EXAMPLE"),
            &mut st,
        );
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.rules.iter().any(|r| r == "bypass.secret_egress"));
        assert!(v.rules.iter().any(|r| r == "secrets.aws_access_key"));
    }

    #[test]
    fn benign_exec_is_allowed() {
        let mut st = SessionState::new("s");
        let v = evaluate_event(&ev(EventKind::Exec, "/usr/bin/ls"), &mut st);
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.severity, Severity::Info);
    }

    #[test]
    fn proc_self_environ_read_is_critical_deny() {
        let mut st = SessionState::new("s");
        // reading one's OWN environment to harvest injected secrets must be caught
        let v = evaluate_event(&ev(EventKind::Open, "/proc/self/environ"), &mut st);
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.rules.iter().any(|r| r == "bypass.proc_environ"));
    }

    #[test]
    fn generic_token_over_tls_is_high_not_critical() {
        let mut st = SessionState::new("s");
        // a generic "token=..." (secrets.bearer_or_kv) is suspicious but matches ordinary
        // HTTPS auth traffic, so it must be High (deny+alert), NOT Critical (no auto-kill).
        let v = evaluate_event(
            &ev(EventKind::TlsWrite, "POST /api token=abcdef0123456789xyz"),
            &mut st,
        );
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::High);
        assert!(v.rules.iter().any(|r| r == "bypass.secret_egress"));
        assert!(v.rules.iter().any(|r| r == "secrets.bearer_or_kv"));
    }

    #[test]
    fn open_write_to_protected_path_is_critical_deny() {
        let mut st = SessionState::new("s");
        let ev = ObservedEvent { pid: 9, kind: EventKind::OpenWrite,
            detail: "/home/u/project/rules/catalog.yaml".into() };
        let v = evaluate_event(&ev, &mut st);
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.rules.iter().any(|r| r == "bypass.self_tamper_write"));
    }

    #[test]
    fn open_write_to_ordinary_path_is_allowed() {
        let mut st = SessionState::new("s");
        let ev = ObservedEvent { pid: 9, kind: EventKind::OpenWrite,
            detail: "/home/u/project/src/main.rs".into() };
        assert_eq!(evaluate_event(&ev, &mut st).decision, Decision::Allow);
    }

    #[test]
    fn sensitive_env_read_is_high_ask() {
        let mut st = SessionState::new("s");
        // Native Windows path (backslashes) must fold to match the POSIX-shaped set.
        let v = evaluate_event(&ev(EventKind::Open, r"C:\Users\dennis\project\.env"), &mut st);
        assert_eq!(v.decision, Decision::Ask);
        assert_eq!(v.severity, Severity::High);
        assert!(v.rules.iter().any(|r| r == "secrets.sensitive_path"));
    }

    #[test]
    fn sensitive_credential_files_are_asked() {
        let mut st = SessionState::new("s");
        for path in [
            "/home/u/.aws/credentials",
            "/home/u/.ssh/id_ed25519",
            r"C:\Users\x\.ssh\id_rsa",
            "/home/u/.git-credentials",
            "/home/u/.env.production",
        ] {
            let v = evaluate_event(&ev(EventKind::Open, path), &mut st);
            assert_eq!(v.decision, Decision::Ask, "expected Ask for {path}");
        }
    }

    #[test]
    fn benign_open_and_lookalikes_stay_allowed() {
        let mut st = SessionState::new("s");
        for path in [
            "/home/u/project/src/main.rs",
            "/home/u/project/.environment", // NOT .env
            "/home/u/notes.txt",
        ] {
            assert_eq!(
                evaluate_event(&ev(EventKind::Open, path), &mut st).decision,
                Decision::Allow,
                "expected Allow for {path}"
            );
        }
    }

    #[test]
    fn read_only_open_of_protected_path_is_allowed() {
        // A plain Open (read) of catalog.yaml is fine — reads are not tampering.
        let mut st = SessionState::new("s");
        let ev = ObservedEvent { pid: 9, kind: EventKind::Open,
            detail: "/home/u/project/rules/catalog.yaml".into() };
        assert_eq!(evaluate_event(&ev, &mut st).decision, Decision::Allow);
    }
}
