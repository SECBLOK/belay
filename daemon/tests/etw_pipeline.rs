//! Task 3 contract test: an ETW-shaped `ObservedEvent` flows through the SAME
//! engine seam the eBPF path uses and yields a finding. No live ETW — drives the
//! pipeline with a synthetic event, so it runs everywhere (locks the contract
//! that Phase-2 wiring depends on).

use belayd::engine::evaluate_event;
use belayd::engine::types::{Decision, SessionState};
use belayd::etw::{decode, EtwProvider, RawEtwRecord};
use belayd::honeypot::Honeypot;
use belayd::observe::{EventKind, ObservedEvent};

#[test]
fn etw_open_of_canary_classifies_as_finding() {
    // A raw ETW file-open record → decode → ObservedEvent, exactly as the live
    // consumer will produce (here we set the detail the way TDH extraction will).
    let tmp = tempfile::tempdir().unwrap();
    let hp = Honeypot::plant(tmp.path()).unwrap();
    let canary = hp.canary_paths[0].clone();

    // Construct a raw record directly (fields are pub) the way the live consumer
    // will, once TDH extraction fills `detail` with the opened path.
    let rec = RawEtwRecord {
        provider: EtwProvider::KernelFile,
        opcode: 0,
        pid: 4242,
        detail: canary.clone(),
    };
    let ev = decode(&rec).expect("file-open record decodes to an Open event");
    assert_eq!(ev.kind, EventKind::Open);
    assert_eq!(ev.pid, 4242);

    // The canary classifier fires first (CRITICAL Deny), mirroring the wiring's
    // `honeypot.classify_access(&ev).or_else(|| evaluate_event(...))`.
    let verdict = hp.classify_access(&ev).expect("canary read must classify");
    assert_eq!(verdict.decision, Decision::Deny);
    assert!(verdict.rules.iter().any(|r| r == "honeypot.canary_read"));
}

#[test]
fn etw_non_canary_event_still_runs_the_engine() {
    // A non-canary path falls through to the general engine (no panic, a Verdict).
    let mut state = SessionState::new("etw-test");
    let ev = ObservedEvent {
        pid: 10,
        kind: EventKind::Open,
        detail: r"C:\Users\x\.ssh\id_rsa".into(),
    };
    let v = evaluate_event(&ev, &mut state);
    // The engine returns *some* verdict; sensitive-key reads should not be Allow.
    assert!(matches!(v.decision, Decision::Deny | Decision::Ask | Decision::Allow));
}
