//! Terminal-channel answer parsing parity. Formerly diffed against a live
//! Python oracle (`tests/parity/channel_oracle.py terminal`); the Python package
//! is deleted, so expected decisions are now committed golden values captured
//! from that oracle while it still existed.
use belay_channels::terminal::TerminalChannel;
use belay_channels::{Decision, DecisionRequest, NotificationChannel};
use std::time::Duration;

/// Golden decisions captured from `channel_oracle.py terminal <answer>`:
///   "y"/"yes"/"allow"/"YES" => allow ; "n"/""/"nope" => deny.
fn golden_terminal(answer: &str) -> &'static str {
    match answer {
        "y" | "yes" | "allow" | "YES" => "allow",
        "n" | "" | "nope" => "deny",
        _ => panic!("no golden for answer={answer:?}"),
    }
}

async fn rust_terminal(answer: &str) -> String {
    let a = answer.to_string();
    let ch = TerminalChannel::new(Box::new(move || Some(a.clone())), Box::new(|_| {}));
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "rm -rf /".into(),
        detail: "danger".into(),
        rule_id: "destructive.rm_rf".into(),
    };
    match ch.ask(&req, Duration::from_secs(1)).await {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
    .to_string()
}

#[tokio::test]
async fn terminal_parity() {
    for ans in ["y", "yes", "allow", "n", "", "nope", "YES"] {
        assert_eq!(
            rust_terminal(ans).await,
            golden_terminal(ans),
            "answer={ans}"
        );
    }
}
