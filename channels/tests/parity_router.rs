//! Router escalation parity. Formerly diffed against a live Python oracle
//! (`tests/parity/channel_oracle.py router`); the Python package is deleted, so
//! the expected decisions are now committed golden values captured from that
//! oracle while it still existed.
use belay_channels::router::{MockChannel, Router};
use belay_channels::{Decision, DecisionRequest};
use std::time::Duration;

/// Golden decisions captured from `channel_oracle.py router` (pre-deletion):
///   responses=["allow"] on_timeout=deny  => allow   (first allow wins)
///   responses=["deny"]  on_timeout=deny  => deny    (first deny wins)
///   responses=[]        on_timeout=deny  => deny    (no channels → on_timeout)
///   responses=[]        on_timeout=allow => allow   (no channels → on_timeout)
///   responses=["ask"]   on_timeout=deny  => deny    (ask is not a decision → on_timeout)
fn golden_router(responses: &[&str], on_timeout: &str) -> &'static str {
    match (responses, on_timeout) {
        (["allow"], "deny") => "allow",
        (["deny"], "deny") => "deny",
        ([], "deny") => "deny",
        ([], "allow") => "allow",
        (["ask"], "deny") => "deny",
        _ => panic!("no golden for responses={responses:?} on_timeout={on_timeout}"),
    }
}

async fn rust_router(responses: &[&str], on_timeout: &str) -> String {
    let to = |s: &str| match s {
        "allow" => Decision::Allow,
        "ask" => Decision::Ask,
        _ => Decision::Deny,
    };
    let chans: Vec<Box<dyn belay_channels::NotificationChannel>> = if responses.is_empty() {
        vec![]
    } else {
        vec![Box::new(MockChannel::new(
            responses.iter().map(|s| to(s)).collect(),
        ))]
    };
    let r = Router::new(chans, Duration::from_secs(1), to(on_timeout));
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "rm -rf /".into(),
        detail: "danger".into(),
        rule_id: "destructive.rm_rf".into(),
    };
    match r.escalate(&req).await {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
    .to_string()
}

#[tokio::test]
async fn router_parity() {
    let cases: &[(&[&str], &str)] = &[
        (&["allow"], "deny"), // first allow wins
        (&["deny"], "deny"),  // first deny wins
        (&[], "deny"),        // no channels → on_timeout
        (&[], "allow"),       // no channels → on_timeout=allow
        (&["ask"], "deny"),   // ask is not a real decision → on_timeout
    ];
    for (resp, to) in cases {
        assert_eq!(
            rust_router(resp, to).await,
            golden_router(resp, to),
            "resp={resp:?} on_timeout={to}"
        );
    }
}
