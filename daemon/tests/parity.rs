//! Differential parity gate: Rust decide(corpus) == expected for every case.
use belayd::engine::decide::decide;
use belayd::engine::rules::RuleSet;
use belayd::engine::types::{Decision, SessionState, ToolCall};
use serde::Deserialize;
use serde_json::Value;
use std::fs;

#[derive(Deserialize)]
struct Case {
    tool: String,
    params: Value,
    expected: String,
}

fn d(s: &str) -> Decision {
    match s {
        "allow" => Decision::Allow,
        "ask" => Decision::Ask,
        "deny" => Decision::Deny,
        other => panic!("bad expected {other}"),
    }
}

#[test]
fn rust_matches_corpus_expected() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus.json");
    let cases: Vec<Case> = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let rs = RuleSet::load().unwrap();
    let mut failed = Vec::new();
    for c in &cases {
        let mut st = SessionState::new("s");
        let v = decide(
            &rs,
            &ToolCall {
                session: "s".into(),
                tool: c.tool.clone(),
                input: c.params.clone(),
            },
            &mut st,
        );
        if v.decision != d(&c.expected) {
            failed.push(format!(
                "tool={} params={} expected={} got={:?}",
                c.tool, c.params, c.expected, v.decision
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "parity mismatches:\n{}",
        failed.join("\n")
    );
}
