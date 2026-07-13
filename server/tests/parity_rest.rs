//! REST endpoint parity. Formerly diffed each endpoint's JSON against a live
//! Python FastAPI oracle (`tests/parity/rest_oracle.py`). The Python package is
//! deleted, so the expected JSON is now the committed golden fixture
//! `fixtures/rest_oracle_golden.json`, captured from that oracle (over the exact
//! same fixed row set) while Python still existed.
use belay_server::audit_reader;
use serde_json::{json, Value};

/// The golden output of `rest_oracle.py` over the fixed row set below, captured
/// pre-deletion. Keys are sorted (the oracle emitted `json.dumps(sort_keys=True)`).
const REST_GOLDEN: &str = include_str!("fixtures/rest_oracle_golden.json");

#[test]
fn rest_parity() {
    let rows = json!([
        {"ts":"2026-06-26T10:00:00Z","event":"PreToolUse","session":"s","tool":"Bash",
         "verdict":"deny","reason":"rm","rules":["destructive.rm_rf"]},
        {"ts":"2026-06-26T10:01:00Z","event":"egress","session":"s","tool":"Bash",
         "verdict":"deny","destination":"webhook.site","rules":["egress.known_sink"]},
        {"ts":"2026-06-26T10:02:00Z","event":"PreToolUse","session":"s2","tool":"Read",
         "verdict":"allow","rules":[]},
        // Bug C: tie-break corpus — device "fleet-dev" has zzz-cat (first-seen) and aaa-cat (second),
        // each appearing once. Python Counter.most_common(1) returns zzz (first-inserted),
        // old Rust BTreeMap max picks aaa (alphabetically last on tie).
        {"ts":"2026-06-26T10:03:00Z","event":"PreToolUse","session":"s3","tool":"Bash",
         "verdict":"deny","device":"fleet-dev","rules":["zzz.first"]},
        {"ts":"2026-06-26T10:04:00Z","event":"PreToolUse","session":"s3","tool":"Bash",
         "verdict":"deny","device":"fleet-dev","rules":["aaa.second"]},
        // Bug D: non-UTC offset corpus — ts has +05:30, wall-clock minute=1 floors to 10:00,
        // but UTC equivalent is 04:31 which floors to 04:30. Python buckets by wall-clock (10:00),
        // old Rust buckets by naive_utc (04:30).
        {"ts":"2026-06-26T10:01:00+05:30","event":"PreToolUse","session":"s4","tool":"Read",
         "verdict":"allow","device":"fleet-dev","rules":[]}
    ]);
    let py: Value = serde_json::from_str(REST_GOLDEN)
        .expect("fixtures/rest_oracle_golden.json must be valid JSON");
    let arr: Vec<Value> = rows.as_array().unwrap().clone();

    assert_eq!(
        serde_json::to_value(audit_reader::summarize(&arr)).unwrap(),
        py["/api/posture"],
        "posture"
    );
    assert_eq!(
        audit_reader::to_findings(&arr),
        py["/api/findings"],
        "findings"
    );
    assert_eq!(
        audit_reader::sessions(&arr),
        py["/api/sessions"],
        "sessions"
    );
    assert_eq!(audit_reader::egress(&arr), py["/api/egress"], "egress");
    #[cfg(feature = "enterprise")]
    assert_eq!(audit_reader::fleet_summary(&arr), py["/api/fleet"], "fleet");
}
