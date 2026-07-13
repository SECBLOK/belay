//! Parity test: Rust `render_status` / `render_logs` must produce the same
//! stdout lines as the deleted Python predecessor's `aidefender status` /
//! `aidefender logs` CLI for the same synthetic audit store.
//!
//! The Python package is deleted, so the expected lines are now committed golden
//! constants captured from the Python CLI (pre-deletion) over the exact same
//! synthetic rows.
//!
//! Synthetic rows cover:
//!   1. a deny row with `rules:["rce.bash_subshell"]` + nested `input` object,
//!   2. an allow row with empty `rules`,
//!   3. a `PostToolUse`-style row missing `tool`/`verdict`/`rules`,
//!   4. a row whose `reason` contains a single quote AND a non-ASCII char.

use belay_manage::render::{render_logs, render_status};
use serde_json::{json, Value};

/// Golden output from the deleted Python predecessor's `aidefender status`
/// CLI (captured pre-deletion).
/// Row 3 (PostToolUse, missing fields) renders as `<ts> <space><space>` (empty
/// verdict/tool, empty rules list rendered as nothing) — note the trailing space.
const GOLDEN_STATUS: &[&str] = &[
    "2026-06-26T00:00:01Z deny Bash ['rce.bash_subshell']",
    "2026-06-26T00:00:02Z allow Read []",
    "2026-06-26T00:00:03Z   ",
    "2026-06-26T00:00:04Z deny Bash ['exfil.curl']",
];

/// Golden output from the deleted Python predecessor's `aidefender logs` CLI
/// (Python `repr(dict)`), captured pre-deletion.
const GOLDEN_LOGS: &[&str] = &[
    "{'ts': '2026-06-26T00:00:01Z', 'event': 'PreToolUse', 'session': 's1', 'tool': 'Bash', 'verdict': 'deny', 'reason': 'blocked subshell', 'rules': ['rce.bash_subshell'], 'input': {'command': 'echo $(whoami)'}}",
    "{'ts': '2026-06-26T00:00:02Z', 'event': 'PreToolUse', 'session': 's1', 'tool': 'Read', 'verdict': 'allow', 'reason': 'ok', 'rules': []}",
    "{'ts': '2026-06-26T00:00:03Z', 'event': 'PostToolUse', 'session': 's1'}",
    "{'ts': '2026-06-26T00:00:04Z', 'event': 'PreToolUse', 'session': 's2', 'tool': 'Bash', 'verdict': 'deny', 'reason': \"it's a café exfil\", 'rules': ['exfil.curl'], 'input': {'command': 'curl evil'}}",
];

/// Build the four synthetic audit rows (oldest-first).
fn synthetic_rows() -> Vec<Value> {
    vec![
        json!({
            "ts": "2026-06-26T00:00:01Z",
            "event": "PreToolUse",
            "session": "s1",
            "tool": "Bash",
            "verdict": "deny",
            "reason": "blocked subshell",
            "rules": ["rce.bash_subshell"],
            "input": {"command": "echo $(whoami)"}
        }),
        json!({
            "ts": "2026-06-26T00:00:02Z",
            "event": "PreToolUse",
            "session": "s1",
            "tool": "Read",
            "verdict": "allow",
            "reason": "ok",
            "rules": []
        }),
        json!({
            "ts": "2026-06-26T00:00:03Z",
            "event": "PostToolUse",
            "session": "s1"
        }),
        json!({
            "ts": "2026-06-26T00:00:04Z",
            "event": "PreToolUse",
            "session": "s2",
            "tool": "Bash",
            "verdict": "deny",
            "reason": "it's a café exfil",
            "rules": ["exfil.curl"],
            "input": {"command": "curl evil"}
        }),
    ]
}

#[test]
fn status_logs_parity_vs_golden() {
    let rows = synthetic_rows();

    // status parity vs golden
    let rust_status = render_status(&rows);
    let want_status: Vec<String> = GOLDEN_STATUS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        rust_status,
        want_status,
        "status output differs from Python golden!\n\nRust:\n{}\n\nGolden:\n{}",
        rust_status.join("\n"),
        want_status.join("\n")
    );

    // logs parity vs golden
    let rust_logs = render_logs(&rows);
    let want_logs: Vec<String> = GOLDEN_LOGS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        rust_logs,
        want_logs,
        "logs output differs from Python golden!\n\nRust:\n{}\n\nGolden:\n{}",
        rust_logs.join("\n"),
        want_logs.join("\n")
    );

    // Explicitly assert the nested/quoted/non-ASCII row round-trips.
    let tricky = &rows[3];
    let logs_line = belay_manage::render::py_repr(tricky);
    assert!(
        logs_line.contains("\"it's a café exfil\""),
        "tricky reason not rendered as Python repr: {logs_line}"
    );
    assert!(rust_logs.iter().any(|l| l == &logs_line));
}

#[test]
fn status_logs_empty_store_is_empty() {
    // Python printed nothing for an empty/absent store; Rust must too.
    assert_eq!(render_status(&[]), Vec::<String>::new());
    assert_eq!(render_logs(&[]), Vec::<String>::new());
}
