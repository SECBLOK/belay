//! Tests for the gated stdio MCP shim (`belayd::mcp_proxy`).
//!
//! This is an enforcement chokepoint: the security-critical invariants are
//! FAIL-CLOSED. The three invariants the reviewer checks:
//!   1. ASK is treated as DENY (a headless proxy cannot answer an ask).
//!   2. ANY error (ruleset load fail, malformed params, UDS error) → DENY.
//!   3. On deny, the original tools/call message is NEVER forwarded to the child.
//!
//! We write fail-closed unit tests first (TDD), then the projection tests, then
//! a real integration test driving `run_proxy` against a fake echo MCP server.

use belayd::engine::types::Decision;
use belayd::mcp_proxy::{deny_envelope, effective_calls, gate_decision_for_test, GateConfig};
use serde_json::json;

// ──────────────────────────────────────────────────────────────
// effective_calls projection
// ──────────────────────────────────────────────────────────────

#[test]
fn effective_calls_base_call_plus_catch_all_for_arbitrary_fields() {
    // The base mcp__ call is always first with the raw args. An arbitrary string
    // field (`foo`) that no explicit command/path projection covers now also adds
    // a catch-all Bash projection so its content is inspected (P2/Task5).
    let params = json!({"name": "list", "arguments": {"foo": "bar"}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls[0].session, "srv");
    assert_eq!(calls[0].tool, "mcp__srv__list");
    assert_eq!(calls[0].input, json!({"foo": "bar"}));
    // The catch-all serializes the full args into a Bash command for rule matching.
    assert!(
        calls.iter().any(|c| c.tool == "Bash"
            && c.input["command"].as_str().is_some_and(|s| s.contains("\"foo\""))),
        "an uncovered string field must add a catch-all Bash projection: {calls:?}"
    );
    // No Read projection (no path-like field).
    assert!(!calls.iter().any(|c| c.tool == "Read"));
}

#[test]
fn effective_calls_command_adds_bash() {
    let params = json!({"name": "shell", "arguments": {"command": "ls -la"}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].tool, "Bash");
    assert_eq!(calls[1].input, json!({"command": "ls -la"}));
}

#[test]
fn effective_calls_cmd_key_also_adds_bash() {
    let params = json!({"name": "shell", "arguments": {"cmd": "whoami"}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].tool, "Bash");
    assert_eq!(calls[1].input, json!({"command": "whoami"}));
}

#[test]
fn effective_calls_path_adds_read() {
    let params = json!({"name": "reader", "arguments": {"path": "/etc/passwd"}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].tool, "Read");
    assert_eq!(calls[1].input, json!({"file_path": "/etc/passwd"}));
}

#[test]
fn effective_calls_file_path_and_file_keys_add_read() {
    for key in ["file_path", "file"] {
        let params = json!({"name": "reader", "arguments": {key: "/tmp/x"}});
        let calls = effective_calls("srv", &params);
        assert_eq!(calls.len(), 2, "key {key} should add a Read call");
        assert_eq!(calls[1].tool, "Read");
        assert_eq!(calls[1].input, json!({"file_path": "/tmp/x"}));
    }
}

#[test]
fn effective_calls_empty_strings_add_nothing() {
    let params = json!({"name": "x", "arguments": {"command": "", "path": ""}});
    let calls = effective_calls("srv", &params);
    assert_eq!(
        calls.len(),
        1,
        "empty-string command/path must NOT add projected calls"
    );
}

#[test]
fn effective_calls_command_and_path_add_both() {
    let params = json!({"name": "x", "arguments": {"command": "ls", "path": "/etc/hosts"}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].tool, "Bash");
    assert_eq!(calls[2].tool, "Read");
}

#[test]
fn effective_calls_non_string_command_ignored() {
    // A non-string command (e.g. a number/array) must not project a Bash call.
    let params = json!({"name": "x", "arguments": {"command": 42}});
    let calls = effective_calls("srv", &params);
    assert_eq!(calls.len(), 1);
}

// ──────────────────────────────────────────────────────────────
// FAIL-CLOSED gate decision (the heart of the chokepoint)
// ──────────────────────────────────────────────────────────────

#[test]
fn gate_dangerous_bash_denies() {
    let cfg = GateConfig::load("srv");
    let params = json!({"name": "shell", "arguments": {"command": "rm -rf /"}});
    let d = gate_decision_for_test(&cfg, &params);
    assert_eq!(d, Decision::Deny, "rm -rf / projected as Bash MUST deny");
}

#[test]
fn gate_benign_call_allows() {
    let cfg = GateConfig::load("srv");
    // A plain MCP call with benign args that trips no rule → Allow.
    let params = json!({"name": "ping", "arguments": {"ok": true}});
    let d = gate_decision_for_test(&cfg, &params);
    assert_eq!(d, Decision::Allow, "benign call should be allowed");
}

#[test]
fn gate_ask_is_treated_as_deny() {
    // INVARIANT 1: ASK → DENY. We force the gate to observe an ASK verdict and
    // assert it is mapped to Deny. `GateConfig::with_forced` lets the test inject
    // a fixed decision to prove the ASK→DENY mapping without depending on a
    // specific catalog rule that happens to ASK.
    let cfg = GateConfig::with_forced(Decision::Ask);
    let params = json!({"name": "x", "arguments": {}});
    let d = gate_decision_for_test(&cfg, &params);
    assert_eq!(
        d,
        Decision::Deny,
        "ASK must be treated as DENY (fail-closed)"
    );
}

#[test]
fn gate_ruleset_load_failure_denies() {
    // INVARIANT 2: any error → DENY. A GateConfig whose ruleset failed to load
    // must deny every tools/call regardless of content.
    let cfg = GateConfig::with_load_failure();
    let params = json!({"name": "ping", "arguments": {"ok": true}});
    let d = gate_decision_for_test(&cfg, &params);
    assert_eq!(
        d,
        Decision::Deny,
        "ruleset-load failure must fail closed (DENY)"
    );
}

#[test]
fn gate_most_restrictive_wins() {
    // benign name + dangerous command: the Bash projection denies, and DENY wins
    // over the (allowed) base mcp__ call.
    let cfg = GateConfig::load("srv");
    let params = json!({"name": "innocent", "arguments": {"command": "rm -rf /"}});
    let d = gate_decision_for_test(&cfg, &params);
    assert_eq!(d, Decision::Deny);
}

// ──────────────────────────────────────────────────────────────
// Deny envelope shape (exact, with id echo incl. null)
// ──────────────────────────────────────────────────────────────

#[test]
fn deny_envelope_shape_with_int_id() {
    let env = deny_envelope(&json!(7), Decision::Deny, "destructive.rm_rf:..");
    assert_eq!(env["jsonrpc"], "2.0");
    assert_eq!(env["id"], json!(7));
    assert_eq!(env["error"]["code"], -32000);
    let msg = env["error"]["message"].as_str().unwrap();
    assert!(
        msg.starts_with("blocked by Belay (deny): "),
        "got: {msg}"
    );
}

#[test]
fn deny_envelope_shape_with_null_id() {
    let env = deny_envelope(&serde_json::Value::Null, Decision::Deny, "r");
    assert_eq!(env["jsonrpc"], "2.0");
    assert_eq!(env["id"], serde_json::Value::Null);
    assert_eq!(env["error"]["code"], -32000);
}

#[test]
fn deny_envelope_decision_is_lowercase() {
    // ASK→deny path still labels the actual decision lowercased ("ask").
    let env = deny_envelope(&json!("abc"), Decision::Ask, "needs approval");
    let msg = env["error"]["message"].as_str().unwrap();
    assert_eq!(msg, "blocked by Belay (ask): needs approval");
    assert_eq!(env["id"], json!("abc"));
}

// ──────────────────────────────────────────────────────────────
// Integration: real subprocess echo MCP server
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn integration_echo_server_forwards_and_blocks() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    // Fake echo MCP server: read each NDJSON line, echo it back verbatim with a
    // trailing newline. Records every line it RECEIVES — used to prove a denied
    // tools/call never reaches the child.
    let echo_cmd = "while IFS= read -r l; do printf '%s\\n' \"$l\"; done";

    // Spawn run_proxy as a child process (the unified binary's mcp-proxy arm
    // shells out to /bin/sh -c). To drive it with piped stdio we run the proxy
    // logic through the library's pump over a real child: we spawn the proxy in
    // a task using `run_proxy`-compatible plumbing via a helper that pumps over
    // our own pipes. The simplest faithful test is to spawn the unified binary
    // itself; but to keep this hermetic we drive `run_proxy` directly by
    // replacing process stdio is not possible — so we use the in-process pump
    // helper exposed for tests.

    // Build the child (echo server) directly and run the c2s/s2c pumps over
    // in-memory duplex pipes via the test-only `pump_streams` entrypoint.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(echo_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn echo server");

    let child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();

    // Our "client stdin" feeding the proxy, and the proxy's "client stdout".
    let (mut client_writer, proxy_in) = tokio::io::duplex(64 * 1024);
    let (proxy_out, client_reader) = tokio::io::duplex(64 * 1024);

    let cfg = GateConfig::load("echo-server");
    let pump = tokio::spawn(async move {
        belayd::mcp_proxy::pump_streams(proxy_in, proxy_out, child_stdin, child_stdout, cfg)
            .await;
    });

    let mut out = BufReader::new(client_reader);

    // 1) initialize → forwarded + echoed (not gated)
    client_writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .await
        .unwrap();
    let mut line = String::new();
    out.read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(v["method"], "initialize", "initialize must be echoed back");
    assert_eq!(v["id"], json!(1));

    // 2) benign tools/call → forwarded + echoed
    line.clear();
    client_writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ping\",\"arguments\":{\"ok\":true}}}\n")
        .await
        .unwrap();
    out.read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        v["method"], "tools/call",
        "benign tools/call must be forwarded+echoed"
    );
    assert_eq!(v["id"], json!(2));

    // 3) dangerous tools/call → -32000 deny on OUR stdout, child never sees it.
    line.clear();
    client_writer
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"shell\",\"arguments\":{\"command\":\"rm -rf /\"}}}\n")
        .await
        .unwrap();
    out.read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        v["error"]["code"], -32000,
        "dangerous call must be denied with -32000"
    );
    assert_eq!(v["id"], json!(3), "deny envelope echoes the request id");
    assert!(v.get("result").is_none(), "deny envelope has no result");

    // 4) malformed line → forwarded verbatim to the child, echoed back verbatim.
    line.clear();
    client_writer
        .write_all(b"this is not json\n")
        .await
        .unwrap();
    out.read_line(&mut line).await.unwrap();
    assert_eq!(
        line, "this is not json\n",
        "malformed line must be forwarded verbatim"
    );

    // Close client stdin → c2s sees EOF → child stdin closes → echo exits.
    drop(client_writer);
    let _ = pump.await;
    let _ = child.wait().await;
}
