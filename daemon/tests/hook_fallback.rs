//! When the socket is unreachable, the hook binary must still emit a decision
//! using the in-process Rust engine fallback and never invoke Python.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn hook_emits_decision_with_no_socket() {
    let bin = env!("CARGO_BIN_EXE_belay-hook");
    let mut child = Command::new(bin)
        .env("BELAY_SOCK", "/nonexistent/belayd.sock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains("permissionDecision"), "got: {txt}");
    assert!(
        txt.contains("deny"),
        "expected in-process engine deny, got: {txt}"
    );
}

#[test]
fn hook_in_process_engine_denies_dangerous_tool_without_socket() {
    // Verifies the in-process Rust fallback returns a deny for rm -rf /
    // when the daemon socket is unavailable — no Python subprocess involved.
    let bin = env!("CARGO_BIN_EXE_belay-hook");
    let mut child = Command::new(bin)
        .env("BELAY_SOCK", "/nonexistent/belayd.sock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(
        txt.contains("permissionDecision") && txt.contains("deny"),
        "in-process Rust engine must deny dangerous tool; got: {txt}"
    );
}
