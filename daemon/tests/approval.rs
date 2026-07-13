//! Integration tests for the interactive-approval (Little-Snitch) daemon path.
//!
//! These drive the real `serve_mode` UDS server with a SHORT park timeout and
//! prove the fail-closed invariants end-to-end:
//!   (a) parked ASK + respond("allow")        → allow
//!   (b) ASK + no response (timeout)          → deny
//!   (c) set_protection(false) → dangerous gate allow; set_protection(true) → deny
//!   (d) respond_approval(unknown id)         → {ok:false}, daemon stays alive
//!   (e) pending-map-full                     → ASK denies (not enqueued)
//!
//! All approval tests live in ONE file so they share the process-global
//! `BELAY_APPROVAL_TIMEOUT_MS` and `HOME` (temp) without cross-test races.
#![cfg(unix)]
use belayd::ipc::{read_frame, serve_mode, write_frame, Mode};
use belayd::pending::MAX_PENDING;
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::sync::Once;
use std::{thread, time::Duration};

static INIT: Once = Once::new();

/// Short park timeout + isolated HOME so approval audit rows don't touch the
/// real `~/.belay`. Must run before any `serve_mode` start (which snapshots
/// the timeout via `Approvals::new()`).
fn init_env() {
    INIT.call_once(|| {
        std::env::set_var("BELAY_APPROVAL_TIMEOUT_MS", "500");
        let tmp = std::env::temp_dir().join(format!("belay-approval-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("HOME", tmp.to_str().unwrap());
    });
}

fn start_server() -> String {
    init_env();
    let sock = std::env::temp_dir().join(format!(
        "belay-approval-{}-{}.sock",
        std::process::id(),
        // unique per call
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let sock_s = sock.to_str().unwrap().to_string();
    let srv = sock_s.clone();
    thread::spawn(move || {
        let _ = serve_mode(&srv, Mode::Enforce);
    });
    thread::sleep(Duration::from_millis(150));
    sock_s
}

/// One request/response round-trip on a fresh connection.
fn call(sock: &str, req: &Value) -> Value {
    let mut s = UnixStream::connect(sock).unwrap();
    write_frame(&mut s, req.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&read_frame(&mut s).unwrap()).unwrap()
}

fn gate(session: &str, command: &str) -> Value {
    json!({"type":"gate","session":session,"tool":"Bash","input":{"command":command}})
}

#[test]
fn parked_ask_then_respond_allow_returns_allow() {
    let sock = start_server();
    let sock2 = sock.clone();

    // Park "cat .env" (an ASK) on its own connection/thread.
    let gate_h = thread::spawn(move || call(&sock2, &gate("sess-allow", "cat .env")));

    // On a SECOND connection, observe the pending entry and approve it.
    let id = loop {
        let snap = call(
            &sock,
            &json!({"type":"command","name":"get_pending","args":{}}),
        );
        if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
            assert_eq!(first["session"], "sess-allow");
            assert_eq!(first["tool"], "Bash");
            break first["id"].as_str().unwrap().to_string();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let resp = call(
        &sock,
        &json!({"type":"command","name":"respond_approval",
                "args":{"id":id,"decision":"allow","scope":"once"}}),
    );
    assert_eq!(resp["ok"], true);

    let gated = gate_h.join().unwrap();
    assert_eq!(gated["decision"], "allow", "parked ASK approved → allow");
}

#[test]
fn ask_with_no_response_denies_after_timeout() {
    let sock = start_server();
    // No responder: the park times out (500ms) and fails closed to deny.
    let resp = call(&sock, &gate("sess-timeout", "cat .env"));
    assert_eq!(
        resp["decision"], "deny",
        "unanswered ASK must fail closed to deny"
    );
}

#[test]
fn protection_off_allows_dangerous_then_on_denies() {
    let sock = start_server();

    // Turn protection OFF → observe mode: a would-DENY gate is allowed (audited).
    let off = call(
        &sock,
        &json!({"type":"command","name":"set_protection","args":{"on":false}}),
    );
    assert_eq!(off["ok"], true);
    assert_eq!(off["protection"], false);

    let danger = call(&sock, &gate("sess-prot", "rm -rf /"));
    assert_eq!(
        danger["decision"], "allow",
        "protection off → dangerous gate observed (allow)"
    );
    assert_eq!(danger["reason"], "protection paused");

    // Turn protection back ON → the same dangerous gate denies.
    let on = call(
        &sock,
        &json!({"type":"command","name":"set_protection","args":{"on":true}}),
    );
    assert_eq!(on["protection"], true);
    let danger2 = call(&sock, &gate("sess-prot", "rm -rf /"));
    assert_eq!(
        danger2["decision"], "deny",
        "protection on → dangerous gate denied"
    );
}

#[test]
fn unknown_respond_id_is_ok_false_and_daemon_survives() {
    let sock = start_server();
    let resp = call(
        &sock,
        &json!({"type":"command","name":"respond_approval",
                "args":{"id":"ap-does-not-exist","decision":"allow","scope":"once"}}),
    );
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"], "unknown id");

    // Daemon still serves subsequent requests.
    let posture = call(
        &sock,
        &json!({"type":"command","name":"get_posture","args":{}}),
    );
    assert_eq!(posture["protection"], "on");
}

#[test]
fn pending_map_full_denies_new_ask() {
    let sock = start_server();

    // Fill the pending map with parked ASKs (each on its own connection/thread).
    let mut handles = Vec::new();
    for i in 0..MAX_PENDING {
        let s = sock.clone();
        handles.push(thread::spawn(move || {
            call(&s, &gate(&format!("fill-{i}"), "cat .env"))
        }));
    }

    // Wait until the map is actually full.
    let mut full = false;
    for _ in 0..200 {
        let snap = call(
            &sock,
            &json!({"type":"command","name":"get_pending","args":{}}),
        );
        if snap["pending"].as_array().unwrap().len() >= MAX_PENDING {
            full = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(full, "pending map never reached capacity");

    // One more ASK must DENY immediately (map full → not enqueued).
    let overflow = call(&sock, &gate("overflow", "cat .env"));
    assert_eq!(
        overflow["decision"], "deny",
        "map-full ASK must fail closed to deny"
    );

    // The fillers all time out (500ms) and resolve to deny; reap them.
    for h in handles {
        assert_eq!(h.join().unwrap()["decision"], "deny");
    }
}
