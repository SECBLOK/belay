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
//!
//! (e) is the one exception to "drives the real serve_mode UDS server": it
//! calls `belayd::pending::Approvals::park` directly instead. Filling the
//! pending map to capacity through 256 live connections over the real
//! `gate` path is both timing-dependent (see the doc comment on
//! `pending_map_full_denies_new_ask` below) and, independently, incompatible
//! with flood detection at that fan-out. Testing the fail-closed-at-capacity
//! invariant at the `pending` API level avoids both.
#![cfg(unix)]
use belayd::ipc::{read_frame, serve_mode, write_frame, Mode};
use belayd::pending::{now_ms, Approvals, ParkOutcome, MAX_PENDING};
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::sync::Once;
use std::{thread, time::Duration};

static INIT: Once = Once::new();

/// Short park timeout + isolated HOME so approval audit rows don't touch the
/// real `~/.belay`. Must run before any `serve_mode` start (which snapshots
/// the timeout via `Approvals::new()`).
///
/// GateGuard self-approval enforcement is turned OFF for this file. These
/// tests drive BOTH roles - the `gate` call and the `respond_approval` - from
/// this one test process, so the daemon sees a resolver that really is a
/// descendant of the recorded gating pid (which is `parent(peer)`, i.e. the
/// cargo test runner). That is indistinguishable from an agent approving its
/// own request, so the guard correctly overrides `allow` to Deny and the
/// round-trip assertions below could never pass with it on (it defaults ON
/// for Linux).
///
/// Disabling it here does not lose coverage: the guard is exercised directly
/// in `pending`'s unit tests, where `enforce_self_approval` is an explicit
/// argument rather than process-global state - see
/// `respond_local_detects_self_approval_from_a_real_descendant` and
/// `respond_local_enforce_on_overrides_self_approval_to_deny`. Keeping the
/// toggle out of this file also avoids a cross-test race, since every test
/// here shares one HOME and the flag is re-read on each respond.
fn init_env() {
    INIT.call_once(|| {
        std::env::set_var("BELAY_APPROVAL_TIMEOUT_MS", "500");
        let tmp = std::env::temp_dir().join(format!("belay-approval-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("HOME", tmp.to_str().unwrap());
        // Written via the daemon's own data-dir resolver so this lands wherever
        // the daemon will actually read it, on every platform.
        let dir = belayd::host_config::belay_dir();
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("gateguard_enforce.json"), br#"{"enabled": false}"#);
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

/// Drives `belayd::pending::Approvals::park` directly instead of through 256
/// live UDS connections routed over the real `gate` path. Two independent
/// problems rule the full-stack version out - not just "make the timeout
/// longer":
///
/// 1. Timing: parking 256 real connections (thread spawn + connect + write +
///    read, with every accept() serialized through the daemon's single
///    accept loop) does not reliably finish inside this file's shared
///    500ms park timeout (see `init_env`/`ask_with_no_response_denies_after_timeout`,
///    which needs that timeout to stay short). Instrumented locally, the
///    live-socket version topped out around 9-20 resident entries out of
///    256 before the earliest parks expired - the map never stayed full
///    long enough to observe, on a loaded machine or under debug-build
///    overhead.
/// 2. Flood detection: every filler here trips the SAME rule
///    (`secrets.sensitive_path`, from "cat .env"). Going through the real
///    `handle_request_approvals` orchestration (what `serve_mode` uses)
///    counts DISTINCT (session, tool, input) signatures per rule, and after
///    the 10th one within its 60s window it installs an auto deny-mute for
///    that rule (`note_ask_and_maybe_trip_flood` / `FLOOD_N` in
///    `pending.rs`, added after this test was first written). From then on
///    fillers 11..256 are denied by the mute BEFORE they ever reach `park`
///    - confirmed locally via each filler's `reason` field flipping to
///    "rule muted: secrets.sensitive_path" / "flood auto-deny (...)" well
///    short of 256. So the map can never hold more than ~10-20 entries via
///    the real gate path for this scenario, independent of timing, and no
///    test-only knob exists to disable flood detection (nor should
///    production behaviour change just to make a test pass).
///
/// The fail-closed-at-capacity invariant this test protects lives entirely
/// in `Approvals::park_with_source` (see `pending.rs`'s module doc), not in
/// the IPC/flood-detection orchestration layered on top of it - so driving
/// it at that API level tests the actual property without inheriting
/// either problem above. A long park timeout keeps every filler resident
/// until this test explicitly resolves it, so filling to capacity is a
/// deterministic wait, not a race against a clock.
#[test]
fn pending_map_full_denies_new_ask() {
    let approvals = Approvals::with_timeout(Duration::from_secs(30));

    // Fill the pending map with parked ASKs (each on its own thread).
    let mut handles = Vec::new();
    for i in 0..MAX_PENDING {
        let a = approvals.clone();
        handles.push(thread::spawn(move || {
            a.park(
                &format!("fill-{i}"),
                "Bash",
                &json!({"command": "cat .env"}),
                "reason",
                "rule.x",
                now_ms(),
                "info",
                None,
                None,
            )
        }));
    }

    // Wait until the map is actually full. Bounded by a generous deadline
    // (not a race against the 500ms park timeout above - there is none
    // here) so a genuine regression fails with a clear message instead of
    // hanging forever.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut full = false;
    while std::time::Instant::now() < deadline {
        if approvals.snapshot()["pending"].as_array().unwrap().len() >= MAX_PENDING {
            full = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(full, "pending map never reached capacity");

    // One more ASK must DENY immediately (map full → not enqueued).
    let overflow = approvals.park(
        "overflow",
        "Bash",
        &json!({"command": "cat .env"}),
        "reason",
        "rule.x",
        now_ms(),
        "info",
        None,
        None,
    );
    assert_eq!(
        overflow,
        ParkOutcome::Deny,
        "map-full ASK must fail closed to deny"
    );
    // Map size unchanged (overflow request was not enqueued).
    assert_eq!(
        approvals.snapshot()["pending"].as_array().unwrap().len(),
        MAX_PENDING
    );

    // Drain the parked fillers so threads exit (respond deny to each), then
    // reap them.
    let snap = approvals.snapshot();
    for item in snap["pending"].as_array().unwrap() {
        approvals.respond(item["id"].as_str().unwrap(), false, "once");
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), ParkOutcome::Deny);
    }
}
