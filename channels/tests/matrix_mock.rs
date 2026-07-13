use belay_channels::matrix::MatrixChannel;
use belay_channels::{ChannelAdapter, DecisionRequest};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Two-way adapter (ChannelAdapter): notify + listen ────────────────────────

/// `notify` PUTs an `m.room.message` whose body carries the correlation nonce and
/// the exact `allow <nonce>` / `deny <nonce>` reply instructions.
#[tokio::test]
async fn matrix_notify_embeds_nonce_in_body() {
    let srv = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(r".*/send/m\.room\.message/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"event_id": "$evt1"})))
        .mount(&srv)
        .await;

    let ch = MatrixChannel::new("tok".into(), "!room:localhost".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one send");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("allow noncexyz"), "allow instruction carries nonce: {body}");
    assert!(body.contains("deny noncexyz"), "deny instruction carries nonce");
    assert!(body.contains("\"msgtype\":\"m.text\""), "sent as a text message");
}

/// `listen` normalizes an `allow <nonce>` text reply from the configured direct
/// room into an `InboundReply` with the platform facts the daemon gate needs
/// (principal, is_dm, nonce, msg_id). The adapter makes NO trust decision.
#[tokio::test]
async fn matrix_listen_yields_normalized_inbound_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/sync$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "next_batch": "s2",
            "rooms": {"join": {"!room:localhost": {
                "summary": {"m.joined_member_count": 2},
                "timeline": {"events": [
                {
                    "type": "m.room.message",
                    "event_id": "$evt42",
                    "sender": "@approver:localhost",
                    "content": {"msgtype": "m.text", "body": "allow abc123nonce"}
                }
            ]}}}}
        })))
        .mount(&srv)
        .await;

    let ch = MatrixChannel::new("tok".into(), "!room:localhost".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("listen produced a reply in time")
        .expect("channel yielded a reply");
    assert_eq!(reply.platform, "matrix");
    assert_eq!(reply.principal, "@approver:localhost");
    assert!(reply.is_dm, "configured 1:1 direct room → is_dm");
    assert_eq!(reply.nonce, "abc123nonce");
    assert_eq!(reply.msg_id, "$evt42");
    assert!(reply.allow);

    drop(rx); // closing the receiver makes listen return on its next send
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A `/deny <nonce>` reply (leading slash, deny intent) is parsed to
/// `allow = false` — proving the case/slash-tolerant text parser.
#[tokio::test]
async fn matrix_listen_parses_slash_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/sync$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "next_batch": "s2",
            "rooms": {"join": {"!room:localhost": {"timeline": {"events": [
                {
                    "type": "m.room.message",
                    "event_id": "$evtD",
                    "sender": "@approver:localhost",
                    "content": {"msgtype": "m.text", "body": "/DENY nonce9"}
                }
            ]}}}}
        })))
        .mount(&srv)
        .await;

    let ch = MatrixChannel::new("tok".into(), "!room:localhost".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert_eq!(reply.nonce, "nonce9");
    assert!(!reply.allow, "deny → allow = false");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A reply from a room with MORE than 2 joined members is reported with
/// `is_dm = false`: the adapter derives DM-ness from the member count, so a
/// misconfigured shared room cannot masquerade as a private approval channel
/// (the daemon gate then rejects the non-DM reply, fail-closed).
#[tokio::test]
async fn matrix_listen_multi_member_room_reports_not_dm() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/sync$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "next_batch": "s2",
            "rooms": {"join": {"!room:localhost": {
                "summary": {"m.joined_member_count": 5},
                "timeline": {"events": [
                {
                    "type": "m.room.message",
                    "event_id": "$evtM",
                    "sender": "@someone:localhost",
                    "content": {"msgtype": "m.text", "body": "allow sharednonce"}
                }
            ]}}}}
        })))
        .mount(&srv)
        .await;

    let ch = MatrixChannel::new("tok".into(), "!room:localhost".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert!(!reply.is_dm, "5-member room must NOT be reported as a DM");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}
