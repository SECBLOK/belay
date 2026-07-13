use belay_channels::whatsapp::WhatsAppChannel;
use belay_channels::{ChannelAdapter, Decision, DecisionRequest, NotificationChannel};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn whatsapp_deny_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "SM1"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"messages": [{"body": "deny"}]})),
        )
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "cat .env".into(),
        detail: "env".into(),
        rule_id: "secrets.x".into(),
    };
    assert_eq!(ch.ask(&req, Duration::from_secs(2)).await, Decision::Deny);
}

#[tokio::test]
async fn whatsapp_allow_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "SM2"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"messages": [{"body": "allow"}]})),
        )
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s2".into(),
        summary: "safe action".into(),
        detail: "details".into(),
        rule_id: "safe.rule".into(),
    };
    assert_eq!(ch.ask(&req, Duration::from_secs(2)).await, Decision::Allow);
}

#[tokio::test]
async fn whatsapp_timeout_is_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "SM3"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages": []})))
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s3".into(),
        summary: "timeout test".into(),
        detail: "details".into(),
        rule_id: "timeout.rule".into(),
    };
    assert_eq!(
        ch.ask(&req, Duration::from_millis(600)).await,
        Decision::Deny
    );
}

// ── Push-model adapter (ChannelAdapter): notify + listen ─────────────────────

/// `notify` sends the prompt to the approver's 1:1 thread with a Body that
/// instructs the exact text reply carrying the correlation nonce.
#[tokio::test]
async fn whatsapp_notify_embeds_nonce_in_body() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"sid": "SMout"})))
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one Messages.json POST");
    let body = String::from_utf8_lossy(&reqs[0].body);
    // Form-encoded body carries the To (approver) and the allow/deny instructions.
    assert!(body.contains("allow+noncexyz"), "instructs allow with nonce: {body}");
    assert!(body.contains("deny+noncexyz"), "instructs deny with nonce");
    assert!(
        body.contains("whatsapp%3A%2B2"),
        "sends to the configured approver number"
    );
}

/// `listen` normalizes an inbound WhatsApp text reply into an `InboundReply` with
/// the platform facts the daemon gate needs (principal, is_dm, nonce, msg_id,
/// allow). WhatsApp is 1:1, so `is_dm` is truthfully true. Case and a leading
/// slash on the verb are tolerated. The adapter makes NO trust decision.
#[tokio::test]
async fn whatsapp_listen_yields_normalized_inbound_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                // Our own outbound prompt — must be ignored.
                {"sid": "SMout", "direction": "outbound-api",
                 "from": "whatsapp:+1", "body": "Belay approval reply allow abc123nonce"},
                // The approver's inbound reply (leading slash + mixed case).
                {"sid": "SMin", "direction": "inbound",
                 "from": "whatsapp:+2", "body": "/Allow abc123nonce"}
            ]
        })))
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("listen produced a reply in time")
        .expect("channel yielded a reply");
    assert_eq!(reply.platform, "whatsapp");
    assert_eq!(reply.principal, "whatsapp:+2");
    assert!(reply.is_dm, "WhatsApp is 1:1 → is_dm");
    assert_eq!(reply.nonce, "abc123nonce");
    assert_eq!(reply.msg_id, "SMin");
    assert!(reply.allow, "'allow' → true");

    drop(rx); // closing the receiver makes listen return on its next loop check
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A `deny <nonce>` inbound reply is normalized with `allow = false`.
#[tokio::test]
async fn whatsapp_listen_reports_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/Messages\.json$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                {"sid": "SMdeny", "direction": "inbound",
                 "from": "whatsapp:+2", "body": "deny abc123nonce"}
            ]
        })))
        .mount(&srv)
        .await;

    let ch = WhatsAppChannel::new(
        "AC".into(),
        "tok".into(),
        "whatsapp:+1".into(),
        "whatsapp:+2".into(),
    )
    .with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert_eq!(reply.msg_id, "SMdeny");
    assert!(!reply.allow, "'deny' → false");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}
