use belay_channels::telegram::TelegramChannel;
use belay_channels::{ChannelAdapter, Decision, DecisionRequest, NotificationChannel};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn telegram_deny_callback() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/sendMessage$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": {"message_id": 1}})),
        )
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/getUpdates$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": [{"update_id": 1,
                "callback_query": {"id": "c1", "data": "deny:req1",
                                   "message": {"message_id": 1}}}]
        })))
        .mount(&srv)
        .await;

    let ch = TelegramChannel::new("tok".into(), "42".into())
        .with_base(srv.uri())
        .with_req_id("req1".into());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "cat .env".into(),
        detail: "reads env".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    assert_eq!(ch.ask(&req, Duration::from_secs(2)).await, Decision::Deny);
}

#[tokio::test]
async fn telegram_timeout_is_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/sendMessage$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": {"message_id": 1}})),
        )
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/getUpdates$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": []})))
        .mount(&srv)
        .await;

    let ch = TelegramChannel::new("tok".into(), "42".into())
        .with_base(srv.uri())
        .with_req_id("req1".into());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "cat .env".into(),
        detail: "reads env".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    assert_eq!(
        ch.ask(&req, Duration::from_millis(400)).await,
        Decision::Deny
    );
}

// ── Push-model adapter (ChannelAdapter): notify + listen ─────────────────────

/// `notify` sends the prompt with both inline buttons carrying the correlation
/// nonce in their callback_data (`a:<nonce>` / `d:<nonce>`).
#[tokio::test]
async fn telegram_notify_embeds_nonce_in_callback_data() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/sendMessage$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": {"message_id": 1}})),
        )
        .mount(&srv)
        .await;

    let ch = TelegramChannel::new("tok".into(), "42".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one sendMessage");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("a:noncexyz"), "allow button carries nonce: {body}");
    assert!(body.contains("d:noncexyz"), "deny button carries nonce");
    assert!(body.contains("\"chat_id\":\"42\""), "sends to configured chat");
}

/// `listen` normalizes a private-chat allow callback into an `InboundReply` with
/// the platform facts the daemon gate needs (principal, is_dm, nonce, msg_id).
/// The adapter itself makes NO trust decision — it only reports.
#[tokio::test]
async fn telegram_listen_yields_normalized_inbound_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/getUpdates$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": [{"update_id": 5, "callback_query": {
                "id": "cq99",
                "data": "a:abc123nonce",
                "from": {"id": 4242},
                "message": {"message_id": 7, "chat": {"id": 4242, "type": "private"}}
            }}]
        })))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/answerCallbackQuery$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&srv)
        .await;

    let ch = TelegramChannel::new("tok".into(), "4242".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("listen produced a reply in time")
        .expect("channel yielded a reply");
    assert_eq!(reply.platform, "telegram");
    assert_eq!(reply.principal, "4242");
    assert!(reply.is_dm, "private chat → is_dm");
    assert_eq!(reply.nonce, "abc123nonce");
    assert_eq!(reply.msg_id, "cq99");
    assert!(reply.allow);

    drop(rx); // closing the receiver makes listen return on its next send
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A callback from a GROUP chat is still reported, but with `is_dm = false` — the
/// adapter reports the fact; the daemon gate is what rejects non-DM replies.
#[tokio::test]
async fn telegram_listen_reports_group_chat_as_not_dm() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/getUpdates$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": [{"update_id": 9, "callback_query": {
                "id": "cqG",
                "data": "a:groupnonce",
                "from": {"id": 5},
                "message": {"message_id": 1, "chat": {"id": -100, "type": "group"}}
            }}]
        })))
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/answerCallbackQuery$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&srv)
        .await;

    let ch = TelegramChannel::new("tok".into(), "5".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert!(!reply.is_dm, "group chat → not a DM");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}
