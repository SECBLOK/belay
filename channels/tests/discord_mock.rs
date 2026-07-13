use belay_channels::discord::DiscordChannel;
use belay_channels::{ChannelAdapter, Decision, DecisionRequest, NotificationChannel};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn discord_deny_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/messages$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "10"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{"id":"11","content":"deny"}])),
        )
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "rm -rf /".into(),
        detail: "danger".into(),
        rule_id: "destructive.rm_rf".into(),
    };
    assert_eq!(ch.ask(&req, Duration::from_secs(2)).await, Decision::Deny);
}

#[tokio::test]
async fn discord_allow_reply() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/messages$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "10"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{"id":"11","content":"allow"}])),
        )
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "rm -rf /".into(),
        detail: "danger".into(),
        rule_id: "destructive.rm_rf".into(),
    };
    assert_eq!(ch.ask(&req, Duration::from_secs(2)).await, Decision::Allow);
}

#[tokio::test]
async fn discord_timeout_is_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/messages$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "10"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "rm -rf /".into(),
        detail: "danger".into(),
        rule_id: "destructive.rm_rf".into(),
    };
    assert_eq!(
        ch.ask(&req, Duration::from_millis(400)).await,
        Decision::Deny
    );
}

// ── Push-model adapter (ChannelAdapter): notify + listen ─────────────────────

/// `notify` POSTs the prompt to the DM channel with reply instructions that
/// carry the correlation nonce (`allow <nonce>` / `deny <nonce>`).
#[tokio::test]
async fn discord_notify_embeds_nonce_in_prompt() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/messages$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "10"})))
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one message POST");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("allow noncexyz"), "allow instruction carries nonce: {body}");
    assert!(body.contains("deny noncexyz"), "deny instruction carries nonce");
}

/// `listen` normalizes a DM allow reply into an `InboundReply` with the platform
/// facts the daemon gate needs (principal, is_dm, nonce, msg_id). A DM message
/// carries no `guild_id`, so `is_dm` must be reported `true`.
#[tokio::test]
async fn discord_listen_yields_normalized_inbound_reply() {
    let srv = MockServer::start().await;
    // Channel-type probe: type 1 = a genuine DM.
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"type": 1})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "555",
            "content": "allow abc123nonce",
            "author": {"id": "4242"},
            "guild_id": null
        }])))
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("listen produced a reply in time")
        .expect("channel yielded a reply");
    assert_eq!(reply.platform, "discord");
    assert_eq!(reply.principal, "4242");
    assert!(reply.is_dm, "no guild_id → is_dm");
    assert_eq!(reply.nonce, "abc123nonce");
    assert_eq!(reply.msg_id, "555");
    assert!(reply.allow);

    drop(rx); // closing the receiver makes listen return on its next send
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A reply that arrives inside a guild (server) channel is still reported, but
/// with `is_dm = false` — the adapter reports the fact; the daemon gate is what
/// rejects non-DM replies.
#[tokio::test]
async fn discord_listen_reports_guild_message_as_not_dm() {
    let srv = MockServer::start().await;
    // Channel-type probe: type 0 = a guild text channel, NOT a DM.
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"type": 0})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "777",
            "content": "deny groupnonce",
            "author": {"id": "5"},
            "guild_id": "900900"
        }])))
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert!(!reply.is_dm, "guild message → not a DM");
    assert!(!reply.allow, "deny → allow=false");
    assert_eq!(reply.nonce, "groupnonce");

    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A `pair <code>` DM is normalized to a `PAIR:<code>` nonce carrying the sender's
/// real principal — the daemon routes it to enrollment, not the approval gate.
/// (Same wiring is applied to whatsapp/matrix/mattermost/telegram listen paths.)
#[tokio::test]
async fn discord_listen_recognizes_pairing_request() {
    let srv = MockServer::start().await;
    // Channel-type probe: type 1 = a genuine DM.
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"type": 1})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/messages.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "888",
            "content": "/pair GH7KQ2",
            "author": {"id": "4242"},
            "guild_id": null
        }])))
        .mount(&srv)
        .await;

    let ch = DiscordChannel::new("tok".into(), "123".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });
    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert_eq!(reply.nonce, "PAIR:GH7KQ2");
    assert_eq!(reply.principal, "4242");
    assert!(reply.is_dm);
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}
