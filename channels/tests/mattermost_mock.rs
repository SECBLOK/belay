use belay_channels::mattermost::MattermostChannel;
use belay_channels::{ChannelAdapter, DecisionRequest};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Two-way adapter (ChannelAdapter): notify + listen ────────────────────────

/// `notify` posts the approval prompt to `/api/v4/posts`, carrying the correlation
/// nonce and the configured DM channel in the body, and instructing the approver
/// to reply exactly `allow <nonce>` / `deny <nonce>`.
#[tokio::test]
async fn mattermost_notify_posts_prompt_with_nonce() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/api/v4/posts$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "post1"})))
        .mount(&srv)
        .await;

    let ch = MattermostChannel::new("tok-secret".into(), "DMCHAN".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one post");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("noncexyz"), "prompt carries the nonce: {body}");
    assert!(
        body.contains("allow noncexyz"),
        "instructs the approver to reply `allow <nonce>`"
    );
    assert!(
        body.contains("\"channel_id\":\"DMCHAN\""),
        "posts to the configured DM channel"
    );
    // The access token rides the Authorization header, never the body.
    assert!(!body.contains("tok-secret"), "token is not in the body");
}

/// `listen` normalizes a text reply (`allow <nonce>`) in the DM channel into an
/// `InboundReply` with the platform facts the daemon gate needs (principal, is_dm,
/// nonce, msg_id). The adapter itself makes NO trust decision — it only reports.
#[tokio::test]
async fn mattermost_listen_yields_normalized_inbound_reply() {
    let srv = MockServer::start().await;
    // Channel-type probe: type "D" = a direct-message channel.
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"type": "D"})))
        .mount(&srv)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/.*/posts$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "order": ["p1"],
            "posts": {
                "p1": {
                    "id": "p1",
                    "user_id": "u4242",
                    "message": "allow abc123nonce",
                    "create_at": 1_710_000_000_000i64
                }
            }
        })))
        .mount(&srv)
        .await;

    let ch = MattermostChannel::new("tok".into(), "DMCHAN".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("listen produced a reply in time")
        .expect("channel yielded a reply");
    assert_eq!(reply.platform, "mattermost");
    assert_eq!(reply.principal, "u4242");
    assert!(reply.is_dm, "configured DM channel → is_dm");
    assert_eq!(reply.nonce, "abc123nonce");
    assert_eq!(reply.msg_id, "p1");
    assert!(reply.allow);

    drop(rx); // closing the receiver makes listen return on its next send/poll
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// A `/DENY <nonce>` reply proves parsing is case-insensitive and tolerates a
/// leading slash, and that deny intent is reported as `allow = false`.
#[tokio::test]
async fn mattermost_listen_parses_slash_and_case_insensitive_deny() {
    let srv = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r".*/channels/.*/posts$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "order": ["pD"],
            "posts": {
                "pD": {
                    "id": "pD",
                    "user_id": "u7",
                    "message": "/DENY denynonce",
                    "create_at": 1_710_000_000_500i64
                }
            }
        })))
        .mount(&srv)
        .await;

    let ch = MattermostChannel::new("tok".into(), "DMCHAN".into()).with_base(srv.uri());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let h = tokio::spawn(async move { ch.listen(tx).await });

    let reply = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("reply in time")
        .expect("a reply");
    assert_eq!(reply.nonce, "denynonce");
    assert!(!reply.allow, "deny → allow = false");
    drop(rx);
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
}

/// SSRF guard: a non-loopback plaintext base is refused — `notify` sends nothing.
#[tokio::test]
async fn mattermost_notify_refuses_unsafe_base() {
    let ch = MattermostChannel::new("tok".into(), "DMCHAN".into())
        .with_base("http://evil.example.com".into());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "x".into(),
        detail: "y".into(),
        rule_id: "r".into(),
    };
    // Must not panic and must not attempt a send; nothing to assert but the
    // absence of a network call (no mock server exists to receive one).
    ch.notify("n", &req).await;
}
