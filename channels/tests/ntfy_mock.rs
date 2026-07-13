use belay_channels::ntfy::NtfyChannel;
use belay_channels::{ChannelAdapter, DecisionRequest};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn req() -> DecisionRequest {
    DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    }
}

/// `notify` publishes the prompt to `{base}/{topic}` with the Belay title,
/// and the body carries the request context.
#[tokio::test]
async fn ntfy_notify_publishes_prompt_to_topic() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/belay-alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "x1"})))
        .mount(&srv)
        .await;

    let ch = NtfyChannel::new("belay-alerts".into()).with_base(srv.uri());
    ch.notify("noncexyz", &req()).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one publish");
    let title = reqs[0]
        .headers
        .get("Title")
        .expect("Title header set")
        .to_str()
        .unwrap();
    assert_eq!(title, "Belay approval");
    // No token configured → no Authorization header (and never leak a token).
    assert!(reqs[0].headers.get("Authorization").is_none());
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("Bash — reads secrets"), "body has summary: {body}");
    assert!(body.contains("session=s"), "body has session");
}

/// A configured access token is sent as `Authorization: Bearer <token>`.
#[tokio::test]
async fn ntfy_notify_sends_bearer_token_when_set() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/secure-topic"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&srv)
        .await;

    let ch = NtfyChannel::new("secure-topic".into())
        .with_base(srv.uri())
        .with_token("tok_abc".into());
    ch.notify("n", &req()).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let auth = reqs[0]
        .headers
        .get("Authorization")
        .expect("Authorization header set")
        .to_str()
        .unwrap();
    assert_eq!(auth, "Bearer tok_abc");
}

/// An unsafe (non-HTTPS remote) base must refuse to publish — no request is sent,
/// so the prompt and any token cannot be exfiltrated (SSRF guard).
#[tokio::test]
async fn ntfy_notify_refuses_unsafe_base() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&srv)
        .await;

    // http:// to a non-loopback host is rejected by is_safe_base.
    let ch = NtfyChannel::new("t".into())
        .with_base("http://evil.example.com".into())
        .with_token("tok_abc".into());
    ch.notify("n", &req()).await;

    let reqs = srv.received_requests().await.unwrap();
    assert!(reqs.is_empty(), "unsafe base → nothing sent");
}

/// Notify-only: `listen` returns immediately (no inbound stream to consume).
#[tokio::test]
async fn ntfy_listen_returns_immediately() {
    let ch = NtfyChannel::new("t".into());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    // Should complete on its own, well within the timeout, and yield no replies.
    tokio::time::timeout(std::time::Duration::from_secs(5), ch.listen(tx))
        .await
        .expect("listen returns promptly");
    assert!(rx.try_recv().is_err(), "notify-only yields no replies");
}
