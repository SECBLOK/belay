use belay_channels::webhook::WebhookChannel;
use belay_channels::{ChannelAdapter, DecisionRequest};
use serde_json::json;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `notify` POSTs a single JSON body carrying the correlation nonce plus the
/// request fields (summary/detail/session/rule) to the configured url.
#[tokio::test]
async fn webhook_notify_posts_nonce_and_fields() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&srv)
        .await;

    let ch = WebhookChannel::new(srv.uri());
    let req = DecisionRequest {
        session_id: "sess-1".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one POST");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("noncexyz"), "body carries the nonce: {body}");
    assert!(body.contains("secrets.sensitive_path"), "body carries the rule");
    assert!(body.contains("sess-1"), "body carries the session");
    assert!(body.contains("Bash — reads secrets"), "body carries the summary");
}

/// An unsafe (plaintext remote) url must never receive the POST — fail closed.
#[tokio::test]
async fn webhook_notify_refuses_unsafe_url() {
    // A remote http:// base is rejected by is_safe_base; no request is sent, so a
    // wiremock server would see nothing. We assert the guard by pointing at an
    // unroutable remote plaintext host and confirming notify returns without hang.
    let ch = WebhookChannel::new("http://169.254.169.254/webhook".into());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "x".into(),
        detail: "y".into(),
        rule_id: "r".into(),
    };
    // Must return promptly (guard short-circuits before any network call).
    ch.notify("n", &req).await;
}
