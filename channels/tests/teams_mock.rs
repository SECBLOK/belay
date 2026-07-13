use belay_channels::teams::TeamsChannel;
use belay_channels::{ChannelAdapter, DecisionRequest};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn req() -> DecisionRequest {
    DecisionRequest {
        session_id: "s1".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    }
}

/// notify() POSTs a MessageCard carrying the request context to the webhook.
#[tokio::test]
async fn teams_notify_posts_message_card() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("1"))
        .mount(&srv)
        .await;

    let ch = TeamsChannel::new(srv.uri());
    ch.notify("noncexyz", &req()).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one POST");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("MessageCard"), "sends a MessageCard: {body}");
    assert!(body.contains("Bash — reads secrets"), "carries the summary");
    assert!(body.contains("session=s1"), "carries the session");
    // Notify-only: the nonce is intentionally NOT actionable/exposed here.
    assert!(!body.contains("noncexyz"), "nonce is not leaked to the channel");
}

/// A non-HTTPS remote URL is refused fail-closed — nothing is sent.
#[tokio::test]
async fn teams_notify_refuses_unsafe_url() {
    let ch = TeamsChannel::new("http://169.254.169.254/hook".into());
    // Must return promptly without a panic or a network attempt.
    ch.notify("n", &req()).await;
}
