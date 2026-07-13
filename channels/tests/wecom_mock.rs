use belay_channels::wecom::WecomChannel;
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

/// notify() POSTs a markdown message carrying the request context.
#[tokio::test]
async fn wecom_notify_posts_markdown() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"errcode\":0}"))
        .mount(&srv)
        .await;

    let ch = WecomChannel::new(srv.uri());
    ch.notify("noncexyz", &req()).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one POST");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("markdown"), "sends a markdown message: {body}");
    assert!(body.contains("session=s1"), "carries the session");
    assert!(!body.contains("noncexyz"), "nonce is not leaked to the group");
}

/// A non-HTTPS remote URL is refused fail-closed — nothing is sent.
#[tokio::test]
async fn wecom_notify_refuses_unsafe_url() {
    let ch = WecomChannel::new("http://169.254.169.254/cgi-bin/webhook/send?key=x".into());
    ch.notify("n", &req()).await;
}
