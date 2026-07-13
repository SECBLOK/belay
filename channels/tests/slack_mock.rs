use belay_channels::slack::SlackChannel;
use belay_channels::{ChannelAdapter, DecisionRequest, InboundReply};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Two-way adapter: notify posts interactive buttons; inbound via receiver ───

/// `notify` posts an interactive Block Kit prompt to `chat.postMessage`, with the
/// Allow/Deny buttons carrying the nonce in their `value` (so a click resolves the
/// exact parked request via the Phase B receiver's SlackVerifier).
#[tokio::test]
async fn slack_notify_posts_prompt_with_nonce() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/chat\.postMessage$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "ts": "1.2"})))
        .mount(&srv)
        .await;

    let ch = SlackChannel::new("xoxb-tok".into(), "D0APPROVER".into()).with_base(srv.uri());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash — reads secrets".into(),
        detail: "{\"command\":\"cat .env\"}".into(),
        rule_id: "secrets.sensitive_path".into(),
    };
    ch.notify("noncexyz", &req).await;

    let reqs = srv.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "exactly one chat.postMessage");
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(body.contains("a:noncexyz"), "allow button value carries the nonce: {body}");
    assert!(body.contains("d:noncexyz"), "deny button value carries the nonce");
    assert!(body.contains("\"blocks\""), "sends an interactive Block Kit prompt");
    assert!(
        body.contains("\"channel\":\"D0APPROVER\""),
        "posts to the configured channel"
    );
    // The bot token must never appear in the JSON body (it rides the header).
    assert!(!body.contains("xoxb-tok"), "token is not in the body");
}

/// `listen` yields no reply and exits once the daemon drops the receiver: Slack
/// inbound arrives over the Phase B receiver (`/hook/slack`), not a client-side
/// poll, so the sweeper loop only runs to expire un-answered prompts.
#[tokio::test]
async fn slack_listen_yields_no_reply_and_exits_on_shutdown() {
    let srv = MockServer::start().await;
    let ch = SlackChannel::new("xoxb-tok".into(), "D0APPROVER".into()).with_base(srv.uri());
    let (tx, rx) = tokio::sync::mpsc::channel::<InboundReply>(8);
    // Daemon shutdown == receiver dropped == tx.is_closed(); the sweeper must exit.
    drop(rx);
    tokio::time::timeout(Duration::from_secs(5), ch.listen(tx))
        .await
        .expect("sweeper exits promptly once the receiver is gone");
}

/// An un-clicked prompt is expired: after the timeout the sweeper edits the
/// original message (via `chat.update` on the captured `ts`) and drops the
/// buttons, so a late click can't look like it might still work.
#[tokio::test]
async fn slack_expires_unanswered_prompt() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/chat\.postMessage$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "channel": "D0APPROVER", "ts": "17.42"})),
        )
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/chat\.update$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&srv)
        .await;

    let ch = SlackChannel::new("xoxb-tok".into(), "D0APPROVER".into())
        .with_base(srv.uri())
        .with_expire_after(Duration::from_millis(150));
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "Bash - reads secrets".into(),
        detail: "{}".into(),
        rule_id: "r".into(),
    };
    ch.notify("noncexyz", &req).await;

    // Run the sweeper; it should fire chat.update once the 150ms threshold passes.
    let (tx, _rx) = tokio::sync::mpsc::channel::<InboundReply>(1);
    let handle = tokio::spawn(async move { ch.listen(tx).await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    handle.abort();

    let reqs = srv.received_requests().await.unwrap();
    let update = reqs
        .iter()
        .find(|r| r.url.path().ends_with("/chat.update"))
        .expect("sweeper edited the expired prompt");
    let body = String::from_utf8_lossy(&update.body);
    assert!(body.contains("\"ts\":\"17.42\""), "edits the captured message ts");
    assert!(body.contains("Expired"), "relabels the prompt expired");
    assert!(!body.contains("belay_approve"), "drops the buttons");
}

/// A resolved nonce is cancelled: after `on_resolved`, the sweeper must NOT
/// expire the (already-answered) prompt.
#[tokio::test]
async fn slack_on_resolved_cancels_expiry() {
    let srv = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/chat\.postMessage$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "channel": "D0APPROVER", "ts": "17.42"})),
        )
        .mount(&srv)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r".*/chat\.update$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&srv)
        .await;

    let ch = SlackChannel::new("xoxb-tok".into(), "D0APPROVER".into())
        .with_base(srv.uri())
        .with_expire_after(Duration::from_millis(150));
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "x".into(),
        detail: "{}".into(),
        rule_id: "r".into(),
    };
    ch.notify("noncexyz", &req).await;
    ch.on_resolved("noncexyz").await; // click accepted before it expires

    let (tx, _rx) = tokio::sync::mpsc::channel::<InboundReply>(1);
    let handle = tokio::spawn(async move { ch.listen(tx).await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    handle.abort();

    let reqs = srv.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path().ends_with("/chat.update")),
        "an answered prompt must never be relabeled expired"
    );
}

/// SSRF guard: a non-loopback plaintext base is refused — `notify` sends nothing.
#[tokio::test]
async fn slack_notify_refuses_unsafe_base() {
    let ch =
        SlackChannel::new("xoxb-tok".into(), "D0APPROVER".into()).with_base("http://evil.com".into());
    let req = DecisionRequest {
        session_id: "s".into(),
        summary: "x".into(),
        detail: "y".into(),
        rule_id: "r".into(),
    };
    // Must not panic and must not attempt any request (unreachable host would hang
    // otherwise); it returns fast because the base is rejected up front.
    tokio::time::timeout(Duration::from_secs(5), ch.notify("n", &req))
        .await
        .expect("unsafe base is refused without a network attempt");
}
