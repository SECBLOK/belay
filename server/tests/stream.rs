use belay_server::{create_app, AppState};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn stream_delivers_published_row() {
    let state = AppState::test(); // tmp audit path, no users
    let tx = state.broadcast(); // broadcast::Sender<Value>
    let app = create_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("http://{addr}/api/stream");
    let client = reqwest::Client::new();
    let mut resp = client.get(&url).send().await.unwrap();

    // publish after the client subscribed
    tokio::time::sleep(Duration::from_millis(100)).await;
    tx.send(json!({"event":"PreToolUse","tool":"Bash","verdict":"deny"}))
        .unwrap();

    let chunk = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event:audit") || text.contains("event: audit"));
    assert!(text.contains("\"verdict\":\"deny\""));
}
