//! AGPL §13 network-use source affordance.
//!
//! `belay serve` is a network-interactive AGPL-3.0-or-later program, so anyone
//! interacting with a running instance over a network must be offered a way to
//! get the Corresponding Source for the exact version they are talking to.
//! `GET /api/source` is that affordance: unauthenticated (it must be reachable
//! by anyone the instance serves, not just logged-in operators), side-effect
//! free, and cheap enough to serve on every request.

use belay_server::{create_app, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn source_route_returns_200_with_repository_and_license() {
    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("GET")
        .uri("/api/source")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        v["license"].as_str(),
        Some("AGPL-3.0-or-later"),
        "unexpected license: {v}"
    );
    let repo = v["repository"].as_str().unwrap_or_default();
    assert!(
        repo.contains("github.com/SECBLOK/belay"),
        "unexpected repository: {v}"
    );
    assert!(
        !v["version"].as_str().unwrap_or_default().is_empty(),
        "missing version: {v}"
    );
    assert!(
        !v["commit"].as_str().unwrap_or_default().is_empty(),
        "missing commit: {v}"
    );
}
