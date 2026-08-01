//! `GET /api/me` - the caller's own identity, learned from the server so the
//! browser console (whose session cookie is `HttpOnly`, and so cannot read
//! it) can gate admin/operator controls without ever holding the JWT in JS.
//! Compiled unconditionally: `open_auth_routes` (and so `/api/me`) exists in
//! both the open and enterprise builds.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use belay_server::{create_app, AppState, User};
use serde_json::Value;
use tower::ServiceExt;

fn state_with_users() -> AppState {
    let mut st = AppState::test();
    st.auth_secret = "test-secret".to_string();
    st.users = vec![User {
        username: "alice".to_string(),
        password_hash: belay_auth::hash_password("pw").unwrap(),
        role: "operator".to_string(),
        org: "acme".to_string(),
        platform_admin: false,
    }];
    st
}

fn token(secret: &str) -> String {
    belay_auth::make_token("alice", "operator", "acme", false, secret).unwrap()
}

async fn me_response(req: Request<Body>, state: AppState) -> (StatusCode, Value) {
    let app = create_app(state);
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn me_returns_role_and_org_for_a_cookie_session() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header("Cookie", format!("belay_session={}", token("test-secret")))
        .body(Body::empty())
        .unwrap();
    let (status, v) = me_response(req, state_with_users()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["sub"], "alice");
    assert_eq!(v["role"], "operator");
    assert_eq!(v["org"], "acme");
    assert_eq!(v["platform_admin"], false);
    assert_eq!(v["open_access"], false);
}

#[tokio::test]
async fn me_returns_role_and_org_for_a_bearer_session() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header("Authorization", format!("Bearer {}", token("test-secret")))
        .body(Body::empty())
        .unwrap();
    let (status, v) = me_response(req, state_with_users()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["sub"], "alice");
    assert_eq!(v["role"], "operator");
    assert_eq!(v["org"], "acme");
    assert_eq!(v["open_access"], false);
}

#[tokio::test]
async fn me_is_401_unauthenticated_when_users_are_configured() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();
    let (status, _) = me_response(req, state_with_users()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_in_open_access_mode_reports_full_access() {
    let req = Request::builder()
        .method("GET")
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();
    let (status, v) = me_response(req, AppState::test()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["open_access"], true);
    assert_eq!(v["role"], "admin");
    assert_eq!(v["platform_admin"], true);
    assert!(
        v["sub"].is_null(),
        "open-access mode must not invent a fake username, got: {v}"
    );
}
