//! `AuthClaims` must accept the browser session cookie as well as the existing
//! Bearer header. Bearer is checked FIRST and its behaviour is unchanged, so
//! every existing caller keeps working byte-for-byte.
//!
//! The machine credentials (device, SCIM, feed) are deliberately NOT covered by
//! this: they have their own extractors and must stay Bearer-only, so that a
//! stolen browser session can never act as an enrolled device. That separation
//! is asserted in `server/tests/machine_creds_reject_cookie.rs`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use belay_server::{create_app, AppState, User};
use tower::ServiceExt;

fn state() -> AppState {
    let mut st = AppState::test();
    st.auth_secret = "test-secret".to_string();
    st.users = vec![User {
        username: "alice".to_string(),
        password_hash: belay_auth::hash_password("pw").unwrap(),
        role: "admin".to_string(),
        org: String::new(),
        platform_admin: true,
    }];
    st
}

fn token(secret: &str) -> String {
    belay_auth::make_token("alice", "admin", "", true, secret).unwrap()
}

async fn get_posture_with(header: (&str, String)) -> StatusCode {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/posture")
        .header(header.0, header.1)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn a_valid_session_cookie_authenticates() {
    let st = get_posture_with(("Cookie", format!("belay_session={}", token("test-secret")))).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn a_bearer_header_still_authenticates() {
    let st = get_posture_with(("Authorization", format!("Bearer {}", token("test-secret")))).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn the_cookie_is_found_among_other_cookies() {
    let c = format!("theme=dark; belay_session={}; other=1", token("test-secret"));
    assert_eq!(get_posture_with(("Cookie", c)).await, StatusCode::OK);
}

#[tokio::test]
async fn a_cookie_signed_with_another_secret_is_rejected() {
    let st = get_posture_with(("Cookie", format!("belay_session={}", token("wrong-secret")))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_garbage_cookie_is_rejected() {
    assert_eq!(
        get_posture_with(("Cookie", "belay_session=not-a-jwt".to_string())).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_unrelated_cookie_alone_is_rejected() {
    assert_eq!(
        get_posture_with(("Cookie", "theme=dark".to_string())).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn no_credential_at_all_is_rejected() {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/posture")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}
