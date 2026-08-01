//! `POST /api/login` must set an httpOnly session cookie in addition to
//! returning the JSON token. The JSON token is retained because `belay push`,
//! `belay enroll` and scripted API use depend on it; the cookie is what the
//! browser console uses, so it can be httpOnly and never touched by JS.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use belay_server::{create_app, AppState, User};
use tower::ServiceExt;

fn state_with_user() -> AppState {
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

async fn login_response(state: AppState) -> axum::response::Response {
    let app = create_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        // A same-origin browser sends this on every fetch/XHR; it is what gets
        // this POST past the CSRF guard (server/src/csrf.rs), which now also
        // covers `/api/login` (login-CSRF).
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::from(r#"{"username":"alice","password":"pw"}"#))
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn login_sets_an_httponly_strict_session_cookie() {
    let resp = login_response(state_with_user()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("login must set a session cookie")
        .to_str()
        .unwrap()
        .to_string();

    assert!(cookie.starts_with("belay_session="), "got: {cookie}");
    assert!(cookie.contains("HttpOnly"), "got: {cookie}");
    assert!(cookie.contains("SameSite=Strict"), "got: {cookie}");
    assert!(cookie.contains("Path=/"), "got: {cookie}");
    assert!(cookie.contains("Max-Age=86400"), "got: {cookie}");
}

#[tokio::test]
async fn a_loopback_bind_omits_secure_so_http_dev_works() {
    // Browsers refuse to STORE a `Secure` cookie sent from a plaintext origin,
    // so a loopback dev server that set it would be unable to log anyone in.
    let mut st = state_with_user();
    st.cookie_secure = false;
    let resp = login_response(st).await;
    let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(!cookie.contains("Secure"), "got: {cookie}");
}

#[tokio::test]
async fn a_non_loopback_bind_sets_secure() {
    let mut st = state_with_user();
    st.cookie_secure = true;
    let resp = login_response(st).await;
    let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("Secure"), "got: {cookie}");
}

#[tokio::test]
async fn the_json_token_is_still_returned_for_cli_callers() {
    let resp = login_response(state_with_user()).await;
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        !v["token"].as_str().unwrap_or_default().is_empty(),
        "the JSON token must remain: belay push/enroll depend on it"
    );
}

#[tokio::test]
async fn bad_credentials_set_no_cookie() {
    let app = create_app(state_with_user());
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::from(r#"{"username":"alice","password":"wrong"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("set-cookie").is_none());
}
