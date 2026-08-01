//! `POST /api/logout` must clear the session cookie the same way it was set:
//! same name, Path and flags, with an immediate expiry - a cookie is only
//! replaced when name, Path and flags all match (see `session_cookie.rs` for
//! the login-side counterpart of this contract).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use belay_server::{create_app, AppState};
use tower::ServiceExt;

async fn logout_response(state: AppState) -> axum::response::Response {
    let app = create_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/logout")
        // A same-origin browser sends this on every fetch/XHR; it is what gets
        // this POST past the CSRF guard (server/src/csrf.rs).
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn logout_clears_the_session_cookie() {
    let resp = logout_response(AppState::test()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("logout must clear the session cookie")
        .to_str()
        .unwrap()
        .to_string();

    let name_value = cookie.split(';').next().unwrap();
    assert_eq!(
        name_value, "belay_session=",
        "expected an empty cleared value, got: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"), "got: {cookie}");
    assert!(cookie.contains("SameSite=Strict"), "got: {cookie}");
    assert!(cookie.contains("Path=/"), "got: {cookie}");
    assert!(cookie.contains("Max-Age=0"), "got: {cookie}");
}

#[tokio::test]
async fn a_non_loopback_bind_sets_secure_on_the_clearing_cookie() {
    let mut st = AppState::test();
    st.cookie_secure = true;
    let resp = logout_response(st).await;
    let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("Secure"), "got: {cookie}");
}

#[tokio::test]
async fn logout_with_no_csrf_credentials_is_rejected() {
    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("POST")
        .uri("/api/logout")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "must fail closed like every other unsafe-method route"
    );
}
