//! Proves single-user auth works in the OPEN build (default features, no
//! `enterprise`): provision an admin, log in, and gate a read route on the
//! Bearer token. Mirrors the helper style of `tests/rbac.rs` but compiles and
//! runs without the fleet plane.
//!
//! Gated to the open build: under `enterprise`, login is org-scoped and resolves
//! the caller against the OrgStore (which this single-user fixture does not
//! attach). The org-aware login path is covered by `tests/org_login.rs`.
#![cfg(not(feature = "enterprise"))]
use belay_server::{create_app, load_users_and_secret, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Provision an admin into a fresh temp data dir (via `users.json`), then build
/// an `AppState` from what `load_users_and_secret` reads back — the same path
/// `run()` takes. Returns the state and the plaintext password.
fn provisioned_state() -> (AppState, String) {
    let dir = std::env::temp_dir().join(format!(
        "belay-open-auth-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let password = "admin-pass".to_string();
    let hash = belay_auth::hash_password(&password).expect("hash");
    let users = json!([{
        "username": "admin",
        "password_hash": hash,
        "role": "admin",
    }]);
    std::fs::write(dir.join("users.json"), users.to_string()).unwrap();

    let (loaded, secret) = load_users_and_secret(&dir);
    assert_eq!(loaded.len(), 1, "one provisioned admin");
    assert!(!secret.is_empty(), "secret generated on first load");

    let audit_path = dir.join("audit.ndjson");
    (AppState::with_users(audit_path, loaded, secret), password)
}

async fn login_token(app: &axum::Router, username: &str, password: &str) -> String {
    let body = json!({"username": username, "password": password});
    let req = Request::builder()
        .method("POST")
        .uri("/api/login")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login should succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["token"].as_str().unwrap().to_string()
}

fn posture_request(token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri("/api/posture");
    if let Some(tok) = token {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    builder.body(Body::empty()).unwrap()
}

// Provisioned admin can log in and read a gated route with the Bearer token;
// the same route with NO token is 401 — auth works without `enterprise`.
#[tokio::test]
async fn open_build_admin_login_and_bearer_gate() {
    let (state, password) = provisioned_state();
    let app = create_app(state);

    let token = login_token(&app, "admin", &password).await;

    let resp = app
        .clone()
        .oneshot(posture_request(Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "posture with a valid Bearer token should be 200"
    );

    let resp = app.oneshot(posture_request(None)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "posture with no token should be 401 when users are configured"
    );
}
