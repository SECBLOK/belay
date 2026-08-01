//! Single-user auth extractors and the open `/api/login` route.
//! Compiled unconditionally (no feature gate).
use crate::SharedState;
use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{header::SET_COOKIE, request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

// ──────────────────────────────────────────────────────────────
// Auth extractor  — mirrors _make_auth_dep from app.py
// ──────────────────────────────────────────────────────────────

/// Read one cookie value out of the request's `Cookie` header(s).
///
/// Hand-rolled rather than pulling in a cookie crate: the console is the only
/// consumer and the format needed here is a flat `k=v; k=v` list. Multiple
/// `Cookie` headers are tolerated because some proxies split them.
fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all("Cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().to_string())
}

/// The claims extracted from a valid Bearer token (or None when auth is disabled).
pub struct AuthClaims(pub Option<belay_auth::Claims>);

#[async_trait]
impl FromRequestParts<SharedState> for AuthClaims {
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Open access when no users are configured (single-user localhost mode).
        if state.users.is_empty() {
            return Ok(AuthClaims(None));
        }

        // Bearer FIRST, so every existing caller is unaffected. The browser
        // console has no Authorization header and falls through to the cookie.
        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string())
            .or_else(|| cookie_value(parts, SESSION_COOKIE));

        match token {
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Not authenticated"})),
            )),
            Some(tok) => match belay_auth::verify_token(&tok, &state.auth_secret) {
                Ok(claims) => Ok(AuthClaims(Some(claims))),
                Err(_) => Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid or expired token"})),
                )),
            },
        }
    }
}

// ──────────────────────────────────────────────────────────────
// RBAC extractor — mirrors _make_role_dep(app, "operator")
// ──────────────────────────────────────────────────────────────

/// Extractor that requires at least "operator" role when auth is enabled.
pub struct RequireOperator(pub Option<belay_auth::Claims>);

#[async_trait]
impl FromRequestParts<SharedState> for RequireOperator {
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Open access when no users are configured.
        if state.users.is_empty() {
            return Ok(RequireOperator(None));
        }

        // Re-use the auth extractor.
        let AuthClaims(claims) = AuthClaims::from_request_parts(parts, state).await?;

        let role = claims.as_ref().map(|c| c.role.as_str()).unwrap_or("viewer");
        if !belay_auth::role_ok(role, "operator") {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Requires role >= operator"})),
            ));
        }

        Ok(RequireOperator(claims))
    }
}

// ──────────────────────────────────────────────────────────────
// Login handler
// ──────────────────────────────────────────────────────────────

/// Name of the browser session cookie. Humans authenticate with this; machines
/// (device, SCIM, feed) use Bearer tokens and are never authenticated by it.
pub const SESSION_COOKIE: &str = "belay_session";

/// Build the `Set-Cookie` value shared by `session_cookie` and
/// `clear_session_cookie`. `HttpOnly` keeps the JWT out of reach of any
/// script on the console origin; `SameSite=Strict` blocks cross-site sends.
/// Neither is sufficient alone, which is why `csrf.rs` also runs: SameSite is
/// SITE-scoped, so on localhost every other port counts as same-site.
///
/// Only `token` and `max_age` ever differ between the set and clear cases -
/// name, `Path` and the flag set are shared here so they cannot drift, since
/// a `Set-Cookie` only replaces a previous cookie when those all match.
fn format_session_cookie(token: &str, max_age: i64, secure: bool) -> String {
    let mut c =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}");
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// Format the session cookie for a fresh login.
pub fn session_cookie(token: &str, secure: bool) -> String {
    format_session_cookie(token, belay_auth::EXPIRE_HOURS * 3600, secure)
}

/// Format the `Set-Cookie` that clears a previously-issued session cookie:
/// same name/Path/flags as `session_cookie`, empty value, immediate expiry.
pub fn clear_session_cookie(secure: bool) -> String {
    format_session_cookie("", 0, secure)
}

/// POST /api/login — find user, verify password, issue JWT.
pub(crate) async fn login(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

    for user in &state.users {
        if user.username == username {
            let ok =
                belay_auth::verify_password(password, &user.password_hash).unwrap_or(false);
            if ok {
                #[cfg(not(feature = "enterprise"))]
                let (org, role, platform_admin) =
                    (user.org.clone(), user.role.clone(), user.platform_admin);
                let token = belay_auth::make_token(
                    username,
                    &role,
                    &org,
                    platform_admin,
                    &state.auth_secret,
                )
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "token generation failed"})),
                    )
                })?;
                let cookie = session_cookie(&token, state.cookie_secure);
                return Ok((
                    [(SET_COOKIE, cookie)],
                    Json(json!({"token": token})),
                )
                    .into_response());
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Bad credentials"})),
    ))
}

/// POST /api/logout - clear the session cookie.
pub(crate) async fn logout(State(state): State<SharedState>) -> Response {
    let c = clear_session_cookie(state.cookie_secure);
    ([(SET_COOKIE, c)], Json(json!({"ok": true}))).into_response()
}

// ──────────────────────────────────────────────────────────────
// GET /api/me - the caller's own identity
// ──────────────────────────────────────────────────────────────

/// GET /api/me - tell the caller who it is. The session JWT is `HttpOnly` by
/// design, so the console UI cannot read its own role or org straight out of
/// the cookie; it asks the server instead, which already re-validates the
/// cookie on every request via `AuthClaims`.
///
/// `AuthClaims` yields `None` only when `state.users` is empty (open-access,
/// the `belay serve` default) - in that mode every caller in fact has full
/// access, so this reports that plainly rather than inventing a username: no
/// `sub`, `role: "admin"`, `platform_admin: true`, and `open_access: true` so
/// the UI can tell "I am an admin" apart from "this server has no auth
/// configured". With users configured, an unauthenticated caller never
/// reaches this handler at all - `AuthClaims` rejects it with 401 first.
pub(crate) async fn me(auth: AuthClaims) -> Json<Value> {
    match auth.0 {
        Some(c) => Json(json!({
            "sub": c.sub,
            "role": c.role,
            "org": c.org,
            "platform_admin": c.platform_admin,
            "open_access": false,
        })),
        None => Json(json!({
            "sub": Value::Null,
            "role": "admin",
            "org": "",
            "platform_admin": true,
            "open_access": true,
        })),
    }
}

// ──────────────────────────────────────────────────────────────
// Open routes
// ──────────────────────────────────────────────────────────────

/// Open auth routes available in every build (login is always reachable).
pub fn open_auth_routes() -> Router<SharedState> {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
}
