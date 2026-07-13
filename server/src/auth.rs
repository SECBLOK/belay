//! Single-user auth extractors and the open `/api/login` route.
//! Compiled unconditionally (no feature gate).
use crate::SharedState;
use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use serde_json::{json, Value};

// ──────────────────────────────────────────────────────────────
// Auth extractor  — mirrors _make_auth_dep from app.py
// ──────────────────────────────────────────────────────────────

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

        // Extract "Authorization: Bearer <token>" header.
        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());

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

/// POST /api/login — find user, verify password, issue JWT.
pub(crate) async fn login(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
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
                return Ok(Json(json!({"token": token})));
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Bad credentials"})),
    ))
}

// ──────────────────────────────────────────────────────────────
// Open routes
// ──────────────────────────────────────────────────────────────

/// Open auth routes available in every build (login is always reachable).
pub fn open_auth_routes() -> Router<SharedState> {
    Router::new().route("/api/login", post(login))
}
