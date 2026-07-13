use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXPIRE_HOURS: i64 = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub platform_admin: bool,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("password hash error: {0}")]
    Hash(String),
}

/// Issue an HS256 JWT with sub/role/org/platform_admin/iat/exp (24 hours, matching Python _EXPIRE_HOURS).
pub fn make_token(sub: &str, role: &str, org: &str, platform_admin: bool, secret: &str) -> Result<String, AuthError> {
    let now = Utc::now();
    let claims = Claims {
        sub: sub.into(),
        role: role.into(),
        org: org.into(),
        platform_admin,
        iat: now.timestamp(),
        exp: (now + Duration::hours(EXPIRE_HOURS)).timestamp(),
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?;
    Ok(token)
}

/// Verify an HS256 JWT; returns Claims on success.
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, AuthError> {
    // Disable aud validation — Python jose does not set it either.
    let mut validation = Validation::default();
    validation.set_required_spec_claims(&["exp", "sub"]);
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

/// Role hierarchy: viewer(0) < operator(1) < admin(2).
/// Unknown `have` → -1 (always fails).  Unknown `need` → 99 (always fails).
pub fn role_ok(have: &str, need: &str) -> bool {
    let order = |r: &str, dflt: i64| match r {
        "viewer" => 0,
        "operator" => 1,
        "admin" => 2,
        _ => dflt,
    };
    order(have, -1) >= order(need, 99)
}

/// Hash a password with Argon2id.
pub fn hash_password(pw: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::Hash(e.to_string()))
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(pw: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed = PasswordHash::new(hash).map_err(|e| AuthError::Hash(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok())
}

/// Generate a fresh HS256 signing secret: 256 bits of CSRNG, hex-encoded to 64
/// lowercase chars. Used when provisioning single-user auth so the operator
/// never has to pick a secret. Never log the returned value.
pub fn generate_secret() -> String {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn token_carries_platform_admin_and_defaults_false() {
        let s = "sec";
        let t = make_token("root", "admin", "", true, s).unwrap();
        assert!(verify_token(&t, s).unwrap().platform_admin);
        let t2 = make_token("u", "viewer", "acme", false, s).unwrap();
        assert!(!verify_token(&t2, s).unwrap().platform_admin);
    }

    #[test]
    fn token_carries_org_and_defaults_empty() {
        let secret = "s";
        let t = make_token("alice", "admin", "acme", false, secret).unwrap();
        let c = verify_token(&t, secret).unwrap();
        assert_eq!(c.org, "acme");
        // A legacy token minted without org (org="") still verifies and defaults empty.
        let t0 = make_token("bob", "viewer", "", false, secret).unwrap();
        assert_eq!(verify_token(&t0, secret).unwrap().org, "");
    }
}

#[cfg(test)]
mod secret_tests {
    use super::generate_secret;

    #[test]
    fn generate_secret_is_64_hex_chars() {
        let s = generate_secret();
        assert_eq!(s.len(), 64, "expected 64 hex chars for 256 bits");
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit()),
            "expected only hex digits, got {s}"
        );
    }

    #[test]
    fn generate_secret_is_unique() {
        assert_ne!(
            generate_secret(),
            generate_secret(),
            "two secrets should differ"
        );
    }
}
