//! Auth invariants — formerly cross-checked against a live Python oracle
//! (`tests/parity/auth_oracle.py`). The Python package has been deleted, so the
//! cross-language checks are now captured as committed golden expectations plus
//! Rust self-consistency round-trips:
//!
//!   * JWT: a token Rust issues must verify in Rust with identical claims, and a
//!     wrong secret must be rejected. (Previously also verified in Python jose;
//!     the HS256 wire format is the standard, so the Rust round-trip is the
//!     authoritative invariant.)
//!   * Role ordering: golden truth table captured from the Python oracle
//!     (`viewer<operator<admin`, unknown have → fail, unknown need → fail).
//!   * Password: Argon2id hash/verify round-trip.
use belay_auth::{hash_password, make_token, role_ok, verify_password, verify_token};

#[test]
fn jwt_self_consistency() {
    // A token Rust issues must verify in Rust with identical claims.
    let tok = make_token("alice", "operator", "", false, "secret").expect("make_token");
    let claims = verify_token(&tok, "secret").expect("verify with right secret");
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.role, "operator");
    // Wrong secret rejected.
    assert!(verify_token(&tok, "wrong").is_err());
}

#[test]
fn role_ordering_golden() {
    // Golden truth table captured from `auth_oracle.py roleok <have> <need>`
    // while Python was still present:
    //   admin   operator => true
    //   viewer  operator => false
    //   operator operator => true
    //   nobody  viewer   => false
    let golden: &[(&str, &str, bool)] = &[
        ("admin", "operator", true),
        ("viewer", "operator", false),
        ("operator", "operator", true),
        ("nobody", "viewer", false),
    ];
    for (have, need, expected) in golden {
        assert_eq!(
            role_ok(have, need),
            *expected,
            "role_ok({have}, {need}) should be {expected}"
        );
    }
}

#[test]
fn password_roundtrip() {
    let h = hash_password("pw").expect("hash_password");
    assert!(verify_password("pw", &h).expect("verify_password"));
    assert!(!verify_password("bad", &h).expect("verify_password bad"));
}
