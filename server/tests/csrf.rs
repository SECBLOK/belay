//! CSRF guard.
//!
//! SameSite=Strict is NOT sufficient on its own. SameSite is site-scoped, not
//! origin-scoped, so on localhost every other port on the machine counts as
//! same-site: a hostile local process serving a page on another port would get
//! Strict cookies attached to its forged requests. Hostile local processes are
//! exactly Belay's threat model, so the Origin check is load-bearing here
//! rather than defence in depth.
//!
//! The guard fails CLOSED when neither Origin nor Sec-Fetch-Site is present.
//! Grafana returns early in that case; Portainer rejects, because legacy
//! browsers and header-stripping proxies produce exactly that shape. Belay
//! follows Portainer.

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
    // Every request built by `post()` below carries `Host: console.example.com`
    // (the fixture's stand-in for this deployment's real, configured host), so
    // the fixture must declare that as its own bind host - otherwise the Host
    // allowlist added for DNS-rebinding defence rejects every request here
    // before the Origin/Bearer/Sec-Fetch-Site logic under test even runs.
    st.bind_host = "console.example.com".to_string();
    // `a_cookie_post_from_another_port_on_the_same_host_is_rejected` below
    // builds its own request with `Host: localhost:8080` rather than using
    // `post()`, to exercise the flagship same-site-different-port case. That
    // test's whole point is reaching the Origin comparison and being rejected
    // THERE - if `localhost` were not allowlisted, the Host check would 403
    // it first, for an unrelated reason, and the test would keep passing even
    // if the Origin check were deleted entirely (F1). Listing it here, rather
    // than leaving it out, is what makes the test discriminate again; see
    // `a_cookie_post_from_the_same_host_and_port_is_accepted` for the
    // matching-case half of that proof.
    st.console_hosts = vec!["localhost".to_string()];
    st
}

/// Open-access mode (no `users` configured) with `bind_host` set to match the
/// `Host` header `post()` sends. `f2_open_access_mode_with_a_mismatched_origin_is_rejected`
/// used to build its state from a bare `AppState::test()`, whose default
/// `bind_host` ("127.0.0.1") does not match `post()`'s `Host:
/// console.example.com` - so, once the Host allowlist started covering every
/// route (F2), that test's request was rejected by the Host check before the
/// Origin comparison it exists to test ever ran, silently making it vacuous
/// (F1). This fixture gives it a bind host the Host check will actually pass.
fn open_access_state() -> AppState {
    let mut st = AppState::test();
    st.bind_host = "console.example.com".to_string();
    st
}

fn cookie() -> String {
    let t = belay_auth::make_token("alice", "admin", "", true, "test-secret").unwrap();
    format!("belay_session={t}")
}

/// Build a POST to a route that exists in every build.
fn post(headers: Vec<(&str, String)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .header("Host", "console.example.com");
    for (k, v) in headers {
        b = b.header(k, v);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn a_cookie_post_with_a_matching_origin_passes_the_guard() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Origin", "https://console.example.com".to_string()),
    ]);
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_cookie_post_from_a_foreign_origin_is_rejected() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Origin", "https://evil.example.net".to_string()),
    ]);
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// The localhost case the whole guard exists for: same SITE, different origin.
#[tokio::test]
async fn a_cookie_post_from_another_port_on_the_same_host_is_rejected() {
    let app = create_app(state());
    let req = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .header("Host", "localhost:8080")
        .header("Cookie", cookie())
        .header("Origin", "http://localhost:9999")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// Discrimination proof for the test above: the identical request, but with
/// Origin's port matching Host's port, must NOT be rejected. Without this
/// counterpart, the flagship test above could pass for the wrong reason (e.g.
/// the Host allowlist rejecting `localhost` outright) and nobody would notice
/// - which is exactly what happened when the `state()` fixture's `bind_host`
/// change silently made it vacuous (F1).
#[tokio::test]
async fn a_cookie_post_from_the_same_host_and_port_is_accepted() {
    let app = create_app(state());
    let req = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .header("Host", "localhost:8080")
        .header("Cookie", cookie())
        .header("Origin", "http://localhost:8080")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a matching Origin/Host port must pass, proving the mismatched-port \
         test above is rejected by the Origin comparison, not the Host check"
    );
}

#[tokio::test]
async fn a_cookie_post_with_neither_origin_nor_sec_fetch_site_is_rejected() {
    let app = create_app(state());
    let req = post(vec![("Cookie", cookie())]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "must fail closed: header-stripping proxies produce this shape"
    );
}

#[tokio::test]
async fn sec_fetch_site_same_origin_is_accepted_when_origin_is_absent() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Sec-Fetch-Site", "same-origin".to_string()),
    ]);
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sec_fetch_site_cross_site_is_rejected() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Sec-Fetch-Site", "cross-site".to_string()),
    ]);
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// A browser never sets Authorization on its own, so Bearer callers are not
/// reachable by CSRF and must not be burdened with an Origin requirement.
#[tokio::test]
async fn a_bearer_post_without_an_origin_is_exempt() {
    let app = create_app(state());
    let t = belay_auth::make_token("alice", "admin", "", true, "test-secret").unwrap();
    let req = post(vec![("Authorization", format!("Bearer {t}"))]);
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_get_with_a_cookie_and_no_origin_is_allowed() {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/posture")
        .header("Host", "console.example.com")
        .header("Cookie", cookie())
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

// ── F1 regression: header presence is not a credential. A merely-present
// `Authorization` header used to exempt the request from the Origin check
// outright, even though it does not authenticate anything - the cookie does,
// via `AuthClaims`'s fallback. All three cases below carry a valid session
// cookie and no Origin, so the pre-fix guard let them straight through.

#[tokio::test]
async fn f1_a_cookie_post_with_a_basic_auth_header_and_no_origin_is_rejected() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Authorization", "Basic YWxpY2U6cHc=".to_string()),
    ]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an Authorization header that isn't a genuine Bearer token must not \
         exempt a cookie-authenticated request from the Origin check"
    );
}

#[tokio::test]
async fn f1_a_cookie_post_with_a_lowercase_bearer_header_and_no_origin_is_rejected() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Authorization", "bearer sometoken".to_string()),
    ]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the Bearer prefix match must be exact-case, matching what AuthClaims \
         actually strips"
    );
}

#[tokio::test]
async fn f1_a_cookie_post_with_an_empty_authorization_header_and_no_origin_is_rejected() {
    let app = create_app(state());
    let req = post(vec![("Cookie", cookie()), ("Authorization", String::new())]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an empty Authorization value must not exempt a cookie-authenticated \
         request from the Origin check"
    );
}

/// The legitimate machine-client path this guard must not burden: a genuine
/// Bearer token, no Origin (machine clients don't send one), no Cookie.
#[tokio::test]
async fn a_genuine_bearer_post_with_no_origin_still_passes() {
    let app = create_app(state());
    let t = belay_auth::make_token("alice", "admin", "", true, "test-secret").unwrap();
    let req = post(vec![("Authorization", format!("Bearer {t}"))]);
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// Rule 2 applies regardless of credential: even a genuine Bearer token does
/// not excuse a mismatched Origin.
#[tokio::test]
async fn a_genuine_bearer_post_with_a_mismatched_origin_is_rejected() {
    let app = create_app(state());
    let t = belay_auth::make_token("alice", "admin", "", true, "test-secret").unwrap();
    let req = post(vec![
        ("Authorization", format!("Bearer {t}")),
        ("Origin", "https://evil.example.net".to_string()),
    ]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an Origin mismatch must reject even a Bearer-authenticated request"
    );
}

/// F2 regression: open-access mode (no `users` configured) authorizes every
/// request with no credential at all, so the Origin check must not be gated
/// on Cookie presence. This covers a mismatched Origin in open-access mode;
/// it does NOT cover DNS rebinding, where the attacker controls both Host and
/// Origin and can make them match - see `a_rebound_host_is_rejected_even_when_origin_matches_it`
/// below for that case, which only the Host allowlist defeats.
#[tokio::test]
async fn f2_open_access_mode_with_a_mismatched_origin_is_rejected() {
    let app = create_app(open_access_state());
    let req = post(vec![("Origin", "https://evil.example.net".to_string())]);
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "open-access mode must still reject a cross-origin unsafe request"
    );
}

/// Discrimination proof for the test above: same open-access state, same
/// request shape, but a matching Origin must pass. A bare `AppState::test()`
/// (bind_host `127.0.0.1`, not matching `post()`'s `Host:
/// console.example.com`) would 403 BOTH this test and the one above at the
/// Host check, before the Origin logic under test ever ran - which is
/// exactly the vacuity F1 found. This counterpart is what proves
/// `open_access_state()` actually fixed it rather than just relocating it.
#[tokio::test]
async fn f2_open_access_mode_with_a_matching_origin_passes_the_guard() {
    let app = create_app(open_access_state());
    let req = post(vec![("Origin", "https://console.example.com".to_string())]);
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a matching Origin must pass in open-access mode, proving the \
         mismatched-origin test above is rejected by the Origin comparison, \
         not the Host check"
    );
}

/// `Sec-Fetch-Site: none` means no initiator (address bar, bookmark), which
/// never accompanies an unsafe method for real - accepting it granted
/// nothing legitimate and only handed a future non-browser bypass its magic
/// word.
#[tokio::test]
async fn sec_fetch_site_none_is_rejected() {
    let app = create_app(state());
    let req = post(vec![
        ("Cookie", cookie()),
        ("Sec-Fetch-Site", "none".to_string()),
    ]);
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// The case the Origin check alone cannot cover: a DNS-rebinding attacker
/// controls Host AND Origin, so they match each other trivially. Only the
/// allowlist rejects this. Open-access mode (empty users) is the belay serve
/// default and needs no credential, which is what makes it worth defending.
#[tokio::test]
async fn a_rebound_host_is_rejected_even_when_origin_matches_it() {
    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .header("Host", "rebind.evil.example")
        .header("Origin", "http://rebind.evil.example")
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// The loopback default must keep working, or every local install breaks.
#[tokio::test]
async fn a_loopback_host_is_still_allowed() {
    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .header("Host", "127.0.0.1:8080")
        .header("Sec-Fetch-Site", "same-origin")
        .body(Body::empty())
        .unwrap();
    assert_ne!(app.oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// ── F2 regression: the Host allowlist used to sit AFTER the safe-method
// early return, so GET requests - the primary DNS-rebinding payoff, since
// reading data needs no write credential in open-access mode - were entirely
// unprotected. It now runs before that return, for every method.

#[tokio::test]
async fn f2_a_get_with_a_disallowed_host_is_rejected() {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/posture")
        .header("Host", "evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "GET must be covered by the Host allowlist too, not just unsafe methods"
    );
}

/// `/api/health` is exempt from the Host allowlist by exact path match:
/// load-balancer and container probes legitimately send arbitrary Host
/// values, and the route is side-effect-free.
#[tokio::test]
async fn f2_health_is_exempt_from_the_host_allowlist() {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/health")
        .header("Host", "evil.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// `/api/source` is exempt from the Host allowlist by exact path match: it is
/// the AGPL section 13 network-use source affordance and must be reachable
/// by anyone the instance serves over the network, not just an
/// allowlisted-host caller, or gating it here would undercut the license
/// obligation it exists to satisfy.
#[tokio::test]
async fn f2_source_is_exempt_from_the_host_allowlist() {
    let app = create_app(state());
    let req = Request::builder()
        .method("GET")
        .uri("/api/source")
        .header("Host", "evil.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// The absent-Host justification correction: hyper does not enforce Host
/// presence on the wire, so a request lacking a `Host` header is not the
/// exotic in-process-only shape the old comment claimed. When one arrives
/// with a request-target authority instead (the URI-authority form HTTP/2
/// always uses, and that a raw HTTP/1.1 client could send in absolute-form),
/// the guard must fall back to that authority rather than waving the request
/// through.
#[tokio::test]
async fn a_missing_host_header_with_a_uri_authority_is_host_checked() {
    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("GET")
        .uri("http://evil.example/api/posture")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an absent Host header must fall back to the URI authority, not bypass the check"
    );
}
