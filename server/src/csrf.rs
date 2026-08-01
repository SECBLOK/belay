//! Fail-closed CSRF guard applied to the whole router.
//!
//! Engages on every unsafe-method request, regardless of how (or whether) the
//! caller authenticates. An earlier version only ran this check when the
//! request carried a `Cookie` header, on the theory that only cookie auth is
//! at risk from CSRF. That reasoning breaks in open-access mode (no `users`
//! configured): `AuthClaims` then authorizes every request with no
//! credential at all, so a cookie-gated guard is inert exactly when it is
//! needed most. The check below runs unconditionally instead.
//!
//! Why this exists when the cookie is already `SameSite=Strict`: SameSite is
//! SITE-scoped, not origin-scoped. On `localhost`, every other port on the
//! machine is same-site, so a hostile local process serving a page on another
//! port would have Strict cookies attached to requests it forges. Belay's
//! threat model is hostile local agents, so that case is in scope.
//!
//! Decision order:
//!   0. Two routes are exempt outright, by exact path match, ahead of every
//!      other check: `GET /api/health` (load-balancer and container probes
//!      legitimately send arbitrary `Host` values) and `GET /api/source` (the
//!      AGPL section 13 network-use source affordance - it must be reachable
//!      by anyone this instance serves over the network, not just a caller on
//!      an allowlisted host, or gating it here would undercut the license
//!      obligation it exists to satisfy; see `source.rs`).
//!   1. A `Host` header - or, when that header is absent, the request-target
//!      authority - must be on the allowlist (`host_allowed`: the server's
//!      own bind host, loopback names when the bind is itself loopback or a
//!      wildcard, plus `BELAY_CONSOLE_HOSTS`) - independent of any credential
//!      and, because this now runs before the safe-method return below,
//!      independent of method too. Reading data over a rebound Host is the
//!      primary DNS-rebinding payoff, so the check has to cover GET as well
//!      as writes. This is what an Origin-vs-Host comparison alone cannot
//!      provide: DNS rebinding makes Origin and Host match each other
//!      trivially, since the attacker controls both. See the Host/authority
//!      fallback note on `csrf_guard` for what happens when neither is
//!      present.
//!   2. Safe methods (GET/HEAD/OPTIONS) pass, then `POST /api/enroll` is
//!      exempted outright (see below).
//!   3. If `Origin` is present, it must match the request's `Host` (host and,
//!      on a non-loopback deployment, scheme) - full stop, regardless of
//!      credential. A mismatch is rejected even for a Bearer-authenticated
//!      request: machine clients never send `Origin`, so this burdens
//!      nothing real, and it closes the login-CSRF gap where a merely-present
//!      `Authorization` header used to exempt a cross-origin write outright.
//!   4. Only once Origin is out of the way does a genuine `Bearer ` prefix
//!      (exact case, exact trailing space - the same test `AuthClaims` uses
//!      to authenticate) exempt the request: a browser never attaches
//!      `Authorization` on its own, so that credential is not reachable by
//!      CSRF.
//!   5. Otherwise, `Sec-Fetch-Site: same-origin` passes; everything else -
//!      including an absent header - fails closed. Grafana returns early
//!      there; Portainer fails closed because legacy browsers and
//!      header-stripping proxies produce that shape too. Belay follows
//!      Portainer.

use axum::{
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, HOST, ORIGIN},
        Method, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::SharedState;

/// Host component of an origin string (`https://h:port` -> `h:port`).
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.split_once("://").map(|(_, r)| r).unwrap_or(origin);
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Scheme component of an origin string (`https://h:port` -> `https`), when
/// the origin is well-formed enough to carry one.
fn origin_scheme(origin: &str) -> Option<&str> {
    origin.split_once("://").map(|(s, _)| s)
}

/// Whether `origin` may be treated as same-origin with a request to `host`.
///
/// Host must match exactly. Scheme is compared only on a non-loopback
/// deployment (F4): `cookie_secure` is true precisely when the bind is
/// non-loopback (see `AppState::cookie_secure`), which is also exactly when
/// the session cookie carries `Secure` and the console is therefore only
/// ever legitimately served over `https`. A same-host `http://` origin
/// arriving at such a deployment is not a legitimate same-origin fetch, so
/// reject it rather than let a bare host match paper over the scheme
/// downgrade. On a loopback dev bind the scheme is left unchecked - the
/// operator's local setup (plain http, a local https proxy, etc.) is not
/// something this guard can infer, and the SameSite/host check already
/// covers the threat model there.
fn origin_matches_host(origin: &str, host: &str, cookie_secure: bool) -> bool {
    if origin_host(origin) != Some(host) {
        return false;
    }
    if cookie_secure {
        if let Some(scheme) = origin_scheme(origin) {
            if !scheme.eq_ignore_ascii_case("https") {
                return false;
            }
        }
    }
    true
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "cross-origin request rejected"})),
    )
        .into_response()
}

pub async fn csrf_guard(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    // Two routes are exempt from every check below, ahead of the Host
    // allowlist: `/api/health` (load-balancer and container probes send
    // arbitrary Host values) and `/api/source` (the AGPL section 13
    // network-use source affordance, documented as unauthenticated by design
    // in `source.rs` - it must reach anyone this instance serves over the
    // network, not just a caller on an allowlisted host, or gating it here
    // would undercut the license obligation it exists to satisfy). Both are
    // GET-only, side-effect-free routes.
    if req.uri().path() == "/api/health" || req.uri().path() == "/api/source" {
        return next.run(req).await;
    }

    // Host allowlist, ahead of the safe-method return below and independent
    // of any credential (F2). Reading data over a rebound Host is the
    // primary DNS-rebinding payoff - `GET /api/posture`, `/api/findings`,
    // `/api/sessions`, `/api/egress`, `/api/stream`, and every enterprise
    // fleet/org/device read route are all reachable with no credential in
    // open-access mode - so this must run before GET is waved through, not
    // after it. The Origin-vs-Host check further down cannot defend against
    // DNS rebinding on its own: a rebinding attacker controls BOTH headers,
    // so they match each other trivially. Only an allowlist of hosts this
    // server is actually reachable at rejects that.
    //
    // `Host` is read from the header first. hyper does NOT enforce Host
    // presence on the wire: a raw four-line HTTP/1.1 request with no Host
    // header reaches this middleware, so when the header is absent this
    // falls back to the request-target authority (`req.uri().authority()`)
    // instead of waving the request through. Under HTTP/2 the authority is
    // always present (it travels as the `:authority` pseudo-header, which
    // the `Uri` here is built from), so this fallback restores the check for
    // exactly the case a browser can produce without a `Host` header. Only
    // when BOTH the header and the authority are absent - the shape an
    // in-process test produces by building a `Request::builder().uri("/api/...")`
    // with no scheme or authority, bypassing the wire entirely - does the
    // request pass through unchecked here; a browser can never reach this
    // middleware in that state, and a raw client crafting such a request by
    // hand gains nothing from it either: it could just as easily set `Host`
    // to a value already on the allowlist (the bind host, a loopback name
    // when the bind is loopback or a wildcard, or a `BELAY_CONSOLE_HOSTS`
    // entry) and get the same pass-through result honestly. This holds on
    // any bind, loopback or not - the allowlist's job is to stop a browser
    // from being tricked into sending a rebound Host on a victim's behalf;
    // it was never meant to stop a client that already controls its own
    // request bytes.
    let header_host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let authority_host = req.uri().authority().map(|a| a.as_str().to_string());
    let host_present = req.headers().contains_key(HOST) || authority_host.is_some();
    let host = header_host.or(authority_host).unwrap_or_default();

    if host_present && !host_allowed(&host, &state.bind_host, &state.console_hosts) {
        return forbidden();
    }

    // Safe methods pass unconditionally beyond the host check. Two GET
    // routes do mutate state - `GET /api/agent/commands` flips queued
    // commands to `Delivered`, and `GET /api/sso/{slug}/callback`
    // JIT-provisions org membership - but neither is reachable by a forged
    // cross-site request: the former requires a device bearer token
    // (`DeviceAuth`, never a cookie) and the latter requires a signed,
    // slug-and-state-bound IdP callback that a hostile page cannot forge.
    // GET stays safe here for that reason, not because nothing on this
    // server mutates on GET.
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }

    // `POST /api/enroll` is structurally immune to CSRF and is exempted
    // outright, ahead of the Origin/Bearer/Sec-Fetch-Site logic below: it
    // never reads a Cookie or any ambient credential (ambient/automatic
    // credentials are the entire premise CSRF exploits), its sole credential
    // is a one-time `enroll_token` the caller supplies IN THE BODY, and it
    // never sets a cookie in response - so forging this request from a
    // hostile page gains an attacker nothing they did not already have (they
    // would need to already know a valid token to make the forgery do
    // anything, at which point they could call the API directly). Its real
    // callers are non-interactive CLI/agent processes (`belay enroll`,
    // fleet-deploy self-registration) that send none of Origin,
    // Sec-Fetch-Site, or an `Authorization` header - unlike `/api/login`,
    // which DOES mint a session cookie and stays fully guarded below because
    // a forged login has a real effect (login-CSRF).
    if req.uri().path() == "/api/enroll" {
        return next.run(req).await;
    }

    // Distinguish "no Origin header" from "Origin header present but not
    // readable as UTF-8" (F3): the latter must reject outright rather than
    // fall through to the Sec-Fetch-Site arm the way `.to_str().ok()` alone
    // would let it.
    let origin = match req.headers().get(ORIGIN) {
        Some(v) => match v.to_str() {
            Ok(s) => Some(s),
            Err(_) => return forbidden(),
        },
        None => None,
    };

    // Rule 3: once Origin is present it must match Host, regardless of any
    // credential the request also carries. This closes F1: a request with an
    // unrelated `Authorization` value (or none at all authenticating it, in
    // open-access mode - F2) plus a mismatched Origin used to sail through
    // on header presence, or Cookie presence, alone.
    if let Some(o) = origin {
        return if origin_matches_host(o, &host, state.cookie_secure) {
            next.run(req).await
        } else {
            forbidden()
        };
    }

    // Rule 4: only once Origin is out of the picture does a genuine Bearer
    // credential exempt the request. Presence of *some* Authorization value
    // is not enough (F1) - it must be the exact prefix `AuthClaims` strips
    // before it will authenticate anything.
    let has_bearer_token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false);
    if has_bearer_token {
        return next.run(req).await;
    }

    // Rule 5: no Origin, no Bearer token. This guard runs regardless of
    // whether the request carries a Cookie, because open-access mode (no
    // `users` configured) authorizes requests with no credential at all - a
    // guard gated on Cookie presence left that mode with no CSRF protection
    // whatsoever (F2). `Sec-Fetch-Site: same-origin` is the only value
    // accepted; `none` (address bar, bookmark - no initiator) is deliberately
    // excluded even though it never accompanies an unsafe method in
    // practice: accepting it grants nothing real and would hand a future
    // non-browser bypass its magic word. Everything else, including an
    // absent header, fails closed: legacy browsers and header-stripping
    // proxies produce that shape too.
    let sec_fetch_site = req
        .headers()
        .get("Sec-Fetch-Site")
        .and_then(|v| v.to_str().ok());
    let ok = matches!(sec_fetch_site, Some(s) if s.eq_ignore_ascii_case("same-origin"));

    if ok {
        next.run(req).await
    } else {
        forbidden()
    }
}

/// Whether a request's `Host` value (or, per `csrf_guard`'s absent-Host
/// fallback, the request-target authority) is one this console may be
/// reached at.
///
/// The allowlist is the server's own bind host, plus the loopback names when
/// the bind host is itself loopback OR a wildcard (`0.0.0.0`, `::`, `[::]`) -
/// a wildcard bind has no single hostname to compare against, so it is
/// treated as "authority unknown" rather than either accepting every Host
/// (which would defeat the allowlist) or rejecting every Host (which would
/// 403 every request on a wildcard bind - F3) - plus any operator-provided
/// extras from `BELAY_CONSOLE_HOSTS`. An empty extras list narrows the
/// allowlist; it never widens it to "any host".
pub fn host_allowed(host: &str, bind_host: &str, extra: &[String]) -> bool {
    // Strip the port and lowercase for case-insensitive comparison (F4). IPv6
    // literals are bracketed, so a bare `:` split is only safe once the
    // bracketed form has been handled - and an UNbracketed literal (more than
    // one colon, no brackets) is not "host:port" at all: a real client always
    // brackets an IPv6 literal that carries a port (RFC 3986 s3.2.2), so a
    // bare multi-colon string is the whole address with no port to strip.
    // Splitting it at the last colon regardless, as an earlier version did,
    // silently truncates it (`bare("::1")` produced `":"`) - a security
    // predicate must not do that (F3).
    let bare = |h: &str| -> String {
        let h = h.trim();
        if let Some(end) = h.strip_prefix('[').and_then(|r| r.split_once(']')) {
            return format!("[{}]", end.0.to_ascii_lowercase());
        }
        if h.matches(':').count() > 1 {
            return h.to_ascii_lowercase();
        }
        h.rsplit_once(':')
            .map(|(a, _)| a)
            .unwrap_or(h)
            .to_ascii_lowercase()
    };

    let h = bare(host);
    if h.is_empty() {
        return false;
    }

    // Route the bind host through the same `bare()` port-stripping as the
    // request Host, not just a trim+lowercase: `run()` never puts a port in
    // `bind_host` today, so this is currently a no-op in practice, but the
    // wildcard/loopback comparisons just below compared the raw trimmed
    // string directly, which would silently stop matching the moment a port
    // ever did show up (`host_allowed("localhost", "127.0.0.1:8080", &[])`
    // was false while `host_allowed("127.0.0.1", "127.0.0.1:8080", &[])` was
    // true) - an inconsistency a security predicate should not have even
    // while unreachable.
    let bind = bare(bind_host);

    // A wildcard bind has no single authority to compare against - matching
    // its literal value against a request Host would be pointless, since a
    // browser never sends `Host: 0.0.0.0` - so it is excluded from the direct
    // bind-host equality check and instead folded into the loopback fallback
    // just below.
    let bind_is_wildcard = matches!(bind.as_str(), "0.0.0.0" | "::" | "[::]");
    if !bind_is_wildcard && h == bind {
        return true;
    }

    let bind_is_loopback = matches!(bind.as_str(), "127.0.0.1" | "::1" | "[::1]" | "localhost");
    if (bind_is_loopback || bind_is_wildcard)
        && matches!(h.as_str(), "localhost" | "127.0.0.1" | "[::1]" | "::1")
    {
        return true;
    }

    extra.iter().any(|e| bare(e) == h)
}
