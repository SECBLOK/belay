//! DNS rebinding defeats both SameSite and an Origin check, because it makes
//! the attacker's page GENUINELY same-origin. A Host allowlist is the only
//! defence that still holds for a console reachable at a bare IP or at
//! `localhost`.
//!
//! Unset means "bind address and loopback names only", never "any host".

use belay_server::csrf::host_allowed;

#[test]
fn the_bind_host_is_allowed() {
    assert!(host_allowed("console.example.com", "console.example.com", &[]));
}

#[test]
fn a_port_suffix_does_not_break_the_match() {
    assert!(host_allowed("console.example.com:8080", "console.example.com", &[]));
}

#[test]
fn loopback_names_are_allowed() {
    assert!(host_allowed("localhost:8080", "127.0.0.1", &[]));
    assert!(host_allowed("127.0.0.1:8080", "127.0.0.1", &[]));
    assert!(host_allowed("[::1]:8080", "127.0.0.1", &[]));
}

#[test]
fn a_rebound_attacker_host_is_rejected() {
    assert!(!host_allowed("evil.example.net", "console.example.com", &[]));
}

#[test]
fn an_extra_entry_is_honoured() {
    let extra = vec!["proxy.corp.example".to_string()];
    assert!(host_allowed("proxy.corp.example", "console.example.com", &extra));
}

#[test]
fn an_empty_allowlist_does_not_mean_allow_everything() {
    assert!(!host_allowed("anything.example", "console.example.com", &[]));
}

#[test]
fn a_missing_host_header_is_rejected() {
    assert!(!host_allowed("", "console.example.com", &[]));
}

#[test]
fn matching_is_case_insensitive() {
    assert!(host_allowed("CONSOLE.example.com", "console.example.com", &[]));
}

// ── F3: IPv6 bind hosts (bracketed, as `derive_bind_host` in lib.rs now
// produces) must match a bracketed IPv6 Host header.

#[test]
fn a_bracketed_ipv6_host_matches_an_ipv6_bind() {
    assert!(host_allowed("[2001:db8::1]:8443", "[2001:db8::1]", &[]));
}

#[test]
fn a_bracketed_ipv6_host_with_no_port_matches_an_ipv6_bind() {
    assert!(host_allowed("[2001:db8::1]", "[2001:db8::1]", &[]));
}

// ── F4: IPv6 literal matching must be case-insensitive, like hostname
// matching already is.

#[test]
fn ipv6_literal_matching_is_case_insensitive() {
    assert!(host_allowed("[2001:DB8::1]:8443", "[2001:db8::1]", &[]));
    assert!(host_allowed("[2001:db8::1]:8443", "[2001:DB8::1]", &[]));
}

// ── F3: a wildcard bind (0.0.0.0 / :: / [::]) has no single authority to
// compare against. It must still allow loopback names and BELAY_CONSOLE_HOSTS
// entries, but never an arbitrary host - silently allowing everything on a
// wildcard bind would be worse than the pre-fix 403-everything bug.

#[test]
fn a_wildcard_ipv4_bind_allows_loopback_but_not_an_arbitrary_host() {
    assert!(host_allowed("localhost:8080", "0.0.0.0", &[]));
    assert!(host_allowed("127.0.0.1:8080", "0.0.0.0", &[]));
    assert!(!host_allowed("evil.example", "0.0.0.0", &[]));
}

#[test]
fn a_wildcard_ipv6_bind_allows_loopback_but_not_an_arbitrary_host() {
    assert!(host_allowed("[::1]:8080", "[::]", &[]));
    assert!(host_allowed("localhost:8080", "[::]", &[]));
    assert!(!host_allowed("evil.example", "[::]", &[]));
}

#[test]
fn a_wildcard_bind_still_honours_console_hosts() {
    let extra = vec!["console.example.com".to_string()];
    assert!(host_allowed("console.example.com", "0.0.0.0", &extra));
    assert!(!host_allowed("other.example.com", "0.0.0.0", &extra));
}

// ── F3: `bare()` must not truncate an unbracketed IPv6 literal at its last
// colon (an earlier version made `bare("::1")` yield `":"`, which made this
// call return true - a security predicate must not produce nonsense).

#[test]
fn bare_does_not_mangle_an_unbracketed_ipv6_literal() {
    // Before the fix, `bare("::1")` (truncating at the last colon) produced
    // `":"`, which made this comparison collapse to `":" == ":"` and return
    // true - the wildcard host `::` must not match a loopback bind.
    assert!(!host_allowed("::", "::1", &[]));
}

// ── the bind host must be port-stripped too, not just the request Host.
// Before the fix, `bind_is_wildcard`/`bind_is_loopback` compared the raw
// trimmed bind string, so a bind host that happened to carry a port matched
// inconsistently depending on which form of the request Host was used
// (unreachable from `run()` today - it never puts a port in `bind_host` -
// but still a real inconsistency in a security predicate).

#[test]
fn a_port_on_the_bind_host_does_not_break_loopback_matching() {
    assert!(host_allowed("localhost", "127.0.0.1:8080", &[]));
}
