//! Off-by-default network-destination enrichment (opt-in via the
//! `netenrich` cargo feature): reverse-DNS + ASN/owner/country lookup for
//! outbound destinations, powered by `trippy-dns`.
//!
//! Strictly DISPLAY-ONLY — this module never influences any allow/deny/ask
//! decision. A lookup failure, timeout, resolver-start failure, or
//! malformed destination always degrades to an empty [`Enrichment`], never
//! a panic.
//!
//! ## Deviation 1: `ResolveMethod::Resolv`, not `ResolveMethod::System`
//!
//! The design for this feature calls for using "the host's DNS" while also
//! getting Team-Cymru ASN lookups. `trippy-dns` 0.13.0 ties AS-info support
//! to which *internal provider* a `ResolveMethod` selects — verified against
//! the real published crate source (not just a local dev-branch clone):
//!
//! - `ResolveMethod::System` selects `DnsProvider::DnsLookup` (libc
//!   `getaddrinfo`/`getnameinfo` via the `dns_lookup` crate). This path
//!   NEVER performs the `*.asn.cymru.com` TXT queries, regardless of the
//!   `with_asinfo` flag passed to `reverse_lookup_with_asinfo` — see
//!   `trippy-dns-0.13.0/src/lazy_resolver.rs`'s free-standing `reverse_lookup`
//!   fn: the `DnsProvider::DnsLookup` arm never calls `lookup_asinfo`, only
//!   the `DnsProvider::TrustDns` arm does. Confirmed experimentally too: a
//!   `ResolveMethod::System` reverse lookup of `1.1.1.1` returns
//!   `Resolved::Normal` (no `AsInfo`), while `Resolv`/`Cloudflare`/`Google`
//!   all return `Resolved::WithAsInfo` for the same address.
//! - `ResolveMethod::Resolv | Google | Cloudflare` select
//!   `DnsProvider::TrustDns` (the `hickory-resolver` client), which is the
//!   only path that performs the Team-Cymru queries.
//!
//! So `System` cannot deliver this feature's actual purpose (surfacing
//! ASN/owner/country) at all — every lookup would silently degrade to
//! hostname-only forever. `Resolv` is used instead: it reads the host's own
//! `/etc/resolv.conf` (so, like `System`, it honors the host's actual
//! configured DNS server(s) rather than hardcoding a public resolver IP),
//! while still going through the `TrustDns` provider that performs the
//! Team-Cymru ASN queries. If `/etc/resolv.conf` is unreadable/malformed,
//! `DnsResolver::start` fails and every [`enrich`] call fails safe to an
//! empty `Enrichment` — no crash, just no enrichment.
//!
//! ## Deviation 2: a thread-local resolver, not a process-wide `OnceLock`
//!
//! `trippy_dns::DnsResolver` wraps an `Rc` internally (its own lookup
//! cache), so it is neither `Send` nor `Sync`. Confirmed by attempting to
//! compile `static R: OnceLock<DnsResolver> = OnceLock::new();` against the
//! real published 0.13.0 crate: it fails with "`Rc<...>` cannot be shared
//! between threads safely" / "cannot be sent between threads safely" (a
//! `static`'s type must be `Sync`, and `OnceLock<T>` is `Sync` only when
//! `T: Send + Sync`). A process-wide `OnceLock<DnsResolver>` therefore
//! cannot compile at all — not a design choice, a hard compiler error.
//!
//! This module instead lazily starts one resolver PER OS THREAD
//! (`thread_local!`), reusing it for every [`enrich`] call made from that
//! thread. Each such resolver keeps its own internal cache and background
//! queue-processing thread — the same lifecycle `DnsResolver::start` would
//! give a shared singleton — just scoped per-thread rather than
//! process-wide. (If a truly process-wide cache/resolver ever matters, the
//! fix would be an actor thread that owns the one `DnsResolver` instance and
//! answers requests over a `Send`-safe channel; out of scope for this task.)

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use trippy_dns::{Config, DnsEntry, DnsResolver, ResolveMethod, Resolved, Resolver, Unresolved};

thread_local! {
    /// Lazily-started, per-thread resolver. `None` means either "not
    /// started yet" or "failed to start" — both are treated identically by
    /// [`with_resolver`] (fail-safe: no enrichment available).
    static RESOLVER: RefCell<Option<DnsResolver>> = const { RefCell::new(None) };
}

/// Network-destination enrichment: reverse hostname + ASN/owner/country,
/// when resolvable. Every field is best-effort; any that could not be
/// determined is simply absent (`None`), never a placeholder value. An
/// empty `Enrichment` (the [`Default`]) serializes to `{}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Enrichment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl Enrichment {
    /// An empty `Enrichment` (all fields `None`). Identical to
    /// [`Default::default`]; exists as a self-documenting alias at call
    /// sites that mean "nothing was resolvable."
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Run `f` against the thread-local resolver, lazily starting it (with
/// `ResolveMethod::Resolv`, a ~2s timeout — see module docs for why not
/// `System`) on first use on this thread. Returns `None` if the resolver
/// has never successfully started (fail-safe: never panics); callers must
/// treat `None` as "no enrichment available."
///
/// The timeout is kept short (2s, not the crate default) because [`enrich`]
/// is called synchronously from the daemon's per-connection IPC thread (via
/// [`enrich_cached`] on a cache miss) and issues up to a couple of
/// sequential queries (forward + reverse) — a longer per-query timeout
/// would let a single slow/unresponsive resolver stall that thread for far
/// too long.
fn with_resolver<R>(f: impl FnOnce(&DnsResolver) -> R) -> Option<R> {
    RESOLVER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let cfg = Config {
                resolve_method: ResolveMethod::Resolv,
                timeout: Duration::from_secs(2),
                ..Config::default()
            };
            *slot = DnsResolver::start(cfg).ok();
        }
        slot.as_ref().map(f)
    })
}

/// Best-effort syntactic sanity check so obviously-malformed "hosts" (e.g.
/// `"???"`) short-circuit to an empty `Enrichment` before ever calling into
/// the resolver's forward `lookup` — which could otherwise still issue a
/// real network query via the system/library resolver even for garbage
/// input. Deliberately permissive (accepts anything that could plausibly be
/// a DNS label sequence); it only needs to catch clearly-invalid input, not
/// validate RFC 1123 precisely.
fn looks_like_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Strip a trailing `:port` from a destination string to get the bare host.
/// Handles a bare IPv4/IPv6 address (with or without a port), a bracketed
/// IPv6 host (`"[::1]:443"` or `"[::1]"`), and a plain `"host:port"` /
/// bare-hostname string. Anything that doesn't fit one of those shapes
/// (e.g. an unbracketed address with multiple colons that isn't itself a
/// valid IP) returns `None` rather than guessing.
fn strip_port(dest: &str) -> Option<&str> {
    let dest = dest.trim();
    if dest.is_empty() {
        return None;
    }
    if let Some(rest) = dest.strip_prefix('[') {
        // "[::1]:443" or "[::1]" — take everything up to the closing ']'.
        return rest.split(']').next().filter(|h| !h.is_empty());
    }
    if dest.parse::<IpAddr>().is_ok() {
        // A bare IP (including unbracketed IPv6 with no port) — use as-is.
        return Some(dest);
    }
    match dest.matches(':').count() {
        0 => Some(dest),
        1 => dest.split_once(':').map(|(h, _)| h).filter(|h| !h.is_empty()),
        // 2+ colons and not a parseable IP: ambiguous/malformed — bail out
        // rather than guess which part is the host.
        _ => None,
    }
}

/// Map a resolved `DnsEntry` to an `Enrichment`.
///
/// `known_hostname` is set only for the forward-resolved-hostname path in
/// [`enrich`] (the original host string the caller already knows); when
/// set, it always wins for the `hostname` field over whatever the reverse
/// lookup itself returns.
///
/// `NotFound` (with or without AS info) intentionally yields no `hostname`
/// even when `known_hostname` is set — the reverse lookup for the
/// underlying IP genuinely came back empty, so nothing is asserted for that
/// field.
fn entry_to_enrichment(entry: DnsEntry, known_hostname: Option<String>) -> Enrichment {
    match entry {
        DnsEntry::Resolved(Resolved::WithAsInfo(_ip, hostnames, asinfo)) => Enrichment {
            hostname: known_hostname.or_else(|| hostnames.into_iter().next()),
            asn: non_empty(asinfo.asn),
            as_name: non_empty(asinfo.name),
            country: non_empty(asinfo.cc),
        },
        DnsEntry::Resolved(Resolved::Normal(_ip, hostnames)) => Enrichment {
            hostname: known_hostname.or_else(|| hostnames.into_iter().next()),
            ..Enrichment::empty()
        },
        DnsEntry::NotFound(Unresolved::WithAsInfo(_ip, asinfo)) => Enrichment {
            asn: non_empty(asinfo.asn),
            as_name: non_empty(asinfo.name),
            country: non_empty(asinfo.cc),
            ..Enrichment::empty()
        },
        DnsEntry::NotFound(Unresolved::Normal(_))
        | DnsEntry::Pending(_)
        | DnsEntry::Timeout(_)
        | DnsEntry::Failed(_) => Enrichment::empty(),
    }
}

/// `trippy-dns`'s `AsInfo` fields are plain (non-`Option`) `String`s that
/// default to `""` when the underlying Team-Cymru query/parse failed (see
/// `lookup_asinfo(..).unwrap_or_default()` in the crate). Treat an empty
/// string as "unavailable" so a failed AS-info lookup never leaks as
/// `Some("")` — `Enrichment` fields are always either a real value or
/// absent.
fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Enrich a destination string — `"host:port"`, a bare host/IP, or a
/// bracketed IPv6 host (`"[::1]:443"`) — with reverse-DNS +
/// ASN/owner/country, best-effort.
///
/// Never panics. Any parse failure, resolver-start failure, lookup error,
/// pending result, or timeout degrades to an empty `Enrichment`.
pub fn enrich(dest: &str) -> Enrichment {
    let Some(host) = strip_port(dest) else {
        return Enrichment::empty();
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return with_resolver(|r| entry_to_enrichment(r.reverse_lookup_with_asinfo(ip), None))
            .unwrap_or_default();
    }

    if !looks_like_hostname(host) {
        return Enrichment::empty();
    }

    let forward_ip =
        with_resolver(|r| r.lookup(host).ok().and_then(|ips| ips.into_iter().next()))
            .flatten();
    let Some(ip) = forward_ip else {
        return Enrichment::empty();
    };

    with_resolver(|r| {
        entry_to_enrichment(r.reverse_lookup_with_asinfo(ip), Some(host.to_string()))
    })
    .unwrap_or_default()
}

/// How long a cached [`enrich_cached`] answer stays fresh before a repeat
/// call re-resolves it from scratch.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Daemon-side shared enrichment cache, keyed by the caller's original
/// `dest` string. [`enrich`]'s own resolver is `thread_local!` (see the
/// module docs — `trippy_dns::DnsResolver` isn't `Send`/`Sync`, so it can't
/// be a process-wide singleton), so it caches nothing across the daemon's
/// per-connection threads. This cache is a plain `Mutex<HashMap<..>>` of
/// owned data — no `DnsResolver` inside it — which *is* `Send + Sync`, so it
/// can be shared across every thread that calls [`enrich_cached`].
static CACHE: OnceLock<Mutex<HashMap<String, (Enrichment, Instant)>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, (Enrichment, Instant)>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached wrapper around [`enrich`] for callers that cannot afford a fresh
/// blocking DNS lookup on every call — namely the `enrich_dest` IPC arm,
/// which runs on a short-lived per-connection thread. A fresh cache hit
/// (age < [`CACHE_TTL`]) returns instantly; a miss falls through to a real
/// [`enrich`] call (bounded by [`with_resolver`]'s ~2s-per-query timeout)
/// and populates the cache for next time.
///
/// The lock is never held across the blocking `enrich(dest)` call itself —
/// it is acquired only to check for a fresh entry, released, and then
/// re-acquired only to insert the result — so one slow cache-miss lookup
/// for one destination can never block cache reads (or another thread's
/// insert) for a different destination.
pub fn enrich_cached(dest: &str) -> Enrichment {
    {
        let guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached, cached_at)) = guard.get(dest) {
            if cached_at.elapsed() < CACHE_TTL {
                return cached.clone();
            }
        }
    } // Lock released before the (potentially slow) lookup below.

    let result = enrich(dest);

    {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(dest.to_string(), (result.clone(), Instant::now()));
    }

    result
}

/// Test-only accessor so cache tests can assert an entry was actually
/// populated, without exposing cache internals outside this module.
#[cfg(test)]
pub(crate) fn test_cache_contains(dest: &str) -> bool {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_enrichment_serializes_to_empty_object() {
        let e = Enrichment::default();
        assert_eq!(serde_json::to_value(&e).unwrap(), serde_json::json!({}));
    }

    #[test]
    fn fully_populated_enrichment_serializes_all_fields() {
        let e = Enrichment {
            hostname: Some("api.anthropic.com".to_string()),
            asn: Some("13335".to_string()),
            as_name: Some("CLOUDFLARENET".to_string()),
            country: Some("US".to_string()),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "hostname": "api.anthropic.com",
                "asn": "13335",
                "as_name": "CLOUDFLARENET",
                "country": "US",
            })
        );
    }

    /// `"???"` fails the hostname-syntax guard before any resolver call is
    /// even attempted (the resolver is never started for this input), so
    /// this test never touches the network and never panics.
    #[test]
    fn enrich_invalid_dest_returns_empty_without_network_or_panic() {
        assert_eq!(enrich("???"), Enrichment::empty());
    }

    #[test]
    fn strip_port_handles_ips_hostnames_ipv6_and_garbage() {
        assert_eq!(strip_port("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(strip_port("1.2.3.4:443"), Some("1.2.3.4"));
        assert_eq!(strip_port("example.com"), Some("example.com"));
        assert_eq!(strip_port("example.com:443"), Some("example.com"));
        assert_eq!(strip_port("[::1]:443"), Some("::1"));
        assert_eq!(strip_port("[::1]"), Some("::1"));
        assert_eq!(strip_port("::1"), Some("::1"));
        assert_eq!(strip_port(""), None);
        assert_eq!(strip_port("   "), None);
        assert_eq!(strip_port("not:valid:ipv6:host"), None);
        assert_eq!(strip_port(":443"), None);
    }

    #[test]
    fn looks_like_hostname_rejects_garbage_accepts_normal_hosts() {
        assert!(looks_like_hostname("example.com"));
        assert!(looks_like_hostname("api.anthropic.com"));
        assert!(!looks_like_hostname("???"));
        assert!(!looks_like_hostname(""));
        assert!(!looks_like_hostname("has space.com"));
    }

    /// `enrich_cached` on a syntactically invalid dest never touches the
    /// network (same guard as `enrich_invalid_dest_returns_empty_...`
    /// above) and populates the shared cache on first call; a second call
    /// for the same key is then served from that cache. Uses a dest string
    /// unique to this test so it can't collide with cache entries any other
    /// test in this module might leave behind.
    #[test]
    fn enrich_cached_invalid_dest_returns_empty_and_populates_cache() {
        let dest = "???enrich-cached-test-key";

        assert!(!test_cache_contains(dest));

        let first = enrich_cached(dest);
        assert_eq!(first, Enrichment::empty());
        assert!(
            test_cache_contains(dest),
            "enrich_cached must populate the shared cache on a miss"
        );

        // Second call: served from cache (no panic, same empty result —
        // the hermetic assertion is "no network, no panic"; the cache-write
        // above is what proves this call *could* be a hit).
        let second = enrich_cached(dest);
        assert_eq!(second, Enrichment::empty());
    }
}
