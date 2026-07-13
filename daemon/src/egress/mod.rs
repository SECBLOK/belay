//! App-aware egress verdict.
//!
//! The pure core (`EgressAllowlist` + `classify_connect`) is always compiled and
//! unit-testable without feature flags.  The actual enforcement — adding a dest IP
//! to the `egress_drop` nftables set — lives in a `#[cfg(fw)]`
//! block.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::engine::types::Decision;

/// Per-process-basename allowlist of permitted egress destinations.
///
/// Keys are process binary basenames (e.g. `"node"`, `"python3"`).
/// Values are the set of allowed host strings or IP addresses.
#[derive(Debug, Default, Clone)]
pub struct EgressAllowlist {
    inner: HashMap<String, HashSet<String>>,
}

impl EgressAllowlist {
    /// Build an allowlist from `(basename, host)` pairs.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut inner: HashMap<String, HashSet<String>> = HashMap::new();
        for (bin, host) in pairs {
            inner
                .entry((*bin).to_string())
                .or_default()
                .insert((*host).to_string());
        }
        Self { inner }
    }

    /// Look up whether `host` is allowed for `basename`.
    pub fn is_allowed(&self, basename: &str, host: &str) -> bool {
        self.inner
            .get(basename)
            .is_some_and(|set| set.contains(host))
    }
}

/// Strip a `:port` suffix from a destination string.
///
/// `"api.anthropic.com:443"` → `"api.anthropic.com"`.
/// `"203.0.113.5:443"` → `"203.0.113.5"`.
/// `"[::1]:443"` → `"[::1]"` (bracketed IPv6 + port).
/// `"2001:db8::1"` → unchanged (bare IPv6, no port — the colons are address bytes,
/// not a port separator, so it must NOT be truncated to `"2001:db8:"`).
/// Already-bare strings are returned unchanged.
fn strip_port(dest: &str) -> &str {
    // Bracketed IPv6 (`[::1]` or `[::1]:443`) — keep the whole bracket group.
    if dest.starts_with('[') {
        return match dest.find(']') {
            Some(end) => &dest[..=end],
            None => dest,
        };
    }
    if let Some(idx) = dest.rfind(':') {
        let candidate = &dest[..idx];
        let port_part = &dest[idx + 1..];
        // Only strip when the suffix is a port (all digits) AND the remaining host
        // has no further ':' — a remaining colon means `dest` is a bare IPv6 literal.
        if !port_part.is_empty()
            && port_part.chars().all(|c| c.is_ascii_digit())
            && !candidate.contains(':')
        {
            return candidate;
        }
    }
    dest
}

/// Pure egress verdict.
///
/// - Strips `:port` from `dest`.
/// - Resolves the process basename from `proc_path`.
/// - Returns `Decision::Allow` if the host is in the allowlist, `Decision::Deny` otherwise.
///
/// `proc_path` is typically the result of `std::fs::read_link(format!("/proc/{pid}/exe"))`.
pub fn classify_connect(
    pid: u32,
    dest: &str,
    allow: &EgressAllowlist,
    proc_path: &str,
) -> Decision {
    let _ = pid; // pid is available to callers for audit; not needed in pure classification
    let host = strip_port(dest);
    let basename = Path::new(proc_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(proc_path);

    if allow.is_allowed(basename, host) {
        Decision::Allow
    } else {
        Decision::Deny
    }
}

// ─── Inline NFQUEUE enforcement (opt-in, off by default) ─────────────────────

#[cfg(feature = "inline-egress")]
pub mod inline;

// ─── Enforcement (firewall-gated) ────────────────────────────────────────────

#[cfg(fw)]
pub mod enforce {
    //! Wires a `Decision::Deny` from `classify_connect` into the approval queue,
    //! audit log, and (on deny-confirm) the `egress_drop` nftables set.
    use std::net::IpAddr;
    use std::time::Duration;

    use crate::firewall::FwError;

    /// Add a destination IP to the `egress_drop` set with the given TTL.
    pub fn deny_to_set(ip: IpAddr, ttl: Duration) -> Result<(), FwError> {
        crate::firewall::add_to_set("egress_drop", ip, ttl)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::Decision;

    #[test]
    fn unknown_destination_for_agent_is_denied() {
        let allow = EgressAllowlist::from_pairs(&[("node", "api.anthropic.com")]);
        let d = classify_connect(1234, "203.0.113.5:443", &allow, "/usr/bin/node");
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn allowlisted_destination_is_allowed() {
        let allow = EgressAllowlist::from_pairs(&[("node", "api.anthropic.com")]);
        let d = classify_connect(1234, "api.anthropic.com:443", &allow, "/usr/bin/node");
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn strip_port_handles_ipv4_and_ipv6() {
        // host:port and ipv4:port strip the port
        assert_eq!(strip_port("api.anthropic.com:443"), "api.anthropic.com");
        assert_eq!(strip_port("203.0.113.5:443"), "203.0.113.5");
        // bracketed IPv6 with port keeps the bracket group
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
        // bare IPv6 (no port) must NOT be truncated to "2001:db8:"
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        // already-bare host unchanged
        assert_eq!(strip_port("example.com"), "example.com");
    }
}
