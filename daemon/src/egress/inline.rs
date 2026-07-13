//! Opt-in NFQUEUE inline egress enforcement.
//!
//! # Safety design (non-negotiable)
//!
//! 1. **Fail-OPEN on unattributed packets**: `nfqueue_verdict` returns `Accept`
//!    whenever `proc_hint` is `None`.  We never drop traffic we cannot attribute to
//!    a process — that is the difference between a detect-and-report path and an
//!    inline block that can sever networking.
//!
//! 2. **Kernel `bypass` flag on the nft rule**: the installed rule is
//!    `queue num 0 bypass`.  If this userspace loop exits or crashes, the kernel
//!    falls back to ACCEPT for all packets — never to DROP.  On a headless VPS a
//!    fail-closed inline filter is equivalent to a network-lockout.
//!
//! 3. **Opt-in, off by default**: this module compiles only when the
//!    `inline-egress` Cargo feature is enabled.  Production builds ship without it.

use super::EgressAllowlist;

// ─── Verdict type ─────────────────────────────────────────────────────────────

/// Inline verdict for a single outbound packet.
///
/// By construction, the only reachable path to `Drop` is:
///   1. `proc_hint` is `Some(path)` — we have a process attribution, and
///   2. the destination IP is **not** in that process's allowlist.
///
/// All other cases, including unattributed traffic, produce `Accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineVerdict {
    Accept,
    Drop,
}

// ─── Pure verdict function ─────────────────────────────────────────────────────

/// Compute the inline verdict for a packet.
///
/// # Fail-open contract
///
/// When `proc_hint` is `None` (traffic cannot be attributed to a process), this
/// function **always** returns `Accept`.  Dropping unattributed traffic would
/// sever legitimate connections from any process not tracked by the eBPF
/// `connect()` → PID map (Task 11).
///
/// # Arguments
///
/// * `dest_ip` — Destination IP address string (no port).
/// * `allow`   — Per-process allowlist to consult.
/// * `proc_hint` — Optional process binary path obtained from the eBPF map.
///   Pass `None` when attribution is unavailable.
pub fn nfqueue_verdict(
    dest_ip: &str,
    allow: &EgressAllowlist,
    proc_hint: Option<&str>,
) -> InlineVerdict {
    // SAFETY CONTRACT: unattributed → Accept (fail-open).
    // This is the primary safety invariant for Task 14.
    // inline.rs:54 — this is the fail-open gate.
    let Some(path) = proc_hint else {
        return InlineVerdict::Accept; // unattributed → never sever
    };

    // Resolve basename from the full binary path (e.g. "/usr/bin/node" → "node").
    let basename = path.rsplit('/').next().unwrap_or(path);

    if allow.is_allowed(basename, dest_ip) {
        InlineVerdict::Accept
    } else {
        InlineVerdict::Drop
    }
}

// ─── NFT rule installer ───────────────────────────────────────────────────────

/// Install the nftables rule that feeds new outbound connections into NFQUEUE 0.
///
/// # The `bypass` keyword is load-bearing
///
/// The rule uses `queue num 0 bypass` (not `queue num 0`).  The `bypass` flag
/// instructs the kernel to **accept** the packet if the userspace queue is full
/// or if no userspace listener is registered — i.e. if this loop dies, traffic
/// flows unimpeded.  Without `bypass`, a dead listener means all new connections
/// are silently dropped, which is a network-lockout on headless hosts.
///
/// # rustables 0.8 limitation
///
/// rustables 0.8 does not expose a `queue` expression type with a queue number or
/// bypass flag.  The `ExpressionRaw` tuple struct (`pub struct ExpressionRaw(Vec<u8>)`)
/// has a private inner field and provides no public constructor, so the raw netlink
/// bytes for `NFT_QUEUE_FLAG_BYPASS` cannot be injected from outside the crate.
/// `VerdictKind::Queue` exists but carries no queue number or bypass flag.
///
/// Until rustables exposes a queue expression (or provides a public `ExpressionRaw`
/// constructor), the caller must install the rule manually:
///
/// ```text
/// nft add table inet belay
/// nft add chain inet belay egress_queue \
///     '{ type filter hook output priority 0; policy accept; }'
/// nft add rule  inet belay egress_queue \
///     ct state new queue num 0 bypass
/// ```
///
/// # Errors
///
/// Always returns `Err` with a descriptive message explaining the library
/// limitation.  The caller should log the error and arrange for the rule to be
/// installed through an alternative mechanism (e.g. a one-time setup script).
pub fn install_nft_rule() -> Result<(), String> {
    // BLOCKER: rustables 0.8 does not expose queue expression with bypass flag.
    // ExpressionRaw(Vec<u8>) has a private inner field — cannot be constructed
    // outside the crate.  VerdictKind::Queue carries no queue number or flags.
    // NFT_QUEUE_FLAG_BYPASS (0x01) cannot be set through any public rustables API.
    //
    // Fail-open is preserved at the queue level via queue.set_fail_open() in
    // run_verdict_loop(), but the kernel-side bypass flag requires manual nft setup.
    Err(
        "install_nft_rule: rustables 0.8 does not expose queue expression with bypass flag; \
         manual nft setup required (see function doc for the exact nft commands)"
            .to_string(),
    )
}

// ─── Extract dest IP from raw IPv4/IPv6 packet payload ────────────────────────

/// Parse the destination IP address (v4 or v6) from a raw packet payload.
///
/// Uses `trippy-packet` (a `#![forbid(unsafe_code)]` crate) for the actual
/// header parsing rather than hand-rolled byte indexing, so both address
/// families are handled correctly.
///
/// Returns `None` if the payload is empty, too short for the header implied
/// by its version nibble, or has a version nibble that is neither 4 nor 6.
/// The caller treats `None` as "cannot attribute" and applies the fail-open
/// policy.
///
/// # Fail-open contract
///
/// This function never panics and never indexes the payload outside of the
/// checked-length parsing performed by `trippy-packet`. Any parse error is
/// mapped to `None`.
fn dest_ip_from_payload(payload: &[u8]) -> Option<std::net::IpAddr> {
    if payload.is_empty() {
        return None;
    }
    let version = payload[0] >> 4;
    match version {
        4 => {
            let pkt = trippy_packet::ipv4::Ipv4Packet::new_view(payload).ok()?;
            Some(std::net::IpAddr::V4(pkt.get_destination()))
        }
        6 => {
            let pkt = trippy_packet::ipv6::Ipv6Packet::new_view(payload).ok()?;
            Some(std::net::IpAddr::V6(pkt.get_destination_address()))
        }
        // Unrecognised version — caller will fail-open.
        _ => None,
    }
}

// ─── NFQUEUE verdict loop ─────────────────────────────────────────────────────

/// Run the NFQUEUE verdict loop (blocking, intended for a dedicated thread).
///
/// Binds to queue number `queue_num` and processes packets indefinitely.
/// For each packet:
/// - Extracts the destination IP from the IPv4 or IPv6 header.
/// - Calls `nfqueue_verdict` with the `proc_hint` supplied by the caller.
/// - Sends the verdict back to the kernel.
///
/// # Fail-soft I/O handling
///
/// All I/O errors (queue open, recv, verdict) are logged via `eprintln!` and
/// the loop continues — or `Accept` is applied — rather than panicking.  This
/// ensures a temporary kernel / socket hiccup does not drop all traffic.
///
/// # proc_hint
///
/// Process attribution (mapping packet → PID → binary path) requires the eBPF
/// `connect()` → PID map from Task 11 and is beyond the scope of this module.
/// The `get_proc_hint` closure is the integration point: pass a function that
/// looks up the binary path for a given destination IP, or always return `None`
/// to engage fail-open for all unattributed traffic.
pub fn run_verdict_loop(
    queue_num: u16,
    allow: &EgressAllowlist,
    get_proc_hint: impl Fn(&str) -> Option<String>,
) {
    // Open the NFQUEUE socket.
    let mut queue = match nfq::Queue::open() {
        Ok(q) => q,
        Err(e) => {
            eprintln!("[inline-egress] failed to open NFQUEUE socket: {e}; exiting loop");
            return;
        }
    };

    // Bind to the queue number configured in the nft rule.
    if let Err(e) = queue.bind(queue_num) {
        eprintln!("[inline-egress] failed to bind queue {queue_num}: {e}; exiting loop");
        return;
    }

    // Enable fail-open at the queue level as an extra safety layer:
    // if the kernel queue fills up, packets are accepted rather than dropped.
    if let Err(e) = queue.set_fail_open(queue_num, true) {
        // Non-fatal: kernel `bypass` in the nft rule already covers this.
        eprintln!("[inline-egress] set_fail_open warning: {e}; continuing");
    }

    eprintln!("[inline-egress] NFQUEUE loop started on queue {queue_num}");

    loop {
        // recv() blocks until a packet arrives.
        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[inline-egress] recv error: {e}; continuing");
                continue;
            }
        };

        // Extract destination IP from the raw packet bytes.
        let dest_str: Option<String> =
            dest_ip_from_payload(msg.get_payload()).map(|ip| ip.to_string());

        // Compute the inline verdict.  Fall back to Accept on any ambiguity.
        let verdict = match dest_str.as_deref() {
            None => InlineVerdict::Accept, // cannot parse IP → fail-open
            Some(dest) => {
                let hint = get_proc_hint(dest);
                nfqueue_verdict(dest, allow, hint.as_deref())
            }
        };

        msg.set_verdict(match verdict {
            InlineVerdict::Accept => nfq::Verdict::Accept,
            InlineVerdict::Drop => nfq::Verdict::Drop,
        });

        if let Err(e) = queue.verdict(msg) {
            eprintln!("[inline-egress] verdict send error: {e}; continuing");
        }
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::EgressAllowlist;

    /// Attributed traffic to a non-allowlisted destination must be dropped.
    #[test]
    fn drop_attributed_unlisted() {
        let allow = EgressAllowlist::from_pairs(&[("node", "203.0.113.9")]);
        let v = nfqueue_verdict("203.0.113.5", &allow, Some("/usr/bin/node"));
        assert_eq!(v, InlineVerdict::Drop);
    }

    /// Attributed traffic to an allowlisted destination must be accepted.
    #[test]
    fn accept_allowlisted() {
        let allow = EgressAllowlist::from_pairs(&[("node", "203.0.113.5")]);
        let v = nfqueue_verdict("203.0.113.5", &allow, Some("/usr/bin/node"));
        assert_eq!(v, InlineVerdict::Accept);
    }

    /// Unattributed traffic (proc_hint = None) must always be accepted — fail-open.
    #[test]
    fn fail_open_when_unattributed() {
        // Even with an empty allowlist, unattributed traffic must not be dropped.
        let allow = EgressAllowlist::from_pairs(&[]);
        let v = nfqueue_verdict("203.0.113.5", &allow, None);
        assert_eq!(v, InlineVerdict::Accept);
    }

    // ─── dest_ip_from_payload ──────────────────────────────────────────────

    /// A minimal valid IPv4 header (20 bytes) parses the destination address
    /// from bytes 16..20.
    #[test]
    fn dest_ip_parses_ipv4() {
        let mut payload = [0u8; 20];
        payload[0] = 0x45; // version 4, IHL 5 (20-byte header, no options)
        payload[16..20].copy_from_slice(&[93, 184, 216, 34]);
        let got = dest_ip_from_payload(&payload);
        assert_eq!(
            got,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                93, 184, 216, 34
            )))
        );
    }

    /// A minimal valid IPv6 header (40 bytes) parses the destination address
    /// from bytes 24..40. This is the regression case: the old hand-rolled
    /// parser returned `None` for any non-IPv4 packet, which made the
    /// inline-egress caller fail-open (silently allow) all IPv6 traffic.
    #[test]
    fn dest_ip_parses_ipv6() {
        let mut payload = [0u8; 40];
        payload[0] = 0x60; // version 6, traffic class 0, flow label 0
        let dest = std::net::Ipv6Addr::new(
            0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946,
        );
        payload[24..40].copy_from_slice(&dest.octets());
        let got = dest_ip_from_payload(&payload);
        assert_eq!(got, Some(std::net::IpAddr::V6(dest)));
    }

    /// A too-short payload (shorter than any recognised header) must not
    /// panic and must return `None` (fail-open, unchanged).
    #[test]
    fn dest_ip_too_short_returns_none() {
        let payload = [0u8; 10];
        assert_eq!(dest_ip_from_payload(&payload), None);
    }

    /// A version nibble that is neither 4 nor 6 is unrecognised and must
    /// return `None` without panicking.
    #[test]
    fn dest_ip_unrecognised_version_returns_none() {
        let mut payload = [0u8; 40];
        payload[0] = 0xF0; // version nibble 15 — not IPv4 or IPv6
        assert_eq!(dest_ip_from_payload(&payload), None);
    }

    /// The version nibble claims IPv4 but the buffer is shorter than the
    /// 20-byte minimum header, so `Ipv4Packet::new_view` returns `Err` and
    /// `.ok()?` must map that to `None` rather than panicking.
    #[test]
    fn dest_ip_short_ipv4_claim_returns_none() {
        let payload = [0x45, 0, 0]; // version 4, IHL 5 — but only 3 bytes present
        assert_eq!(dest_ip_from_payload(&payload), None);
    }

    /// The version nibble claims IPv6 but the buffer is shorter than the
    /// 40-byte minimum header, so `Ipv6Packet::new_view` returns `Err` and
    /// `.ok()?` must map that to `None` rather than panicking.
    #[test]
    fn dest_ip_short_ipv6_claim_returns_none() {
        let mut payload = [0u8; 30]; // < 40-byte IPv6 minimum
        payload[0] = 0x60; // version 6
        assert_eq!(dest_ip_from_payload(&payload), None);
    }
}
