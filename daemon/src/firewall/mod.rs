//! Firewall host-control layer for Belay.
//!
//! Three submodules:
//! - `mod.rs` (this file): nftables wrapper — [`NftProgram`], [`ManagedRuleset`],
//!   [`FwBackend`], [`apply_with`], [`RustablesBackend`].
//! - [`guard`]: dead-man's-switch auto-revert.
//! - [`assistant`]: observe listen ports → propose least-privilege ruleset.
//!
//! # Anti-lockout guarantee
//! [`apply_with`] always emits the SSH-source allow rule **before** any default-drop
//! rule, so the kernel never sees a ruleset that would block an existing SSH session.

pub mod assistant;
pub mod detect;
pub mod guard;

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// Public error type
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced by the firewall subsystem.
#[derive(Debug)]
pub enum FwError {
    /// The kernel netlink backend returned an error.
    Backend(String),
    /// Snapshot I/O failed.
    SnapshotIo(std::io::Error),
    /// A `batch.send()` or table-operation call to the kernel failed.
    Apply(String),
}

impl fmt::Display for FwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FwError::Backend(msg) => write!(f, "firewall backend error: {msg}"),
            FwError::SnapshotIo(e) => write!(f, "firewall snapshot I/O error: {e}"),
            FwError::Apply(msg) => write!(f, "firewall apply error: {msg}"),
        }
    }
}

impl std::error::Error for FwError {}

impl From<std::io::Error> for FwError {
    fn from(e: std::io::Error) -> Self {
        FwError::SnapshotIo(e)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Privilege-aware error mapping
// ──────────────────────────────────────────────────────────────────────────────

/// Best-effort effective-UID == 0 check. Uses a bare `extern "C"` `geteuid`
/// (mirrors the pattern in `daemon/tests/`) so we pull in NO new dependency and
/// keep the pure-Rust directive. Only used to ENRICH an error message — never to
/// gate behaviour — so a false negative is harmless.
#[cfg(fw)]
fn running_as_root() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid() always succeeds and takes no arguments.
    unsafe { geteuid() == 0 }
}

/// Build an actionable message from a kernel/netlink error.
///
/// `rustables` collapses the kernel errno into a generic "Error received from
/// the kernel". We surface the actual `errno` (so ENOENT/-2, EINVAL/-22 etc. are
/// visible), and append the privilege remedy ONLY for a genuine permission errno
/// (EPERM/-1 or EACCES/-13) while unprivileged — so a non-permission kernel fault
/// is never hidden behind a misleading "needs root" hint.
///
/// Pure (takes `errno` and `is_root` explicitly) so it is unit-testable.
#[cfg(fw)]
fn apply_err_message(detail: &str, errno: Option<i32>, is_root: bool) -> String {
    let is_permission = matches!(errno, Some(-1) | Some(-13)); // EPERM | EACCES
    if is_root || !is_permission {
        detail.to_string()
    } else {
        format!(
            "{detail}: applying firewall rules requires CAP_NET_ADMIN, but the \
             Belay daemon is running unprivileged (euid != 0). Run the daemon \
             as root (e.g. via the system service), or grant the binary the \
             capability once with `sudo setcap cap_net_admin+ep <belay>` and \
             restart the daemon."
        )
    }
}

/// Map a `rustables` `batch.send()` failure to an [`FwError::Apply`], surfacing
/// the kernel errno and a privilege-aware hint.
#[cfg(fw)]
fn map_apply_err(e: rustables::error::QueryError) -> FwError {
    let errno = match &e {
        rustables::error::QueryError::NetlinkError(inner) => Some(inner.error),
        _ => None,
    };
    let detail = match errno {
        Some(n) => format!("{e} (errno {n})"),
        None => e.to_string(),
    };
    FwError::Apply(apply_err_message(&detail, errno, running_as_root()))
}

/// Pre-flight privilege gate, run *before* the netlink round-trip.
///
/// The existing [`map_apply_err`] enriches a kernel EPERM *after* the kernel
/// rejects the batch; this complements it by failing fast with the same
/// actionable hint when we can already prove (via `/proc/self/status`) that we
/// lack `CAP_NET_ADMIN`. It only blocks on a *definitive* `Some(false)` while
/// unprivileged — an unknown cap status (`None`) or a root daemon never blocks,
/// so a false negative can never wrongly reject a legitimate apply.
///
/// Pure (takes `is_root` and `cap_status` explicitly) so it is unit-testable.
#[cfg(fw)]
fn precheck_privilege(is_root: bool, cap_status: Option<bool>) -> Result<(), FwError> {
    if !is_root && cap_status == Some(false) {
        Err(FwError::Apply(apply_err_message(
            "cannot apply firewall rules",
            Some(-1), // EPERM → triggers the privilege remedy hint
            false,
        )))
    } else {
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// NftProgram — ordered list of statements (pure Rust, kernel-free, testable)
// ──────────────────────────────────────────────────────────────────────────────

/// A single statement in an nftables program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NftStmt {
    /// Allow already-established/related connections.
    AllowEstablished,
    /// Allow all traffic from a specific source IP.
    AllowSource(IpAddr),
    /// Allow traffic to a specific destination port (TCP + UDP).
    AllowPort(u16),
    /// Drop everything that did not match an earlier accept rule.
    DefaultDrop,
}

/// An ordered sequence of nftables statements.
///
/// The ordering produced by [`apply_with`] is:
/// 1. `AllowEstablished`
/// 2. `AllowSource(ssh_ip)` (when `ssh_source` is set)
/// 3. `AllowPort(p)` for each port in `allow_ports`
/// 4. `DefaultDrop` (when `default_drop` is true)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NftProgram {
    pub stmts: Vec<NftStmt>,
}

impl NftProgram {
    /// Returns the index of the `AllowSource` rule for `ip`, if present.
    pub fn allow_index(&self, ip: &str) -> Option<usize> {
        let addr: IpAddr = ip.parse().ok()?;
        self.stmts
            .iter()
            .position(|s| matches!(s, NftStmt::AllowSource(a) if *a == addr))
    }

    /// Returns the index of the `DefaultDrop` rule, if present.
    pub fn drop_index(&self) -> Option<usize> {
        self.stmts.iter().position(|s| s == &NftStmt::DefaultDrop)
    }

    /// Returns `true` if an `AllowPort` rule for `port` exists.
    pub fn allows_port(&self, port: u16) -> bool {
        self.stmts
            .iter()
            .any(|s| matches!(s, NftStmt::AllowPort(p) if *p == port))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ManagedRuleset — user-facing description of the desired firewall state
// ──────────────────────────────────────────────────────────────────────────────

/// The desired firewall configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRuleset {
    /// Destination ports to open (TCP + UDP).
    pub allow_ports: Vec<u16>,
    /// Source IP that is always allowed (the operator's SSH origin).
    /// MUST appear before any default-drop rule.
    pub ssh_source: Option<IpAddr>,
    /// If true, append a `DefaultDrop` rule after all allow rules.
    pub default_drop: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// FwBackend trait
// ──────────────────────────────────────────────────────────────────────────────

/// Abstraction over the kernel nftables backend.
///
/// The only implementation that touches the kernel is [`RustablesBackend`]
/// (feature = `"firewall"`). Tests use `MockBackend` / `SharedMock`.
pub trait FwBackend: Send + 'static {
    /// Apply the given program to the kernel (or record it in tests).
    ///
    /// Returns `Err` if the kernel rejected the ruleset.
    fn apply(&mut self, prog: &NftProgram) -> Result<(), FwError>;
    /// Dump the current ruleset as opaque bytes for snapshot/restore.
    fn dump(&mut self) -> Vec<u8>;
    /// Restore a ruleset from opaque bytes.
    ///
    /// For [`RustablesBackend`] this deletes the `belay` table entirely,
    /// returning the host to its pre-Belay firewall state.
    fn load(&mut self, bytes: &[u8]) -> Result<(), FwError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// apply_with — pure ordering logic (kernel-free, always unit-testable)
// ──────────────────────────────────────────────────────────────────────────────

/// Build an [`NftProgram`] from `rs` and apply it via `backend`.
///
/// Statement order (anti-lockout contract):
/// 1. `AllowEstablished`
/// 2. `AllowSource(ssh_source)` — before any drop rule
/// 3. `AllowPort(p)` for each port
/// 4. `DefaultDrop` (only if `default_drop`)
pub fn apply_with<B: FwBackend>(backend: &mut B, rs: &ManagedRuleset) -> Result<(), FwError> {
    let mut prog = NftProgram::default();

    prog.stmts.push(NftStmt::AllowEstablished);

    if let Some(src) = rs.ssh_source {
        prog.stmts.push(NftStmt::AllowSource(src));
    }

    for &port in &rs.allow_ports {
        prog.stmts.push(NftStmt::AllowPort(port));
    }

    if rs.default_drop {
        prog.stmts.push(NftStmt::DefaultDrop);
    }

    backend.apply(&prog)
}

// ──────────────────────────────────────────────────────────────────────────────
// RustablesBackend — real kernel backend (feature-gated)
// ──────────────────────────────────────────────────────────────────────────────

/// The real nftables backend that speaks NETLINK via `rustables`.
///
/// Requires `CAP_NET_ADMIN`. Tests are gated with `#[cfg(all(test, feature = "fw-live-tests"))]`.
#[cfg(fw)]
pub struct RustablesBackend;

#[cfg(fw)]
impl FwBackend for RustablesBackend {
    fn apply(&mut self, prog: &NftProgram) -> Result<(), FwError> {
        use rustables::{
            Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol,
            ProtocolFamily, Rule, Table,
        };

        // Fail fast with an actionable hint if we can already prove we lack
        // CAP_NET_ADMIN, instead of waiting for the kernel to reject the batch.
        precheck_privilege(running_as_root(), crate::distro::cap_net_admin_status())?;

        // Build table and chain skeletons.
        let table = Table::new(ProtocolFamily::Inet).with_name("belay");
        // Determine chain policy from program: DefaultDrop present → Drop, else Accept.
        let final_policy = if prog.stmts.iter().any(|s| s == &NftStmt::DefaultDrop) {
            ChainPolicy::Drop
        } else {
            ChainPolicy::Accept
        };

        let chain = Chain::new(&table)
            .with_name("input")
            .with_hook(Hook::new(
                HookClass::In,
                0i32, /* NF_IP_PRI_FILTER = 0 */
            ))
            .with_type(ChainType::Filter)
            .with_policy(final_policy);

        // Atomic chain refresh that is safe on the FIRST apply. The previous code
        // did `add table; del chain; add chain`, but on a freshly-created table the
        // `input` chain does not exist yet, so `del chain` returned ENOENT and the
        // kernel aborted the whole batch ("Error received from the kernel"). The
        // leading `add chain` guarantees the chain exists, so the following `del`
        // can never ENOENT; `del`+`add` then replaces the rule set without
        // accumulating duplicates. The TABLE is preserved (Add is idempotent), so
        // sibling objects in it — the `sshd_bans` and egress sets — survive.
        let mut batch = Batch::new();
        batch.add(&table, MsgType::Add);
        batch.add(&chain, MsgType::Add);
        batch.add(&chain, MsgType::Del);
        batch.add(&chain, MsgType::Add);

        for stmt in &prog.stmts {
            match stmt {
                NftStmt::AllowEstablished => {
                    if let Ok(rule) = Rule::new(&chain) {
                        if let Ok(r) = rule.established() {
                            batch.add(&r.accept(), MsgType::Add);
                        }
                    }
                }
                NftStmt::AllowSource(ip) => {
                    if let Ok(rule) = Rule::new(&chain) {
                        batch.add(&rule.saddr(*ip).accept(), MsgType::Add);
                    }
                }
                NftStmt::AllowPort(port) => {
                    // Allow both TCP and UDP on the given port.
                    if let Ok(rule_tcp) = Rule::new(&chain) {
                        batch.add(&rule_tcp.dport(*port, Protocol::TCP).accept(), MsgType::Add);
                    }
                    if let Ok(rule_udp) = Rule::new(&chain) {
                        batch.add(&rule_udp.dport(*port, Protocol::UDP).accept(), MsgType::Add);
                    }
                }
                // DefaultDrop is encoded as chain policy (set above); no explicit rule needed.
                NftStmt::DefaultDrop => {}
            }
        }

        batch.send().map_err(map_apply_err)
    }

    /// Dump returns empty bytes. The guard layer serializes [`ManagedRuleset`] directly
    /// (a full NETLINK dump-and-restore is architecturally complex; see implementation report).
    fn dump(&mut self) -> Vec<u8> {
        Vec::new()
    }

    /// Delete the `belay` table entirely, returning the host to its
    /// pre-Belay firewall state.
    ///
    /// This is Option B for revert: instead of trying to restore an opaque blob,
    /// we simply remove the table we own. If another firewall (iptables, ufw, etc.)
    /// was running before Belay, its rules are unaffected.
    fn load(&mut self, _bytes: &[u8]) -> Result<(), FwError> {
        use rustables::{Batch, MsgType, ProtocolFamily, Table};
        let table = Table::new(ProtocolFamily::Inet).with_name("belay");
        let mut batch = Batch::new();
        batch.add(&table, MsgType::Del);
        batch.send().map_err(map_apply_err)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// add_to_set — add an IP element to a named nftables set (feature-gated)
// ──────────────────────────────────────────────────────────────────────────────

/// Add `ip` to the named set `set_name` in the `belay` table.
///
/// Used by the SSH brute-force guard (`sshd_bans`) and egress enforcer (`egress_drop`).
///
/// # TTL note
/// rustables 0.8 does not expose a set-element timeout (NFTA_SET_ELEM_TIMEOUT) in its
/// public API — the `SetElement` struct only carries `key`.  The set is therefore created
/// without a per-element TTL; elements persist until the table is flushed or the daemon
/// restarts.  A production deployment should pair this with a periodic cleanup task or
/// use `nft` to set a set-level `timeout` flag at table-initialisation time.
/// This is documented rather than using `todo!` / `unimplemented!`.
#[cfg(fw)]
pub fn add_to_set(set_name: &str, ip: IpAddr, _ttl: std::time::Duration) -> Result<(), FwError> {
    use rustables::{set::SetBuilder, Batch, MsgType, ProtocolFamily, Table};
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    let table = Table::new(ProtocolFamily::Inet).with_name("belay");
    let mut batch = Batch::new();

    match ip {
        IpAddr::V4(v4) => {
            let mut builder = SetBuilder::<Ipv4Addr>::new(set_name, &table)
                .map_err(|e| FwError::Backend(format!("set builder: {e:?}")))?;
            builder.add(&v4);
            let (set, elem_list) = builder.finish();
            batch.add(&set, MsgType::Add);
            batch.add(&elem_list, MsgType::Add);
        }
        IpAddr::V6(v6) => {
            let mut builder = SetBuilder::<Ipv6Addr>::new(set_name, &table)
                .map_err(|e| FwError::Backend(format!("set builder: {e:?}")))?;
            builder.add(&v6);
            let (set, elem_list) = builder.finish();
            batch.add(&set, MsgType::Add);
            batch.add(&elem_list, MsgType::Add);
        }
    }

    batch.send().map_err(|e| FwError::Apply(e.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────────
// MockBackend — test-only, no kernel, no root
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod mock {
    use super::{FwBackend, FwError, NftProgram};

    #[derive(Default)]
    pub struct MockBackend {
        pub applied: Option<NftProgram>,
        pub restored: bool,
    }

    impl FwBackend for MockBackend {
        fn apply(&mut self, prog: &NftProgram) -> Result<(), FwError> {
            self.applied = Some(prog.clone());
            Ok(())
        }

        fn dump(&mut self) -> Vec<u8> {
            serde_json::to_vec(&self.applied).unwrap_or_default()
        }

        fn load(&mut self, _bytes: &[u8]) -> Result<(), FwError> {
            self.restored = true;
            Ok(())
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 7 tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::mock::MockBackend;
    use super::*;

    #[test]
    fn apply_builds_managed_ruleset_with_ssh_exemption() {
        let mut backend = MockBackend::default();
        let rs = ManagedRuleset {
            allow_ports: vec![443, 8080],
            ssh_source: Some("203.0.113.9".parse().unwrap()),
            default_drop: true,
        };
        apply_with(&mut backend, &rs).unwrap();
        let prog = backend.applied.expect("a ruleset was applied");
        // SSH source must be allowed BEFORE any drop rule.
        assert!(prog.allow_index("203.0.113.9").unwrap() < prog.drop_index().unwrap());
        assert!(prog.allows_port(443) && prog.allows_port(8080));
    }

    // The privilege hint must appear ONLY for a real permission errno while
    // unprivileged — never for root, never for a non-permission kernel error.
    #[cfg(fw)]
    #[test]
    fn apply_err_message_adds_privilege_hint_only_for_permission_errno() {
        let raw = "Error received from the kernel (errno -1)";
        // EPERM (-1) while unprivileged -> append the remedy.
        let hinted = apply_err_message(raw, Some(-1), false);
        assert!(hinted.starts_with(raw), "must preserve the raw kernel error");
        assert!(hinted.contains("CAP_NET_ADMIN"));
        assert!(hinted.contains("setcap cap_net_admin+ep"));
        // EPERM while root -> raw, no misleading hint.
        assert_eq!(apply_err_message(raw, Some(-1), true), raw);
        // ENOENT (-2) while unprivileged -> raw, NOT a privilege problem.
        let enoent = "Error received from the kernel (errno -2)";
        assert_eq!(apply_err_message(enoent, Some(-2), false), enoent);
    }

    // The pre-flight gate must block ONLY when we can prove we lack the
    // capability while unprivileged; unknown status and root must pass through.
    #[cfg(fw)]
    #[test]
    fn precheck_privilege_blocks_only_when_definitely_unprivileged() {
        // Definitively lacking CAP_NET_ADMIN and not root -> fail with the hint.
        let err = precheck_privilege(false, Some(false)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("setcap cap_net_admin+ep"), "{msg}");
        // Has the capability -> proceed.
        assert!(precheck_privilege(false, Some(true)).is_ok());
        // Unknown cap status (couldn't read /proc) -> never block.
        assert!(precheck_privilege(false, None).is_ok());
        // Root daemon -> never block, even if the parse said false.
        assert!(precheck_privilege(true, Some(false)).is_ok());
    }
}
