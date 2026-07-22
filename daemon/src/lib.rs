pub mod app;
pub mod audit;
/// Off-by-default AI explainer config (no client wiring yet — Task 1 of 7).
#[cfg(feature = "ai")]
pub mod ai;
/// Messaging-approval trust boundary — the authz gate + resolve-join that lets a
/// chat reply resolve a parked ASK. Opt-in (never in the default/open build).
#[cfg(feature = "channels")]
pub mod channels_bridge;
/// Phase B inbound-webhook receiver — a loopback HTTP server that authenticates
/// platform callbacks (per-platform HMAC) and feeds them to the same authz gate.
#[cfg(feature = "channels")]
pub mod inbound_http;
/// Off-by-default network-destination enrichment (reverse-DNS + ASN/owner/
/// country via `trippy-dns`). Display-only; never gates any decision.
#[cfg(feature = "netenrich")]
pub mod netenrich;
pub mod distro;
pub mod ebpf;
pub mod egress;
pub mod engine;
pub mod etw;
pub mod finding;
#[cfg(fw)]
pub mod firewall;
pub mod hardening;
pub mod honeypot;
pub mod host_api;
pub mod host_config;
pub mod ipc;
pub mod kfilter;
pub mod mcp_proxy;
pub mod mcp_scan;
pub mod observe;
pub mod paths;
pub mod pending;
/// Process-ancestry primitives (Linux `/proc` parent-pid walk) backing the
/// GateGuard self-approval detector — is the resolver a descendant of the
/// agent that was gated?
pub mod proc_ancestry;
pub mod reflex;
pub mod service;
/// Discover installed agent skills on disk. Foundation for the Phase-2 triggers.
pub mod skills;
pub mod sshguard;
pub mod state;
pub mod vuln;
// WFP egress block is native Win32 (uses the `windows` crate) — Windows-only.
#[cfg(windows)]
pub mod wfp;
