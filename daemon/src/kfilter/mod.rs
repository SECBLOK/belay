//! Phase-3 user-mode **kfilter decision layer** — the OS-independent half of the
//! signed-minifilter tier (see
//! `docs/superpowers/plans/2026-07-15-phase3-kernel-driver-plan.md`, Spike 3).
//!
//! The kernel minifilter's `IRP_MJ_CREATE` pre-op makes a SYNCHRONOUS up-call
//! (`FltSendMessage`) carrying `(pid, path)`; this layer turns that into a
//! terminal allow/deny by reusing the EXACT engine + approvals the cooperative
//! hook already runs, then the pre-op completes with `STATUS_ACCESS_DENIED` on
//! deny. Unlike ETW (fire-and-forget, detect-only — see [`crate::etw`]), this is
//! **block-before-read**: a reachable `Deny` PREVENTS the open, so the verdict
//! path is deliberately **fail-CLOSED**.
//!
//! ## What lives here (and is fully unit-tested off-Windows)
//! * [`decide_open`] — the whole decision: safety allowlist → [`ObservedEvent`]
//!   → engine verdict → allow / deny / (ask → park).
//! * [`Allowlist`] — the Spike-5 boot-safety backstop: system + Belay-self paths
//!   are allowed BEFORE the engine is ever consulted, so no rule can brick boot.
//! * [`KfilterVerdict`] / [`KfilterAsker`] — the two seams, abstracted as traits
//!   exactly like Phase-2's `EgressBlocker` so the dispatch is testable without
//!   Windows / a kernel / a human. Production impls: [`EngineVerdict`] (→
//!   [`crate::engine::evaluate_event`]) and [`ApprovalsAsker`] (→
//!   [`crate::pending::Approvals::park`], already fail-closed).
//!
//! ## Honest boundaries (NOT in this slice — deferred, not faked)
//! 1. **Kernel transport.** The `#[cfg(windows)]`
//!    `FilterConnectCommunicationPort` receive loop that feeds real driver
//!    messages into [`decide_open`] is authored + verified ON THE BOX (it needs
//!    the WDK, a signed driver, and admin) — not written blind on Linux. The
//!    contract it targets is stable: decode a message to [`KfilterRequest`],
//!    call [`decide_open`], reply [`KfilterDecision::reply_byte`].
//! 2. **`.env` coverage — now wired.** [`crate::engine::evaluate_event`]'s
//!    `Open` arm matches the `secrets.sensitive_path` set (`.env`,
//!    `~/.aws/credentials`, SSH private keys, …, folding `\` → `/` so native
//!    Windows paths match) and returns `Ask`, so a sensitive read flows
//!    `Ask` → [`ApprovalsAsker`] (park) → human here — a real block-until-
//!    approved. Broadening that set to full catalog parity remains a follow-up.

use crate::engine::types::{Decision, SessionState, Verdict};
use crate::observe::{EventKind, ObservedEvent};
use crate::pending::{Approvals, ParkOutcome};

/// A decoded kernel pre-op request: process `pid` is attempting to open `path`.
/// Built by the (on-box) Windows port from an `FltSendMessage` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KfilterRequest {
    pub pid: u32,
    pub path: String,
}

/// The terminal reply the driver's pre-op needs.
///
/// `Allow` → `FLT_PREOP_SUCCESS_NO_CALLBACK` (the read proceeds); `Deny` →
/// `FLT_PREOP_COMPLETE` with `STATUS_ACCESS_DENIED` (the read is prevented).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfilterDecision {
    Allow,
    Deny,
}

impl KfilterDecision {
    /// Wire byte the kernel reads back: `0` = allow, `1` = deny. The driver's
    /// reply buffer is a single byte; keep this in lockstep with the WDK side.
    pub fn reply_byte(self) -> u8 {
        match self {
            KfilterDecision::Allow => 0,
            KfilterDecision::Deny => 1,
        }
    }
}

/// Map a fail-closed [`ParkOutcome`] to a [`KfilterDecision`]. Only an explicit
/// `Allow` allows; every fail-closed path (`Deny`, timeout, disconnect) blocks.
fn park_outcome_to_decision(o: ParkOutcome) -> KfilterDecision {
    match o {
        ParkOutcome::Allow => KfilterDecision::Allow,
        ParkOutcome::Deny => KfilterDecision::Deny,
    }
}

/// Turn a raw kernel request into the [`ObservedEvent`] the engine consumes.
/// A file open is `EventKind::Open` with the path as `detail` — the same shape
/// the eBPF/ETW producers emit, so it runs through the identical engine seam.
pub fn to_observed(req: &KfilterRequest) -> ObservedEvent {
    ObservedEvent {
        pid: req.pid,
        kind: EventKind::Open,
        detail: req.path.clone(),
    }
}

// ---------------------------------------------------------------------------
// Boot-safety allowlist (Spike 5)
// ---------------------------------------------------------------------------

/// A hard allowlist of target-path prefixes that must NEVER be blocked, checked
/// BEFORE the engine so a misconfigured rule can't render the box unbootable or
/// lock Belay out of its own files. Prefixes are stored normalized (backslashes
/// folded to `/`, lowercased); [`is_allowed`](Self::is_allowed) normalizes the
/// candidate the same way, so `C:\Windows\...` and `c:/windows/...` match alike.
#[derive(Debug, Clone)]
pub struct Allowlist {
    prefixes: Vec<String>,
}

/// Normalize a Windows path for prefix comparison: fold `\` → `/` and lowercase
/// (Windows paths are case-insensitive). Matching-only — never used for I/O.
fn normalize(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

impl Allowlist {
    /// Build an allowlist from explicit prefixes (normalized on the way in).
    pub fn from_prefixes<I, S>(prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Allowlist {
            prefixes: prefixes.into_iter().map(|p| normalize(p.as_ref())).collect(),
        }
    }

    /// The default system + Belay-self allowlist. Boot-critical system files and
    /// Belay's own install/data trees are never gated. Deliberately small and
    /// explicit; extend as real false-blocks surface on the box.
    pub fn system_default() -> Self {
        Self::from_prefixes([
            r"C:\Windows\",
            r"C:\Program Files\Belay\",
            r"C:\Program Files (x86)\Belay\",
            r"C:\ProgramData\Belay\",
        ])
    }

    /// Is `path` on the allowlist (i.e. must never be blocked)?
    pub fn is_allowed(&self, path: &str) -> bool {
        let p = normalize(path);
        self.prefixes.iter().any(|pref| p.starts_with(pref))
    }
}

// ---------------------------------------------------------------------------
// Decision seams (abstracted for off-Windows testing — mirrors EgressBlocker)
// ---------------------------------------------------------------------------

/// Source of the engine verdict for an observed open. Abstracted so the
/// dispatch is testable without the real rule set / session state.
///
/// Production: [`EngineVerdict`] → [`crate::engine::evaluate_event`].
pub trait KfilterVerdict {
    fn verdict(&mut self, ev: &ObservedEvent) -> Verdict;
}

/// Resolver for an `Ask` verdict — the human-in-the-loop step. Abstracted so
/// dispatch is testable without a real approvals runtime or a person.
///
/// Production: [`ApprovalsAsker`] → [`crate::pending::Approvals::park`], which is
/// itself FAIL-CLOSED (timeout / disconnect → deny). Because the boot-safety
/// [`Allowlist`] is applied first, no system path can ever reach an ask, so a
/// fail-closed timeout here can only ever block a non-system, rule-flagged path.
pub trait KfilterAsker {
    fn ask(&self, ev: &ObservedEvent, verdict: &Verdict) -> KfilterDecision;
}

/// Decide a single kernel open request: **the block-before-read core.**
///
/// 1. **Safety first** — an allowlisted target is allowed immediately, WITHOUT
///    consulting the engine (no rule can brick boot or lock Belay out).
/// 2. Otherwise map to an [`ObservedEvent`] and get the engine [`Verdict`].
/// 3. `Deny` → block (fail-closed on a reachable deny); `Allow` → allow;
///    `Ask` → escalate to the [`KfilterAsker`] (park) for a human decision.
pub fn decide_open(
    req: &KfilterRequest,
    allowlist: &Allowlist,
    verdict_src: &mut dyn KfilterVerdict,
    asker: &dyn KfilterAsker,
) -> KfilterDecision {
    // Boot-safety backstop — before ANY engine work.
    if allowlist.is_allowed(&req.path) {
        return KfilterDecision::Allow;
    }

    let ev = to_observed(req);
    let verdict = verdict_src.verdict(&ev);
    match verdict.decision {
        Decision::Deny => KfilterDecision::Deny,
        Decision::Allow => KfilterDecision::Allow,
        Decision::Ask => asker.ask(&ev, &verdict),
    }
}

// ---------------------------------------------------------------------------
// Production seam impls (cross-platform: both reuse existing, tested Rust)
// ---------------------------------------------------------------------------

/// Production verdict source: run the observed open through the SAME engine the
/// cooperative hook uses. Holds the caller's live `SessionState` (egress
/// destinations, correlation, …) so kernel-observed events accrue state exactly
/// like hook-observed ones.
pub struct EngineVerdict<'a> {
    pub state: &'a mut SessionState,
}

impl KfilterVerdict for EngineVerdict<'_> {
    fn verdict(&mut self, ev: &ObservedEvent) -> Verdict {
        crate::engine::evaluate_event(ev, self.state)
    }
}

/// Production asker: park the request on the existing [`Approvals`] map until a
/// human resolves it or it times out (fail-closed → deny). This is the very
/// same primitive the CLI hook's `Ask` path already uses, so a kernel-gated open
/// and a hook-gated tool call are decided by identical machinery.
pub struct ApprovalsAsker<'a> {
    pub approvals: &'a Approvals,
    /// Millisecond wall-clock the park entry is stamped with.
    pub now_ms: u64,
}

impl KfilterAsker for ApprovalsAsker<'_> {
    fn ask(&self, ev: &ObservedEvent, verdict: &Verdict) -> KfilterDecision {
        let input = serde_json::json!({ "path": ev.detail, "pid": ev.pid });
        let rule = verdict.rules.first().map(String::as_str).unwrap_or("kfilter.open");
        let explain = verdict
            .explain
            .as_ref()
            .and_then(|e| serde_json::to_value(e).ok());
        let outcome = self.approvals.park(
            "kfilter",
            "file-open",
            &input,
            &verdict.reason,
            rule,
            self.now_ms,
            verdict.severity.as_wire_str(),
            verdict.category.as_deref(),
            explain,
        );
        park_outcome_to_decision(outcome)
    }
}

// ---------------------------------------------------------------------------
// Windows kernel transport (deferred to on-box — see module doc, boundary #1)
// ---------------------------------------------------------------------------
//
// The `#[cfg(windows)]` `FilterConnectCommunicationPort` receive loop that pumps
// real `FltSendMessage` payloads through `decide_open` and writes back
// `KfilterDecision::reply_byte` is authored + verified in the WDK ON THE TEST VM
// (Spike 1-4), NOT written blind here. When it lands it will live in a
// `#[cfg(windows)] pub mod port;` submodule, exactly as `etw::session` /
// `wfp` gate their Win32 FFI.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::Severity;

    // ── test doubles ──────────────────────────────────────────────────────────

    /// A verdict source returning a fixed verdict, recording whether it was hit
    /// (so we can prove the allowlist short-circuits BEFORE the engine).
    struct MockVerdict {
        canned: Verdict,
        called: std::cell::Cell<bool>,
    }
    impl MockVerdict {
        fn new(decision: Decision) -> Self {
            MockVerdict {
                canned: Verdict {
                    decision,
                    reason: "test".into(),
                    rules: vec!["test.rule".into()],
                    severity: Severity::High,
                    primary_rule: None,
                    category: None,
                    owasp: None,
                    atlas: None,
                    explain: None,
                },
                called: std::cell::Cell::new(false),
            }
        }
    }
    impl KfilterVerdict for MockVerdict {
        fn verdict(&mut self, _ev: &ObservedEvent) -> Verdict {
            self.called.set(true);
            self.canned.clone()
        }
    }

    /// An asker that returns a fixed decision and records whether it was hit.
    struct MockAsker {
        reply: KfilterDecision,
        called: std::cell::Cell<bool>,
    }
    impl MockAsker {
        fn new(reply: KfilterDecision) -> Self {
            MockAsker { reply, called: std::cell::Cell::new(false) }
        }
    }
    impl KfilterAsker for MockAsker {
        fn ask(&self, _ev: &ObservedEvent, _v: &Verdict) -> KfilterDecision {
            self.called.set(true);
            self.reply
        }
    }

    fn req(path: &str) -> KfilterRequest {
        KfilterRequest { pid: 4242, path: path.into() }
    }

    // ── mapping + contract ────────────────────────────────────────────────────

    #[test]
    fn to_observed_maps_open_with_path() {
        let ev = to_observed(&req(r"C:\Users\x\.env"));
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.kind, EventKind::Open);
        assert_eq!(ev.detail, r"C:\Users\x\.env");
    }

    #[test]
    fn reply_byte_contract_is_stable() {
        assert_eq!(KfilterDecision::Allow.reply_byte(), 0);
        assert_eq!(KfilterDecision::Deny.reply_byte(), 1);
    }

    #[test]
    fn park_outcome_maps_fail_closed() {
        assert_eq!(park_outcome_to_decision(ParkOutcome::Allow), KfilterDecision::Allow);
        assert_eq!(park_outcome_to_decision(ParkOutcome::Deny), KfilterDecision::Deny);
    }

    // ── allowlist (boot-safety) ────────────────────────────────────────────────

    #[test]
    fn allowlist_covers_system_and_self_case_and_slash_insensitive() {
        let a = Allowlist::system_default();
        // System path, native backslashes + mixed case.
        assert!(a.is_allowed(r"C:\Windows\System32\config\SYSTEM"));
        // Same, normalized form.
        assert!(a.is_allowed("c:/windows/system32/kernel32.dll"));
        // Belay's own data dir (self) — must never lock itself out.
        assert!(a.is_allowed(r"C:\ProgramData\Belay\audit.ndjson"));
        // A user secret is NOT allowlisted — it's eligible for gating.
        assert!(!a.is_allowed(r"C:\Users\dennis\project\.env"));
    }

    // ── decide_open: the block-before-read core ────────────────────────────────

    #[test]
    fn allowlisted_path_allows_without_consulting_engine() {
        let mut v = MockVerdict::new(Decision::Deny); // would deny if reached
        let asker = MockAsker::new(KfilterDecision::Deny);
        let d = decide_open(
            &req(r"C:\Windows\System32\ntdll.dll"),
            &Allowlist::system_default(),
            &mut v,
            &asker,
        );
        assert_eq!(d, KfilterDecision::Allow);
        assert!(!v.called.get(), "engine must not be consulted for an allowlisted path");
        assert!(!asker.called.get());
    }

    #[test]
    fn deny_verdict_blocks_the_read() {
        let mut v = MockVerdict::new(Decision::Deny);
        let asker = MockAsker::new(KfilterDecision::Allow); // must NOT be consulted
        let d = decide_open(&req(r"C:\Users\x\.env"), &Allowlist::system_default(), &mut v, &asker);
        assert_eq!(d, KfilterDecision::Deny, "a reachable deny must block (fail-closed)");
        assert!(!asker.called.get(), "a terminal deny does not go to the human asker");
    }

    #[test]
    fn allow_verdict_allows_the_read() {
        let mut v = MockVerdict::new(Decision::Allow);
        let asker = MockAsker::new(KfilterDecision::Deny);
        let d = decide_open(&req(r"C:\Users\x\notes.txt"), &Allowlist::system_default(), &mut v, &asker);
        assert_eq!(d, KfilterDecision::Allow);
        assert!(!asker.called.get());
    }

    #[test]
    fn ask_verdict_routes_to_human_and_honors_allow() {
        let mut v = MockVerdict::new(Decision::Ask);
        let asker = MockAsker::new(KfilterDecision::Allow);
        let d = decide_open(&req(r"C:\Users\x\.env"), &Allowlist::system_default(), &mut v, &asker);
        assert!(asker.called.get(), "an Ask verdict must escalate to the asker");
        assert_eq!(d, KfilterDecision::Allow);
    }

    #[test]
    fn ask_verdict_routes_to_human_and_honors_deny() {
        let mut v = MockVerdict::new(Decision::Ask);
        let asker = MockAsker::new(KfilterDecision::Deny);
        let d = decide_open(&req(r"C:\Users\x\.env"), &Allowlist::system_default(), &mut v, &asker);
        assert!(asker.called.get());
        assert_eq!(d, KfilterDecision::Deny);
    }

    // ── production verdict source wired to the REAL engine ─────────────────────

    #[test]
    fn engine_verdict_gates_a_dot_env_read_end_to_end() {
        // End-to-end proof that the Open arm is now wired: a real `.env` read
        // through EngineVerdict returns Ask, decide_open escalates to the human
        // asker (the park stand-in), and honors the human's deny → the read is
        // blocked. This is the capability the whole tier exists for.
        let mut state = SessionState::new("kfilter-test");
        let mut ev = EngineVerdict { state: &mut state };
        let asker = MockAsker::new(KfilterDecision::Deny); // human denies at the prompt
        let d = decide_open(
            &req(r"C:\Users\dennis\project\.env"),
            &Allowlist::system_default(),
            &mut ev,
            &asker,
        );
        assert!(asker.called.get(), "a .env read must escalate to the human asker");
        assert_eq!(d, KfilterDecision::Deny, "the human's deny blocks the read");
    }

    #[test]
    fn engine_verdict_allows_a_benign_open_through_the_real_engine() {
        // Proves EngineVerdict is wired to the real evaluate_event (not a stub):
        // a benign, non-secret open is allowed end-to-end through decide_open.
        let mut state = SessionState::new("kfilter-test");
        let mut ev = EngineVerdict { state: &mut state };
        let asker = MockAsker::new(KfilterDecision::Deny);
        let d = decide_open(
            &req(r"C:\Users\x\src\main.rs"),
            &Allowlist::system_default(),
            &mut ev,
            &asker,
        );
        assert_eq!(d, KfilterDecision::Allow);
    }
}
