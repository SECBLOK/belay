//! Interactive-approval queue for the enforcement daemon (Little-Snitch model).
//!
//! A `gate` request that the engine resolves to **ASK** is PARKED here until a
//! user decides via a separate `respond_approval` command delivered on another
//! connection — or until a hard timeout fires.
//!
//! ## Fail-closed invariants (security-critical; every error path returns DENY)
//! - Park timeout elapses → DENY.
//! - The resolution channel disconnects / errors → DENY.
//! - The pending map is at capacity → DENY (the request is NOT enqueued).
//! - Any other internal error → DENY.
//!
//! The ONLY ways a gate that *would* ask gets allowed are:
//!   1. an explicit `respond_approval(id, "allow", scope)` from the user, or
//!   2. an explicit `set_protection(false)` (observe mode — allow + audited), or
//!   3. a prior `respond_approval(..., "allow", "always")` whose stable signature
//!      now matches (the approved-allow set).
//!
//! The sessions mutex must NOT be held while parked (deadlock); callers compute
//! the verdict under that lock, drop it, then call [`Approvals::park`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
#[cfg(feature = "channels")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// Hard cap on concurrently-parked approvals. A flood past this → new ASKs DENY
/// (fail-closed) rather than growing daemon memory without bound.
pub const MAX_PENDING: usize = 256;

/// Default park timeout if `BELAY_APPROVAL_TIMEOUT_MS` is unset/invalid.
const DEFAULT_TIMEOUT_MS: u64 = 60_000;

// ============================================================================
// Rule-scoped deny mutes ("deny, and apply to all similar") + flood detection.
//
// Framing that makes the whole design fall out: this is not a new authority.
// It is a temporary, reversible promotion of one catalog rule from Ask to
// Deny -- strictly MORE restrictive than doing nothing, never less. That is
// what makes it safe to build without the self-approval/chat-trust-root
// machinery the ALLOW-side "always" scope needs: a mute can only ever cause
// an agent to be blocked sooner, never approved when it shouldn't be.
//
// See docs/research/2026-07-26-deny-mute-engine.md for the full design
// rationale (why rule-id-only, why in-memory + TTL rather than persisted,
// why the ask_rules "all must be muted" check is the single most important
// line in this file, and why the flood detector counts distinct signatures
// rather than raw park attempts).
// ============================================================================

/// How long a human-installed rule mute lasts before it silently expires and
/// the rule reprompts normally. Deliberately short and never "forever": a
/// mute the operator forgets about is a silent-failure generator, worse than
/// the noise it suppresses. A genuinely permanent change has a correct home
/// already -- a catalog patch, reviewed and applied by a human -- and a
/// one-click mute must not be able to produce that same permanent effect
/// with none of the review.
const DENY_MUTE_TTL_MS: u64 = 30 * 60_000;

/// How long a `scope:"always"` approval stays reusable before the next
/// matching call parks an Ask again.
///
/// Continuous-authorization / anti-TOCTOU: an authorization decision should not
/// outlive the context it was made in. Deliberately generous — this exists to
/// bound an unbounded grant, not to nag — and deliberately LONGER than
/// `DENY_MUTE_TTL_MS`, because re-confirming an allow is a prompt while
/// re-confirming a mute risks re-opening a flood.
///
/// The important half of this problem is already closed elsewhere:
/// `ipc.rs` refuses to honour a stored approval unless the freshly recomputed
/// verdict is still `Ask`, which is what stops the
/// approve-`curl` → `cat .env` → re-issue-`curl` correlation bypass. The
/// residual this TTL closes is narrower: a still-Ask command whose meaning
/// drifted (a referenced script's contents changed) inside one long session.
const APPROVED_TTL_MS: u64 = 4 * 60 * 60_000;

/// Shorter TTL for a daemon-installed (flood-triggered) mute: the daemon
/// decided this without a human looking at it, so it re-checks itself sooner
/// than a human-granted mute would.
const FLOOD_MUTE_TTL_MS: u64 = 5 * 60_000;

/// Hard cap on simultaneously active rule mutes. The (N+1)th install attempt
/// is refused outright -- never silently evicting an earlier mute, which
/// would let a bait flood knock out a mute the operator deliberately
/// installed. Refusal leaves the gate at its normal Ask, the correct failure
/// direction.
pub const MAX_DENY_MUTES: usize = 8;

/// Distinct-signature threshold that trips automatic flood muting: this many
/// DIFFERENT `(session, tool, input)` asks for the same rule inside
/// [`FLOOD_WINDOW_MS`] auto-installs a mute. Counting distinct signatures
/// rather than raw park attempts is load-bearing: a stuck byte-identical
/// retry loop (the known duplicate-delivery class the existing park-coalesce
/// logic already handles) can never trip this, only genuinely different
/// calls can.
const FLOOD_N: usize = 10;

/// Sliding window the flood detector counts distinct signatures within.
const FLOOD_WINDOW_MS: u64 = 60_000;

/// Hard cap on how many distinct rules the flood detector tracks at once
/// (bounds memory under an adversary that floods many different rules
/// simultaneously rather than one).
const MAX_FLOOD_TRACKED_RULES: usize = 64;

/// Where a rule mute came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuteOrigin {
    /// A local operator resolving a real parked prompt with `scope:"rule"`.
    Local,
    /// The daemon's own flood detector, with no human in the loop.
    Auto,
}

impl MuteOrigin {
    pub fn label(self) -> &'static str {
        match self {
            MuteOrigin::Local => "local",
            MuteOrigin::Auto => "auto",
        }
    }
}

/// A live rule-scoped deny mute.
#[derive(Debug, Clone)]
pub struct DenyMute {
    pub rule: String,
    pub installed_ms: u64,
    pub expires_ms: u64,
    pub origin: MuteOrigin,
    /// Number of calls this mute has auto-denied since it was installed.
    /// This is what turns "I muted something earlier" into "this has
    /// silently allowed-to-deny N times, most recently just now" — the
    /// number that makes the mute's cost legible rather than invisible.
    pub hits: u64,
}

/// Compiled-in eligibility check for rule-scoped deny mutes — deliberately
/// independent of the catalog, so a hand-edited `catalog.yaml` cannot widen
/// what can be muted (same reasoning `self_tamper.rs` is a compiled-in
/// backstop rather than expressed only in YAML).
///
/// Excluded, and why:
///  - `tamper.*`, `correlate.*` — the only self-protection and cross-call
///    detections in the product; muting them defeats their entire purpose.
///  - `skill.install.*`, `mcp.install.*` — the population behind these is
///    unbounded and adversary-chosen; the whole point is catching something
///    never seen before.
///  - `persist.*` — act-shaped, not observe-shaped: a sudo/scheduler/shell-
///    profile change is exactly the class of action where the prompt IS the
///    control, not an obstacle to it.
///  - `destructive.git_force` — irreversible local data loss.
///  - `rce.untrusted_install`, `rce.fetch_chmod_exec` — a per-package/
///    per-dropper decision, not a class to blanket-suppress.
///
/// An empty rule id is never mutable (nothing to key on, and every real
/// verdict has a non-empty primary rule).
pub fn is_mutable_rule(rule_id: &str) -> bool {
    if rule_id.is_empty() {
        return false;
    }
    if rule_id.starts_with("tamper.")
        || rule_id.starts_with("correlate.")
        || rule_id.starts_with("skill.install.")
        || rule_id.starts_with("mcp.install.")
        || rule_id.starts_with("persist.")
    {
        return false;
    }
    !matches!(
        rule_id,
        "destructive.git_force" | "rce.untrusted_install" | "rce.fetch_chmod_exec"
    )
}

/// Fire-and-forget sink invoked when a request parks (channels fan-out). Boxed as
/// a trait object so `serve_mode` can install a closure that captures the bridge.
#[cfg(feature = "channels")]
type NotifierFn = Arc<dyn Fn(PendingNotice) + Send + Sync>;

/// Where a park's decision came from. Recorded in the `approval.resolved` audit
/// event so "who allowed/denied this?" is answerable from a single line rather
/// than by correlating `approval.respond` by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSource {
    /// Local operator via IPC `respond` (desktop UI / CLI).
    Local,
    /// Messaging-channel reply via `respond_by_nonce` (authorized principal).
    Channel,
    /// Park timeout elapsed with no decision → fail-closed deny.
    Timeout,
    /// Every resolver dropped before deciding → fail-closed deny.
    Disconnected,
    /// Pending map at capacity; refused without parking → deny.
    MapFull,
    /// Pending lock poisoned → fail-closed deny.
    Poisoned,
}

impl ResolveSource {
    /// Stable lowercase wire label for the audit event.
    pub fn label(self) -> &'static str {
        match self {
            ResolveSource::Local => "local",
            ResolveSource::Channel => "channel",
            ResolveSource::Timeout => "timeout",
            ResolveSource::Disconnected => "disconnected",
            ResolveSource::MapFull => "map_full",
            ResolveSource::Poisoned => "poisoned",
        }
    }
}

/// Self-approval lineage detail carried alongside a [`Resolution`]. `Local`
/// resolutions carry the real (possibly-detected) value; every other source
/// (`Channel`, and the synthetic timeout/disconnected/map_full/poisoned
/// fail-closed paths) always carries [`SelfApprovalInfo::default()`] — those
/// paths have no local resolver pid to compare against, so self-approval is
/// definitionally not applicable (fail-open: absence of evidence is treated
/// as absence of self-approval, never the reverse).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SelfApprovalInfo {
    /// `true` iff process ancestry POSITIVELY PROVED the resolver is a
    /// descendant of the gated request's agent pid — i.e.
    /// `proc_ancestry::is_ancestor_of(gating_pid, resolver_pid) ==
    /// Some(true)`. This is audit-truth and is recorded regardless of
    /// whether enforcement is on.
    pub detected: bool,
    /// `true` iff `detected` AND enforcement was ON at resolve time, meaning
    /// the resolution actually delivered to the parked gate thread(s) below
    /// was forcibly overridden to `Deny` regardless of what the resolver
    /// asked for.
    pub blocked: bool,
}

/// Resolution decision delivered over a pending entry's channel, tagged with the
/// source that produced it (`Local` from IPC, `Channel` from a messaging reply)
/// and any self-approval lineage detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Allow(ResolveSource, SelfApprovalInfo),
    Deny(ResolveSource, SelfApprovalInfo),
}

/// Outcome of [`Approvals::respond_local`]: whether the entry was found,
/// self-approval lineage, and whether a requested `scope:"rule"` deny mute
/// was installed or refused.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RespondOutcome {
    pub found: bool,
    pub self_approval: bool,
    pub blocked: bool,
    /// The rule id a mute was installed for, if `scope:"rule"` was
    /// requested and succeeded.
    pub mute_installed_for: Option<String>,
    /// Why `scope:"rule"` was refused, if it was requested and didn't
    /// succeed. `None` when no mute was requested, or one was installed.
    pub mute_refused: Option<&'static str>,
}

impl RespondOutcome {
    fn not_found() -> Self {
        Self::default()
    }
}

/// Outcome of parking a request — what the gate path returns to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkOutcome {
    Allow,
    /// Any fail-closed path: explicit deny, timeout, channel error, map-full.
    Deny,
}

/// A request awaiting user decision. `resolver` is the producer half of the
/// channel the parked gate thread is blocked on.
#[derive(Debug)]
pub struct PendingEntry {
    pub id: String,
    pub session: String,
    pub tool: String,
    pub input: Value,
    pub reason: String,
    pub rule: String,
    pub created_ms: u64,
    /// Winning-rule severity (lowercase wire label, e.g. `high`). Additive
    /// Explain & Advise field so the ApprovalCard can colour/prioritise.
    pub severity: String,
    /// Winning-rule category (e.g. `secrets`); `None` for synthetic hits.
    pub category: Option<String>,
    /// Standards mappings of the winning rule (OWASP ASI/LLM Top 10, MITRE
    /// ATLAS), carried from the verdict so the ApprovalCard can show what the
    /// rule that fired maps to. `None` when the rule authors no mapping, or
    /// when the caller came through `park()` (which has no verdict to hand).
    pub owasp: Option<String>,
    pub atlas: Option<String>,
    /// Curated plain-English explanation of the winning rule, if authored.
    pub explain: Option<Value>,
    /// Producer halves of every gate thread blocked on THIS request. Normally one,
    /// but a retry of an identical (session, tool, input) that is still pending is
    /// coalesced onto this same entry (see `park`) - so a single user decision
    /// signals every waiting copy. Resolving sends the outcome to all of them.
    pub resolvers: Vec<mpsc::Sender<Resolution>>,
    /// CSPRNG correlation nonce for messaging-channel replies. Never leaked in
    /// `snapshot()` (the local UI resolves by `id`, channels by `nonce`), so it
    /// is unguessable/unenumerable. Present only in the `channels` build.
    #[cfg(feature = "channels")]
    pub nonce: String,
    /// The GATED AGENT's pid (NOT the hook/mcp child that made the `gate` IPC
    /// call — that peer's pid's PARENT). `None` whenever it couldn't be
    /// determined (non-Linux, a `/proc` read failure, or the caller simply
    /// not supplying one) — the self-approval guard fails open on `None`; it
    /// never engages for this entry. Set once at park time and never mutated;
    /// a coalesced retry of the SAME (session, tool, input) keeps the FIRST
    /// park's value rather than overwriting it.
    pub gating_pid: Option<u32>,
}

/// Per-rule flood-tracking map: rule id -> a bounded deque of
/// (timestamp_ms, signature hash) for distinct asks within the window.
type FloodMap = HashMap<String, VecDeque<(u64, u64)>>;

/// Shared interactive-approval state, cloned (via `Arc`) into each connection
/// thread by `serve_mode`.
#[derive(Clone)]
pub struct Approvals {
    pending: Arc<Mutex<HashMap<String, PendingEntry>>>,
    /// `true` = enforcing (default). `false` = observe mode: dangerous gates are
    /// ALLOWED (explicit + audited) — the only non-approval allow-override.
    protection: Arc<AtomicBool>,
    /// Stable signatures approved with `scope:"always"`, each with the epoch-ms
    /// at which the grant expires.
    ///
    /// The TTL is the point. This set used to be an unbounded, never-expiring
    /// `HashSet`, while [`DenyMute`] right above it has always carried
    /// `installed_ms`/`expires_ms` — so the SAFE direction expired and the
    /// UNSAFE one did not. An "always" granted early in a long session stayed
    /// reusable hours later on a materially different task.
    ///
    /// Expiry can only ever cost a prompt: a lapsed grant falls back to parking
    /// an Ask, exactly as if it had never been given, so no hard false positive
    /// is reachable from here. See [`APPROVED_TTL_MS`].
    approved: Arc<Mutex<HashMap<String, u64>>>,
    /// Live rule-scoped deny mutes, keyed by rule id. In-memory only, never
    /// persisted — see the module-level "Rule-scoped deny mutes" doc.
    denied_rules: Arc<Mutex<HashMap<String, DenyMute>>>,
    /// Per-rule flood tracking: a bounded deque of (timestamp_ms, signature
    /// hash) for distinct asks seen within the last [`FLOOD_WINDOW_MS`].
    flood: Arc<Mutex<FloodMap>>,
    /// Process-unique monotonic counter feeding the id derivation (no extra deps).
    counter: Arc<AtomicU64>,
    timeout: Duration,
    /// Optional sink invoked (once, fire-and-forget) each time a request is
    /// PARKED, carrying its correlation `nonce` + display fields so the channels
    /// bridge can fan the prompt out to messaging adapters. Set once at startup
    /// by `serve_mode`; `None` (default) preserves exactly today's behaviour.
    /// Per-instance (not a process global) so tests stay isolated. Channels build
    /// only — the default binary carries no such field.
    #[cfg(feature = "channels")]
    notifier: Arc<OnceLock<NotifierFn>>,
}

/// Details handed to the channels notifier when a request parks. Carries the
/// secret `nonce` (so the bridge can embed it in the outbound prompt / callback
/// data) alongside the same fields the local UI shows. Channels build only.
#[cfg(feature = "channels")]
#[derive(Clone, Debug)]
pub struct PendingNotice {
    pub nonce: String,
    pub session: String,
    pub tool: String,
    pub input: Value,
    pub reason: String,
    pub rule: String,
    pub created_ms: u64,
    /// Winning-rule severity (lowercase wire label, e.g. `high`) so the channel
    /// prompt can show a plain-language risk badge instead of a rule id.
    pub severity: String,
    /// Curated plain-English explanation of the winning rule, if authored. Lets
    /// the channel bridge render a non-technical alert (title / why / suggested
    /// action) rather than dumping the raw tool input JSON.
    pub explain: Option<Value>,
}

impl Default for Approvals {
    fn default() -> Self {
        Self::new()
    }
}

impl Approvals {
    /// Construct with the park timeout taken from `BELAY_APPROVAL_TIMEOUT_MS`
    /// (milliseconds; default 60000). Injectable so tests use a short value.
    pub fn new() -> Self {
        let ms = std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        Self::with_timeout(Duration::from_millis(ms))
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            protection: Arc::new(AtomicBool::new(true)),
            approved: Arc::new(Mutex::new(HashMap::new())),
            denied_rules: Arc::new(Mutex::new(HashMap::new())),
            flood: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(0)),
            timeout,
            #[cfg(feature = "channels")]
            notifier: Arc::new(OnceLock::new()),
        }
    }

    /// Install the park notifier (channels bridge fan-out sink). First writer
    /// wins; subsequent calls are ignored so a second `serve_mode` cannot swap
    /// the sink out from under a running daemon. Channels build only.
    #[cfg(feature = "channels")]
    pub fn set_notifier(&self, f: NotifierFn) {
        let _ = self.notifier.set(f);
    }

    /// Current protection state (`true` = enforcing).
    pub fn protection_on(&self) -> bool {
        self.protection.load(Ordering::SeqCst)
    }

    /// Set protection. `false` ⇒ observe mode (dangerous gates allowed, audited).
    pub fn set_protection(&self, on: bool) {
        self.protection.store(on, Ordering::SeqCst);
    }

    /// Stable signature for an (session, tool, input) tuple, used by the
    /// approved-allow (scope:"always") set. Canonical JSON keeps key order stable.
    pub fn sig(session: &str, tool: &str, input: &Value) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}",
            session,
            tool,
            crate::audit::canonical_json(input)
        )
    }

    /// True if this exact (session,tool,input) was previously approved "always"
    /// AND that grant has not expired.
    ///
    /// Prunes on read, mirroring the deny-mute path, so a lapsed grant is
    /// dropped rather than lingering. A `false` here simply parks an Ask, which
    /// is the same thing that would have happened had the grant never existed.
    pub fn is_approved_always(&self, session: &str, tool: &str, input: &Value) -> bool {
        let sig = Self::sig(session, tool, input);
        let now = now_ms();
        self.approved
            .lock()
            .map(|mut m| {
                m.retain(|_, &mut expires| expires > now);
                m.contains_key(&sig)
            })
            .unwrap_or(false)
    }

    /// Installs a rule-scoped deny mute, subject to the compiled-in
    /// eligibility check ([`is_mutable_rule`]), the severity cap (never
    /// `critical`), and the concurrent-mute cap ([`MAX_DENY_MUTES`]).
    /// Re-muting an already-muted rule refreshes its TTL/origin without
    /// counting against the cap a second time. Returns the refusal reason on
    /// failure so the caller can report it rather than silently doing
    /// nothing.
    fn install_deny_mute(
        &self,
        rule: &str,
        severity: &str,
        origin: MuteOrigin,
    ) -> Result<(), &'static str> {
        if !is_mutable_rule(rule) {
            return Err("rule_not_mutable");
        }
        if severity.eq_ignore_ascii_case("critical") {
            return Err("severity_critical");
        }
        let mut map = self.denied_rules.lock().map_err(|_| "lock_poisoned")?;
        if !map.contains_key(rule) && map.len() >= MAX_DENY_MUTES {
            return Err("cap_reached");
        }
        let now = now_ms();
        let ttl = match origin {
            MuteOrigin::Local => DENY_MUTE_TTL_MS,
            MuteOrigin::Auto => FLOOD_MUTE_TTL_MS,
        };
        map.insert(
            rule.to_string(),
            DenyMute {
                rule: rule.to_string(),
                installed_ms: now,
                expires_ms: now + ttl,
                origin,
                hits: 0,
            },
        );
        Ok(())
    }

    /// Checks whether EVERY id in `ask_rules` is currently muted (lazily
    /// pruning expired entries as it goes), bumping each matched mute's hit
    /// counter. Returns `None` — meaning "park normally" — when `ask_rules`
    /// is empty or ANY rule in it is not muted.
    ///
    /// SECURITY: this "all must be muted" requirement, not "the primary rule
    /// is muted", is the single most important line in this file. Matching
    /// on the primary/winning rule alone would let a muted noisy rule mask a
    /// SECOND, un-muted, more serious finding that fired on the same call —
    /// the action would still be blocked, but the operator would never
    /// learn the attack shape had escalated. See `engine::types::Verdict
    /// ::ask_rules` and `skills::gate::more_restrictive`'s union of
    /// `ask_rules`, both added specifically to make this check possible.
    pub fn deny_mute_covers_all(&self, ask_rules: &[String]) -> Option<Vec<String>> {
        if ask_rules.is_empty() {
            return None;
        }
        let now = now_ms();
        let mut map = self.denied_rules.lock().ok()?;
        map.retain(|_, m| m.expires_ms > now);
        if !ask_rules.iter().all(|r| map.contains_key(r)) {
            return None;
        }
        for r in ask_rules {
            if let Some(m) = map.get_mut(r) {
                m.hits += 1;
            }
        }
        Some(ask_rules.to_vec())
    }

    /// Records a distinct ask for `rule` (keyed by `sig`, the same stable
    /// signature `scope:"always"` uses) toward flood detection, installing
    /// an [`MuteOrigin::Auto`] deny mute and returning `true` exactly when
    /// THIS call is the one that trips [`FLOOD_N`] within [`FLOOD_WINDOW_MS`]
    /// — so the caller audits `approval.flood_detected` once, not on every
    /// subsequent call while the mute is live (once installed,
    /// [`deny_mute_covers_all`] short-circuits before this is ever reached
    /// again for the same rule, so no separate cooldown bookkeeping is
    /// needed: the auto-mute's own TTL IS the cooldown).
    pub fn note_ask_and_maybe_trip_flood(&self, rule: &str, sig: &str) -> bool {
        if rule.is_empty() {
            return false;
        }
        let now = now_ms();
        let sig_hash = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            sig.hash(&mut h);
            h.finish()
        };
        let tripped = {
            let mut map = match self.flood.lock() {
                Ok(m) => m,
                Err(_) => return false,
            };
            if !map.contains_key(rule) && map.len() >= MAX_FLOOD_TRACKED_RULES {
                // Bounded: evict the least-recently-touched tracked rule to
                // make room, rather than growing without bound.
                if let Some(lru) = map
                    .iter()
                    .min_by_key(|(_, dq)| dq.back().map(|(ts, _)| *ts).unwrap_or(0))
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&lru);
                }
            }
            let dq = map.entry(rule.to_string()).or_default();
            while dq.front().is_some_and(|(ts, _)| now.saturating_sub(*ts) > FLOOD_WINDOW_MS) {
                dq.pop_front();
            }
            // De-dupe: an identical signature already in the window doesn't
            // count again — this is what makes a stuck byte-identical retry
            // loop structurally unable to trip the detector.
            if dq.iter().any(|(_, h)| *h == sig_hash) {
                return false;
            }
            dq.push_back((now, sig_hash));
            dq.len() >= FLOOD_N
        };
        tripped && self.install_deny_mute(rule, "high", MuteOrigin::Auto).is_ok()
    }

    /// Snapshot of every currently-live (unexpired) deny mute, for the
    /// `get_deny_mutes` IPC command.
    pub fn snapshot_deny_mutes(&self) -> Value {
        let now = now_ms();
        let map = match self.denied_rules.lock() {
            Ok(m) => m,
            Err(_) => return json!({"mutes": []}),
        };
        let mutes: Vec<Value> = map
            .values()
            .filter(|m| m.expires_ms > now)
            .map(|m| {
                json!({
                    "rule": m.rule,
                    "installed_ms": m.installed_ms,
                    "expires_ms": m.expires_ms,
                    "origin": m.origin.label(),
                    "hits": m.hits,
                })
            })
            .collect();
        json!({"mutes": mutes})
    }

    /// Revokes a single rule mute. Returns `true` if one was actually
    /// removed. Effective immediately — the next gate call for this rule
    /// parks normally.
    pub fn revoke_deny_mute(&self, rule: &str) -> bool {
        match self.denied_rules.lock() {
            Ok(mut m) => m.remove(rule).is_some(),
            Err(_) => false,
        }
    }

    /// Revokes every active rule mute. Returns the number removed.
    pub fn revoke_all_deny_mutes(&self) -> usize {
        match self.denied_rules.lock() {
            Ok(mut m) => {
                let n = m.len();
                m.clear();
                n
            }
            Err(_) => 0,
        }
    }

    /// Park a would-ask request until the user resolves it or the timeout fires.
    /// Thin wrapper over [`park_with_source`] for callers that don't need to know
    /// how the decision was reached. Always passes `gating_pid: None` — the
    /// self-approval guard is a no-op for every caller that goes through this
    /// wrapper (fail-open); only [`park_with_source`]'s callers that supply a
    /// real gating pid (the `gate` IPC path) can ever trigger it.
    #[allow(clippy::too_many_arguments)]
    pub fn park(
        &self,
        session: &str,
        tool: &str,
        input: &Value,
        reason: &str,
        rule: &str,
        created_ms: u64,
        severity: &str,
        category: Option<&str>,
        explain: Option<Value>,
    ) -> ParkOutcome {
        // `None, None` for the standards mappings: this wrapper's callers
        // (channel inbound paths, tests) have no Verdict in hand. The gate IPC
        // path calls `park_with_source` directly and does supply them.
        self.park_with_source(
            session, tool, input, reason, rule, created_ms, severity, category, None, None,
            explain, None,
        )
        .0
    }

    /// Park a would-ask request, returning the outcome, the SOURCE that
    /// produced it (for the `approval.resolved` audit event), and any
    /// self-approval lineage detail attached by the resolver.
    ///
    /// `gating_pid` is the AGENT's pid (not the hook/mcp child that made the
    /// `gate` call) — the value the self-approval guard compares the eventual
    /// resolver's pid against. `None` disables the guard for this entry
    /// entirely (fail-open).
    ///
    /// FAIL-CLOSED: map-full → `Deny` (not enqueued); timeout/disconnect → `Deny`;
    /// only an explicit `Resolution::Allow` returns `Allow`. The entry is always
    /// removed from the map before returning.
    #[allow(clippy::too_many_arguments)]
    pub fn park_with_source(
        &self,
        session: &str,
        tool: &str,
        input: &Value,
        reason: &str,
        rule: &str,
        created_ms: u64,
        severity: &str,
        category: Option<&str>,
        owasp: Option<&str>,
        atlas: Option<&str>,
        explain: Option<Value>,
        gating_pid: Option<u32>,
    ) -> (ParkOutcome, ResolveSource, SelfApprovalInfo) {
        let (tx, rx) = mpsc::channel::<Resolution>();
        let sig = Self::sig(session, tool, input);

        // Under the pending lock, decide whether this is a NEW question or a retry
        // of one already awaiting the user. Two identical (session, tool, input)
        // ASKs that are BOTH still pending are the SAME question re-issued - a
        // fact-forcing hook re-running the call, the agent re-attempting after a
        // block, a duplicate transport delivery. Coalescing the retry onto the
        // first park means ONE alert and ONE decision applied to every copy,
        // instead of two independent prompts whose conflicting replies made the
        // acted-on choice nondeterministic. `primary_id` is Some only for the
        // first (owning) park; a coalesced waiter attaches its resolver and never
        // inserts, alerts, or evicts the shared entry. NOTE: a coalesced waiter
        // does NOT overwrite `gating_pid` on the shared entry — the FIRST park's
        // value is kept, since that's genuinely the agent pid that asked the
        // original question (a retry's own `gating_pid` argument is simply
        // discarded once coalesced).
        #[cfg(feature = "channels")]
        let mut notice: Option<PendingNotice> = None;
        let primary_id: Option<String> = {
            let mut map = match self.pending.lock() {
                Ok(m) => m,
                // poisoned → fail closed
                Err(_) => {
                    return (
                        ParkOutcome::Deny,
                        ResolveSource::Poisoned,
                        SelfApprovalInfo::default(),
                    )
                }
            };
            if let Some(entry) = map
                .values_mut()
                .find(|e| Self::sig(&e.session, &e.tool, &e.input) == sig)
            {
                // Retry of a still-pending identical ASK → wait on the in-flight
                // decision. No new entry, no second alert.
                entry.resolvers.push(tx);
                None
            } else {
                if map.len() >= MAX_PENDING {
                    return (
                        ParkOutcome::Deny,
                        ResolveSource::MapFull,
                        SelfApprovalInfo::default(),
                    );
                }
                let id = self.next_id(session, created_ms);
                #[cfg(feature = "channels")]
                let nonce = gen_nonce();
                map.insert(
                    id.clone(),
                    PendingEntry {
                        id: id.clone(),
                        session: session.to_string(),
                        tool: tool.to_string(),
                        input: input.clone(),
                        reason: reason.to_string(),
                        rule: rule.to_string(),
                        created_ms,
                        severity: severity.to_string(),
                        category: category.map(str::to_string),
                        owasp: owasp.map(str::to_string),
                        atlas: atlas.map(str::to_string),
                        explain: explain.clone(),
                        resolvers: vec![tx],
                        #[cfg(feature = "channels")]
                        nonce: nonce.clone(),
                        gating_pid,
                    },
                );
                #[cfg(feature = "channels")]
                {
                    notice = Some(PendingNotice {
                        nonce,
                        session: session.to_string(),
                        tool: tool.to_string(),
                        input: input.clone(),
                        reason: reason.to_string(),
                        rule: rule.to_string(),
                        created_ms,
                        severity: severity.to_string(),
                        explain: explain.clone(),
                    });
                }
                Some(id)
            }
        }; // lock dropped before parking

        // Fan the parked prompt out to messaging adapters (if a bridge installed a
        // notifier). Only the PRIMARY park alerts - a coalesced retry must stay
        // silent. Done AFTER the lock drops and AFTER the entry (with its nonce) is
        // in the map, so an instant channel reply can already resolve it; before
        // recv so the approver is notified while we block. Fire-and-forget: the
        // closure must not block (it spawns its own async sends).
        #[cfg(feature = "channels")]
        if let (Some(n), Some(cb)) = (notice, self.notifier.get()) {
            cb(n);
        }

        let (outcome, source, self_approval) = match rx.recv_timeout(self.timeout) {
            Ok(Resolution::Allow(src, sa)) => (ParkOutcome::Allow, src, sa),
            // Explicit deny carries its own source; timeout / sender-dropped map
            // to the corresponding fail-closed source. All → DENY.
            Ok(Resolution::Deny(src, sa)) => (ParkOutcome::Deny, src, sa),
            Err(RecvTimeoutError::Timeout) => (
                ParkOutcome::Deny,
                ResolveSource::Timeout,
                SelfApprovalInfo::default(),
            ),
            Err(RecvTimeoutError::Disconnected) => (
                ParkOutcome::Deny,
                ResolveSource::Disconnected,
                SelfApprovalInfo::default(),
            ),
        };

        // Only the primary owns the entry lifecycle: reclaim its slot on return. A
        // coalesced waiter must NOT evict the shared entry other retries (or the
        // primary) may still be blocked on.
        if let Some(id) = primary_id {
            if let Ok(mut map) = self.pending.lock() {
                map.remove(&id);
            }
        }
        (outcome, source, self_approval)
    }

    /// Snapshot of the pending queue for `get_pending` (no resolver leaked).
    pub fn snapshot(&self) -> Value {
        let map = match self.pending.lock() {
            Ok(m) => m,
            Err(_) => return json!({ "pending": [] }),
        };
        let mut items: Vec<Value> = map
            .values()
            .map(|e| {
                json!({
                    "id": e.id,
                    "session": e.session,
                    "tool": e.tool,
                    "input": e.input,
                    "reason": e.reason,
                    "rule": e.rule,
                    "created_ms": e.created_ms,
                    // Additive Explain & Advise fields for the ApprovalCard.
                    "severity": e.severity,
                    "category": e.category,
                    "owasp": e.owasp,
                    "atlas": e.atlas,
                    "explain": e.explain,
                })
            })
            .collect();
        // Stable order for deterministic UIs/tests: oldest first.
        items.sort_by_key(|v| v.get("created_ms").and_then(|c| c.as_u64()).unwrap_or(0));
        json!({ "pending": items })
    }

    /// Resolve a parked request. Returns `true` if the id was found and signalled.
    ///
    /// `scope == "always" && allow` also records the stable signature so future
    /// identical requests are allowed without re-parking. An unknown id returns
    /// `false` and must NOT error the daemon.
    ///
    /// Thin wrapper over [`respond_local`] with `resolver_pid: None` and
    /// `enforce_self_approval: false` — every existing caller of this method
    /// (every test, and any future caller that doesn't have a resolver pid to
    /// offer) gets EXACTLY today's behaviour: the self-approval guard never
    /// engages, because with no resolver pid there is nothing to compare
    /// against (fail-open).
    pub fn respond(&self, id: &str, allow: bool, scope: &str) -> bool {
        self.respond_local(id, allow, scope, None, false).found
    }

    /// Resolve a parked request from the LOCAL IPC path (`respond_approval`),
    /// with self-approval detection.
    ///
    /// - `resolver_pid` is the resolving peer's pid (`stream.peer_pid().ok()`
    ///   from the connection making this call) — `None` on any platform/error
    ///   where it's unavailable.
    /// - `enforce_self_approval` is `host_config::gateguard_enforce_enabled()`,
    ///   read by the ipc.rs caller so this module stays config-agnostic.
    ///
    /// Self-approval is `entry.gating_pid == resolver_pid`, OR
    /// `proc_ancestry::is_ancestor_of(entry.gating_pid, resolver_pid) ==
    /// Some(true)` — EVERY other combination (either pid `None`, a gating pid
    /// of 0/1, or a non-`Some(true)` ancestry result) is `false` (fail-open).
    /// The equality arm covers an agent that resolves from its own process:
    /// `is_ancestor_of(A, A)` is `Some(false)`, since a process is not its own
    /// ancestor, so ancestry alone would miss the most direct self-approval.
    ///
    /// When self-approval is detected AND `enforce_self_approval`, the
    /// resolution actually delivered to the parked gate thread(s) is
    /// forcibly overridden to `Deny` regardless of `allow` — and, since that
    /// override makes the effective decision `Deny`, no `scope:"always"`
    /// signature is ever recorded for a blocked self-approval either.
    ///
    /// Returns a [`RespondOutcome`] describing whether the entry was found,
    /// self-approval lineage, and — new — whether a requested
    /// `scope:"rule"` deny mute was installed or refused.
    pub fn respond_local(
        &self,
        id: &str,
        allow: bool,
        scope: &str,
        resolver_pid: Option<u32>,
        enforce_self_approval: bool,
    ) -> RespondOutcome {
        let entry = match self.pending.lock() {
            Ok(mut map) => map.remove(id),
            Err(_) => return RespondOutcome::not_found(),
        };
        let entry = match entry {
            Some(e) => e,
            None => return RespondOutcome::not_found(), // unknown id — caller returns ok:false, daemon lives
        };

        // FAIL-OPEN: the ONLY ways `self_approval` becomes `true` are both pids
        // being known AND either (a) the resolver IS the gated agent, or (b) the
        // ancestry walk returning the POSITIVE, confident `Some(true)`. A missing
        // pid on either side, or `is_ancestor_of` returning `Some(false)`/`None`,
        // all fall through to `false`.
        //
        // The equality arm matters: `gating_pid` is `parent(gate_peer)`, i.e. the
        // agent that spawned the hook. If that same process answers its own
        // request in-process instead of forking a helper, `resolver == agent` -
        // and `is_ancestor_of(A, A)` is `Some(false)`, because a process is not
        // its own ancestor. Without this arm the guard caught an agent that
        // shells out to resolve but missed the agent that just opens the socket
        // itself, which is the easier move of the two.
        //
        // `agent <= 1` is excluded for the same reason `is_ancestor_of` excludes
        // it: pid 0/1 is kernel/init, and an unknown/unresolved gating pid must
        // never be treated as a positive match.
        let self_approval = matches!(
            (entry.gating_pid, resolver_pid),
            (Some(agent), Some(resolver))
                if agent > 1
                    && (agent == resolver
                        || crate::proc_ancestry::is_ancestor_of(agent, resolver) == Some(true))
        );
        let blocked = self_approval && enforce_self_approval;
        let effective_allow = allow && !blocked;

        if effective_allow && scope == "always" {
            if let Ok(mut set) = self.approved.lock() {
                // Timestamped, not bare: see APPROVED_TTL_MS for why an
                // always-allow must not outlive the context it was granted in.
                set.insert(
                    Self::sig(&entry.session, &entry.tool, &entry.input),
                    now_ms() + APPROVED_TTL_MS,
                );
            }
        }

        // `scope:"rule"` — install a rule-scoped deny mute. Deliberately
        // stricter than the always-allow path above in two ways:
        //   1. Gated on `self_approval` DETECTED, not `blocked` (detected &&
        //      enforcing). The always-allow path uses `blocked`, so with
        //      GateGuard enforcement off a detected self-approval can still
        //      install an always-allow. A mute is a state change with
        //      availability impact and no legitimate agent use case, so an
        //      agent must not be able to install one even in audit-only
        //      mode.
        //   2. Only meaningful alongside an effective DENY — requesting
        //      `scope:"rule"` with `decision:"allow"` is refused rather than
        //      silently ignored, so the caller can report it honestly
        //      instead of the mute looking like it "just didn't happen".
        let mut mute_refused: Option<&'static str> = None;
        let mut mute_installed_for: Option<String> = None;
        if scope == "rule" {
            if effective_allow {
                mute_refused = Some("scope_rule_requires_deny");
            } else if self_approval {
                mute_refused = Some("self_approval_detected");
            } else {
                match self.install_deny_mute(&entry.rule, &entry.severity, MuteOrigin::Local) {
                    Ok(()) => mute_installed_for = Some(entry.rule.clone()),
                    Err(reason) => mute_refused = Some(reason),
                }
            }
        }

        let info = SelfApprovalInfo {
            detected: self_approval,
            blocked,
        };
        let resolution = if effective_allow {
            Resolution::Allow(ResolveSource::Local, info)
        } else {
            Resolution::Deny(ResolveSource::Local, info)
        };
        // If the parked thread already gave up (timeout), the receiver is gone;
        // send() Err is harmless — the gate already failed closed.
        // Fan the outcome to EVERY waiter coalesced onto this park (normally one):
        // a single decision resolves all identical retries. A losing racer whose
        // gate already timed out has a dropped receiver → send Err, harmless.
        for tx in &entry.resolvers {
            let _ = tx.send(resolution);
        }
        RespondOutcome {
            found: true,
            self_approval,
            blocked,
            mute_installed_for,
            mute_refused,
        }
    }

    /// Resolve a parked request by its CSPRNG `nonce` (messaging-channel path).
    ///
    /// The caller (the channels bridge) MUST have already authorized the replying
    /// principal (allowlist / pairing) — this is the resolve primitive, NOT the
    /// authz gate. Fail-closed: an unknown/mismatched nonce → `false` (nothing is
    /// resolved; the park keeps waiting and eventually times out → DENY).
    ///
    /// SECURITY: a channel reply may only ever grant `scope:"once"`. Durable
    /// `scope:"always"` authority is never installable over messaging — it stays
    /// local-operator-only via [`respond`]. The requested scope is therefore
    /// ignored beyond that guarantee (no `approved` signature is recorded here).
    ///
    /// This path is HUMAN-ONLY by construction (an authorized, out-of-band
    /// messaging principal) and has no local resolver pid to compare — it
    /// never carries self-approval lineage detail (always
    /// [`SelfApprovalInfo::default()`], i.e. `detected: false`).
    #[cfg(feature = "channels")]
    pub fn respond_by_nonce(&self, nonce: &str, allow: bool, _scope: &str) -> bool {
        let entry = match self.pending.lock() {
            Ok(mut map) => {
                let id = map
                    .iter()
                    .find(|(_, e)| e.nonce == nonce)
                    .map(|(k, _)| k.clone());
                id.and_then(|id| map.remove(&id))
            }
            Err(_) => return false, // poisoned → fail closed
        };
        let Some(entry) = entry else { return false };
        let resolution = if allow {
            Resolution::Allow(ResolveSource::Channel, SelfApprovalInfo::default())
        } else {
            Resolution::Deny(ResolveSource::Channel, SelfApprovalInfo::default())
        };
        // Losing racer (timeout already fired) → receiver gone → send Err, harmless.
        // Fan the outcome to EVERY waiter coalesced onto this park (normally one):
        // a single decision resolves all identical retries. A losing racer whose
        // gate already timed out has a dropped receiver → send Err, harmless.
        for tx in &entry.resolvers {
            let _ = tx.send(resolution);
        }
        true
    }

    /// Process-unique, collision-resistant id (counter + created_ms + session).
    fn next_id(&self, session: &str, created_ms: u64) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("ap-{}-{}-{}", created_ms, n, session)
    }

    /// Test-only: number of gate threads currently coalesced onto the entry `id`
    /// (0 if unknown). Lets the coalescing test wait for a retry to attach before
    /// resolving, so the assertion is deterministic rather than sleep-timed.
    #[cfg(test)]
    fn waiters_for(&self, id: &str) -> usize {
        self.pending
            .lock()
            .ok()
            .and_then(|m| m.get(id).map(|e| e.resolvers.len()))
            .unwrap_or(0)
    }

    /// Test-only: the `gating_pid` recorded on entry `id`. Outer `Option` is
    /// "was the id found at all"; inner is the field itself (which is
    /// legitimately `Option<u32>` — `None` means the guard is disabled for
    /// that entry, not "id not found").
    #[cfg(test)]
    fn gating_pid_for(&self, id: &str) -> Option<Option<u32>> {
        self.pending.lock().ok().and_then(|m| m.get(id).map(|e| e.gating_pid))
    }
}

/// Wall-clock milliseconds since the Unix epoch (best-effort; 0 on clock error).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 128-bit CSPRNG hex nonce correlating a parked ASK to a messaging-channel
/// reply. Unguessable/unenumerable (unlike the display `id`), so a chat reply
/// cannot target a request the sender was never shown. Channels build only.
#[cfg(feature = "channels")]
fn gen_nonce() -> String {
    use std::fmt::Write;
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("CSPRNG (getrandom) unavailable");
    let mut s = String::with_capacity(32);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::thread;
    use std::time::Duration;

    fn fast() -> Approvals {
        Approvals::with_timeout(Duration::from_millis(300))
    }

    #[test]
    fn snapshot_carries_severity_and_explain() {
        let a = fast();
        let a2 = a.clone();
        let explain = json!({"summary":"s"});
        let h = thread::spawn(move || {
            a2.park(
                "sess",
                "Bash",
                &json!({}),
                "reason",
                "secrets.env_dump",
                now_ms(),
                "high",
                Some("secrets"),
                Some(explain),
            );
        });
        // Wait for the entry to park, then assert the snapshot carries the new
        // fields; respond deny to unblock the parked thread.
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                assert_eq!(first["severity"], "high");
                assert_eq!(first["category"], "secrets");
                assert_eq!(first["explain"]["summary"], "s");
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert!(a.respond(&id, false, "once"));
        h.join().unwrap();
    }

    /// The ApprovalCard's "Standards" footnote is built from these two fields,
    /// so they have to survive the park -> snapshot round trip. Without this
    /// the GUI silently renders nothing: the panel is present, the data never
    /// arrives, and the failure looks identical to a rule that maps to nothing.
    #[test]
    fn snapshot_carries_the_standards_mappings() {
        let a = fast();
        let a2 = a.clone();
        let h = thread::spawn(move || {
            a2.park_with_source(
                "sess",
                "Bash",
                &json!({}),
                "reason",
                "tamper.agent_config_write",
                now_ms(),
                "critical",
                Some("tamper"),
                Some("ASI04"),
                Some("AML.ModifyAgentConfig"),
                None,
                None,
            );
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                assert_eq!(first["owasp"], "ASI04");
                assert_eq!(first["atlas"], "AML.ModifyAgentConfig");
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert!(a.respond(&id, false, "once"));
        h.join().unwrap();
    }

    /// A rule that authors no mapping must yield explicit nulls, not missing
    /// keys: the card distinguishes "maps to nothing" from "field absent", and
    /// `park()` (the channel inbound path) has no verdict to carry.
    #[test]
    fn parks_without_a_verdict_snapshot_null_mappings() {
        let a = fast();
        let a2 = a.clone();
        let h = thread::spawn(move || {
            a2.park(
                "sess", "Bash", &json!({}), "reason", "rule.x", now_ms(), "info", None, None,
            );
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                assert!(first.get("owasp").is_some(), "key must be present");
                assert!(first["owasp"].is_null());
                assert!(first["atlas"].is_null());
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert!(a.respond(&id, false, "once"));
        h.join().unwrap();
    }

    #[test]
    fn park_then_allow_returns_allow() {
        let a = fast();
        let a2 = a.clone();
        // Resolver thread: wait for the entry to appear, then approve it.
        let h = thread::spawn(move || {
            let id = loop {
                let snap = a2.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            assert!(a2.respond(&id, true, "once"));
        });
        let out = a.park(
            "s",
            "Bash",
            &json!({"command": "cat .env"}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow);
        // Slot reclaimed.
        assert!(a.snapshot()["pending"].as_array().unwrap().is_empty());
    }

    #[test]
    fn park_with_source_reports_timeout_then_local() {
        // No responder → fail-closed deny, source = Timeout (audited as such).
        let a = Approvals::with_timeout(Duration::from_millis(40));
        let (out, src, sa) = a.park_with_source(
            "s", "Bash", &json!({"command": "x"}), "r", "rule.x", now_ms(), "info", None, None,
            None, None, None,
        );
        assert_eq!(out, ParkOutcome::Deny);
        assert_eq!(src, ResolveSource::Timeout);
        assert_eq!(src.label(), "timeout");
        assert!(!sa.detected, "a timeout must never report self-approval");

        // An explicit local respond(allow) → allow, source = Local.
        let a2 = fast();
        let a2c = a2.clone();
        let h = thread::spawn(move || {
            let id = loop {
                let snap = a2c.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            assert!(a2c.respond(&id, true, "once"));
        });
        let (out, src, sa) = a2.park_with_source(
            "s", "Bash", &json!({"command": "y"}), "r", "rule.y", now_ms(), "info", None, None,
            None, None, None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow);
        assert_eq!(src, ResolveSource::Local);
        assert_eq!(src.label(), "local");
        assert!(
            !sa.detected,
            "a plain respond() (no resolver pid supplied) must never report self-approval"
        );
    }

    #[test]
    fn identical_pending_retry_coalesces_and_one_decision_resolves_all() {
        // Regression: a fact-forcing hook (or the agent) re-issuing the SAME tool
        // call while the first ASK is still parked used to create a SECOND pending
        // entry and a SECOND alert - two prompts whose conflicting replies made the
        // acted-on choice nondeterministic (the user's "asked twice, sometimes
        // takes my first answer, sometimes my last"). A retry must coalesce onto
        // the in-flight park: one prompt, and a single decision resolves every
        // waiter identically.
        let a = Approvals::with_timeout(Duration::from_secs(5));
        let input = json!({ "command": "cat /tmp/aidefender-test/.env" });

        // Primary park.
        let a1 = a.clone();
        let in1 = input.clone();
        let h1 = thread::spawn(move || {
            a1.park(
                "s1", "Bash", &in1, "r", "secrets.sensitive_path", 1, "high",
                Some("secrets"), None,
            )
        });
        // Wait for the primary entry to appear; capture its id.
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };

        // A retry of the IDENTICAL (session, tool, input) request.
        let a2 = a.clone();
        let in2 = input.clone();
        let h2 = thread::spawn(move || {
            a2.park(
                "s1", "Bash", &in2, "r", "secrets.sensitive_path", 2, "high",
                Some("secrets"), None,
            )
        });
        // Wait until the retry has attached (deterministic, not sleep-timed). It
        // must coalesce onto the SAME entry, so the queue still shows exactly one
        // prompt with two waiters.
        loop {
            if a.waiters_for(&id) == 2 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            a.snapshot()["pending"].as_array().unwrap().len(),
            1,
            "a retry of a still-pending identical ASK must coalesce, never add a second prompt"
        );

        // A single decision resolves BOTH parked waiters to the same outcome.
        assert!(a.respond(&id, true, "once"));
        assert_eq!(h1.join().unwrap(), ParkOutcome::Allow);
        assert_eq!(h2.join().unwrap(), ParkOutcome::Allow);
        assert!(a.snapshot()["pending"].as_array().unwrap().is_empty());
    }

    #[cfg(feature = "channels")]
    #[test]
    fn coalesced_retry_fires_only_one_channel_alert() {
        // The user-facing property: a still-pending identical retry must NOT fan a
        // SECOND prompt out to the messaging channels. Count notifier invocations
        // across a primary park + one retry - it must be exactly one.
        let a = Approvals::with_timeout(Duration::from_secs(5));
        let calls = Arc::new(Mutex::new(0usize));
        let c = calls.clone();
        a.set_notifier(Arc::new(move |_n: PendingNotice| {
            *c.lock().unwrap() += 1;
        }));
        let input = json!({ "command": "cat /tmp/aidefender-test/.env" });

        let a1 = a.clone();
        let in1 = input.clone();
        let h1 = thread::spawn(move || {
            a1.park("s", "Bash", &in1, "r", "secrets.sensitive_path", 1, "high", Some("secrets"), None)
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        let a2 = a.clone();
        let in2 = input.clone();
        let h2 = thread::spawn(move || {
            a2.park("s", "Bash", &in2, "r", "secrets.sensitive_path", 2, "high", Some("secrets"), None)
        });
        while a.waiters_for(&id) != 2 {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(a.respond(&id, true, "once"));
        assert_eq!(h1.join().unwrap(), ParkOutcome::Allow);
        assert_eq!(h2.join().unwrap(), ParkOutcome::Allow);
        assert_eq!(*calls.lock().unwrap(), 1, "the coalesced retry must not fire a second alert");
    }

    #[test]
    fn park_timeout_denies() {
        let a = Approvals::with_timeout(Duration::from_millis(80));
        let out = a.park(
            "s",
            "Bash",
            &json!({"command": "cat .env"}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        assert_eq!(out, ParkOutcome::Deny);
        assert!(a.snapshot()["pending"].as_array().unwrap().is_empty());
    }

    #[test]
    fn explicit_deny_denies() {
        let a = fast();
        let a2 = a.clone();
        let h = thread::spawn(move || {
            let id = loop {
                let snap = a2.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            assert!(a2.respond(&id, false, "once"));
        });
        let out = a.park(
            "s",
            "Bash",
            &json!({"command": "cat .env"}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Deny);
    }

    #[test]
    fn unknown_id_does_not_panic_and_returns_false() {
        let a = fast();
        assert!(!a.respond("ap-nonexistent", true, "once"));
    }

    #[test]
    fn map_full_denies_without_enqueue() {
        // Long timeout so the filler parks block and hold their slots.
        let a = Approvals::with_timeout(Duration::from_secs(30));
        // Fill the map with parked threads.
        let mut handles = Vec::new();
        for i in 0..MAX_PENDING {
            let a2 = a.clone();
            handles.push(thread::spawn(move || {
                a2.park(
                    "s",
                    "Bash",
                    &json!({"i": i}),
                    "r",
                    "rule.x",
                    now_ms(),
                    "info",
                    None,
                    None,
                );
            }));
        }
        // Wait until the map is actually full.
        loop {
            if a.snapshot()["pending"].as_array().unwrap().len() >= MAX_PENDING {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        // One more ASK must DENY immediately (not enqueue).
        let a3 = Approvals {
            // share the same maps/state
            pending: a.pending.clone(),
            protection: a.protection.clone(),
            approved: a.approved.clone(),
            denied_rules: a.denied_rules.clone(),
            flood: a.flood.clone(),
            counter: a.counter.clone(),
            timeout: Duration::from_secs(30),
            #[cfg(feature = "channels")]
            notifier: a.notifier.clone(),
        };
        let out = a3.park(
            "s",
            "Bash",
            &json!({"command": "overflow"}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        assert_eq!(out, ParkOutcome::Deny);
        // Map size unchanged (overflow request was not enqueued).
        assert_eq!(
            a.snapshot()["pending"].as_array().unwrap().len(),
            MAX_PENDING
        );

        // Drain the parked fillers so threads exit (respond deny to each).
        let snap = a.snapshot();
        for item in snap["pending"].as_array().unwrap() {
            a.respond(item["id"].as_str().unwrap(), false, "once");
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    /// An `always` grant expires, and expiry falls back to "not approved" —
    /// which parks an Ask, never a Deny. The asymmetry this fixes: `DenyMute`
    /// has always been TTL'd, so the SAFE direction expired while the UNSAFE
    /// one did not.
    #[test]
    fn an_always_approval_expires_and_expiry_can_only_cost_a_prompt() {
        let a = fast();
        let input = json!({"command": "cat .env"});
        let sig = Approvals::sig("s", "Bash", &input);

        // Live grant: honoured.
        a.approved
            .lock()
            .unwrap()
            .insert(sig.clone(), now_ms() + APPROVED_TTL_MS);
        assert!(a.is_approved_always("s", "Bash", &input));

        // Same grant, expired one second ago: no longer honoured...
        a.approved
            .lock()
            .unwrap()
            .insert(sig.clone(), now_ms() - 1_000);
        assert!(
            !a.is_approved_always("s", "Bash", &input),
            "an expired grant must not be honoured"
        );

        // ...and it is PRUNED on read rather than left to accumulate, which is
        // what keeps this set bounded over a long session.
        assert!(
            !a.approved.lock().unwrap().contains_key(&sig),
            "expired grant must be pruned on read"
        );
    }

    #[test]
    fn scope_always_records_signature() {
        let a = fast();
        let input = json!({"command": "cat .env"});
        assert!(!a.is_approved_always("s", "Bash", &input));
        let a2 = a.clone();
        let inp2 = input.clone();
        let h = thread::spawn(move || {
            let id = loop {
                let snap = a2.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            let _ = &inp2;
            assert!(a2.respond(&id, true, "always"));
        });
        let out = a.park(
            "s",
            "Bash",
            &input,
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow);
        assert!(a.is_approved_always("s", "Bash", &input));
    }

    #[test]
    fn protection_toggle_roundtrips() {
        let a = fast();
        assert!(a.protection_on());
        a.set_protection(false);
        assert!(!a.protection_on());
        a.set_protection(true);
        assert!(a.protection_on());
    }

    // ── Messaging-channel resolve path (feature = "channels") ─────────────────

    /// A channel reply resolves the park by nonce, AND a `scope:"always"` over a
    /// channel is clamped to once — no durable bypass is ever installed remotely.
    #[cfg(feature = "channels")]
    #[test]
    fn respond_by_nonce_resolves_and_clamps_always() {
        let a = fast();
        let a2 = a.clone();
        let h = thread::spawn(move || {
            // Wait for the entry, read its (module-private) nonce, resolve by it.
            let nonce = loop {
                if let Ok(map) = a2.pending.lock() {
                    if let Some(e) = map.values().next() {
                        break e.nonce.clone();
                    }
                }
                thread::sleep(Duration::from_millis(5));
            };
            // Even requesting "always", durable authority must NOT be recorded.
            assert!(a2.respond_by_nonce(&nonce, true, "always"));
        });
        let input = json!({"command": "cat .env"});
        let out = a.park(
            "s",
            "Bash",
            &input,
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow);
        assert!(
            !a.is_approved_always("s", "Bash", &input),
            "scope:always over a channel must be clamped — no durable approval"
        );
    }

    /// An unknown/forged nonce resolves nothing and the park still fails closed.
    #[cfg(feature = "channels")]
    #[test]
    fn respond_by_nonce_unknown_is_false_and_times_out_deny() {
        let a = Approvals::with_timeout(Duration::from_millis(80));
        assert!(!a.respond_by_nonce("deadbeefdeadbeef", true, "once"));
        let out = a.park(
            "s",
            "Bash",
            &json!({"c": 1}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        assert_eq!(out, ParkOutcome::Deny);
    }

    /// The 3-way resolver race (timeout / local id / channel nonce) is mutually
    /// exclusive via map.remove-first: a local respond() still wins in a channels
    /// build. Guards the ApprovalCard path against regression.
    #[cfg(feature = "channels")]
    #[test]
    fn local_respond_still_wins_in_channels_build() {
        let a = fast();
        let a2 = a.clone();
        let h = thread::spawn(move || {
            let id = loop {
                let snap = a2.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            assert!(a2.respond(&id, true, "once"));
        });
        let out = a.park(
            "s",
            "Bash",
            &json!({"c": 1}),
            "r",
            "rule.x",
            now_ms(),
            "info",
            None,
            None,
        );
        h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow);
    }

    // ── Task 2: self-approval guard ───────────────────────────────────────────

    #[test]
    fn park_with_source_stores_gating_pid() {
        let a = Approvals::with_timeout(Duration::from_secs(5));
        let a2 = a.clone();
        let h = thread::spawn(move || {
            a2.park_with_source(
                "s", "Bash", &json!({"command": "x"}), "r", "rule.x", now_ms(), "info", None,
                None, None, None, Some(4242),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(a.gating_pid_for(&id), Some(Some(4242)));
        assert!(a.respond(&id, false, "once"));
        let (out, _src, _sa) = h.join().unwrap();
        assert_eq!(out, ParkOutcome::Deny);
    }

    #[test]
    fn coalesced_retry_keeps_the_first_parks_gating_pid() {
        // Regression guard for the "keep the FIRST park's gating_pid" rule: a
        // retry of the identical (session, tool, input) while the primary is
        // still pending must coalesce WITHOUT overwriting the agent pid the
        // self-approval guard will compare against.
        let a = Approvals::with_timeout(Duration::from_secs(5));
        let input = json!({ "command": "cat /tmp/aidefender-test/.env" });

        let a1 = a.clone();
        let in1 = input.clone();
        let h1 = thread::spawn(move || {
            a1.park_with_source(
                "s1", "Bash", &in1, "r", "secrets.sensitive_path", 1, "high", Some("secrets"),
                None, None, None, Some(111),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(a.gating_pid_for(&id), Some(Some(111)));

        // A retry of the IDENTICAL request with a DIFFERENT gating_pid.
        let a2 = a.clone();
        let in2 = input.clone();
        let h2 = thread::spawn(move || {
            a2.park_with_source(
                "s1", "Bash", &in2, "r", "secrets.sensitive_path", 2, "high", Some("secrets"),
                None, None, None, Some(999),
            )
        });
        loop {
            if a.waiters_for(&id) == 2 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            a.gating_pid_for(&id),
            Some(Some(111)),
            "a coalesced retry must NOT overwrite the first park's gating_pid"
        );

        assert!(a.respond(&id, true, "once"));
        let (out1, _, _) = h1.join().unwrap();
        let (out2, _, _) = h2.join().unwrap();
        assert_eq!(out1, ParkOutcome::Allow);
        assert_eq!(out2, ParkOutcome::Allow);
    }

    /// Fail-open sweep: every combination that lacks a POSITIVE, confident
    /// ancestry match — missing gating_pid, missing resolver_pid, or an
    /// unrelated resolver — must deliver the REQUESTED allow unchanged, even
    /// with `enforce_self_approval` forced on. Proves the guard can only ever
    /// narrow to Deny via an explicit `Some(true)`, never as a side effect of
    /// missing data.
    #[test]
    fn every_fail_open_case_never_blocks_an_allow_even_with_enforcement_on() {
        for (gating_pid, resolver_pid) in [
            (None, Some(1u32)),
            (Some(std::process::id()), None),
            (Some(std::process::id()), Some(1)),
        ] {
            let a = Approvals::with_timeout(Duration::from_secs(5));
            let a2 = a.clone();
            let h = thread::spawn(move || {
                a2.park_with_source(
                    "s", "Bash", &json!({"c": 1}), "r", "rule.x", now_ms(), "info", None, None,
                    None, None, gating_pid,
                )
            });
            let id = loop {
                let snap = a.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            let out = a.respond_local(&id, true, "once", resolver_pid, true);
            assert!(out.found);
            assert!(
                !out.self_approval,
                "case gating_pid={gating_pid:?} resolver_pid={resolver_pid:?} must not detect self-approval"
            );
            assert!(!out.blocked);
            let (out, _, sa) = h.join().unwrap();
            assert_eq!(
                out,
                ParkOutcome::Allow,
                "case gating_pid={gating_pid:?} resolver_pid={resolver_pid:?} must not block"
            );
            assert!(!sa.detected);
            assert!(!sa.blocked);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn respond_local_detects_self_approval_from_a_real_descendant() {
        // This test process stands in for "the agent": it's the real,
        // kernel-verified parent of the spawned child, which stands in for
        // "the agent's own resolving helper" — is_ancestor_of(gating_pid,
        // resolver_pid) must be Some(true) via the real /proc walk.
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("spawn sleep");
        let resolver_pid = child.id();
        let gating_pid = std::process::id();

        let a = Approvals::with_timeout(Duration::from_secs(5));
        let a2 = a.clone();
        let h = thread::spawn(move || {
            a2.park_with_source(
                "s", "Bash", &json!({"c": 1}), "r", "rule.x", now_ms(), "info", None, None,
                None, None, Some(gating_pid),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };

        // Enforcement OFF: self-approval is DETECTED and would be AUDITED,
        // but the requested Allow is still honored (audit-only).
        let out = a.respond_local(&id, true, "once", Some(resolver_pid), false);
        assert!(out.found);
        assert!(out.self_approval, "the spawned child IS a descendant of this process");
        assert!(!out.blocked, "enforcement is off — must not override");
        let (out, _src, sa) = h.join().unwrap();
        assert_eq!(out, ParkOutcome::Allow, "enforcement off must honor the Allow");
        assert!(sa.detected);
        assert!(!sa.blocked);

        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn respond_local_enforce_on_overrides_self_approval_to_deny() {
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("spawn sleep");
        let resolver_pid = child.id();
        let gating_pid = std::process::id();

        let a = Approvals::with_timeout(Duration::from_secs(5));
        let a2 = a.clone();
        let input = json!({"c": 2});
        let in1 = input.clone();
        let h = thread::spawn(move || {
            a2.park_with_source(
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, None, None,
                Some(gating_pid),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };

        // The resolver asks for Allow with scope:"always" — enforcement must
        // override BOTH the delivered decision AND suppress the durable
        // "always" signature (the whole resolution is overridden, not just
        // the immediate decision).
        let out = a.respond_local(&id, true, "always", Some(resolver_pid), true);
        assert!(out.found);
        assert!(out.self_approval);
        assert!(out.blocked, "enforcement on + detected self-approval must block");
        let (out, _src, sa) = h.join().unwrap();
        assert_eq!(
            out,
            ParkOutcome::Deny,
            "must be overridden to Deny regardless of the Allow request"
        );
        assert!(sa.detected);
        assert!(sa.blocked);
        assert!(
            !a.is_approved_always("s", "Bash", &input),
            "a blocked self-approval must never install a durable always-allow"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// The degenerate self-approval ancestry alone cannot see: the gated agent
    /// answers its OWN parked request from its own process, so
    /// `resolver == gating_pid`. `is_ancestor_of(A, A)` is `Some(false)` (a
    /// process is not its own ancestor), so before the equality arm this - the
    /// most direct form of self-approval, and the easiest for an agent to
    /// perform - sailed straight through while the fork-a-helper variant was
    /// correctly blocked.
    #[test]
    fn respond_local_blocks_self_approval_when_resolver_is_the_agent_itself() {
        let pid = std::process::id();
        // The precondition that makes the equality arm necessary.
        assert_eq!(
            crate::proc_ancestry::is_ancestor_of(pid, pid),
            Some(false),
            "a process must not be its own ancestor - equality is what catches this"
        );

        let a = Approvals::with_timeout(Duration::from_secs(5));
        let a2 = a.clone();
        let input = json!({"c": 3});
        let in1 = input.clone();
        let h = thread::spawn(move || {
            a2.park_with_source(
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, None, None,
                Some(pid),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };

        let out = a.respond_local(&id, true, "always", Some(pid), true);
        assert!(out.found);
        assert!(
            out.self_approval,
            "a resolver that IS the gated agent must count as self-approval"
        );
        assert!(out.blocked, "enforcement on + detected self-approval must block");
        let (out, _src, sa) = h.join().unwrap();
        assert_eq!(out, ParkOutcome::Deny, "must be overridden to Deny");
        assert!(sa.detected);
        assert!(sa.blocked);
        assert!(
            !a.is_approved_always("s", "Bash", &input),
            "a blocked self-approval must never install a durable always-allow"
        );
    }

    /// pid 0/1 is kernel/init. An unresolved or bogus gating pid must never
    /// match, or the equality arm would turn "gating pid unknown" into
    /// "everything is self-approval" the moment a resolver reported pid 1.
    #[test]
    fn respond_local_never_treats_init_pid_as_self_approval() {
        let a = Approvals::with_timeout(Duration::from_millis(400));
        let a2 = a.clone();
        let in1 = json!({"c": 4});
        let h = thread::spawn(move || {
            a2.park_with_source(
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, None, None,
                Some(1),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        let out = a.respond_local(&id, true, "once", Some(1), true);
        assert!(out.found);
        assert!(!out.self_approval, "pid 1 must never be a positive match");
        assert!(!out.blocked);
        assert_eq!(h.join().unwrap().0, ParkOutcome::Allow, "the allow must stand");
    }

    // ========================================================================
    // Rule-scoped deny mutes + flood detection (2026-07-26 deny-mute engine).
    // ========================================================================

    mod deny_mute {
        use super::*;

        /// Parks `rule`/`severity` on a background thread and returns the
        /// join handle plus the parked entry's id, once it appears in the
        /// snapshot — the same pattern every self-approval test above uses.
        fn park_and_get_id(
            a: &Approvals,
            session: &str,
            rule: &str,
            severity: &str,
        ) -> (thread::JoinHandle<(ParkOutcome, ResolveSource, SelfApprovalInfo)>, String) {
            let a2 = a.clone();
            let (session, rule, severity) =
                (session.to_string(), rule.to_string(), severity.to_string());
            let h = thread::spawn(move || {
                a2.park_with_source(
                    &session,
                    "Bash",
                    &json!({"c": 1}),
                    "r",
                    &rule,
                    now_ms(),
                    &severity,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            });
            let id = loop {
                let snap = a.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            (h, id)
        }

        #[test]
        fn is_mutable_rule_excludes_the_documented_categories() {
            for excluded in [
                "tamper.self_protect",
                "tamper.indirect_write",
                "tamper.direct_write",
                "correlate.arm_sink",
                "correlate.lethal_trifecta",
                "correlate.injection_to_action",
                "skill.install.review",
                "skill.install.blocked",
                "mcp.install.review",
                "mcp.install.blocked",
                "persist.sudo",
                "persist.scheduler",
                "persist.shell_profile",
                "destructive.git_force",
                "rce.untrusted_install",
                "rce.fetch_chmod_exec",
                "",
            ] {
                assert!(!is_mutable_rule(excluded), "{excluded:?} must not be mutable");
            }
            for eligible in [
                "secrets.sensitive_path",
                "secrets.env_dump",
                "secrets.grep_hunt",
                "secrets.cred_store",
                "egress.exfil_host",
                "egress.post_file",
                "recon.fs_secret_sweep",
                "recon.agent_config_read",
                "recon.identity_probe",
                "recon.agent_runtime_discovery",
                "mcp.indirection",
            ] {
                assert!(is_mutable_rule(eligible), "{eligible:?} must be mutable");
            }
        }

        #[test]
        fn scope_rule_installs_a_mute_and_denies_the_current_call() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            let out = a.respond_local(&id, false, "rule", None, false);
            assert!(out.found);
            assert_eq!(out.mute_installed_for.as_deref(), Some("secrets.sensitive_path"));
            assert_eq!(out.mute_refused, None);
            let (outcome, _src, _sa) = h.join().unwrap();
            assert_eq!(outcome, ParkOutcome::Deny, "the current call is still denied too");

            let mutes = a.snapshot_deny_mutes();
            let arr = mutes["mutes"].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["rule"], "secrets.sensitive_path");
            assert_eq!(arr[0]["origin"], "local");
        }

        #[test]
        fn scope_rule_with_allow_is_refused_and_installs_nothing() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            let out = a.respond_local(&id, true, "rule", None, false);
            assert!(out.found);
            assert_eq!(out.mute_installed_for, None);
            assert_eq!(out.mute_refused, Some("scope_rule_requires_deny"));
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
            let (outcome, _, _) = h.join().unwrap();
            assert_eq!(outcome, ParkOutcome::Allow, "the requested allow is still honored");
        }

        #[test]
        fn scope_rule_on_an_excluded_rule_is_refused() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "persist.sudo", "high");
            let out = a.respond_local(&id, false, "rule", None, false);
            assert_eq!(out.mute_refused, Some("rule_not_mutable"));
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
            h.join().unwrap();
        }

        #[test]
        fn scope_rule_on_critical_severity_is_refused() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "critical");
            let out = a.respond_local(&id, false, "rule", None, false);
            assert_eq!(out.mute_refused, Some("severity_critical"));
            h.join().unwrap();
        }

        /// STRICTER than the always-allow path: gated on `self_approval`
        /// DETECTED, not `blocked` (detected && enforcing) — a mute must be
        /// refused even when GateGuard enforcement is off.
        #[cfg(target_os = "linux")]
        #[test]
        fn scope_rule_refuses_a_detected_self_approval_even_with_enforcement_off() {
            let mut child = std::process::Command::new("sleep")
                .arg("2")
                .spawn()
                .expect("spawn sleep");
            let resolver_pid = child.id();
            let gating_pid = std::process::id();
            let a = Approvals::with_timeout(Duration::from_secs(5));
            let a2 = a.clone();
            let h = thread::spawn(move || {
                a2.park_with_source(
                    "s",
                    "Bash",
                    &json!({"c": 1}),
                    "r",
                    "secrets.sensitive_path",
                    now_ms(),
                    "high",
                    None,
                    None,
                    None,
                    None,
                    Some(gating_pid),
                )
            });
            let id = loop {
                let snap = a.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            // enforce_self_approval = false: an always-allow would still be
            // HONORED here (audit-only mode). A rule mute must NOT be.
            let out = a.respond_local(&id, false, "rule", Some(resolver_pid), false);
            assert!(out.self_approval);
            assert_eq!(out.mute_refused, Some("self_approval_detected"));
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
            h.join().unwrap();
            let _ = child.kill();
            let _ = child.wait();
        }

        #[test]
        fn cap_refuses_the_ninth_mute() {
            let a = fast();
            let rules = [
                "secrets.sensitive_path",
                "secrets.env_dump",
                "secrets.grep_hunt",
                "secrets.cred_store",
                "egress.exfil_host",
                "egress.post_file",
                "recon.fs_secret_sweep",
                "recon.agent_config_read",
            ];
            assert_eq!(rules.len(), MAX_DENY_MUTES);
            for rule in rules {
                let (h, id) = park_and_get_id(&a, "s", rule, "high");
                let out = a.respond_local(&id, false, "rule", None, false);
                assert_eq!(out.mute_refused, None, "{rule} should install");
                h.join().unwrap();
            }
            let (h, id) = park_and_get_id(&a, "s", "recon.identity_probe", "medium");
            let out = a.respond_local(&id, false, "rule", None, false);
            assert_eq!(out.mute_refused, Some("cap_reached"));
            h.join().unwrap();
            assert_eq!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().len(), MAX_DENY_MUTES);
        }

        #[test]
        fn re_muting_an_already_muted_rule_does_not_count_against_the_cap() {
            let a = fast();
            for _ in 0..3 {
                let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
                let out = a.respond_local(&id, false, "rule", None, false);
                assert_eq!(out.mute_refused, None);
                h.join().unwrap();
            }
            assert_eq!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().len(), 1);
        }

        #[test]
        fn deny_mute_covers_all_requires_every_ask_rule_muted() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            a.respond_local(&id, false, "rule", None, false);
            h.join().unwrap();

            // Only the muted rule fired -> covered.
            assert!(a
                .deny_mute_covers_all(&["secrets.sensitive_path".to_string()])
                .is_some());

            // The muted rule co-occurring with an UN-MUTED ask rule on the
            // SAME call -> NOT covered. This is the load-bearing masking-
            // prevention behaviour: a muted noisy rule must never silently
            // absorb a second, more serious, un-muted finding.
            assert!(a
                .deny_mute_covers_all(&[
                    "secrets.sensitive_path".to_string(),
                    "egress.post_file".to_string(),
                ])
                .is_none());

            // Empty ask_rules -> never covered (park normally).
            assert!(a.deny_mute_covers_all(&[]).is_none());
        }

        #[test]
        fn deny_mute_covers_all_bumps_hit_count() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            a.respond_local(&id, false, "rule", None, false);
            h.join().unwrap();

            for _ in 0..3 {
                assert!(a
                    .deny_mute_covers_all(&["secrets.sensitive_path".to_string()])
                    .is_some());
            }
            let mutes = a.snapshot_deny_mutes();
            let arr = mutes["mutes"].as_array().unwrap();
            assert_eq!(arr[0]["hits"], 3);
        }

        #[test]
        fn mute_expires_and_stops_covering() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            // Install, then manually age it past expiry by re-inserting with a
            // past expiry — simplest deterministic way to test TTL without a
            // real sleep. Exercise via the public surface: install, then
            // directly manipulate the (private, in-module-scope) map.
            a.respond_local(&id, false, "rule", None, false);
            h.join().unwrap();
            assert!(a
                .deny_mute_covers_all(&["secrets.sensitive_path".to_string()])
                .is_some());

            // Force expiry.
            {
                let mut map = a.denied_rules.lock().unwrap();
                if let Some(m) = map.get_mut("secrets.sensitive_path") {
                    m.expires_ms = now_ms().saturating_sub(1);
                }
            }
            assert!(
                a.deny_mute_covers_all(&["secrets.sensitive_path".to_string()]).is_none(),
                "an expired mute must no longer cover"
            );
            // Lazily pruned: no longer in the snapshot either.
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
        }

        #[test]
        fn revoke_deny_mute_is_immediate() {
            let a = fast();
            let (h, id) = park_and_get_id(&a, "s", "secrets.sensitive_path", "high");
            a.respond_local(&id, false, "rule", None, false);
            h.join().unwrap();
            assert!(a.revoke_deny_mute("secrets.sensitive_path"));
            assert!(!a.revoke_deny_mute("secrets.sensitive_path"), "already gone");
            assert!(
                a.deny_mute_covers_all(&["secrets.sensitive_path".to_string()]).is_none(),
                "revoked mute must not cover"
            );
        }

        #[test]
        fn revoke_all_deny_mutes_clears_everything() {
            let a = fast();
            for rule in ["secrets.sensitive_path", "secrets.env_dump"] {
                let (h, id) = park_and_get_id(&a, "s", rule, "high");
                a.respond_local(&id, false, "rule", None, false);
                h.join().unwrap();
            }
            assert_eq!(a.revoke_all_deny_mutes(), 2);
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
        }

        // ---- flood detection ---------------------------------------------

        #[test]
        fn flood_trips_at_n_distinct_signatures_in_window() {
            let a = fast();
            for i in 0..FLOOD_N - 1 {
                let sig = format!("sig-{i}");
                assert!(
                    !a.note_ask_and_maybe_trip_flood("secrets.env_dump", &sig),
                    "must not trip before reaching FLOOD_N"
                );
            }
            let final_sig = format!("sig-{}", FLOOD_N - 1);
            assert!(
                a.note_ask_and_maybe_trip_flood("secrets.env_dump", &final_sig),
                "the Nth distinct signature must trip"
            );
            assert_eq!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().len(), 1);
            assert_eq!(
                a.snapshot_deny_mutes()["mutes"][0]["origin"],
                "auto",
                "a flood-triggered mute must be tagged auto, not local"
            );
        }

        #[test]
        fn identical_signature_retries_never_trip_the_flood() {
            let a = fast();
            let sig = "same-signature-every-time";
            for _ in 0..(FLOOD_N * 3) {
                assert!(
                    !a.note_ask_and_maybe_trip_flood("secrets.env_dump", sig),
                    "an identical signature repeated must never trip the detector"
                );
            }
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
        }

        #[test]
        fn flood_counter_is_per_rule() {
            let a = fast();
            for i in 0..FLOOD_N - 1 {
                a.note_ask_and_maybe_trip_flood("secrets.env_dump", &format!("a-{i}"));
                a.note_ask_and_maybe_trip_flood("secrets.grep_hunt", &format!("b-{i}"));
            }
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
        }

        #[test]
        fn flood_window_slides_and_old_entries_are_pruned() {
            let a = fast();
            // Manually seed old entries far outside the window, then confirm
            // a fresh burst of fewer-than-N new ones does not trip (the old
            // ones must not still be counted).
            {
                let mut map = a.flood.lock().unwrap();
                let dq = map.entry("secrets.env_dump".to_string()).or_default();
                let ancient = now_ms().saturating_sub(FLOOD_WINDOW_MS * 10);
                for i in 0..(FLOOD_N - 1) {
                    dq.push_back((ancient, i as u64));
                }
            }
            for i in 0..(FLOOD_N - 2) {
                assert!(!a.note_ask_and_maybe_trip_flood(
                    "secrets.env_dump",
                    &format!("fresh-{i}")
                ));
            }
            assert!(
                a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty(),
                "stale entries outside the window must not count toward the threshold"
            );
        }

        #[test]
        fn flood_disabled_for_empty_rule_id() {
            let a = fast();
            for i in 0..(FLOOD_N * 2) {
                assert!(!a.note_ask_and_maybe_trip_flood("", &format!("s-{i}")));
            }
            assert!(a.snapshot_deny_mutes()["mutes"].as_array().unwrap().is_empty());
        }

        #[test]
        fn flood_state_is_bounded_across_many_distinct_rules() {
            let a = fast();
            for i in 0..(MAX_FLOOD_TRACKED_RULES * 3) {
                a.note_ask_and_maybe_trip_flood(&format!("rule.{i}"), "sig");
            }
            let tracked = a.flood.lock().unwrap().len();
            assert!(
                tracked <= MAX_FLOOD_TRACKED_RULES,
                "flood tracking must stay bounded, got {tracked}"
            );
        }
    }
}
