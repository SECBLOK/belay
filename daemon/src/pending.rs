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

use std::collections::{HashMap, HashSet};
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

/// Shared interactive-approval state, cloned (via `Arc`) into each connection
/// thread by `serve_mode`.
#[derive(Clone)]
pub struct Approvals {
    pending: Arc<Mutex<HashMap<String, PendingEntry>>>,
    /// `true` = enforcing (default). `false` = observe mode: dangerous gates are
    /// ALLOWED (explicit + audited) — the only non-approval allow-override.
    protection: Arc<AtomicBool>,
    /// Stable signatures approved with `scope:"always"`; future matches allow
    /// without re-parking.
    approved: Arc<Mutex<HashSet<String>>>,
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
            approved: Arc::new(Mutex::new(HashSet::new())),
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

    /// True if this exact (session,tool,input) was previously approved "always".
    pub fn is_approved_always(&self, session: &str, tool: &str, input: &Value) -> bool {
        let sig = Self::sig(session, tool, input);
        self.approved
            .lock()
            .map(|s| s.contains(&sig))
            .unwrap_or(false)
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
        self.park_with_source(
            session, tool, input, reason, rule, created_ms, severity, category, explain, None,
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
        self.respond_local(id, allow, scope, None, false).0
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
    /// Returns `(found, self_approval_detected, blocked)`.
    pub fn respond_local(
        &self,
        id: &str,
        allow: bool,
        scope: &str,
        resolver_pid: Option<u32>,
        enforce_self_approval: bool,
    ) -> (bool, bool, bool) {
        let entry = match self.pending.lock() {
            Ok(mut map) => map.remove(id),
            Err(_) => return (false, false, false),
        };
        let entry = match entry {
            Some(e) => e,
            None => return (false, false, false), // unknown id — caller returns ok:false, daemon lives
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
                set.insert(Self::sig(&entry.session, &entry.tool, &entry.input));
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
        (true, self_approval, blocked)
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
            None,
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
            None,
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
                None, Some(4242),
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
                None, Some(111),
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
                None, Some(999),
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
                    gating_pid,
                )
            });
            let id = loop {
                let snap = a.snapshot();
                if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                    break first["id"].as_str().unwrap().to_string();
                }
                thread::sleep(Duration::from_millis(5));
            };
            let (found, self_approval, blocked) =
                a.respond_local(&id, true, "once", resolver_pid, true);
            assert!(found);
            assert!(
                !self_approval,
                "case gating_pid={gating_pid:?} resolver_pid={resolver_pid:?} must not detect self-approval"
            );
            assert!(!blocked);
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

        // Enforcement OFF: self-approval is DETECTED and would be AUDITED,
        // but the requested Allow is still honored (audit-only).
        let (found, self_approval, blocked) =
            a.respond_local(&id, true, "once", Some(resolver_pid), false);
        assert!(found);
        assert!(self_approval, "the spawned child IS a descendant of this process");
        assert!(!blocked, "enforcement is off — must not override");
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
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, Some(gating_pid),
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
        let (found, self_approval, blocked) =
            a.respond_local(&id, true, "always", Some(resolver_pid), true);
        assert!(found);
        assert!(self_approval);
        assert!(blocked, "enforcement on + detected self-approval must block");
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
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, Some(pid),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };

        let (found, self_approval, blocked) = a.respond_local(&id, true, "always", Some(pid), true);
        assert!(found);
        assert!(
            self_approval,
            "a resolver that IS the gated agent must count as self-approval"
        );
        assert!(blocked, "enforcement on + detected self-approval must block");
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
                "s", "Bash", &in1, "r", "rule.x", now_ms(), "info", None, None, Some(1),
            )
        });
        let id = loop {
            let snap = a.snapshot();
            if let Some(first) = snap["pending"].as_array().and_then(|v| v.first()) {
                break first["id"].as_str().unwrap().to_string();
            }
            thread::sleep(Duration::from_millis(5));
        };
        let (found, self_approval, blocked) = a.respond_local(&id, true, "once", Some(1), true);
        assert!(found);
        assert!(!self_approval, "pid 1 must never be a positive match");
        assert!(!blocked);
        assert_eq!(h.join().unwrap().0, ParkOutcome::Allow, "the allow must stand");
    }
}
