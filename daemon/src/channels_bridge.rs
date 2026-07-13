//! Messaging-approval trust boundary (channels build only).
//!
//! When a gate resolves to **ASK**, the daemon parks the request (see
//! [`crate::pending`]) and — if a channels bridge is installed — fans the prompt
//! out to messaging adapters (Telegram/Discord/…). An approver replies in a chat;
//! the reply arrives here as an [`InboundReply`]. This module is the shim that
//! decides whether that reply is allowed to resolve the parked approval.
//!
//! ## Security invariant (the whole reason this module exists)
//!
//! Messaging is **additive friction**, never a softer road to ALLOW. A chat reply
//! must clear STRICTLY MORE checks than a local operator (who is already gated by
//! the 0600 socket + owner-UID peer check). Every reply is run through
//! [`AuthzGate::check`] — a fail-closed AND of:
//!
//!   1. **DM-only** — group/channel messages are dropped (an attacker in a shared
//!      channel must never be able to approve).
//!   2. **default-deny allowlist** — the `(platform, principal)` pair must be
//!      explicitly enrolled; anything else is rejected.
//!   3. **rate-limit** — per-principal sliding window, so a compromised-but-
//!      allowlisted account can't brute-force/replay a flood of decisions.
//!   4. **dedup** — a `(platform, msg_id)` is honoured at most once (defeats
//!      duplicate delivery / replay of a captured "yes").
//!
//! Only after ALL pass does the bridge call
//! [`crate::pending::Approvals::respond_by_nonce`], which itself requires an exact
//! match to the request's 128-bit CSPRNG nonce (unguessable, delivered only to the
//! allowlisted approver's DM) and CLAMPS scope to `once` — durable `always`
//! authority is never installable over a channel. Any failure resolves nothing;
//! the park keeps waiting and eventually times out → **DENY**.

use crate::pending::{Approvals, PendingNotice};
use belay_channels::{ChannelAdapter, DecisionRequest};
pub use belay_channels::InboundReply;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use std::{fs, io};

/// Upper bound on remembered `(platform,msg_id)` dedup keys before the oldest is
/// evicted. Bounds memory under a flood while still catching realistic replays.
const SEEN_CAP: usize = 4096;

/// Max distinct `(platform,principal)` rate-limit buckets before empties are
/// reclaimed and, failing that, new principals are refused (bounds an
/// unauthenticated pairing flood from growing the rate map without limit).
const MAX_RATE_PRINCIPALS: usize = 4096;

/// Sliding window for the per-principal reply rate limit.
const RATE_WINDOW: Duration = Duration::from_secs(60);

// The inbound-reply wire type ([`InboundReply`]) is defined in the `channels`
// crate — adapters produce it, this gate consumes it — and re-exported above.

/// Why a reply was refused by the gate. Purely for audit/telemetry — every
/// variant means "did not resolve the approval" (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a direct message (group/channel).
    NotDm,
    /// `(platform, principal)` is not on the allowlist.
    NotAllowlisted,
    /// Per-principal rate limit exceeded.
    RateLimited,
    /// This `(platform, msg_id)` was already processed.
    Duplicate,
    /// Gate state lock poisoned — fail closed.
    Internal,
}

/// Outcome of feeding a reply through the bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// The reply passed the gate AND matched a parked request, which was resolved
    /// with the carried allow/deny.
    Resolved(bool),
    /// The reply passed the gate but no parked request matched its nonce (a late
    /// or wrong nonce). Nothing was resolved; the reply is consumed.
    Stale,
    /// The reply was refused by the gate; nothing was resolved.
    Rejected(Rejection),
    /// A `pair <code>` request with a valid code — the sender was enrolled.
    Paired,
    /// A pairing request whose code was unknown/expired/wrong-platform.
    BadCode,
}

// ── Config (`~/.belay/channels.json`, 0600) ─────────────────────────────

fn default_timeout_secs() -> u64 {
    60
}
fn default_max_replies_per_min() -> u32 {
    10
}

/// One enrolled approver principal on one platform.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AllowEntry {
    pub platform: String,
    pub principal: String,
}

/// Telegram adapter credentials. `chat_id` is where prompts are SENT (the
/// approver's DM); the reply's sender must still be on the [`ChannelsConfig`]
/// allowlist (`platform:"telegram", principal:<user id>`) to be honoured.
#[derive(Clone, Debug, Deserialize)]
pub struct TelegramCfg {
    pub bot_token: String,
    pub chat_id: String,
    /// Optional API base override (mock/self-host); guarded by `is_safe_base`.
    #[serde(default)]
    pub base: Option<String>,
}

/// Discord adapter (two-way). `channel_id` MUST be a 1:1 DM channel — prompts are
/// sent there so only the approver sees the nonce; replies are still allowlist-gated.
#[derive(Clone, Debug, Deserialize)]
pub struct DiscordCfg {
    pub bot_token: String,
    pub channel_id: String,
    #[serde(default)]
    pub base: Option<String>,
}

/// WhatsApp (Twilio) adapter (two-way). `to` is the approver's 1:1 WhatsApp address.
#[derive(Clone, Debug, Deserialize)]
pub struct WhatsAppCfg {
    pub account_sid: String,
    pub auth_token: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub base: Option<String>,
}

/// Matrix adapter (two-way). `room_id` should be a 1:1 direct room; the adapter
/// reports is_dm from the room's real member count, so a shared room fails closed.
#[derive(Clone, Debug, Deserialize)]
pub struct MatrixCfg {
    pub access_token: String,
    pub room_id: String,
    #[serde(default)]
    pub base: Option<String>,
}

/// Mattermost adapter (two-way). `base` is the self-hosted server URL (required);
/// `channel_id` should be a direct (type `D`) channel.
#[derive(Clone, Debug, Deserialize)]
pub struct MattermostCfg {
    pub token: String,
    pub channel_id: String,
    pub base: String,
}

/// Slack adapter (notify-only). Inbound needs the Events API / Socket Mode, so
/// approval must come from a two-way channel or the local UI.
#[derive(Clone, Debug, Deserialize)]
pub struct SlackCfg {
    pub token: String,
    pub channel: String,
    #[serde(default)]
    pub base: Option<String>,
}

/// ntfy.sh adapter (notify-only). Publishes the prompt to a pub/sub `topic`.
#[derive(Clone, Debug, Deserialize)]
pub struct NtfyCfg {
    pub topic: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
}

/// Generic outbound webhook (notify-only). POSTs the prompt as JSON to `url`.
#[derive(Clone, Debug, Deserialize)]
pub struct WebhookCfg {
    pub url: String,
}

/// Microsoft Teams Incoming Webhook (notify-only). `webhook_url` posts a
/// MessageCard to a channel; interactive Teams approval needs the future inbound
/// receiver, so approve via a two-way channel or the local UI.
#[derive(Clone, Debug, Deserialize)]
pub struct TeamsCfg {
    pub webhook_url: String,
}

/// WeCom / 企业微信 group-robot webhook (notify-only). `webhook_url` includes the
/// robot `key`. Interactive WeCom/Official-Account approval needs the future
/// inbound receiver; personal WeChat has no official API and is unsupported.
#[derive(Clone, Debug, Deserialize)]
pub struct WecomCfg {
    pub webhook_url: String,
}

/// Phase B inbound-webhook receiver. `bind` defaults to loopback — expose it via
/// the operator's TLS reverse proxy, never a raw public bind. Per-platform secrets
/// authenticate callbacks (Line today; Slack/Twilio/… as verifiers land).
#[derive(Clone, Debug, Deserialize)]
pub struct InboundCfg {
    #[serde(default = "default_bind")]
    pub bind: String,
    /// LINE channel secret — enables the `/hook/line` inbound verifier.
    #[serde(default)]
    pub line_channel_secret: Option<String>,
    /// Slack signing secret — enables the `/hook/slack` interactivity verifier.
    #[serde(default)]
    pub slack_signing_secret: Option<String>,
}

fn default_bind() -> String {
    "127.0.0.1:8787".to_string()
}

/// Bridge configuration. Deliberately JSON (serde_json is already a hard daemon
/// dependency) so enabling `channels` adds no new config-parser crate.
#[derive(Clone, Debug, Deserialize)]
pub struct ChannelsConfig {
    /// Park/escalation timeout hint (seconds) surfaced to adapters.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Max accepted replies per principal per [`RATE_WINDOW`].
    #[serde(default = "default_max_replies_per_min")]
    pub max_replies_per_min: u32,
    /// Default-deny allowlist of approver principals.
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
    /// Telegram adapter, if configured.
    #[serde(default)]
    pub telegram: Option<TelegramCfg>,
    #[serde(default)]
    pub discord: Option<DiscordCfg>,
    #[serde(default)]
    pub whatsapp: Option<WhatsAppCfg>,
    #[serde(default)]
    pub matrix: Option<MatrixCfg>,
    #[serde(default)]
    pub mattermost: Option<MattermostCfg>,
    #[serde(default)]
    pub slack: Option<SlackCfg>,
    #[serde(default)]
    pub ntfy: Option<NtfyCfg>,
    #[serde(default)]
    pub webhook: Option<WebhookCfg>,
    #[serde(default)]
    pub teams: Option<TeamsCfg>,
    #[serde(default)]
    pub wecom: Option<WecomCfg>,
    /// Phase B inbound-webhook receiver, if configured.
    #[serde(default)]
    pub inbound: Option<InboundCfg>,
    /// Platform ids administratively disabled (config kept, adapter/verifier not
    /// started). Independent of whether the platform is configured — lets an
    /// operator pause a connector without deleting its credentials.
    #[serde(default)]
    pub disabled: Vec<String>,
}

impl Default for ChannelsConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
            max_replies_per_min: default_max_replies_per_min(),
            allow: Vec::new(),
            telegram: None,
            discord: None,
            whatsapp: None,
            matrix: None,
            mattermost: None,
            slack: None,
            ntfy: None,
            webhook: None,
            teams: None,
            wecom: None,
            inbound: None,
            disabled: Vec::new(),
        }
    }
}

/// `true` if `platform` is NOT in the administrative disabled list.
pub(crate) fn platform_enabled(cfg: &ChannelsConfig, platform: &str) -> bool {
    !cfg.disabled.iter().any(|d| d == platform)
}

/// Load the channels config, refusing (fail-closed) any file that is not
/// owner-only (0600). The file may hold bot tokens + the approver allowlist, so a
/// group/world-readable config is treated as an error rather than silently used.
pub fn load_config(path: &Path) -> io::Result<ChannelsConfig> {
    let meta = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "channels config {} must be owner-only (0600); found {:03o}",
                    path.display(),
                    mode & 0o777
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = &meta;
    let raw = fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── The authorization gate ───────────────────────────────────────────────────

#[derive(Default)]
struct GateState {
    /// `"platform\x1fmsg_id"` seen (dedup), bounded by `SEEN_CAP`.
    seen: HashSet<String>,
    /// FIFO of seen keys for O(1) oldest-eviction.
    seen_order: VecDeque<String>,
    /// `"platform\x1fprincipal"` → accept timestamps within the window.
    rate: HashMap<String, VecDeque<Instant>>,
}

/// Stateful, fail-closed authorization gate for inbound approval replies.
pub struct AuthzGate {
    /// Default-deny allowlist of `(platform, principal)`. Runtime-mutable so the
    /// owner can enroll/unenroll principals live (via `ChannelsAdmin`) without a
    /// daemon restart; a poisoned lock fails closed (empty → deny).
    allow: RwLock<HashSet<(String, String)>>,
    /// Max accepted replies per principal per [`RATE_WINDOW`].
    max_per_window: u32,
    state: Mutex<GateState>,
}

impl AuthzGate {
    pub fn from_config(cfg: &ChannelsConfig) -> Self {
        let allow = cfg
            .allow
            .iter()
            .map(|e| (e.platform.clone(), e.principal.clone()))
            .collect();
        Self {
            allow: RwLock::new(allow),
            max_per_window: cfg.max_replies_per_min,
            state: Mutex::new(GateState::default()),
        }
    }

    /// Enroll a principal (live). Returns `true` if newly added.
    pub fn add_allow(&self, platform: &str, principal: &str) -> bool {
        match self.allow.write() {
            Ok(mut a) => a.insert((platform.to_string(), principal.to_string())),
            Err(_) => false,
        }
    }

    /// Unenroll a principal (live). Returns `true` if it was present.
    pub fn remove_allow(&self, platform: &str, principal: &str) -> bool {
        match self.allow.write() {
            Ok(mut a) => a.remove(&(platform.to_string(), principal.to_string())),
            Err(_) => false,
        }
    }

    /// Run a reply through every gate check. `Ok(())` means "authorized to attempt
    /// resolution"; `Err` names the first failed check. Rate + dedup state is
    /// recorded ONLY for a fully-authorized reply, so an unauthenticated flood
    /// cannot grow gate memory or exhaust another principal's budget.
    pub fn check(&self, r: &InboundReply) -> Result<(), Rejection> {
        // 1) DM-only — cheapest, no state, most decisive.
        if !r.is_dm {
            return Err(Rejection::NotDm);
        }
        // 2) Default-deny allowlist (a poisoned lock fails closed → deny).
        let allowed = self
            .allow
            .read()
            .map(|a| a.contains(&(r.platform.clone(), r.principal.clone())))
            .unwrap_or(false);
        if !allowed {
            return Err(Rejection::NotAllowlisted);
        }
        // 3+4) Rate limit + dedup.
        self.rate_dedup(r)
    }

    /// The rate-limit + dedup portion of the gate, WITHOUT the allowlist check.
    /// Reused by the pairing path — pairing is how a principal GETS on the
    /// allowlist, so it cannot require being on it, but it must still be
    /// DM-only (checked by the caller) + rate-limited + deduped to bound a
    /// code-guessing flood. State is recorded only on the accept side.
    pub fn rate_dedup(&self, r: &InboundReply) -> Result<(), Rejection> {
        let mut st = self.state.lock().map_err(|_| Rejection::Internal)?;
        let now = Instant::now();
        let rkey = format!("{}\u{1f}{}", r.platform, r.principal);
        let skey = format!("{}\u{1f}{}", r.platform, r.msg_id);

        // 3) Rate limit (prune the window, then check — no recording yet).
        // Bound the number of tracked principals: the pairing path runs this for
        // UNALLOWLISTED ids, so a sockpuppet flood could otherwise grow the map
        // without limit. Before adding a NEW principal at the cap, reclaim empty
        // windows; if still at the cap, fail closed (RateLimited).
        {
            if !st.rate.contains_key(&rkey) && st.rate.len() >= MAX_RATE_PRINCIPALS {
                st.rate.retain(|_, dq| {
                    while let Some(&front) = dq.front() {
                        if now.duration_since(front) > RATE_WINDOW {
                            dq.pop_front();
                        } else {
                            break;
                        }
                    }
                    !dq.is_empty()
                });
                if st.rate.len() >= MAX_RATE_PRINCIPALS {
                    return Err(Rejection::RateLimited);
                }
            }
            let dq = st.rate.entry(rkey.clone()).or_default();
            while let Some(&front) = dq.front() {
                if now.duration_since(front) > RATE_WINDOW {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            if dq.len() >= self.max_per_window as usize {
                return Err(Rejection::RateLimited);
            }
        } // dq borrow ends before touching `st.seen`

        // 4) Dedup.
        if st.seen.contains(&skey) {
            return Err(Rejection::Duplicate);
        }

        // All checks passed — NOW record rate + dedup (accept side only).
        if let Some(dq) = st.rate.get_mut(&rkey) {
            dq.push_back(now);
        }
        st.seen.insert(skey.clone());
        st.seen_order.push_back(skey);
        if st.seen_order.len() > SEEN_CAP {
            if let Some(old) = st.seen_order.pop_front() {
                st.seen.remove(&old);
            }
        }
        Ok(())
    }
}

// ── Interactive pairing ──────────────────────────────────────────────────────

/// TTL for a pairing code.
const PAIR_TTL: Duration = Duration::from_secs(300);

struct Pairing {
    platform: String,
    expires: Instant,
}

/// Single-use, short-lived pairing codes. The owner starts a pairing (`pair_start`
/// shows a code); the approver DMs `pair <code>` from the account to enroll; the
/// daemon captures that account's real principal and adds it to the allowlist.
/// Codes expire (5 min) and are consumed on first use, so an observed/leaked code
/// is low-risk — and pairing still requires a DM + passes rate-limit/dedup.
#[derive(Default)]
pub struct PendingPairings {
    inner: Mutex<HashMap<String, Pairing>>,
}

impl PendingPairings {
    /// Start a pairing for `platform`; returns the code to show the operator.
    pub fn start(&self, platform: &str) -> String {
        let code = gen_pair_code();
        if let Ok(mut m) = self.inner.lock() {
            let now = Instant::now();
            m.retain(|_, p| p.expires > now); // prune expired
            m.insert(
                code.clone(),
                Pairing {
                    platform: platform.to_string(),
                    expires: now + PAIR_TTL,
                },
            );
        }
        code
    }

    /// Consume a code: `true` only if it exists, matches `platform`, and is
    /// unexpired. Single-use (removed on success).
    pub fn consume(&self, platform: &str, code: &str) -> bool {
        let mut m = match self.inner.lock() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let now = Instant::now();
        match m.get(code) {
            Some(p) if p.platform == platform && p.expires > now => {
                m.remove(code);
                true
            }
            _ => false,
        }
    }
}

/// 8-char code from a 32-symbol unambiguous alphabet (no 0/1/I/O). 256 = 32*8, so
/// reducing a CSPRNG byte `% 32` is perfectly uniform (no modulo bias). ~40 bits.
fn gen_pair_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("CSPRNG (getrandom) unavailable");
    buf.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

// ── The bridge (gate + resolve join) ─────────────────────────────────────────

/// Joins the authorization gate to the parked-approval queue. This is the object
/// the reply-listener tasks call into: `process_reply` gates the reply and, only
/// on success, resolves the matching park by nonce (scope clamped to `once`).
pub struct ChannelBridge {
    approvals: Approvals,
    gate: Arc<AuthzGate>,
    pairings: Arc<PendingPairings>,
    timeout: Duration,
}

impl ChannelBridge {
    pub fn new(approvals: Approvals, cfg: &ChannelsConfig) -> Self {
        Self {
            approvals,
            gate: Arc::new(AuthzGate::from_config(cfg)),
            pairings: Arc::new(PendingPairings::default()),
            timeout: Duration::from_secs(cfg.timeout_secs.max(1)),
        }
    }

    /// The live authorization gate — shared with [`ChannelsAdmin`] so runtime
    /// enroll/unenroll takes effect without rebuilding the bridge.
    pub fn gate(&self) -> Arc<AuthzGate> {
        self.gate.clone()
    }

    /// The pending-pairings store — shared with [`ChannelsAdmin`] so `pair_start`
    /// (over IPC) and the inbound pairing handler use the same code table.
    pub fn pairings(&self) -> Arc<PendingPairings> {
        self.pairings.clone()
    }

    /// Escalation timeout hint for adapters (from config).
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Gate an inbound reply and, if authorized, resolve the matching parked
    /// approval. A `PAIR:<code>` nonce is routed to enrollment instead. Never
    /// resolves/enrolls anything on a gate failure (fail-closed).
    pub fn process_reply(&self, r: &InboundReply) -> ReplyOutcome {
        if let Some(code) = r
            .nonce
            .strip_prefix(belay_channels::inbound::PAIR_NONCE_PREFIX)
        {
            return self.process_pairing(r, code);
        }
        if let Err(rej) = self.gate.check(r) {
            return ReplyOutcome::Rejected(rej);
        }
        // Authorized. respond_by_nonce is authoritative on nonce validity and
        // clamps scope to `once`; unknown nonce → nothing resolved (stale).
        if self.approvals.respond_by_nonce(&r.nonce, r.allow, "once") {
            ReplyOutcome::Resolved(r.allow)
        } else {
            ReplyOutcome::Stale
        }
    }

    /// Handle a `pair <code>` request. Gated by DM-only + rate-limit/dedup (NOT
    /// allowlist — pairing is how you GET allowlisted) + a valid single-use code.
    /// On success, enrolls the sender's real principal (live + persisted).
    fn process_pairing(&self, r: &InboundReply, code: &str) -> ReplyOutcome {
        if !r.is_dm {
            return ReplyOutcome::Rejected(Rejection::NotDm);
        }
        if let Err(rej) = self.gate.rate_dedup(r) {
            return ReplyOutcome::Rejected(rej);
        }
        if !self.pairings.consume(&r.platform, code) {
            return ReplyOutcome::BadCode;
        }
        // Enroll. If the runtime admin is installed (production), it updates the
        // live gate AND persists to channels.json; otherwise (tests) enroll the
        // live gate directly so the effect is observable.
        match admin() {
            Some(a) => {
                let _ = a.allow_add(&r.platform, &r.principal);
            }
            None => {
                self.gate.add_allow(&r.platform, &r.principal);
            }
        }
        ReplyOutcome::Paired
    }
}

// ── Live wiring: adapters + dedicated runtime ────────────────────────────────

/// Build the enabled push-model adapters from config. Adds one `Arc<dyn
/// ChannelAdapter>` per configured platform (Telegram today; more to come).
fn build_adapters(cfg: &ChannelsConfig) -> Vec<Arc<dyn ChannelAdapter>> {
    let mut out: Vec<Arc<dyn ChannelAdapter>> = Vec::new();
    if let Some(tg) = cfg.telegram.as_ref().filter(|_| platform_enabled(cfg, "telegram")) {
        let mut ch =
            belay_channels::telegram::TelegramChannel::new(tg.bot_token.clone(), tg.chat_id.clone());
        if let Some(base) = &tg.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(dc) = cfg.discord.as_ref().filter(|_| platform_enabled(cfg, "discord")) {
        let mut ch = belay_channels::discord::DiscordChannel::new(
            dc.bot_token.clone(),
            dc.channel_id.clone(),
        );
        if let Some(base) = &dc.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(wa) = cfg.whatsapp.as_ref().filter(|_| platform_enabled(cfg, "whatsapp")) {
        let mut ch = belay_channels::whatsapp::WhatsAppChannel::new(
            wa.account_sid.clone(),
            wa.auth_token.clone(),
            wa.from.clone(),
            wa.to.clone(),
        );
        if let Some(base) = &wa.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(mx) = cfg.matrix.as_ref().filter(|_| platform_enabled(cfg, "matrix")) {
        let mut ch = belay_channels::matrix::MatrixChannel::new(
            mx.access_token.clone(),
            mx.room_id.clone(),
        );
        if let Some(base) = &mx.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(mm) = cfg.mattermost.as_ref().filter(|_| platform_enabled(cfg, "mattermost")) {
        let ch = belay_channels::mattermost::MattermostChannel::new(
            mm.token.clone(),
            mm.channel_id.clone(),
        )
        .with_base(mm.base.clone());
        out.push(Arc::new(ch));
    }
    if let Some(sl) = cfg.slack.as_ref().filter(|_| platform_enabled(cfg, "slack")) {
        let mut ch =
            belay_channels::slack::SlackChannel::new(sl.token.clone(), sl.channel.clone());
        if let Some(base) = &sl.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(nt) = cfg.ntfy.as_ref().filter(|_| platform_enabled(cfg, "ntfy")) {
        let mut ch = belay_channels::ntfy::NtfyChannel::new(nt.topic.clone());
        if let Some(token) = &nt.token {
            ch = ch.with_token(token.clone());
        }
        if let Some(base) = &nt.base {
            ch = ch.with_base(base.clone());
        }
        out.push(Arc::new(ch));
    }
    if let Some(wh) = cfg.webhook.as_ref().filter(|_| platform_enabled(cfg, "webhook")) {
        out.push(Arc::new(belay_channels::webhook::WebhookChannel::new(
            wh.url.clone(),
        )));
    }
    if let Some(tm) = cfg.teams.as_ref().filter(|_| platform_enabled(cfg, "teams")) {
        out.push(Arc::new(belay_channels::teams::TeamsChannel::new(
            tm.webhook_url.clone(),
        )));
    }
    if let Some(wc) = cfg.wecom.as_ref().filter(|_| platform_enabled(cfg, "wecom")) {
        out.push(Arc::new(belay_channels::wecom::WecomChannel::new(
            wc.webhook_url.clone(),
        )));
    }
    out
}

/// Owns the bridge's dedicated runtime + tasks for the daemon's lifetime.
/// Dropping it stops every listener. Uses `shutdown_background` so it is safe to
/// drop even from within another tokio runtime's worker thread (the root binary
/// serves from `#[tokio::main]`); a blocking `Runtime` drop there would panic.
pub struct BridgeHandle {
    rt: Option<tokio::runtime::Runtime>,
    _bridge: Arc<ChannelBridge>,
}

impl BridgeHandle {
    /// The live authorization gate, for installing the runtime admin.
    pub fn gate(&self) -> Arc<AuthzGate> {
        self._bridge.gate()
    }

    /// The pending-pairings store, for installing the runtime admin.
    pub fn pairings(&self) -> Arc<PendingPairings> {
        self._bridge.pairings()
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Load `~/.belay/channels.json` and, if it enables at least one adapter,
/// start the messaging-approval bridge. Returns `None` (channels stay off,
/// local-only) when there is no config, it is insecure/invalid, or no adapter is
/// configured — the daemon then behaves exactly as a default build.
pub fn start_from_config(approvals: &Approvals) -> Option<BridgeHandle> {
    let path = crate::paths::data_dir().join("channels.json");
    let cfg = match load_config(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!("belay channels: disabled — {e}");
            return None;
        }
    };
    let handle = start(approvals, cfg)?;
    // Install the owner-gated runtime admin sharing this bridge's live gate +
    // pairing store, so `channel_allow_add/remove` and `channel_pair_start` over
    // the IPC socket take effect without a restart.
    set_admin(ChannelsAdmin::new(handle.gate(), handle.pairings(), path));
    Some(handle)
}

/// Start the bridge from an already-loaded config: spin up a dedicated runtime,
/// spawn one listener per adapter feeding a shared reply channel, a consumer that
/// runs each reply through the gate + resolve join, and the park notifier that
/// fans prompts out to every adapter. Split from [`start_from_config`] so the
/// live path is exercisable without touching the filesystem.
/// Map a lowercase severity wire label to a plain-language risk badge (emoji +
/// ALL-CAPS word) shown at the top of every channel alert.
fn risk_badge(severity: &str) -> &'static str {
    match severity {
        "critical" => "🔴 CRITICAL",
        "high" => "🔴 HIGH RISK",
        "medium" => "🟠 MEDIUM RISK",
        "low" => "🟢 LOW RISK",
        "info" => "⚪ INFO",
        _ => "⚪ REVIEW",
    }
}

/// A single-line, whitespace-collapsed, length-capped preview of the command for
/// the collapsed "Technical" line. Prefers the tool input's `command` field,
/// else the whole input serialized. Truncation is char-based (unicode-safe).
fn command_preview(input: &serde_json::Value) -> String {
    let raw = input
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| input.to_string());
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 140;
    if collapsed.chars().count() > MAX {
        let mut s: String = collapsed.chars().take(MAX).collect();
        s.push('…');
        s
    } else {
        collapsed
    }
}

/// Build a NON-technical `(summary, detail)` pair for a channel approval prompt
/// from the curated per-rule Explain: a risk badge + plain-English title, why it
/// matters, and a suggested action, with the raw command tucked into a short
/// "Technical" line (always length-capped). Falls back to a compact tool/reason
/// line when no Explain was authored, so un-curated hits still notify. No path
/// ever dumps the raw tool-input JSON - that was the original wall-of-text bug.
pub(crate) fn friendly_prompt(
    severity: &str,
    explain: Option<&serde_json::Value>,
    tool: &str,
    reason: &str,
    rule: &str,
    input: &serde_json::Value,
) -> (String, String) {
    let badge = risk_badge(severity);
    let field = |k: &str| -> String {
        explain
            .and_then(|e| e.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let preview = command_preview(input);
    let title = field("summary");
    if title.is_empty() {
        // No curated explanation: compact tool/reason line, still no raw JSON.
        return (badge.to_string(), format!("{tool}: {reason}\n\n▸ {preview}"));
    }
    let mut detail = format!("{title}\n\n");
    let why = field("why_risky");
    if !why.is_empty() {
        detail.push_str(&format!("Why it matters: {why}\n\n"));
    }
    let action = field("suggested_action");
    if !action.is_empty() {
        detail.push_str(&format!("👉 {action}\n\n"));
    }
    if preview.is_empty() {
        detail.push_str(&format!("▸ Technical: {tool} · {rule}"));
    } else {
        detail.push_str(&format!("▸ Technical: {tool} · {rule}\n   {preview}"));
    }
    (badge.to_string(), detail)
}

/// Plain-language click feedback for a Slack `response_url` update, matching what
/// the poll-based adapters render when they edit the prompt after a click.
fn slack_feedback_text(outcome: &ReplyOutcome) -> String {
    match outcome {
        ReplyOutcome::Resolved(true) => {
            "✅ *Allow recorded* - Belay is proceeding with the action.".into()
        }
        ReplyOutcome::Resolved(false) => {
            "⛔ *Deny recorded* - Belay blocked the action.".into()
        }
        ReplyOutcome::Stale => {
            "⏱️ *Too late* - this approval already expired and was auto-denied. Re-run the action if you still want it.".into()
        }
        ReplyOutcome::Rejected(_) => {
            "🚫 *Not authorized* - you are not an enrolled Belay approver.".into()
        }
        ReplyOutcome::Paired => {
            "✅ *Paired* - you can now approve Belay alerts.".into()
        }
        ReplyOutcome::BadCode => {
            "⚠️ *Invalid or expired pairing code.*".into()
        }
    }
}

pub fn start(approvals: &Approvals, cfg: ChannelsConfig) -> Option<BridgeHandle> {
    let adapters = build_adapters(&cfg);
    let verifiers = crate::inbound_http::build_verifiers(&cfg);
    // Nothing to do unless there is at least one outbound adapter OR an inbound
    // verifier (an inbound-only config — e.g. Line webhooks — is valid).
    if adapters.is_empty() && verifiers.is_empty() {
        return None;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .ok()?;
    let bridge = Arc::new(ChannelBridge::new(approvals.clone(), &cfg));

    // Inbound: every adapter's listener feeds one shared channel; a single
    // consumer runs each reply through the gate + resolve join.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundReply>(256);
    for a in &adapters {
        let a = a.clone();
        let tx = tx.clone();
        rt.spawn(async move { a.listen(tx).await });
    }
    let consumer_bridge = bridge.clone();
    let consumer_adapters = adapters.clone();
    let feedback_http = reqwest::Client::new();
    rt.spawn(async move {
        while let Some(reply) = rx.recv().await {
            let outcome = consumer_bridge.process_reply(&reply);
            // Audit the security-relevant event. Never logs the nonce; the
            // principal (a platform user id) is logged for accountability.
            crate::ipc::audit_approval(serde_json::json!({
                "event": "approval.channel_reply",
                "ts_ms": crate::pending::now_ms(),
                "platform": reply.platform,
                "principal": reply.principal,
                "outcome": format!("{outcome:?}"),
            }));
            // Tell the originating adapter the nonce was answered so a poll-less
            // adapter (Slack) cancels any pending expiry rewrite of the prompt.
            if matches!(outcome, ReplyOutcome::Resolved(_)) {
                if let Some(a) = consumer_adapters
                    .iter()
                    .find(|a| a.platform() == reply.platform)
                {
                    a.on_resolved(&reply.nonce).await;
                }
            }
            // Slack has no poll loop to edit the prompt in place, so it carries a
            // one-shot response_url instead: POST the outcome there so the approver
            // sees their click land (and the buttons are replaced). Best-effort.
            if let Some(url) = reply.response_url.as_deref() {
                if belay_channels::is_safe_base(url) {
                    let text = slack_feedback_text(&outcome);
                    let _ = feedback_http
                        .post(url)
                        .json(&serde_json::json!({ "replace_original": true, "text": text }))
                        .send()
                        .await;
                }
            }
        }
    });

    // Outbound: on every park, fan the prompt out to all adapters concurrently.
    let notify_adapters = adapters.clone();
    let handle = rt.handle().clone();
    approvals.set_notifier(Arc::new(move |n: PendingNotice| {
        let (summary, detail) = friendly_prompt(
            &n.severity,
            n.explain.as_ref(),
            &n.tool,
            &n.reason,
            &n.rule,
            &n.input,
        );
        let req = DecisionRequest {
            session_id: n.session.clone(),
            summary,
            detail,
            rule_id: n.rule.clone(),
        };
        for a in &notify_adapters {
            let a = a.clone();
            let nonce = n.nonce.clone();
            let req = req.clone();
            handle.spawn(async move { a.notify(&nonce, &req).await });
        }
    }));

    // Phase B: the inbound-webhook receiver (authenticates platform callbacks and
    // feeds them to the same gate). Started only when a verifier is configured.
    if !verifiers.is_empty() {
        let bind = cfg
            .inbound
            .as_ref()
            .map(|i| i.bind.clone())
            .unwrap_or_else(default_bind);
        let verifiers = Arc::new(verifiers);
        let receiver_bridge = bridge.clone();
        rt.spawn(async move {
            crate::inbound_http::serve(bind, verifiers, receiver_bridge).await;
        });
    }

    Some(BridgeHandle {
        rt: Some(rt),
        _bridge: bridge,
    })
}

// ── Runtime administration (owner-gated IPC) ─────────────────────────────────

/// Owner-gated runtime management of channels config. Shares the LIVE gate (so
/// enroll/unenroll takes effect without a restart) and persists changes to
/// channels.json (0600). Reached from the daemon's owner-only IPC command socket.
pub struct ChannelsAdmin {
    gate: Arc<AuthzGate>,
    pairings: Arc<PendingPairings>,
    config_path: PathBuf,
}

impl ChannelsAdmin {
    pub fn new(
        gate: Arc<AuthzGate>,
        pairings: Arc<PendingPairings>,
        config_path: PathBuf,
    ) -> Self {
        Self {
            gate,
            pairings,
            config_path,
        }
    }

    /// Start an interactive pairing for `platform`; returns the code to show the
    /// operator. The approver then DMs `pair <code>` from the account to enroll.
    pub fn pair_start(&self, platform: &str) -> String {
        self.pairings.start(platform)
    }

    /// Enroll `(platform, principal)`: PERSIST first, then update the live gate
    /// only on a successful write — so a persist failure leaves disk and the live
    /// gate consistent (neither changed) rather than a live-only enrollment that
    /// vanishes on restart. Returns whether it was newly added to the gate.
    pub fn allow_add(&self, platform: &str, principal: &str) -> io::Result<bool> {
        self.mutate_allow(|arr| {
            let exists = arr
                .iter()
                .any(|e| e["platform"] == platform && e["principal"] == principal);
            if !exists {
                arr.push(serde_json::json!({"platform": platform, "principal": principal}));
            }
        })?;
        Ok(self.gate.add_allow(platform, principal))
    }

    /// Unenroll `(platform, principal)`: PERSIST first, then update the live gate
    /// only on success — so a failed write cannot leave a principal removed live
    /// but re-authorized on the next restart (stale-ALLOW resurrection).
    pub fn allow_remove(&self, platform: &str, principal: &str) -> io::Result<bool> {
        self.mutate_allow(|arr| {
            arr.retain(|e| !(e["platform"] == platform && e["principal"] == principal));
        })?;
        Ok(self.gate.remove_allow(platform, principal))
    }

    /// Redacted config for `get_channels`. Delegates to [`redacted_view`], which
    /// is also reachable WITHOUT a `ChannelsAdmin` (no bridge/gate/pairings
    /// needed) so the GUI's connector list renders even before anything is
    /// configured — see that function's docs for why this matters.
    pub fn redacted(&self) -> serde_json::Value {
        redacted_view(&self.config_path)
    }

    fn mutate_allow(
        &self,
        f: impl FnOnce(&mut Vec<serde_json::Value>),
    ) -> io::Result<()> {
        // Load the existing config as raw JSON so unrelated fields (adapter
        // secrets, inbound config) round-trip untouched. A file that EXISTS but
        // does not parse is a hard error — we must NEVER overwrite it with a stub
        // and silently discard its secrets (SEC: config data-loss).
        let mut v = load_value_checked(&self.config_path)?;
        if !v.is_object() {
            v = serde_json::json!({});
        }
        if !v.get("allow").map(|a| a.is_array()).unwrap_or(false) {
            v["allow"] = serde_json::json!([]);
        }
        if let Some(arr) = v["allow"].as_array_mut() {
            f(arr);
        }
        save_value(&self.config_path, &v)
    }
}

/// Load channels.json as raw JSON. A MISSING file → `{}` (fresh start); a file
/// that exists but does not parse → `Err`, so an allowlist mutation ABORTS rather
/// than clobbering the file and discarding adapter secrets.
fn load_value_checked(path: &Path) -> io::Result<serde_json::Value> {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not valid JSON: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(e) => Err(e),
    }
}

/// Atomically write channels.json owner-only (0600): write a sibling temp file,
/// chmod it 0600, then rename over the target — so a crash or a concurrent reader
/// never sees a truncated/partial config, and the file is never world-readable
/// even momentarily.
fn save_value(path: &Path, v: &serde_json::Value) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body =
        serde_json::to_vec_pretty(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

// ── Config writes for the GUI setup UI (owner-gated IPC) ─────────────────────
//
// These edit ~/.belay/channels.json directly (atomic, 0600, refuse to
// clobber a corrupt file) and do NOT require a running bridge — so the FIRST
// connector can be configured before any bridge exists. Changes take effect on
// the next daemon start (the GUI restarts the daemon after a save).

/// Upsert a platform's adapter block, and (if `allow` is given) REPLACE that
/// platform's allowlist entries with the provided principals. `config` is the
/// adapter's field object, e.g. `{"bot_token":"…","chat_id":"…"}` for telegram.
pub fn config_set_channel(
    path: &Path,
    platform: &str,
    config: &serde_json::Value,
    allow: Option<&[String]>,
) -> io::Result<()> {
    let mut v = load_value_checked(path)?;
    if !v.is_object() {
        v = serde_json::json!({});
    }
    // MERGE the provided fields into the existing block (a new platform starts
    // from `{}`). This preserves a secret the user did NOT re-enter — secrets are
    // never shown back in the redacted view, so an edit that leaves the token
    // field blank must not blank the stored token. Callers omit blank fields.
    if !v[platform].is_object() {
        v[platform] = serde_json::json!({});
    }
    if let (Some(dst), Some(src)) = (v[platform].as_object_mut(), config.as_object()) {
        for (k, val) in src {
            dst.insert(k.clone(), val.clone());
        }
    }
    if let Some(principals) = allow {
        let arr = ensure_allow_array(&mut v);
        arr.retain(|e| e["platform"] != platform);
        for p in principals {
            arr.push(serde_json::json!({"platform": platform, "principal": p}));
        }
    }
    save_value(path, &v)
}

/// Remove a platform's adapter block AND its allowlist entries.
pub fn config_remove_channel(path: &Path, platform: &str) -> io::Result<()> {
    let mut v = load_value_checked(path)?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove(platform);
    }
    if v.get("allow").map(|a| a.is_array()).unwrap_or(false) {
        if let Some(arr) = v["allow"].as_array_mut() {
            arr.retain(|e| e["platform"] != platform);
        }
    }
    save_value(path, &v)
}

/// Set (or clear, with `null`) the `inbound` receiver config block.
pub fn config_set_inbound(path: &Path, inbound: &serde_json::Value) -> io::Result<()> {
    let mut v = load_value_checked(path)?;
    if !v.is_object() {
        v = serde_json::json!({});
    }
    if inbound.is_null() {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("inbound");
        }
    } else {
        // MERGE (like set_channel) so setting one inbound field (e.g. a Slack
        // signing secret) never drops a hand-set line_channel_secret or bind.
        if !v["inbound"].is_object() {
            v["inbound"] = serde_json::json!({});
        }
        if let (Some(dst), Some(src)) = (v["inbound"].as_object_mut(), inbound.as_object()) {
            for (k, val) in src {
                dst.insert(k.clone(), val.clone());
            }
        }
    }
    save_value(path, &v)
}

/// Enroll/unenroll `platform` in the administrative disabled list. Free function
/// (like `config_set_channel`/`config_remove_channel`) so it works with NO bridge
/// running — e.g. disabling a connector right after configuring it, before the
/// first restart ever brings up a bridge.
pub fn config_set_disabled(path: &Path, platform: &str, disabled: bool) -> io::Result<()> {
    let mut v = load_value_checked(path)?;
    if !v.is_object() {
        v = serde_json::json!({});
    }
    if !v.get("disabled").map(|a| a.is_array()).unwrap_or(false) {
        v["disabled"] = serde_json::json!([]);
    }
    if let Some(arr) = v["disabled"].as_array_mut() {
        arr.retain(|x| x.as_str() != Some(platform));
        if disabled {
            arr.push(serde_json::json!(platform));
        }
    }
    save_value(path, &v)
}

/// Borrow (creating if absent) the top-level `allow` array of a raw config Value.
fn ensure_allow_array(v: &mut serde_json::Value) -> &mut Vec<serde_json::Value> {
    if !v.get("allow").map(|a| a.is_array()).unwrap_or(false) {
        v["allow"] = serde_json::json!([]);
    }
    v["allow"].as_array_mut().expect("allow set to an array above")
}

/// The 10 GUI-facing connector ids — the only top-level keys `fields_set`
/// inspects (skips `allow`/`inbound`/`disabled`/timeouts, which aren't adapters).
const PLATFORM_IDS: &[&str] = &[
    "telegram", "discord", "whatsapp", "matrix", "mattermost", "slack", "ntfy", "webhook", "teams",
    "wecom",
];

/// For each configured platform, which of ITS OWN keys currently hold a
/// non-empty string. Booleans only — never the value — so the GUI can render a
/// per-field "Saved" mark without the redacted view ever carrying a secret.
/// Generic over the raw JSON (not the typed config), so it needs no per-struct
/// enumeration and stays correct as connector schemas evolve.
fn fields_set(raw: &serde_json::Value) -> std::collections::HashMap<String, Vec<String>> {
    let mut out = std::collections::HashMap::new();
    for id in PLATFORM_IDS {
        if let Some(obj) = raw.get(id).and_then(|v| v.as_object()) {
            let keys: Vec<String> = obj
                .iter()
                .filter(|(_, v)| v.as_str().map(|s| !s.is_empty()).unwrap_or(false))
                .map(|(k, _)| k.clone())
                .collect();
            if !keys.is_empty() {
                out.insert(id.to_string(), keys);
            }
        }
    }
    out
}

/// Secret-free view of the config for display over IPC (`get_channels`), usable
/// with NO bridge/gate/pairings running. This is deliberately independent of
/// [`admin()`]: that global is only installed once `start()` has actually built a
/// bridge (i.e. at least one adapter/verifier is enabled), so on a fresh install
/// — or once every configured connector has been administratively disabled —
/// there is no bridge and `admin()` is `None`. Gating the READ side on it too
/// would mean the connector list (and therefore the only way to configure or
/// re-enable a connector from the GUI) never renders on a cold start — a
/// chicken-and-egg trap. Read-only and best-effort: a missing OR unparseable
/// config degrades to "nothing configured" rather than erroring the whole view.
pub fn redacted_view(path: &Path) -> serde_json::Value {
    let cfg = load_config(path).unwrap_or_default();
    let mut v = redacted_config(&cfg);
    v["disabled"] = serde_json::json!(cfg.disabled);
    let raw = load_value_checked(path).unwrap_or_else(|_| serde_json::json!({}));
    v["fields_set"] = serde_json::json!(fields_set(&raw));
    v
}

/// Secret-free view of the config for display over IPC.
pub fn redacted_config(cfg: &ChannelsConfig) -> serde_json::Value {
    serde_json::json!({
        "max_replies_per_min": cfg.max_replies_per_min,
        "adapters": {
            "telegram": cfg.telegram.is_some(),
            "discord": cfg.discord.is_some(),
            "whatsapp": cfg.whatsapp.is_some(),
            "matrix": cfg.matrix.is_some(),
            "mattermost": cfg.mattermost.is_some(),
            "slack": cfg.slack.is_some(),
            "ntfy": cfg.ntfy.is_some(),
            "webhook": cfg.webhook.is_some(),
            "teams": cfg.teams.is_some(),
            "wecom": cfg.wecom.is_some(),
        },
        "inbound": cfg.inbound.as_ref().map(|i| serde_json::json!({
            "bind": i.bind,
            "line": i.line_channel_secret.is_some(),
            "slack": i.slack_signing_secret.is_some(),
        })),
        "allow": cfg.allow.iter().map(|e| serde_json::json!({
            "platform": e.platform, "principal": e.principal
        })).collect::<Vec<_>>(),
    })
}

/// Process-wide channels admin, installed once at serve_mode startup.
static CHANNELS_ADMIN: OnceLock<ChannelsAdmin> = OnceLock::new();

/// Install the process channels admin (first writer wins).
pub fn set_admin(admin: ChannelsAdmin) {
    let _ = CHANNELS_ADMIN.set(admin);
}

/// The channels admin, if a channels bridge has started this process.
pub fn admin() -> Option<&'static ChannelsAdmin> {
    CHANNELS_ADMIN.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::{now_ms, ParkOutcome, PendingNotice};
    use serde_json::json;
    use std::sync::mpsc;

    #[test]
    fn friendly_prompt_uses_curated_explain_and_hides_raw_json() {
        let explain = json!({
            "summary": "This runs a command with administrator privileges.",
            "why_risky": "Anything run as root can change or damage the whole system.",
            "suggested_action": "Allow if you expected an admin action and trust the command.",
        });
        let input = json!({"command": "sudo rm -rf /var/log/app", "description": "clear logs"});
        let (summary, detail) = friendly_prompt(
            "high",
            Some(&explain),
            "Bash",
            "privilege escalation",
            "persist.sudo",
            &input,
        );
        // Risk badge + plain-English title lead; why + suggested action present.
        assert_eq!(summary, "🔴 HIGH RISK");
        assert!(detail.starts_with("This runs a command with administrator privileges."));
        assert!(detail.contains("Why it matters: Anything run as root"));
        assert!(detail.contains("👉 Allow if you expected"));
        // Technical line carries the command preview, but NOT a raw JSON blob.
        assert!(detail.contains("▸ Technical: Bash · persist.sudo"));
        assert!(detail.contains("sudo rm -rf /var/log/app"));
        assert!(!detail.contains("\"description\""));
        assert!(!detail.contains("\"command\""));
    }

    #[test]
    fn friendly_prompt_falls_back_without_explain_never_dumps_json() {
        let input = json!({"command": "systemctl restart nginx", "description": "x"});
        let (summary, detail) = friendly_prompt("medium", None, "Bash", "restart service", "svc.restart", &input);
        assert_eq!(summary, "🟠 MEDIUM RISK");
        assert!(detail.contains("Bash: restart service"));
        assert!(detail.contains("systemctl restart nginx"));
        // Fallback must not dump the raw JSON object either.
        assert!(!detail.contains("\"description\""));
    }

    #[test]
    fn command_preview_caps_length_and_is_unicode_safe() {
        let long = "é".repeat(500); // multi-byte chars
        let input = json!({ "command": long });
        let p = command_preview(&input);
        assert!(p.chars().count() <= 141, "should cap ~140 chars + ellipsis");
        assert!(p.ends_with('…'));
    }

    #[test]
    fn slack_feedback_text_matches_outcome() {
        // The approver must be able to tell allow from deny from expiry at a glance.
        assert!(slack_feedback_text(&ReplyOutcome::Resolved(true)).contains("Allow recorded"));
        assert!(slack_feedback_text(&ReplyOutcome::Resolved(false)).contains("Deny recorded"));
        assert!(slack_feedback_text(&ReplyOutcome::Stale).contains("auto-denied"));
        assert!(slack_feedback_text(&ReplyOutcome::Rejected(Rejection::NotDm))
            .contains("Not authorized"));
        assert!(slack_feedback_text(&ReplyOutcome::Paired).contains("Paired"));
        // No em dashes leak into user-facing copy.
        for o in [
            ReplyOutcome::Resolved(true),
            ReplyOutcome::Resolved(false),
            ReplyOutcome::Stale,
            ReplyOutcome::Paired,
            ReplyOutcome::BadCode,
        ] {
            assert!(!slack_feedback_text(&o).contains('—'), "no em dashes in copy");
        }
    }
    use std::sync::Arc;
    use std::thread;

    fn cfg_allowing(pairs: &[(&str, &str)], max: u32) -> ChannelsConfig {
        ChannelsConfig {
            timeout_secs: 1,
            max_replies_per_min: max,
            allow: pairs
                .iter()
                .map(|(p, u)| AllowEntry {
                    platform: p.to_string(),
                    principal: u.to_string(),
                })
                .collect(),
            telegram: None,
            discord: None,
            whatsapp: None,
            matrix: None,
            mattermost: None,
            slack: None,
            ntfy: None,
            webhook: None,
            teams: None,
            wecom: None,
            inbound: None,
            disabled: Vec::new(),
        }
    }

    fn reply(
        platform: &str,
        principal: &str,
        is_dm: bool,
        nonce: &str,
        msg_id: &str,
    ) -> InboundReply {
        InboundReply {
            platform: platform.to_string(),
            principal: principal.to_string(),
            is_dm,
            nonce: nonce.to_string(),
            msg_id: msg_id.to_string(),
            allow: true,
            response_url: None,
        }
    }

    // ── Gate unit checks (the threat-model matrix) ───────────────────────────

    #[test]
    fn group_message_is_rejected() {
        let g = AuthzGate::from_config(&cfg_allowing(&[("telegram", "42")], 10));
        let r = reply("telegram", "42", false, "n", "m1");
        assert_eq!(g.check(&r), Err(Rejection::NotDm));
    }

    #[test]
    fn non_allowlisted_is_rejected() {
        let g = AuthzGate::from_config(&cfg_allowing(&[("telegram", "42")], 10));
        // Right platform, wrong principal.
        assert_eq!(
            g.check(&reply("telegram", "999", true, "n", "m1")),
            Err(Rejection::NotAllowlisted)
        );
        // Right principal, wrong platform.
        assert_eq!(
            g.check(&reply("discord", "42", true, "n", "m2")),
            Err(Rejection::NotAllowlisted)
        );
    }

    #[test]
    fn duplicate_msg_id_is_rejected_second_time() {
        let g = AuthzGate::from_config(&cfg_allowing(&[("telegram", "42")], 10));
        assert_eq!(g.check(&reply("telegram", "42", true, "n", "m1")), Ok(()));
        assert_eq!(
            g.check(&reply("telegram", "42", true, "n", "m1")),
            Err(Rejection::Duplicate)
        );
        // A different msg id from the same principal is still fine.
        assert_eq!(g.check(&reply("telegram", "42", true, "n", "m2")), Ok(()));
    }

    #[test]
    fn rate_limit_locks_out_after_max() {
        let g = AuthzGate::from_config(&cfg_allowing(&[("telegram", "42")], 2));
        assert_eq!(g.check(&reply("telegram", "42", true, "n", "m1")), Ok(()));
        assert_eq!(g.check(&reply("telegram", "42", true, "n", "m2")), Ok(()));
        // Third within the window → locked out (distinct msg id, so not dedup).
        assert_eq!(
            g.check(&reply("telegram", "42", true, "n", "m3")),
            Err(Rejection::RateLimited)
        );
    }

    #[test]
    fn rejected_reply_does_not_consume_rate_budget() {
        // A group (NotDm) message from an allowlisted principal must not count
        // toward the rate budget, and must not poison dedup.
        let g = AuthzGate::from_config(&cfg_allowing(&[("telegram", "42")], 1));
        assert_eq!(
            g.check(&reply("telegram", "42", false, "n", "m1")),
            Err(Rejection::NotDm)
        );
        // The one budgeted slot is still available for a real DM with that msg id.
        assert_eq!(g.check(&reply("telegram", "42", true, "n", "m1")), Ok(()));
    }

    // ── Bridge end-to-end (gate + real park) ─────────────────────────────────

    /// The canonical happy path: a request parks, the notifier hands us the
    /// nonce, an authorized DM reply resolves the park to ALLOW.
    #[test]
    fn authorized_reply_resolves_park() {
        let approvals = Approvals::with_timeout(Duration::from_secs(2));
        // Capture the nonce the moment the request parks.
        let (tx, rx) = mpsc::channel::<PendingNotice>();
        let tx = Arc::new(Mutex::new(tx));
        approvals.set_notifier(Arc::new(move |n: PendingNotice| {
            let _ = tx.lock().unwrap().send(n);
        }));
        let bridge = Arc::new(ChannelBridge::new(
            approvals.clone(),
            &cfg_allowing(&[("telegram", "42")], 10),
        ));

        let b2 = bridge.clone();
        let h = thread::spawn(move || {
            let notice = rx.recv().unwrap();
            let r = InboundReply {
                platform: "telegram".into(),
                principal: "42".into(),
                is_dm: true,
                nonce: notice.nonce,
                msg_id: "m1".into(),
                allow: true,
                response_url: None,
            };
            assert_eq!(b2.process_reply(&r), ReplyOutcome::Resolved(true));
        });
        let out = approvals.park(
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

    /// An UNAUTHORIZED reply carrying the CORRECT nonce must NOT resolve the park:
    /// the gate rejects it before `respond_by_nonce` is ever reached, and the park
    /// fails closed to DENY on timeout. This is the core "no softer road" proof.
    #[test]
    fn unauthorized_reply_cannot_resolve_even_with_right_nonce() {
        let approvals = Approvals::with_timeout(Duration::from_millis(250));
        let (tx, rx) = mpsc::channel::<PendingNotice>();
        let tx = Arc::new(Mutex::new(tx));
        approvals.set_notifier(Arc::new(move |n: PendingNotice| {
            let _ = tx.lock().unwrap().send(n);
        }));
        // Allowlist is empty → nobody is authorized.
        let bridge = Arc::new(ChannelBridge::new(approvals.clone(), &cfg_allowing(&[], 10)));

        let b2 = bridge.clone();
        let h = thread::spawn(move || {
            let notice = rx.recv().unwrap();
            let r = InboundReply {
                platform: "telegram".into(),
                principal: "42".into(),
                is_dm: true,
                nonce: notice.nonce, // correct nonce, but sender not allowlisted
                msg_id: "m1".into(),
                allow: true,
                response_url: None,
            };
            assert_eq!(
                b2.process_reply(&r),
                ReplyOutcome::Rejected(Rejection::NotAllowlisted)
            );
        });
        let out = approvals.park(
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
        assert_eq!(out, ParkOutcome::Deny, "gate-rejected reply must not allow");
    }

    /// An authorized reply with a bogus nonce is consumed as Stale (resolves
    /// nothing); a concurrent park still fails closed to DENY on timeout.
    #[test]
    fn authorized_reply_with_unknown_nonce_is_stale() {
        let approvals = Approvals::with_timeout(Duration::from_millis(150));
        let bridge =
            ChannelBridge::new(approvals.clone(), &cfg_allowing(&[("telegram", "42")], 10));
        let r = reply("telegram", "42", true, "deadbeef", "m1");
        assert_eq!(bridge.process_reply(&r), ReplyOutcome::Stale);
        let out = approvals.park(
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

    // ── Config loader ────────────────────────────────────────────────────────

    #[test]
    fn load_config_parses_owner_only_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("channels.json");
        fs::write(
            &p,
            r#"{"max_replies_per_min":5,"allow":[{"platform":"telegram","principal":"42"}]}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cfg = load_config(&p).unwrap();
        assert_eq!(cfg.max_replies_per_min, 5);
        assert_eq!(cfg.timeout_secs, 60); // defaulted
        assert_eq!(cfg.allow.len(), 1);
        assert_eq!(cfg.allow[0].principal, "42");
    }

    // ── Live wiring smoke test ───────────────────────────────────────────────

    /// `start` builds the dedicated runtime + listener/consumer/notifier when an
    /// adapter is configured, and the handle drops cleanly (shutdown_background)
    /// from a non-runtime thread without panicking. A config with no adapters
    /// yields `None` (channels stay off).
    #[test]
    fn start_builds_and_tears_down_with_telegram_adapter() {
        let approvals = Approvals::with_timeout(Duration::from_millis(50));
        let mut cfg = cfg_allowing(&[("telegram", "42")], 10);
        cfg.telegram = Some(TelegramCfg {
            bot_token: "tok".into(),
            chat_id: "42".into(),
            // Loopback (is_safe_base ok) + unreachable: the listener just backs
            // off harmlessly until we drop the handle.
            base: Some("http://127.0.0.1:1".into()),
        });
        let handle = start(&approvals, cfg);
        assert!(handle.is_some(), "telegram config → bridge starts");
        drop(handle); // must not panic off-runtime

        // No adapters configured → no bridge.
        assert!(
            start(&approvals, cfg_allowing(&[("telegram", "42")], 10)).is_none(),
            "empty adapter set → None"
        );
    }

    // ── Runtime admin (enroll/unenroll + redaction) ──────────────────────────

    fn reply_from(platform: &str, principal: &str, msg_id: &str) -> InboundReply {
        InboundReply {
            platform: platform.into(),
            principal: principal.into(),
            is_dm: true,
            nonce: "no-such-nonce".into(),
            msg_id: msg_id.into(),
            allow: true,
            response_url: None,
        }
    }

    /// `allow_add`/`allow_remove` update the LIVE gate the bridge uses AND persist
    /// to channels.json — enrollment takes effect without rebuilding the bridge.
    #[test]
    fn admin_allow_add_takes_live_effect_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.json");
        fs::write(&path, r#"{"allow":[]}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let approvals = Approvals::with_timeout(Duration::from_millis(100));
        let bridge = ChannelBridge::new(approvals, &cfg_allowing(&[], 10));
        let admin = ChannelsAdmin::new(bridge.gate(), bridge.pairings(), path.clone());

        // Not enrolled → rejected by the gate.
        assert_eq!(
            bridge.process_reply(&reply_from("line", "U1", "m1")),
            ReplyOutcome::Rejected(Rejection::NotAllowlisted)
        );

        // Enroll live → the gate now authorizes (nonce is unknown, so Stale — but
        // crucially NOT NotAllowlisted), and the change is on disk.
        assert!(admin.allow_add("line", "U1").unwrap());
        assert_eq!(
            bridge.process_reply(&reply_from("line", "U1", "m2")),
            ReplyOutcome::Stale
        );
        assert!(load_config(&path)
            .unwrap()
            .allow
            .iter()
            .any(|e| e.platform == "line" && e.principal == "U1"));

        // Unenroll live → rejected again, and removed from disk.
        assert!(admin.allow_remove("line", "U1").unwrap());
        assert_eq!(
            bridge.process_reply(&reply_from("line", "U1", "m3")),
            ReplyOutcome::Rejected(Rejection::NotAllowlisted)
        );
        assert!(!load_config(&path)
            .unwrap()
            .allow
            .iter()
            .any(|e| e.platform == "line" && e.principal == "U1"));
    }

    /// A config mutation preserves unrelated adapter secrets, and REFUSES to
    /// persist over an existing-but-unparseable file (which would silently wipe
    /// every secret). Regression for the config data-loss finding.
    #[test]
    fn config_persist_preserves_secrets_and_refuses_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.json");
        fs::write(
            &path,
            r#"{"telegram":{"bot_token":"SECRET-TOKEN","chat_id":"1"},"allow":[]}"#,
        )
        .unwrap();

        let approvals = Approvals::with_timeout(Duration::from_millis(50));
        let bridge = ChannelBridge::new(approvals, &cfg_allowing(&[], 10));
        let admin = ChannelsAdmin::new(bridge.gate(), bridge.pairings(), path.clone());

        // Enrolling an approver keeps the adapter secret and writes 0600.
        admin.allow_add("telegram", "99").unwrap();
        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("SECRET-TOKEN"), "adapter secret survives an allowlist edit");
        assert!(after.contains("\"99\""), "new principal persisted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config rewritten owner-only");
        }

        // A corrupt existing file → the mutation ERRORS and leaves the file intact
        // (never clobbers it with a stub that drops the secrets).
        fs::write(&path, "{ not valid json").unwrap();
        assert!(
            admin.allow_add("telegram", "100").is_err(),
            "must refuse to persist over an unparseable config"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{ not valid json",
            "corrupt config left untouched"
        );
    }

    /// `config_set_channel` upserts a platform block, replaces only THAT
    /// platform's allow entries, and preserves unrelated blocks; remove drops both.
    #[test]
    fn config_set_channel_upserts_and_scopes_allow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.json");
        fs::write(
            &path,
            r#"{"webhook":{"url":"https://x/h"},"allow":[{"platform":"telegram","principal":"old"},{"platform":"webhook","principal":"w"}]}"#,
        )
        .unwrap();

        config_set_channel(
            &path,
            "telegram",
            &serde_json::json!({"bot_token": "T", "chat_id": "1"}),
            Some(&["a".to_string(), "b".to_string()]),
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["telegram"]["bot_token"], "T");
        assert_eq!(v["webhook"]["url"], "https://x/h", "unrelated block preserved");
        let tg: Vec<String> = v["allow"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["platform"] == "telegram")
            .map(|e| e["principal"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(tg, vec!["a", "b"], "telegram allow replaced");
        assert!(
            v["allow"].as_array().unwrap().iter().any(|e| e["platform"] == "webhook"),
            "other platforms' allow untouched"
        );

        // Editing WITHOUT re-entering the token (blank field omitted) preserves it.
        config_set_channel(
            &path,
            "telegram",
            &serde_json::json!({"chat_id": "2"}),
            None,
        )
        .unwrap();
        let v1: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v1["telegram"]["bot_token"], "T", "un-provided secret preserved");
        assert_eq!(v1["telegram"]["chat_id"], "2", "provided field updated");

        config_remove_channel(&path, "telegram").unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v2.get("telegram").is_none(), "block removed");
        assert!(v2["allow"].as_array().unwrap().iter().all(|e| e["platform"] != "telegram"));
        assert_eq!(v2["webhook"]["url"], "https://x/h", "webhook preserved");
    }

    /// `redacted_view` on a channels.json that DOES NOT EXIST still succeeds with
    /// an all-empty shape (rather than needing an admin()/bridge to exist first).
    /// This is the fix for the cold-start trap: without it, get_channels would
    /// report "not enabled" on a fresh install and the GUI could never render
    /// the connector list to configure the very first connector.
    #[test]
    fn redacted_view_succeeds_with_no_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let v = redacted_view(&path);
        assert_eq!(v["adapters"]["telegram"], serde_json::json!(false));
        assert!(v["allow"].as_array().unwrap().is_empty());
        assert!(v["disabled"].as_array().unwrap().is_empty());
        assert!(v["fields_set"].as_object().unwrap().is_empty());
    }

    /// A platform that is configured but administratively disabled is NOT built
    /// into the adapter list, even though `adapters[id]` still reports true
    /// (configured != enabled — matches the "keep credentials, pause the
    /// connector" semantics).
    #[test]
    fn disabled_platform_is_excluded_from_build_adapters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.json");
        fs::write(
            &path,
            r#"{"webhook":{"url":"https://x/h"},"allow":[]}"#,
        )
        .unwrap();
        config_set_disabled(&path, "webhook", true).unwrap();

        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.disabled, vec!["webhook".to_string()]);
        assert!(build_adapters(&cfg).is_empty(), "disabled platform must not be built");

        // The redacted view still reports it as configured (secrets kept) but disabled.
        let v = redacted_view(&path);
        assert_eq!(v["adapters"]["webhook"], serde_json::json!(true));
        assert_eq!(v["disabled"], serde_json::json!(["webhook"]));

        // Re-enabling removes it from the disabled list and it builds again.
        config_set_disabled(&path, "webhook", false).unwrap();
        let cfg2 = load_config(&path).unwrap();
        assert!(cfg2.disabled.is_empty());
        assert_eq!(build_adapters(&cfg2).len(), 1);
    }

    /// `fields_set` reports which keys are present per platform (booleans only —
    /// never the value), so the GUI can show a per-field "Saved" mark.
    #[test]
    fn fields_set_reports_present_keys_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.json");
        fs::write(
            &path,
            r#"{"telegram":{"bot_token":"T","chat_id":""},"webhook":{"url":"https://x"}}"#,
        )
        .unwrap();
        let v = redacted_view(&path);
        let tg: Vec<String> = v["fields_set"]["telegram"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(tg, vec!["bot_token"], "empty chat_id is NOT reported set");
        assert_eq!(v["fields_set"]["webhook"], serde_json::json!(["url"]));
        assert!(v["fields_set"].get("discord").is_none(), "unconfigured platform absent");
    }

    /// The redacted view exposes platform/allowlist shape but NEVER a secret.
    #[test]
    fn redacted_config_hides_secrets() {
        let mut cfg = cfg_allowing(&[("telegram", "42")], 10);
        cfg.telegram = Some(TelegramCfg {
            bot_token: "SECRET-BOT-TOKEN".into(),
            chat_id: "42".into(),
            base: None,
        });
        cfg.inbound = Some(InboundCfg {
            bind: "127.0.0.1:8787".into(),
            line_channel_secret: Some("LINE-SEKRET".into()),
            slack_signing_secret: None,
        });
        let v = redacted_config(&cfg);
        let s = v.to_string();
        assert!(!s.contains("SECRET-BOT-TOKEN"), "bot token must not leak");
        assert!(!s.contains("LINE-SEKRET"), "inbound secret must not leak");
        assert_eq!(v["adapters"]["telegram"], serde_json::json!(true));
        assert_eq!(v["adapters"]["discord"], serde_json::json!(false));
        assert_eq!(v["inbound"]["line"], serde_json::json!(true));
        assert_eq!(v["inbound"]["slack"], serde_json::json!(false));
        assert_eq!(v["allow"][0]["principal"], serde_json::json!("42"));
    }

    // ── Interactive pairing ──────────────────────────────────────────────────

    fn pair_reply(platform: &str, principal: &str, code: &str, msg_id: &str) -> InboundReply {
        InboundReply {
            platform: platform.into(),
            principal: principal.into(),
            is_dm: true,
            nonce: format!("PAIR:{code}"),
            msg_id: msg_id.into(),
            allow: false,
            response_url: None,
        }
    }

    /// A valid single-use code enrolls the sender (live), NOT gated by allowlist;
    /// a wrong/replayed code is BadCode and enrolls nobody. (No global admin in
    /// tests → the bridge enrolls its live gate directly, which the assert reads.)
    #[test]
    fn pairing_enrolls_on_valid_code_only() {
        let approvals = Approvals::with_timeout(Duration::from_millis(100));
        let bridge = ChannelBridge::new(approvals, &cfg_allowing(&[], 10));

        // Unknown code → BadCode; the principal stays unenrolled.
        assert_eq!(
            bridge.process_reply(&pair_reply("line", "Uapp", "WRONGCOD", "mb")),
            ReplyOutcome::BadCode
        );
        assert_eq!(
            bridge.process_reply(&reply_from("line", "Uapp", "mx")),
            ReplyOutcome::Rejected(Rejection::NotAllowlisted)
        );

        // Real code → Paired, and the gate now authorizes that principal.
        let code = bridge.pairings().start("line");
        assert_eq!(
            bridge.process_reply(&pair_reply("line", "Uapp", &code, "mg")),
            ReplyOutcome::Paired
        );
        assert_eq!(
            bridge.process_reply(&reply_from("line", "Uapp", "mz")),
            ReplyOutcome::Stale, // authorized now → unknown nonce is Stale, not NotAllowlisted
        );

        // Single-use: replaying the same code fails.
        assert_eq!(
            bridge.process_reply(&pair_reply("line", "Uapp", &code, "mr")),
            ReplyOutcome::BadCode
        );
    }

    /// Pairing requires a DM — a group `pair <code>` is refused even with a valid
    /// code (an attacker in a shared channel must never enroll).
    #[test]
    fn pairing_requires_dm() {
        let approvals = Approvals::with_timeout(Duration::from_millis(100));
        let bridge = ChannelBridge::new(approvals, &cfg_allowing(&[], 10));
        let code = bridge.pairings().start("line");
        let mut r = pair_reply("line", "Uapp", &code, "m1");
        r.is_dm = false;
        assert_eq!(
            bridge.process_reply(&r),
            ReplyOutcome::Rejected(Rejection::NotDm)
        );
        // And the (unused) code is still valid for a real DM afterwards.
        let mut ok = pair_reply("line", "Uapp", &code, "m2");
        ok.is_dm = true;
        assert_eq!(bridge.process_reply(&ok), ReplyOutcome::Paired);
    }

    /// Wrong-platform code is refused (a code minted for `line` can't pair `slack`).
    #[test]
    fn pairing_code_is_platform_scoped() {
        let approvals = Approvals::with_timeout(Duration::from_millis(100));
        let bridge = ChannelBridge::new(approvals, &cfg_allowing(&[], 10));
        let code = bridge.pairings().start("line");
        assert_eq!(
            bridge.process_reply(&pair_reply("slack", "Uapp", &code, "m1")),
            ReplyOutcome::BadCode
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_config_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("channels.json");
        fs::write(&p, "{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        let err = load_config(&p).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
