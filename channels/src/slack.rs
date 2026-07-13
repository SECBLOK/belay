//! Slack Web API adapter — **two-way** (outbound here, inbound via the Phase B
//! receiver).
//!
//! [`notify`] posts an interactive Block Kit prompt (Allow / Deny buttons whose
//! `value` carries `a:<nonce>` / `d:<nonce>`) to a Slack conversation — use a
//! user/DM id so only the approver sees it. When the approver clicks a button,
//! Slack POSTs a signed interactivity callback to the daemon's inbound receiver
//! (`/hook/slack`, verified by `inbound::SlackVerifier`), which resolves the
//! parked ASK. That callback carries a one-shot `response_url`; the daemon POSTs
//! the outcome there so the approver sees their click land and the buttons are
//! replaced.
//!
//! Slack has no client-side poll, so [`listen`] never yields an [`InboundReply`]
//! (inbound arrives over the receiver). It instead runs an expiry sweeper: a
//! prompt left un-clicked past the daemon's park timeout has already been
//! auto-denied, so the sweeper edits it (via `chat.update` on the captured
//! message `ts`) to "Expired" and drops the buttons — matching what the
//! poll-based adapters do in their own loops. The daemon calls [`on_resolved`]
//! when a click is accepted so an answered prompt is never relabeled expired.
//!
//! [`notify`]: ChannelAdapter::notify
//! [`listen`]: ChannelAdapter::listen
//! [`on_resolved`]: ChannelAdapter::on_resolved

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A sent approval prompt we may need to "expire": the resolved conversation id
/// and message `ts` (needed to `chat.update` it), when it was sent, and the
/// short summary line (kept so the expired message still shows which request
/// died).
struct SentPrompt {
    channel: String,
    ts: String,
    at: Instant,
    summary: String,
}

pub struct SlackChannel {
    token: String,
    channel: String,
    api_base: String,
    http: reqwest::Client,
    /// nonce -> the prompt we sent for it, so the sweeper can rewrite prompts
    /// that timed out (the daemon already auto-denied them) instead of leaving
    /// live-looking buttons that silently do nothing when clicked late.
    sent: Arc<Mutex<HashMap<String, SentPrompt>>>,
    /// Override the expire threshold (tests only); production derives it from
    /// `BELAY_APPROVAL_TIMEOUT_MS` + a grace buffer.
    expire_after: Option<Duration>,
}

impl SlackChannel {
    /// `token` is a Slack bot token (`xoxb-…`); `channel` is the destination
    /// conversation id — use a user/DM id so only the approver sees the prompt.
    pub fn new(token: String, channel: String) -> Self {
        Self {
            token,
            channel,
            api_base: "https://slack.com/api".into(),
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
            expire_after: None,
        }
    }

    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }

    /// Override how long an un-answered prompt lingers before the sweeper marks
    /// it expired. Intended for tests; production uses the park-timeout + grace.
    pub fn with_expire_after(mut self, after: Duration) -> Self {
        self.expire_after = Some(after);
        self
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// A prompt is "expired" once the daemon's park timeout has elapsed (it has
    /// already auto-denied it). Mirror that timeout (same env var) plus a small
    /// buffer so we only expire AFTER the daemon has given up.
    fn expire_threshold(&self) -> Duration {
        self.expire_after.unwrap_or_else(|| {
            Duration::from_millis(
                std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60_000),
            ) + Duration::from_secs(5)
        })
    }
}

#[async_trait]
impl ChannelAdapter for SlackChannel {
    fn platform(&self) -> &'static str {
        "slack"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the bot token) to a non-HTTPS
        // remote base — a misconfigured `with_base()` must not become an SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Slack api_base: {}",
                self.api_base
            );
            return;
        }
        // Interactive prompt: the buttons carry the nonce in their `value`, so a
        // click delivers an unforgeable correlation back through the receiver.
        let heading = format!(
            "🛡️ *Belay approval*\n{}\n\n{}\nsession={}",
            req.summary, req.detail, req.session_id
        );
        let body = json!({
            "channel": self.channel,
            // Fallback text for notifications / no-Block-Kit clients.
            "text": format!("Belay approval: {}", req.summary),
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": heading}},
                {"type": "actions", "block_id": "belay_approve", "elements": [
                    {"type": "button", "action_id": "belay_allow",
                     "text": {"type": "plain_text", "text": "✅ Allow"},
                     "style": "primary", "value": format!("a:{nonce}")},
                    {"type": "button", "action_id": "belay_deny",
                     "text": {"type": "plain_text", "text": "⛔ Deny"},
                     "style": "danger", "value": format!("d:{nonce}")}
                ]}
            ]
        });
        let resp = self
            .http
            .post(format!("{}/chat.postMessage", self.api_base))
            .header("Authorization", self.auth())
            .json(&body)
            .send()
            .await;
        // Record the sent message (its resolved channel + ts) so the sweeper can
        // expire it later. Prefer the channel Slack echoes back (a user id posts
        // into a freshly-opened DM whose id differs from the configured one).
        if let Ok(r) = resp {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Some(ts) = v["ts"].as_str() {
                    let channel = v["channel"].as_str().unwrap_or(&self.channel).to_string();
                    if let Ok(mut m) = self.sent.lock() {
                        m.insert(
                            nonce.to_string(),
                            SentPrompt {
                                channel,
                                ts: ts.to_string(),
                                at: Instant::now(),
                                summary: req.summary.clone(),
                            },
                        );
                    }
                }
            }
        }
    }

    async fn listen(&self, tx: mpsc::Sender<InboundReply>) {
        // Slack inbound arrives over the Phase B receiver (`/hook/slack`), not a
        // client-side poll, so this never sends on `tx`. It runs only to expire
        // prompts the approver never answered.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing to sweep unsafe Slack api_base: {}",
                self.api_base
            );
            return;
        }
        let expire_after = self.expire_threshold();
        // Wake often enough to expire promptly, but never busier than needed.
        let tick = expire_after
            .min(Duration::from_secs(2))
            .max(Duration::from_millis(100));
        while !tx.is_closed() {
            // Collect stale prompts under the lock, then edit outside it (never
            // hold the Mutex across an await).
            let stale: Vec<SentPrompt> = match self.sent.lock() {
                Ok(mut m) => {
                    let keys: Vec<String> = m
                        .iter()
                        .filter(|(_, p)| p.at.elapsed() > expire_after)
                        .map(|(k, _)| k.clone())
                        .collect();
                    keys.into_iter().filter_map(|k| m.remove(&k)).collect()
                }
                Err(_) => Vec::new(),
            };
            for p in stale {
                let text = format!(
                    "🛡️ Belay approval\n{}\n\n⏱️ Expired (auto-denied). Re-run the action to get a fresh prompt.",
                    p.summary
                );
                // chat.update with a plain section (no actions block) drops the
                // buttons so a late click can't look like it might still work.
                let _ = self
                    .http
                    .post(format!("{}/chat.update", self.api_base))
                    .header("Authorization", self.auth())
                    .json(&json!({
                        "channel": p.channel,
                        "ts": p.ts,
                        "text": text,
                        "blocks": [
                            {"type": "section", "text": {"type": "mrkdwn", "text": text}}
                        ]
                    }))
                    .send()
                    .await;
            }
            tokio::time::sleep(tick).await;
        }
    }

    async fn on_resolved(&self, nonce: &str) {
        // The click was accepted (feedback goes out over its response_url); drop
        // the prompt so the sweeper won't later relabel an answered request.
        if let Ok(mut m) = self.sent.lock() {
            m.remove(nonce);
        }
    }
}
