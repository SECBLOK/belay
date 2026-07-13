//! Mattermost push-model approval adapter (two-way).
//!
//! Mattermost has no inline-button primitive for bot posts, so approval rides on
//! a TEXT reply: [`notify`] posts the prompt (embedding the correlation nonce)
//! into the approver's 1:1 DM channel, and [`listen`] polls that channel for a
//! reply that reads exactly `allow <nonce>` / `deny <nonce>` (case-insensitive, a
//! leading `/` is tolerated for slash-command muscle memory). Each matching reply
//! is normalized into an [`InboundReply`] and handed to the daemon's authorization
//! gate — the adapter itself makes NO trust decision; it only REPORTS the
//! platform's facts (sender, msg id, echoed nonce, allow/deny).
//!
//! The configured `channel_id` is a direct-message channel (Mattermost channel
//! type `D`), so the prompt (and its unguessable nonce) is delivered only to the
//! approver; that is why `is_dm` is reported `true`. The gate still enforces the
//! DM-only + default-deny allowlist checks downstream.
//!
//! [`notify`]: ChannelAdapter::notify
//! [`listen`]: ChannelAdapter::listen

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long to wait between channel polls. Mattermost's posts endpoint is a plain
/// GET (no long-poll), so a fixed interval keeps the listener from busy-spinning.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A sent approval prompt we may need to "expire": its post id (to edit it),
/// when it was sent, and the short summary line (kept so the expired message
/// still shows which request died).
struct SentPrompt {
    post_id: String,
    at: Instant,
    summary: String,
}

pub struct MattermostChannel {
    token: String,
    channel_id: String,
    api_base: String,
    http: reqwest::Client,
    /// nonce -> the prompt we sent for it, so the listener can rewrite prompts
    /// that timed out (the daemon already auto-denied them) instead of leaving
    /// stale-looking instructions the user can still reply to after the fact.
    sent: Arc<Mutex<HashMap<String, SentPrompt>>>,
}

impl MattermostChannel {
    pub fn new(token: String, channel_id: String) -> Self {
        Self {
            token,
            channel_id,
            // Mattermost is self-hosted; the real server URL is supplied via
            // `with_base()`. This placeholder is a safe (HTTPS) default so an
            // un-overridden instance never sends anywhere useful.
            api_base: "https://mattermost.example.com".into(),
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// True ONLY if the configured channel is a Mattermost direct message channel
    /// (`type == "D"`). Probed once at listen start; any error / other type ⇒
    /// false, so the daemon gate's DM-only check fails closed for a mis-configured
    /// group/open channel.
    async fn channel_is_dm(&self) -> bool {
        let url = format!("{}/api/v4/channels/{}", self.api_base, self.channel_id);
        match self
            .http
            .get(&url)
            .header("Authorization", self.auth())
            .send()
            .await
        {
            Ok(r) => r
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v["type"].as_str().map(|t| t == "D"))
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

/// Parse a chat message into an approval intent + echoed nonce, or `None` if it is
/// not an approval reply. Anchored at the start of the trimmed message (optionally
/// after a single leading `/`) so the adapter's OWN multi-line prompt — which
/// quotes `allow <nonce>` / `deny <nonce>` as instructions — is never mistaken for
/// a reply when it is polled back.
fn parse_reply(message: &str) -> Option<(bool, String)> {
    let trimmed = message.trim();
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let mut parts = trimmed.split_whitespace();
    let verb = parts.next()?;
    let nonce = parts.next()?;
    if nonce.is_empty() {
        return None;
    }
    let allow = if verb.eq_ignore_ascii_case("allow") {
        true
    } else if verb.eq_ignore_ascii_case("deny") {
        false
    } else {
        return None;
    };
    Some((allow, nonce.to_string()))
}

/// Current wall-clock time in epoch milliseconds (Mattermost's `create_at` unit),
/// used to seed the poll cursor so only replies posted after startup are read.
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl ChannelAdapter for MattermostChannel {
    fn platform(&self) -> &'static str {
        "mattermost"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the access token in the header)
        // to a non-HTTPS remote base — a misconfigured `with_base()` must not SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Mattermost api_base: {}",
                self.api_base
            );
            return;
        }
        let text = format!(
            "Belay approval\n{}\n\n{}\nsession={}\n\nReply exactly `allow {nonce}` to approve or `deny {nonce}` to refuse.",
            req.summary, req.detail, req.session_id
        );
        if let Ok(resp) = self
            .http
            .post(format!("{}/api/v4/posts", self.api_base))
            .header("Authorization", self.auth())
            .json(&json!({"channel_id": self.channel_id, "message": text}))
            .send()
            .await
        {
            // Record the created post so the listener can expire it if it is
            // never answered before the daemon's park timeout elapses. The POST
            // response is the created post object, carrying its `id`.
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(pid) = v["id"].as_str() {
                    if let Ok(mut m) = self.sent.lock() {
                        m.insert(
                            nonce.to_string(),
                            SentPrompt {
                                post_id: pid.to_string(),
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
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing to poll unsafe Mattermost api_base: {}",
                self.api_base
            );
            return;
        }
        // Verify ONCE the configured channel is a genuine 1:1 DM (type "D"); a
        // posts response carries no channel type, so this cannot be inferred
        // per-message. Fail closed (not-DM) on any uncertainty.
        let channel_is_dm = self.channel_is_dm().await;
        // Only read replies posted after we start; advance past every post seen.
        let mut since = now_ms();
        // A prompt is "expired" once the daemon's park timeout has elapsed (it
        // has already auto-denied it). Mirror that timeout (same env var) plus a
        // small buffer so we only expire AFTER the daemon has given up.
        let expire_after = Duration::from_millis(
            std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60_000),
        ) + Duration::from_secs(5);
        while !tx.is_closed() {
            // Sweep: rewrite any prompt that timed out with no answer so a late
            // reply can't look like it might still work. Collect under the lock,
            // then edit outside it (never hold the lock across an await).
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
                let _ = self
                    .http
                    .put(format!("{}/api/v4/posts/{}", self.api_base, p.post_id))
                    .header("Authorization", self.auth())
                    .json(&json!({"id": p.post_id, "message": text}))
                    .send()
                    .await;
            }
            let url = format!(
                "{}/api/v4/channels/{}/posts?since={}",
                self.api_base, self.channel_id, since
            );
            let resp = self
                .http
                .get(&url)
                .header("Authorization", self.auth())
                .send()
                .await;
            let v = match resp {
                Ok(r) => match r.json::<serde_json::Value>().await {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                },
                Err(_) => {
                    // Network blip — back off briefly, keep the listener alive.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            // `order` lists post ids oldest→newest; `posts` maps id → post object.
            let posts = &v["posts"];
            let mut newest = since - 1;
            for id in v["order"].as_array().cloned().unwrap_or_default() {
                let Some(id) = id.as_str() else { continue };
                let post = &posts[id];
                let created = post["create_at"].as_i64().unwrap_or(0);
                if created > newest {
                    newest = created;
                }
                let text = post["message"].as_str().unwrap_or("");
                // A `pair <code>` request rides the pipe as a PAIR:<code> nonce.
                let (nonce, allow) = if let Some(code) = crate::inbound::parse_pair(text) {
                    (format!("{}{code}", crate::inbound::PAIR_NONCE_PREFIX), false)
                } else if let Some((allow, nonce)) = parse_reply(text) {
                    (nonce, allow)
                } else {
                    continue;
                };
                // Report the platform's facts; the daemon gate enforces them.
                // is_dm is the channel-type probe result (type "D"), not an
                // assumption — a mis-configured group channel is reported not-DM.
                let principal = post["user_id"].as_str().unwrap_or_default().to_string();
                let msg_id = post["id"].as_str().unwrap_or(id).to_string();
                // Feedback + de-dup: if this reply answers a prompt we sent, drop
                // it from the expiry map (so the sweep never rewrites a prompt the
                // user already acted on) and edit that prompt in place to show the
                // recorded choice. A `pair` reply carries a PAIR:<code> nonce that
                // is never in the map, so it is left untouched. This confirms
                // RECEIPT of the reply, independent of the gate's authz outcome
                // (which the daemon still enforces).
                let answered = self.sent.lock().ok().and_then(|mut m| m.remove(&nonce));
                if let Some(prompt) = answered {
                    let mark = if allow {
                        "✅ You pressed Allow."
                    } else {
                        "⛔ You pressed Deny."
                    };
                    let text = format!("🛡️ Belay approval\n{}\n\n{mark}", prompt.summary);
                    let _ = self
                        .http
                        .put(format!("{}/api/v4/posts/{}", self.api_base, prompt.post_id))
                        .header("Authorization", self.auth())
                        .json(&json!({"id": prompt.post_id, "message": text}))
                        .send()
                        .await;
                }
                let reply = InboundReply {
                    platform: "mattermost".into(),
                    principal,
                    is_dm: channel_is_dm,
                    nonce,
                    msg_id,
                    allow,
                    response_url: None,
                };
                if tx.send(reply).await.is_err() {
                    return; // daemon gone
                }
            }
            if newest >= since {
                since = newest + 1;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}
