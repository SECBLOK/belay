//! Discord bot REST adapter.
//!
//! Two-way: prompts are POSTed to a **DM channel** (`channel_id` must be a 1:1
//! DM so only the approver sees the correlation nonce), and replies are polled
//! back from that same channel. Discord bots cannot attach interactive buttons
//! to a plain REST message here, so approval is by **text reply**: the approver
//! answers exactly `allow <nonce>` or `deny <nonce>` (a leading `/` is accepted
//! and matching is case-insensitive). The adapter makes NO trust decision — it
//! only REPORTS `is_dm` (from the absence of `guild_id`), `principal` (the reply
//! author's id) and `msg_id` (dedup key) for the daemon's authorization gate.
use crate::{ChannelAdapter, Decision, DecisionRequest, InboundReply, NotificationChannel};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A sent approval prompt we may need to "expire": its message id (a Discord
/// snowflake, so a string), when it was sent, and the short summary line (kept
/// so the expired message still shows which request died).
struct SentPrompt {
    message_id: String,
    at: Instant,
    summary: String,
}

pub struct DiscordChannel {
    token: String,
    channel_id: String,
    api_base: String,
    http: reqwest::Client,
    /// nonce -> the prompt we sent for it, so the listener can rewrite prompts
    /// that timed out (the daemon already auto-denied them) instead of leaving
    /// a live-looking prompt that silently does nothing when replied to late.
    sent: Arc<Mutex<HashMap<String, SentPrompt>>>,
}

impl DiscordChannel {
    pub fn new(bot_token: String, channel_id: String) -> Self {
        Self {
            token: bot_token,
            channel_id,
            api_base: "https://discord.com/api/v10".into(),
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }

    fn auth(&self) -> String {
        format!("Bot {}", self.token)
    }

    /// True ONLY if the configured channel is a real 1:1 DM (Discord channel
    /// `type == 1`). REST message objects omit `guild_id`, so per-message
    /// inference is unreliable — we probe the channel once. Any error / unexpected
    /// type ⇒ false, so the daemon gate's DM-only check fails closed for a
    /// mis-configured guild channel.
    async fn channel_is_dm(&self) -> bool {
        let url = format!("{}/channels/{}", self.api_base, self.channel_id);
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
                .and_then(|v| v["type"].as_i64())
                .map(|t| t == 1)
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

#[async_trait]
impl NotificationChannel for DiscordChannel {
    async fn ask(&self, req: &DecisionRequest, timeout: Duration) -> Decision {
        // Fail closed: never send the prompt (or the bot token) to a non-HTTPS
        // remote base — a misconfigured `with_base()` must not become an SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Discord api_base: {}",
                self.api_base
            );
            return Decision::Deny;
        }
        let text = format!(
            "🛡️ **Belay** — {}\n```\n{}\n```\nReply `allow` or `deny` (session {})",
            req.summary, req.detail, req.session_id
        );
        let post = format!("{}/channels/{}/messages", self.api_base, self.channel_id);
        let msg_id = match self
            .http
            .post(&post)
            .header("Authorization", self.auth())
            .json(&json!({"content": text}))
            .send()
            .await
        {
            Ok(r) => r
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v["id"].as_str().map(str::to_string))
                .unwrap_or_default(),
            Err(_) => String::new(),
        };

        let deadline = Instant::now() + timeout;
        let list = format!("{}/channels/{}/messages", self.api_base, self.channel_id);
        while Instant::now() < deadline {
            if let Ok(r) = self
                .http
                .get(&list)
                .header("Authorization", self.auth())
                .query(&[("after", msg_id.as_str()), ("limit", "10")])
                .send()
                .await
            {
                if let Ok(arr) = r.json::<serde_json::Value>().await {
                    for m in arr.as_array().cloned().unwrap_or_default() {
                        match m["content"]
                            .as_str()
                            .unwrap_or("")
                            .trim()
                            .to_lowercase()
                            .as_str()
                        {
                            "allow" => return Decision::Allow,
                            "deny" => return Decision::Deny,
                            _ => {}
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Decision::Deny
    }
}

/// Parse a free-text approval reply. Accepts (case-insensitively, with an
/// optional leading `/`) `allow <nonce>` or `deny <nonce>`; the nonce is the
/// first whitespace-delimited token after the verb. Returns `(allow, nonce)`.
fn parse_decision(content: &str) -> Option<(bool, String)> {
    let t = content.trim();
    let t = t.strip_prefix('/').unwrap_or(t);
    let mut parts = t.splitn(2, char::is_whitespace);
    let verb = parts.next()?.to_lowercase();
    let nonce = parts.next()?.split_whitespace().next()?;
    match verb.as_str() {
        "allow" => Some((true, nonce.to_string())),
        "deny" => Some((false, nonce.to_string())),
        _ => None,
    }
}

/// Push-model adapter: the daemon fans a parked ASK out via [`notify`] to the
/// approver's DM channel, and a single shared [`listen`] task polls that channel
/// for the approver's text reply and streams normalized [`InboundReply`]s back to
/// the daemon's authorization gate. Correlation is by the request's CSPRNG
/// `nonce`, echoed back in `allow <nonce>` / `deny <nonce>`.
///
/// [`notify`]: ChannelAdapter::notify
/// [`listen`]: ChannelAdapter::listen
#[async_trait]
impl ChannelAdapter for DiscordChannel {
    fn platform(&self) -> &'static str {
        "discord"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the bot token) to a non-HTTPS
        // remote base — a misconfigured `with_base()` must not become an SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Discord api_base: {}",
                self.api_base
            );
            return;
        }
        let text = format!(
            "🛡️ **Belay** approval — {}\n```\n{}\n```\nsession {}\nReply `allow {n}` to approve or `deny {n}` to reject.",
            req.summary,
            req.detail,
            req.session_id,
            n = nonce
        );
        let post = format!("{}/channels/{}/messages", self.api_base, self.channel_id);
        if let Ok(resp) = self
            .http
            .post(&post)
            .header("Authorization", self.auth())
            .json(&json!({ "content": text }))
            .send()
            .await
        {
            // Record the sent message so the listener can expire it if it is
            // never answered before the daemon's park timeout elapses.
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(mid) = v["id"].as_str() {
                    if let Ok(mut m) = self.sent.lock() {
                        m.insert(
                            nonce.to_string(),
                            SentPrompt {
                                message_id: mid.to_string(),
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
                "belay channels: refusing to poll unsafe Discord api_base: {}",
                self.api_base
            );
            return;
        }
        // Verify ONCE that the configured channel is a genuine 1:1 DM; a REST
        // message object omits guild_id, so a per-message `guild_id.is_null()`
        // check is always-true and would report every reply as a DM. Fail closed.
        let channel_is_dm = self.channel_is_dm().await;
        let list = format!("{}/channels/{}/messages", self.api_base, self.channel_id);
        // Discord snowflake high-water mark; only fetch messages newer than this.
        let mut after: u64 = 0;
        // A prompt is "expired" once the daemon's park timeout has elapsed (it
        // has already auto-denied it). Mirror that timeout (same env var) plus a
        // small buffer so we only expire AFTER the daemon has given up.
        let expire_after = Duration::from_millis(
            std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60_000),
        ) + Duration::from_secs(5);
        // REST polling (no long-poll): sleep between rounds so we never busy-spin.
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
                let edit = format!(
                    "{}/channels/{}/messages/{}",
                    self.api_base, self.channel_id, p.message_id
                );
                let content = format!(
                    "🛡️ Belay approval\n{}\n\n⏱️ Expired (auto-denied). Re-run the action to get a fresh prompt.",
                    p.summary
                );
                let _ = self
                    .http
                    .patch(&edit)
                    .header("Authorization", self.auth())
                    .json(&json!({ "content": content }))
                    .send()
                    .await;
            }
            let mut query: Vec<(&str, String)> = vec![("limit", "10".into())];
            if after > 0 {
                query.push(("after", after.to_string()));
            }
            let resp = self
                .http
                .get(&list)
                .header("Authorization", self.auth())
                .query(&query)
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
            for m in v.as_array().cloned().unwrap_or_default() {
                let id = m["id"].as_str().unwrap_or_default();
                // Advance the high-water mark to the newest id we have seen.
                if let Ok(n) = id.parse::<u64>() {
                    if n > after {
                        after = n;
                    }
                }
                let text = m["content"].as_str().unwrap_or("");
                // A `pair <code>` request rides the pipe as a PAIR:<code> nonce
                // (the daemon routes it to enrollment, not the approval gate).
                let (nonce, allow) = if let Some(code) = crate::inbound::parse_pair(text) {
                    (format!("{}{code}", crate::inbound::PAIR_NONCE_PREFIX), false)
                } else if let Some((allow, nonce)) = parse_decision(text) {
                    // Answered: drop it from the expiry map so the sweep never
                    // rewrites a prompt the user already acted on, and give the
                    // approver visible feedback by editing the original prompt to
                    // show the pressed choice. This confirms RECEIPT of the reply,
                    // independent of the gate's authz outcome (the daemon still
                    // enforces that).
                    let prompt = self.sent.lock().ok().and_then(|mut m| m.remove(&nonce));
                    if let Some(p) = prompt {
                        let mark = if allow {
                            "\n\n✅ You pressed Allow."
                        } else {
                            "\n\n⛔ You pressed Deny."
                        };
                        let edit = format!(
                            "{}/channels/{}/messages/{}",
                            self.api_base, self.channel_id, p.message_id
                        );
                        let content = format!("🛡️ Belay approval\n{}{mark}", p.summary);
                        let _ = self
                            .http
                            .patch(&edit)
                            .header("Authorization", self.auth())
                            .json(&json!({ "content": content }))
                            .send()
                            .await;
                    }
                    (nonce, allow)
                } else {
                    continue;
                };
                // Report the platform's facts; the daemon gate enforces them.
                // is_dm is the channel-type probe result (above), not a per-message
                // guess, so a mis-configured guild channel is reported not-DM.
                let principal = m["author"]["id"].as_str().unwrap_or_default().to_string();
                let is_dm = channel_is_dm;
                let msg_id = id.to_string();
                let reply = InboundReply {
                    platform: "discord".into(),
                    principal,
                    is_dm,
                    nonce,
                    msg_id,
                    allow,
                    response_url: None,
                };
                if tx.send(reply).await.is_err() {
                    return; // daemon gone
                }
            }
            // Poll interval between REST rounds.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
