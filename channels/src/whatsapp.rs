//! Twilio WhatsApp approval adapter.
//!
//! Twilio's WhatsApp REST channel is a plain text medium — there are no inline
//! buttons — so approval is a TEXT reply the approver types back: `allow <nonce>`
//! / `deny <nonce>` (case-insensitive, an optional leading `/` is tolerated). The
//! outbound prompt (sent to the approver's 1:1 WhatsApp thread) instructs exactly
//! that. WhatsApp is inherently 1:1, so every inbound reply is a DM.
//!
//! This module exposes both flows:
//!   * [`NotificationChannel::ask`] — the blocking poll-until-answer model.
//!   * [`ChannelAdapter`] — the push model the daemon's messaging bridge drives:
//!     [`notify`](ChannelAdapter::notify) fans the prompt (carrying the CSPRNG
//!     nonce) to the approver, and a single shared
//!     [`listen`](ChannelAdapter::listen) task polls the Messages resource and
//!     streams normalized [`InboundReply`] values back to the authorization gate.
//!     The adapter makes NO trust decision; it only REPORTS the platform's facts.

use crate::{ChannelAdapter, Decision, DecisionRequest, InboundReply, NotificationChannel};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct WhatsAppChannel {
    account_sid: String,
    auth_token: String,
    from: String,
    to: String,
    api_base: String,
    http: reqwest::Client,
    /// nonce -> (sent_at, summary) for each prompt we sent. WhatsApp/Twilio can
    /// NOT edit an already-sent message, so (unlike Telegram's in-place edit) the
    /// listener expires a stale prompt and confirms a reply by sending a NEW
    /// follow-up text message. There is no message_id to keep here.
    sent: Arc<Mutex<HashMap<String, (Instant, String)>>>,
}

impl WhatsAppChannel {
    pub fn new(account_sid: String, auth_token: String, from: String, to: String) -> Self {
        Self {
            account_sid,
            auth_token,
            from,
            to,
            api_base: "https://api.twilio.com".into(),
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }
    fn basic_auth(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.account_sid, self.auth_token))
        )
    }
    fn path(&self) -> String {
        format!(
            "{}/2010-04-01/Accounts/{}/Messages.json",
            self.api_base, self.account_sid
        )
    }
}

#[async_trait]
impl NotificationChannel for WhatsAppChannel {
    async fn ask(&self, req: &DecisionRequest, timeout: Duration) -> Decision {
        // Fail closed: never send the prompt (or the Twilio credentials) to a
        // non-HTTPS remote base — a misconfigured `with_base()` must not SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe WhatsApp api_base: {}",
                self.api_base
            );
            return Decision::Deny;
        }
        let body_text = format!(
            "Belay alert\nSession: {}\nRule: {}\nSummary: {}\nReply 'allow' or 'deny'.",
            req.session_id, req.rule_id, req.summary
        );
        let _ = self
            .http
            .post(self.path())
            .header("Authorization", self.basic_auth())
            .form(&[("From", &self.from), ("To", &self.to), ("Body", &body_text)])
            .send()
            .await;

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(r) = self
                .http
                .get(self.path())
                .header("Authorization", self.basic_auth())
                .send()
                .await
            {
                if r.status().as_u16() == 200 {
                    if let Ok(v) = r.json::<serde_json::Value>().await {
                        for m in v["messages"].as_array().cloned().unwrap_or_default() {
                            match m["body"]
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
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Decision::Deny
    }
}

/// Parse a WhatsApp text approval: `allow <nonce>` / `deny <nonce>`. The verb is
/// matched case-insensitively and a single leading `/` (some clients auto-insert
/// one for command-looking text) is tolerated; the nonce keeps its exact case so
/// it can be matched byte-for-byte against the request's CSPRNG nonce. Returns
/// `(allow, nonce)` or `None` for anything else.
fn parse_reply(body: &str) -> Option<(bool, String)> {
    let trimmed = body.trim();
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let mut words = trimmed.split_whitespace();
    let verb = words.next()?.to_ascii_lowercase();
    let nonce = words.next()?.to_string();
    let allow = match verb.as_str() {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    Some((allow, nonce))
}

/// Push-model adapter: the daemon fans a parked ASK out via [`notify`], and a
/// single shared [`listen`] task polls the Twilio Messages resource for inbound
/// WhatsApp replies and streams them back to the daemon's authorization gate.
/// Correlation is by the request's CSPRNG `nonce`, echoed in the approver's text
/// reply (`allow <nonce>` / `deny <nonce>`). The adapter itself makes NO trust
/// decision (not even the DM check gates here — WhatsApp is 1:1, so it truthfully
/// reports `is_dm = true` for the gate to enforce).
///
/// [`notify`]: ChannelAdapter::notify
/// [`listen`]: ChannelAdapter::listen
#[async_trait]
impl ChannelAdapter for WhatsAppChannel {
    fn platform(&self) -> &'static str {
        "whatsapp"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the Twilio credentials) to a
        // non-HTTPS remote base — a misconfigured `with_base()` must not SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe WhatsApp api_base: {}",
                self.api_base
            );
            return;
        }
        // WhatsApp has no buttons: instruct the exact text reply the listener
        // parses back. The nonce is delivered only to the approver's 1:1 thread.
        let body_text = format!(
            "🛡️ Belay approval\n{}\n\n{}\nsession={}\n\nReply \"allow {nonce}\" to approve or \"deny {nonce}\" to deny.",
            req.summary, req.detail, req.session_id
        );
        let _ = self
            .http
            .post(self.path())
            .header("Authorization", self.basic_auth())
            .form(&[("From", &self.from), ("To", &self.to), ("Body", &body_text)])
            .send()
            .await;
        // Record the sent prompt so the listener can expire it (via a follow-up
        // text) if it is never answered before the daemon's park timeout elapses.
        if let Ok(mut m) = self.sent.lock() {
            m.insert(nonce.to_string(), (Instant::now(), req.summary.clone()));
        }
    }

    async fn listen(&self, tx: mpsc::Sender<InboundReply>) {
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing to poll unsafe WhatsApp api_base: {}",
                self.api_base
            );
            return;
        }
        // Twilio returns the full message list each poll; remember the sids we
        // have already forwarded so a re-poll does not re-emit the same reply.
        let mut forwarded: HashSet<String> = HashSet::new();
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
            // Sweep: WhatsApp/Twilio can NOT edit a sent message, so (unlike
            // Telegram's in-place edit) expire each stale prompt by sending a NEW
            // follow-up text. Collect stale nonces under the lock, drop the guard,
            // then send outside it (never hold the std Mutex across an await).
            let stale: Vec<(String, String)> = match self.sent.lock() {
                Ok(m) => m
                    .iter()
                    .filter(|(_, (at, _))| at.elapsed() > expire_after)
                    .map(|(k, (_, summary))| (k.clone(), summary.clone()))
                    .collect(),
                Err(_) => Vec::new(),
            };
            for (nonce, summary) in &stale {
                let body_text = format!(
                    "⏱️ Belay: the approval request ({summary}) expired and was auto-denied. Re-run the action to get a fresh prompt."
                );
                let _ = self
                    .http
                    .post(self.path())
                    .header("Authorization", self.basic_auth())
                    .form(&[("From", &self.from), ("To", &self.to), ("Body", &body_text)])
                    .send()
                    .await;
                if let Ok(mut m) = self.sent.lock() {
                    m.remove(nonce);
                }
            }
            let resp = self
                .http
                .get(self.path())
                .header("Authorization", self.basic_auth())
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
            for m in v["messages"].as_array().cloned().unwrap_or_default() {
                // Only inbound (approver → Twilio) messages can approve; skip our
                // own outbound prompts. The approver's number equals what we sent
                // the prompt TO, so accept either signal.
                let direction = m["direction"].as_str().unwrap_or("");
                let from = m["from"].as_str().unwrap_or("").to_string();
                if direction != "inbound" && from != self.to {
                    continue;
                }
                let msg_id = m["sid"].as_str().unwrap_or_default().to_string();
                if msg_id.is_empty() || forwarded.contains(&msg_id) {
                    continue;
                }
                let text = m["body"].as_str().unwrap_or("");
                // A `pair <code>` request rides the pipe as a PAIR:<code> nonce.
                // `is_approval` marks an actual allow/deny reply (not a pairing),
                // so we only confirm/expire those against the `sent` map.
                let mut is_approval = false;
                let (nonce, allow) = if let Some(code) = crate::inbound::parse_pair(text) {
                    (format!("{}{code}", crate::inbound::PAIR_NONCE_PREFIX), false)
                } else if let Some((allow, nonce)) = parse_reply(text) {
                    is_approval = true;
                    (nonce, allow)
                } else {
                    continue;
                };
                forwarded.insert(msg_id.clone());
                if is_approval {
                    // Answered: drop it from the expiry map so the sweep never
                    // sends an "expired" follow-up for a prompt already acted on.
                    if let Ok(mut m) = self.sent.lock() {
                        m.remove(&nonce);
                    }
                    // WhatsApp/Twilio can NOT edit the prompt, so confirm RECEIPT
                    // of the reply with a NEW follow-up text (this only confirms
                    // receipt; the daemon gate still enforces the authz outcome).
                    let body_text = if allow {
                        "✅ Belay: your Allow was recorded.".to_string()
                    } else {
                        "⛔ Belay: your Deny was recorded.".to_string()
                    };
                    let _ = self
                        .http
                        .post(self.path())
                        .header("Authorization", self.basic_auth())
                        .form(&[("From", &self.from), ("To", &self.to), ("Body", &body_text)])
                        .send()
                        .await;
                }
                // Report the platform's facts; the daemon gate enforces them.
                // WhatsApp is a 1:1 medium, so every inbound reply is a DM.
                let reply = InboundReply {
                    platform: "whatsapp".into(),
                    principal: from,
                    is_dm: true,
                    nonce,
                    msg_id,
                    allow,
                    response_url: None,
                };
                if tx.send(reply).await.is_err() {
                    return; // daemon gone
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
