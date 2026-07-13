use crate::{ChannelAdapter, Decision, DecisionRequest, InboundReply, NotificationChannel};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A sent approval prompt we may need to "expire": its message id (to edit it),
/// when it was sent, and the short summary line (kept so the expired message
/// still shows which request died).
struct SentPrompt {
    message_id: i64,
    at: Instant,
    summary: String,
}

pub struct TelegramChannel {
    token: String,
    chat_id: String,
    api_base: String,
    req_id: Option<String>,
    http: reqwest::Client,
    /// nonce -> the prompt we sent for it, so the listener can rewrite prompts
    /// that timed out (the daemon already auto-denied them) instead of leaving
    /// live-looking buttons that silently do nothing when clicked late.
    sent: Arc<Mutex<HashMap<String, SentPrompt>>>,
}

impl TelegramChannel {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            token: bot_token,
            chat_id,
            api_base: "https://api.telegram.org".into(),
            req_id: None,
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }
    pub fn with_req_id(mut self, id: String) -> Self {
        self.req_id = Some(id);
        self
    }
    fn url(&self, m: &str) -> String {
        format!("{}/bot{}/{}", self.api_base, self.token, m)
    }
}

#[async_trait]
impl NotificationChannel for TelegramChannel {
    async fn ask(&self, req: &DecisionRequest, timeout: Duration) -> Decision {
        // Fail closed: never send the prompt (or the bot token) to a non-HTTPS
        // remote base — a misconfigured `with_base()` must not become an SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Telegram api_base: {}",
                self.api_base
            );
            return Decision::Deny;
        }
        let rid = self.req_id.clone().unwrap_or_else(|| req.rule_id.clone());
        let kb = json!({"inline_keyboard": [[
            {"text": "✅ Allow", "callback_data": format!("allow:{rid}")},
            {"text": "⛔ Deny",  "callback_data": format!("deny:{rid}")}
        ]]});
        let text = format!(
            "🛡️ Belay\n{}\n\n{}\nsession={}",
            req.summary, req.detail, req.session_id
        );
        let _ = self
            .http
            .post(self.url("sendMessage"))
            .json(&json!({"chat_id": self.chat_id, "text": text, "reply_markup": kb}))
            .send()
            .await;

        let deadline = Instant::now() + timeout;
        let mut offset = 0i64;
        let suffix = format!(":{rid}");
        while Instant::now() < deadline {
            if let Ok(r) = self
                .http
                .post(self.url("getUpdates"))
                .json(&json!({"offset": offset, "timeout": 1}))
                .send()
                .await
            {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    for upd in v["result"].as_array().cloned().unwrap_or_default() {
                        offset = upd["update_id"].as_i64().unwrap_or(offset) + 1;
                        if let Some(data) = upd["callback_query"]["data"].as_str() {
                            if data.ends_with(&suffix) {
                                return if data.starts_with("allow:") {
                                    Decision::Allow
                                } else {
                                    Decision::Deny
                                };
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Decision::Deny
    }
}

/// Push-model adapter: the daemon fans a parked ASK out via [`notify`], and a
/// single shared [`listen`] task streams inbound button presses back to the
/// daemon's authorization gate. Correlation is by the request's CSPRNG `nonce`
/// carried in the inline-button `callback_data` (`a:<nonce>` / `d:<nonce>`) — the
/// adapter itself makes NO trust decision (not even the DM check gates here; it
/// only REPORTS `is_dm` for the gate to enforce).
///
/// [`notify`]: ChannelAdapter::notify
/// [`listen`]: ChannelAdapter::listen
#[async_trait]
impl ChannelAdapter for TelegramChannel {
    fn platform(&self) -> &'static str {
        "telegram"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the bot token in the URL) to a
        // non-HTTPS remote base — a misconfigured `with_base()` must not be SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Telegram api_base: {}",
                self.api_base
            );
            return;
        }
        let kb = json!({"inline_keyboard": [[
            {"text": "✅ Allow", "callback_data": format!("a:{nonce}")},
            {"text": "⛔ Deny",  "callback_data": format!("d:{nonce}")}
        ]]});
        let text = format!(
            "🛡️ Belay approval\n{}\n\n{}\nsession={}",
            req.summary, req.detail, req.session_id
        );
        if let Ok(resp) = self
            .http
            .post(self.url("sendMessage"))
            .json(&json!({"chat_id": self.chat_id, "text": text, "reply_markup": kb}))
            .send()
            .await
        {
            // Record the sent message so the listener can expire it if it is
            // never answered before the daemon's park timeout elapses.
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(mid) = v["result"]["message_id"].as_i64() {
                    if let Ok(mut m) = self.sent.lock() {
                        m.insert(
                            nonce.to_string(),
                            SentPrompt {
                                message_id: mid,
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
                "belay channels: refusing to poll unsafe Telegram api_base: {}",
                self.api_base
            );
            return;
        }
        let mut offset = 0i64;
        // A prompt is "expired" once the daemon's park timeout has elapsed (it
        // has already auto-denied it). Mirror that timeout (same env var) plus a
        // small buffer so we only expire AFTER the daemon has given up.
        let expire_after = Duration::from_millis(
            std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60_000),
        ) + Duration::from_secs(5);
        // Long-poll callback queries until the daemon drops the receiver.
        while !tx.is_closed() {
            // Sweep: rewrite any prompt that timed out with no answer so a late
            // click can't look like it might still work. Collect under the lock,
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
                    .post(self.url("editMessageText"))
                    .json(&json!({
                        "chat_id": self.chat_id,
                        "message_id": p.message_id,
                        "text": text,
                    }))
                    .send()
                    .await;
            }
            let resp = self
                .http
                .post(self.url("getUpdates"))
                .json(&json!({
                    "offset": offset,
                    "timeout": 25,
                    // callback_query = Allow/Deny button clicks; message = `pair <code>`.
                    "allowed_updates": ["callback_query", "message"]
                }))
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
            for upd in v["result"].as_array().cloned().unwrap_or_default() {
                offset = upd["update_id"].as_i64().unwrap_or(offset) + 1;

                // (a) Button click → approval (callback_data `a:`/`d:` + nonce).
                if let Some(data) = upd["callback_query"]["data"].as_str() {
                    let cq = &upd["callback_query"];
                    let (allow, nonce) = if let Some(n) = data.strip_prefix("a:") {
                        (true, n)
                    } else if let Some(n) = data.strip_prefix("d:") {
                        (false, n)
                    } else {
                        continue;
                    };
                    // Answered: drop it from the expiry map so the sweep never
                    // rewrites a prompt the user already acted on.
                    if let Ok(mut m) = self.sent.lock() {
                        m.remove(nonce);
                    }
                    // Report the platform's facts; the daemon gate enforces them.
                    let principal = cq["from"]["id"]
                        .as_i64()
                        .map(|i| i.to_string())
                        .or_else(|| cq["from"]["id"].as_str().map(str::to_string))
                        .unwrap_or_default();
                    let is_dm = cq["message"]["chat"]["type"].as_str() == Some("private");
                    let cq_id = cq["id"].as_str().unwrap_or_default().to_string();
                    // Give the user visible feedback that the click registered:
                    // a toast, and rewrite the prompt to show the pressed choice
                    // with the buttons removed (so it can't be tapped twice and
                    // it's obvious the decision was captured). This confirms
                    // RECEIPT of the click, independent of the gate's authz
                    // outcome (which the daemon still enforces).
                    let toast = if allow {
                        "✅ Allow recorded"
                    } else {
                        "⛔ Deny recorded"
                    };
                    let _ = self
                        .http
                        .post(self.url("answerCallbackQuery"))
                        .json(&json!({"callback_query_id": cq_id, "text": toast}))
                        .send()
                        .await;
                    let chat_id = cq["message"]["chat"]["id"].clone();
                    let message_id = cq["message"]["message_id"].clone();
                    if !chat_id.is_null() && !message_id.is_null() {
                        let orig = cq["message"]["text"].as_str().unwrap_or("");
                        let mark = if allow {
                            "\n\n✅ You pressed Allow."
                        } else {
                            "\n\n⛔ You pressed Deny."
                        };
                        // editMessageText without reply_markup drops the buttons.
                        let _ = self
                            .http
                            .post(self.url("editMessageText"))
                            .json(&json!({
                                "chat_id": chat_id,
                                "message_id": message_id,
                                "text": format!("{orig}{mark}"),
                            }))
                            .send()
                            .await;
                    }
                    let reply = InboundReply {
                        platform: "telegram".into(),
                        principal,
                        is_dm,
                        nonce: nonce.to_string(),
                        msg_id: cq_id,
                        allow,
                        response_url: None,
                    };
                    if tx.send(reply).await.is_err() {
                        return; // daemon gone
                    }
                    continue;
                }

                // (b) Text message → pairing (`pair <code>`). Approvals use the
                //     inline buttons above; a text message is only for enrollment.
                if let Some(code) = upd["message"]["text"]
                    .as_str()
                    .and_then(crate::inbound::parse_pair)
                {
                    let m = &upd["message"];
                    let principal = m["from"]["id"]
                        .as_i64()
                        .map(|i| i.to_string())
                        .or_else(|| m["from"]["id"].as_str().map(str::to_string))
                        .unwrap_or_default();
                    let is_dm = m["chat"]["type"].as_str() == Some("private");
                    let msg_id = m["message_id"]
                        .as_i64()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    let reply = InboundReply {
                        platform: "telegram".into(),
                        principal,
                        is_dm,
                        nonce: format!("{}{code}", crate::inbound::PAIR_NONCE_PREFIX),
                        msg_id,
                        allow: false,
                        response_url: None,
                    };
                    if tx.send(reply).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
