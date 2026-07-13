//! Two-way Matrix approval adapter (client-server API).
//!
//! `notify` PUTs an `m.room.message` into a configured DIRECT 1:1 room, embedding
//! the correlation nonce and instructing the approver to reply exactly
//! `allow <nonce>` / `deny <nonce>` (Matrix has no inline buttons, so approval is
//! a plain text reply). `listen` long-polls `/sync`, walks the configured room's
//! timeline, and normalizes matching text replies into [`InboundReply`] values.
//!
//! The adapter makes NO trust decision: it only REPORTS the platform's facts
//! (sender, event id, echoed nonce, allow/deny) plus `is_dm`, derived from the
//! room's joined-member count in the sync `summary` (exactly 2 ⇒ a genuine 1:1;
//! anything else, or unknown, ⇒ false). Every enforcement (DM-only, allowlist,
//! rate-limit, dedup, nonce match) happens downstream in the daemon's gate.

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A sent approval prompt we may need to "expire" (or acknowledge): its original
/// event id (to target an m.replace edit), when it was sent, and the short
/// summary line (kept so the rewritten message still shows which request it was).
struct SentPrompt {
    event_id: String,
    at: Instant,
    summary: String,
}

pub struct MatrixChannel {
    access_token: String,
    room_id: String,
    api_base: String,
    http: reqwest::Client,
    /// nonce -> the prompt we sent for it, so the listener can rewrite prompts
    /// that timed out (the daemon already auto-denied them) into an "expired"
    /// notice, and rewrite an answered prompt to show the recorded choice.
    sent: Arc<Mutex<HashMap<String, SentPrompt>>>,
}

impl MatrixChannel {
    pub fn new(access_token: String, room_id: String) -> Self {
        Self {
            access_token,
            room_id,
            api_base: "https://matrix.org".into(),
            http: reqwest::Client::new(),
            sent: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }
    fn auth(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    /// Rewrite an earlier prompt in place. Matrix has no edit endpoint: an edit is
    /// a NEW `m.room.message` carrying `m.new_content` and an `m.relates_to` of
    /// `rel_type: m.replace` pointing at the original event id. `txnid` MUST be a
    /// fresh transaction id (the original nonce was already consumed by the send).
    /// Callers reach this only after the `is_safe_base` guard in notify/listen.
    async fn edit_prompt(&self, orig_event_id: &str, txnid: &str, new_text: &str) {
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.api_base,
            enc(&self.room_id),
            enc(txnid)
        );
        let _ = self
            .http
            .put(url)
            .header("Authorization", self.auth())
            .json(&json!({
                "msgtype": "m.text",
                "body": new_text,
                "m.new_content": {"msgtype": "m.text", "body": new_text},
                "m.relates_to": {"rel_type": "m.replace", "event_id": orig_event_id}
            }))
            .send()
            .await;
    }
}

/// Percent-encode a Matrix identifier for a URL path segment. Room ids
/// (`!abc:server`) and transaction ids can carry characters (`!`, `:`, `/`, `#`,
/// `+`) that would otherwise be read as path/query delimiters.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse a plain-text approval reply, case-insensitively: `allow <nonce>` /
/// `deny <nonce>`, tolerating a leading slash (`/allow <nonce>`). Returns the
/// approver intent and the echoed nonce, or `None` if it is not a decision.
fn parse_reply(body: &str) -> Option<(bool, String)> {
    let t = body.trim();
    let t = t.strip_prefix('/').unwrap_or(t);
    let mut it = t.split_whitespace();
    let verb = it.next()?.to_lowercase();
    let nonce = it.next()?;
    let allow = match verb.as_str() {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    Some((allow, nonce.to_string()))
}

#[async_trait]
impl ChannelAdapter for MatrixChannel {
    fn platform(&self) -> &'static str {
        "matrix"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never send the prompt (or the access token) to a non-HTTPS
        // remote base — a misconfigured `with_base()` must not become an SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe Matrix api_base: {}",
                self.api_base
            );
            return;
        }
        let text = format!(
            "🛡️ Belay approval\n{}\n\n{}\nsession={}\n\nReply exactly: allow {nonce}  — or —  deny {nonce}",
            req.summary, req.detail, req.session_id
        );
        // The nonce doubles as the (idempotent) transaction id for this send.
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.api_base,
            enc(&self.room_id),
            enc(nonce)
        );
        if let Ok(resp) = self
            .http
            .put(url)
            .header("Authorization", self.auth())
            .json(&json!({"msgtype": "m.text", "body": text}))
            .send()
            .await
        {
            // Record the sent message so the listener can expire it if it is never
            // answered before the daemon's park timeout elapses. The PUT response
            // returns the created event id, which an m.replace edit must target.
            if let Ok(v) = resp.json::<serde_json::Value>().await {
                if let Some(eid) = v["event_id"].as_str() {
                    if let Ok(mut m) = self.sent.lock() {
                        m.insert(
                            nonce.to_string(),
                            SentPrompt {
                                event_id: eid.to_string(),
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
                "belay channels: refusing to poll unsafe Matrix api_base: {}",
                self.api_base
            );
            return;
        }
        let sync = format!("{}/_matrix/client/v3/sync", self.api_base);
        let mut since: Option<String> = None;
        // Whether the configured room is a genuine 1:1 (exactly 2 joined members).
        // Derived from the sync `summary` (authoritative, present in the initial
        // full sync); defaults to FALSE until observed so an unknown/multi-member
        // room is never reported as a DM (the gate rejects non-DM replies).
        let mut room_is_dm = false;
        // A prompt is "expired" once the daemon's park timeout has elapsed (it has
        // already auto-denied it). Mirror that timeout (same env var) plus a small
        // buffer so we only expire AFTER the daemon has given up.
        let expire_after = Duration::from_millis(
            std::env::var("BELAY_APPROVAL_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60_000),
        ) + Duration::from_secs(5);
        // Long-poll the sync stream until the daemon drops the receiver.
        while !tx.is_closed() {
            // Sweep: rewrite any prompt that timed out with no answer so a late
            // reply can't look like it might still work. Collect under the lock,
            // then edit outside it (never hold the lock across an await).
            let stale: Vec<(String, SentPrompt)> = match self.sent.lock() {
                Ok(mut m) => {
                    let keys: Vec<String> = m
                        .iter()
                        .filter(|(_, p)| p.at.elapsed() > expire_after)
                        .map(|(k, _)| k.clone())
                        .collect();
                    keys.into_iter()
                        .filter_map(|k| m.remove(&k).map(|p| (k, p)))
                        .collect()
                }
                Err(_) => Vec::new(),
            };
            for (nonce, p) in stale {
                let text = format!(
                    "🛡️ Belay approval\n{}\n\n⏱️ Expired (auto-denied). Re-run the action to get a fresh prompt.",
                    p.summary
                );
                // Fresh txn id: the nonce was already consumed by the original send.
                self.edit_prompt(&p.event_id, &format!("{nonce}-exp"), &text)
                    .await;
            }
            let mut q: Vec<(&str, String)> = vec![("timeout", "25000".into())];
            if let Some(s) = &since {
                q.push(("since", s.clone()));
            }
            let resp = self
                .http
                .get(&sync)
                .header("Authorization", self.auth())
                .query(&q)
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
            // Refresh the 1:1 determination whenever the server reports member
            // count (the initial full sync always does); keep the last known value
            // otherwise. Set BEFORE any events in this batch are emitted.
            if let Some(c) = v["rooms"]["join"][self.room_id.as_str()]["summary"]
                ["m.joined_member_count"]
                .as_i64()
            {
                room_is_dm = c == 2;
            }
            let next = v["next_batch"].as_str();
            // First successful sync only establishes the stream position, so a
            // restart never re-acts on historical messages. If the server sent no
            // token we cannot advance, so fall through and process.
            if since.is_none() {
                if let Some(n) = next {
                    since = Some(n.to_string());
                    continue;
                }
            } else if let Some(n) = next {
                since = Some(n.to_string());
            }
            let events =
                v["rooms"]["join"][self.room_id.as_str()]["timeline"]["events"].clone();
            for ev in events.as_array().cloned().unwrap_or_default() {
                if ev["type"].as_str() != Some("m.room.message") {
                    continue;
                }
                let text = ev["content"]["body"].as_str().unwrap_or("");
                // A `pair <code>` request rides the pipe as a PAIR:<code> nonce.
                let (nonce, allow) = if let Some(code) = crate::inbound::parse_pair(text) {
                    (format!("{}{code}", crate::inbound::PAIR_NONCE_PREFIX), false)
                } else if let Some((allow, nonce)) = parse_reply(text) {
                    (nonce, allow)
                } else {
                    continue;
                };
                // Answered: drop it from the expiry map (so the sweep never
                // rewrites a prompt the user already acted on) and rewrite the
                // original prompt to show the recorded choice. Only a real approval
                // reply matches a stored prompt; a `pair` nonce is never in the map,
                // so its removal is a no-op and no edit is sent. The MutexGuard is
                // dropped before the await (never hold a std Mutex across .await).
                if let Some(p) = self
                    .sent
                    .lock()
                    .ok()
                    .and_then(|mut m| m.remove(&nonce))
                {
                    let mark = if allow {
                        "\n\n✅ You pressed Allow."
                    } else {
                        "\n\n⛔ You pressed Deny."
                    };
                    let text = format!("🛡️ Belay approval\n{}{mark}", p.summary);
                    self.edit_prompt(&p.event_id, &format!("{nonce}-ack"), &text)
                        .await;
                }
                // Report the platform's facts; the daemon gate enforces them.
                // `is_dm` reflects the room's real membership (derived above), not a
                // blind assumption — a misconfigured multi-member room is reported
                // is_dm=false and the gate then rejects the reply.
                let principal = ev["sender"].as_str().unwrap_or_default().to_string();
                let msg_id = ev["event_id"].as_str().unwrap_or_default().to_string();
                let reply = InboundReply {
                    platform: "matrix".into(),
                    principal,
                    is_dm: room_is_dm,
                    nonce,
                    msg_id,
                    allow,
                    response_url: None,
                };
                if tx.send(reply).await.is_err() {
                    return; // daemon gone
                }
            }
        }
    }
}
