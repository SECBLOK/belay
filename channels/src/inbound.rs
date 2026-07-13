//! Inbound-webhook verification (Phase B): authenticate + normalize a platform's
//! callback POST into [`InboundReply`] values for the daemon's authorization gate.
//!
//! Webhook-only platforms (Line, Slack, Twilio, WeCom, …) deliver an approver's
//! reply by POSTing to a public HTTPS endpoint. The daemon runs that endpoint
//! (behind the operator's TLS proxy) and, for each request, calls the matching
//! [`InboundVerifier`]. A verifier's ONLY job is to prove the request genuinely
//! came from the platform (a per-platform HMAC over the raw body) and to report
//! the platform's facts — it makes NO trust decision. The normalized replies are
//! then run through the daemon's gate (DM-only ∧ allowlist ∧ rate-limit ∧ dedup ∧
//! exact nonce) exactly like a polled reply, so the inbound path inherits every
//! protection; the verifier only adds request authentication on top.
//!
//! FAIL-CLOSED: any verification failure (missing/invalid signature, unparseable
//! body) returns `None` — the receiver then rejects the request and NOTHING
//! reaches the approval queue.

use crate::InboundReply;
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// Verifies + normalizes one inbound platform webhook request. Headers are passed
/// with lowercased names so the daemon's HTTP layer (which owns the concrete
/// header type) need not leak into the channels crate.
pub trait InboundVerifier: Send + Sync {
    /// Stable platform id, e.g. `"line"`. Selects the receiver route `/hook/<id>`
    /// and must match the `platform` stamped on produced replies.
    fn platform(&self) -> &'static str;

    /// Authenticate the request (per-platform signature over `body`) and, if
    /// valid, extract every approval reply it carries (a single webhook POST may
    /// batch several). MUST return `None` on ANY authentication/parse failure —
    /// never yields replies from an unauthenticated request.
    fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<Vec<InboundReply>>;
}

/// Base64(HMAC-SHA256(key, msg)). `new_from_slice` accepts any key length.
/// Public so a verifier's callers/tests can construct matching signatures.
pub fn b64_hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    STANDARD.encode(mac.finalize().into_bytes())
}

/// Constant-time string comparison for signatures (avoids a timing side channel
/// on the HMAC digest). The length check leaks only the (fixed) digest length.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Parse a plain-text approval reply, case-insensitively: `allow <nonce>` /
/// `deny <nonce>`, tolerating a leading slash. Returns `(allow, nonce)` or `None`.
pub(crate) fn parse_text_reply(text: &str) -> Option<(bool, String)> {
    let t = text.trim();
    let t = t.strip_prefix('/').unwrap_or(t);
    let mut it = t.split_whitespace();
    let allow = match it.next()?.to_lowercase().as_str() {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    Some((allow, it.next()?.to_string()))
}

/// Sentinel nonce prefix carrying an interactive pairing code through the normal
/// [`InboundReply`] pipe (the daemon routes `PAIR:*` nonces to pairing, not the
/// approval gate). A real approval nonce is 32-char hex, so it never collides.
pub const PAIR_NONCE_PREFIX: &str = "PAIR:";

/// Parse a pairing request `pair <code>` (case-insensitive, optional leading
/// slash). Returns the code, or `None` if the text is not a pairing message.
pub(crate) fn parse_pair(text: &str) -> Option<String> {
    let t = text.trim();
    let t = t.strip_prefix('/').unwrap_or(t);
    let mut it = t.split_whitespace();
    if !it.next()?.eq_ignore_ascii_case("pair") {
        return None;
    }
    Some(it.next()?.to_string())
}

// ── LINE ─────────────────────────────────────────────────────────────────────

/// LINE Messaging API webhook verifier. LINE signs the raw request body with the
/// channel secret: `X-Line-Signature: base64(HMAC-SHA256(body, channel_secret))`.
/// A 1:1 user chat (`source.type == "user"`) is a genuine DM; group/room replies
/// are reported `is_dm = false` and the gate rejects them.
pub struct LineVerifier {
    channel_secret: String,
}

impl LineVerifier {
    pub fn new(channel_secret: String) -> Self {
        Self { channel_secret }
    }
}

impl InboundVerifier for LineVerifier {
    fn platform(&self) -> &'static str {
        "line"
    }

    fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<Vec<InboundReply>> {
        // 1) Authenticate: constant-time compare against the recomputed HMAC.
        let sig = headers.get("x-line-signature")?;
        let expected = b64_hmac_sha256(self.channel_secret.as_bytes(), body);
        if !ct_eq(sig, &expected) {
            return None;
        }
        // 2) Normalize (post-auth): report the platform's facts; the gate decides.
        let v: serde_json::Value = serde_json::from_slice(body).ok()?;
        let mut out = Vec::new();
        for ev in v["events"].as_array().into_iter().flatten() {
            if ev["type"].as_str() != Some("message")
                || ev["message"]["type"].as_str() != Some("text")
            {
                continue;
            }
            let text = ev["message"]["text"].as_str().unwrap_or("");
            // A `pair <code>` request rides the pipe as a PAIR:<code> nonce; the
            // daemon routes it to pairing (enroll), not the approval gate.
            let (nonce, allow) = if let Some(code) = parse_pair(text) {
                (format!("{PAIR_NONCE_PREFIX}{code}"), false)
            } else if let Some((allow, nonce)) = parse_text_reply(text) {
                (nonce, allow)
            } else {
                continue;
            };
            out.push(InboundReply {
                platform: "line".into(),
                principal: ev["source"]["userId"].as_str().unwrap_or_default().to_string(),
                is_dm: ev["source"]["type"].as_str() == Some("user"),
                nonce,
                msg_id: ev["message"]["id"].as_str().unwrap_or_default().to_string(),
                allow,
                response_url: None,
            });
        }
        Some(out)
    }
}

// ── SLACK ────────────────────────────────────────────────────────────────────

/// Lowercase-hex of HMAC-SHA256(key, msg). Slack signs with hex (not base64).
pub fn hex_hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    use std::fmt::Write;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let mut s = String::with_capacity(64);
    for b in mac.finalize().into_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `a:<nonce>` → (true, nonce); `d:<nonce>` → (false, nonce); else None. Matches
/// the button `value` the Slack outbound adapter stamps.
fn parse_button_value(v: &str) -> Option<(bool, String)> {
    if let Some(n) = v.strip_prefix("a:") {
        Some((true, n.to_string()))
    } else {
        v.strip_prefix("d:").map(|n| (false, n.to_string()))
    }
}

/// Extract one percent-decoded field from an `application/x-www-form-urlencoded`
/// body. Slack interactivity posts a single `payload=<json>` field.
fn form_field(body: &str, key: &str) -> Option<String> {
    for pair in body.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            let raw = it.next().unwrap_or("");
            return urlencoding::decode(raw).ok().map(|c| c.into_owned());
        }
    }
    None
}

/// Slack interactivity (Block Kit button) verifier. Each request is signed
/// `X-Slack-Signature: v0=hex(HMAC-SHA256("v0:{ts}:{raw_body}", signing_secret))`
/// with an `X-Slack-Request-Timestamp`; requests skewed more than 5 minutes are
/// rejected (replay guard). The clicked button's `value` carries
/// `a:<nonce>`/`d:<nonce>`; a DM is a channel id beginning with `D`.
pub struct SlackVerifier {
    signing_secret: String,
}

impl SlackVerifier {
    pub fn new(signing_secret: String) -> Self {
        Self { signing_secret }
    }
}

impl InboundVerifier for SlackVerifier {
    fn platform(&self) -> &'static str {
        "slack"
    }

    fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Option<Vec<InboundReply>> {
        let sig = headers.get("x-slack-signature")?;
        let ts = headers.get("x-slack-request-timestamp")?;
        // Replay window: reject a timestamp more than 5 minutes from now.
        let ts_num: i64 = ts.parse().ok()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;
        if (now - ts_num).abs() > 300 {
            return None;
        }
        let raw = std::str::from_utf8(body).ok()?;
        // Signature is over the EXACT raw body prefixed with "v0:{ts}:".
        let expected = format!(
            "v0={}",
            hex_hmac_sha256(
                self.signing_secret.as_bytes(),
                format!("v0:{ts}:{raw}").as_bytes()
            )
        );
        if !ct_eq(sig, &expected) {
            return None;
        }
        // Authenticated — parse the interactivity payload.
        let payload = form_field(raw, "payload")?;
        let v: serde_json::Value = serde_json::from_str(&payload).ok()?;
        let principal = v["user"]["id"].as_str().unwrap_or_default().to_string();
        let is_dm = v["channel"]["id"]
            .as_str()
            .unwrap_or_default()
            .starts_with('D');
        let trigger = v["trigger_id"].as_str().unwrap_or_default().to_string();
        let mut out = Vec::new();
        for a in v["actions"].as_array().into_iter().flatten() {
            let Some((allow, nonce)) = parse_button_value(a["value"].as_str().unwrap_or("")) else {
                continue;
            };
            // trigger_id is unique per interaction → a solid dedup key.
            let msg_id = if trigger.is_empty() {
                format!("{nonce}:{}", a["action_ts"].as_str().unwrap_or(""))
            } else {
                trigger.clone()
            };
            out.push(InboundReply {
                platform: "slack".into(),
                principal: principal.clone(),
                is_dm,
                nonce,
                msg_id,
                allow,
                // Slack gives a one-shot response_url per interaction; the daemon
                // POSTs click feedback there so the approver sees their choice land.
                response_url: v["response_url"].as_str().map(str::to_string),
            });
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "line-channel-secret";

    fn signed(body: &[u8]) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert(
            "x-line-signature".to_string(),
            b64_hmac_sha256(SECRET.as_bytes(), body),
        );
        h
    }

    fn dm_event(text: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "events": [{
                "type": "message",
                "message": {"type": "text", "id": "m1", "text": text},
                "source": {"type": "user", "userId": "Uapprover"}
            }]
        }))
        .unwrap()
    }

    #[test]
    fn valid_signature_yields_normalized_reply() {
        let body = dm_event("allow abc123nonce");
        let v = LineVerifier::new(SECRET.into());
        let replies = v.verify_and_parse(&signed(&body), &body).expect("verified");
        assert_eq!(replies.len(), 1);
        let r = &replies[0];
        assert_eq!(r.platform, "line");
        assert_eq!(r.principal, "Uapprover");
        assert!(r.is_dm, "1:1 user source → DM");
        assert_eq!(r.nonce, "abc123nonce");
        assert_eq!(r.msg_id, "m1");
        assert!(r.allow);
    }

    #[test]
    fn bad_signature_is_rejected() {
        let body = dm_event("allow abc123nonce");
        let mut h = HashMap::new();
        h.insert("x-line-signature".to_string(), "deadbeef".to_string());
        assert!(
            LineVerifier::new(SECRET.into())
                .verify_and_parse(&h, &body)
                .is_none(),
            "forged signature must fail closed"
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        // A valid signature under a DIFFERENT secret must not verify.
        let body = dm_event("allow abc123nonce");
        let mut h = HashMap::new();
        h.insert(
            "x-line-signature".to_string(),
            b64_hmac_sha256(b"attacker-secret", &body),
        );
        assert!(LineVerifier::new(SECRET.into())
            .verify_and_parse(&h, &body)
            .is_none());
    }

    #[test]
    fn missing_signature_header_is_rejected() {
        let body = dm_event("allow abc123nonce");
        assert!(LineVerifier::new(SECRET.into())
            .verify_and_parse(&HashMap::new(), &body)
            .is_none());
    }

    #[test]
    fn group_source_reported_as_not_dm() {
        let body = serde_json::to_vec(&json!({
            "events": [{
                "type": "message",
                "message": {"type": "text", "id": "m2", "text": "allow n"},
                "source": {"type": "group", "groupId": "Cxxx", "userId": "Uinsider"}
            }]
        }))
        .unwrap();
        let replies = LineVerifier::new(SECRET.into())
            .verify_and_parse(&signed(&body), &body)
            .expect("signature valid");
        assert_eq!(replies.len(), 1);
        assert!(!replies[0].is_dm, "group source must not be a DM");
    }

    #[test]
    fn non_decision_text_yields_no_replies() {
        let body = dm_event("hello there");
        let replies = LineVerifier::new(SECRET.into())
            .verify_and_parse(&signed(&body), &body)
            .expect("signature valid");
        assert!(replies.is_empty(), "non-approval text is ignored");
    }

    #[test]
    fn pair_request_rides_as_pair_nonce() {
        // `pair <code>` is normalized to a PAIR:<code> nonce carrying the sender's
        // real principal — the daemon routes it to enrollment, not the gate.
        let body = dm_event("/Pair GH7KQ2");
        let replies = LineVerifier::new(SECRET.into())
            .verify_and_parse(&signed(&body), &body)
            .expect("signature valid");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].nonce, "PAIR:GH7KQ2");
        assert_eq!(replies[0].principal, "Uapprover");
        assert!(replies[0].is_dm);
    }

    #[test]
    fn parse_pair_matches_only_pair_verb() {
        assert_eq!(parse_pair("pair ABC123"), Some("ABC123".into()));
        assert_eq!(parse_pair("/PAIR xyz"), Some("xyz".into()));
        assert_eq!(parse_pair("allow ABC123"), None);
        assert_eq!(parse_pair("pair"), None);
    }

    #[test]
    fn deny_and_slash_prefix_parse() {
        assert_eq!(parse_text_reply("/DENY nonce9"), Some((false, "nonce9".into())));
        assert_eq!(parse_text_reply("Allow  xyz"), Some((true, "xyz".into())));
        assert_eq!(parse_text_reply("maybe xyz"), None);
    }

    // ── Slack interactivity ──────────────────────────────────────────────────

    const SLACK_SECRET: &str = "slack-signing-secret";

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Build a signed Slack interactivity request at timestamp `ts`.
    fn slack_signed_at(payload_json: &str, ts: i64) -> (HashMap<String, String>, Vec<u8>) {
        let body = format!("payload={}", urlencoding::encode(payload_json));
        let sig = format!(
            "v0={}",
            hex_hmac_sha256(SLACK_SECRET.as_bytes(), format!("v0:{ts}:{body}").as_bytes())
        );
        let mut h = HashMap::new();
        h.insert("x-slack-signature".to_string(), sig);
        h.insert("x-slack-request-timestamp".to_string(), ts.to_string());
        (h, body.into_bytes())
    }

    fn slack_dm_payload(nonce: &str, allow: bool, channel: &str) -> String {
        json!({
            "user": {"id": "Uapprover"},
            "channel": {"id": channel},
            "trigger_id": "trg1",
            "response_url": "https://hooks.slack.com/actions/T0/1/abc",
            "actions": [{"value": format!("{}:{}", if allow {"a"} else {"d"}, nonce), "action_ts": "1.2"}]
        })
        .to_string()
    }

    #[test]
    fn slack_valid_button_click_yields_reply() {
        let (h, body) = slack_signed_at(&slack_dm_payload("abc123nonce", true, "D123"), now_secs());
        let replies = SlackVerifier::new(SLACK_SECRET.into())
            .verify_and_parse(&h, &body)
            .expect("verified");
        assert_eq!(replies.len(), 1);
        let r = &replies[0];
        assert_eq!(r.platform, "slack");
        assert_eq!(r.principal, "Uapprover");
        assert!(r.is_dm, "channel id starting with D → DM");
        assert_eq!(r.nonce, "abc123nonce");
        assert_eq!(r.msg_id, "trg1");
        assert!(r.allow);
        assert_eq!(
            r.response_url.as_deref(),
            Some("https://hooks.slack.com/actions/T0/1/abc"),
            "Slack response_url is captured for click feedback"
        );
    }

    #[test]
    fn slack_bad_signature_is_rejected() {
        let (mut h, body) = slack_signed_at(&slack_dm_payload("n", true, "D1"), now_secs());
        h.insert("x-slack-signature".into(), "v0=deadbeef".into());
        assert!(SlackVerifier::new(SLACK_SECRET.into())
            .verify_and_parse(&h, &body)
            .is_none());
    }

    #[test]
    fn slack_stale_timestamp_is_rejected() {
        // A correctly-signed request older than 5 minutes must be refused (replay).
        let (h, body) = slack_signed_at(&slack_dm_payload("n", true, "D1"), now_secs() - 1000);
        assert!(SlackVerifier::new(SLACK_SECRET.into())
            .verify_and_parse(&h, &body)
            .is_none());
    }

    #[test]
    fn slack_non_dm_channel_reported_as_not_dm() {
        let (h, body) = slack_signed_at(&slack_dm_payload("n", false, "C_public"), now_secs());
        let replies = SlackVerifier::new(SLACK_SECRET.into())
            .verify_and_parse(&h, &body)
            .expect("signature valid");
        assert_eq!(replies.len(), 1);
        assert!(!replies[0].is_dm, "public channel (C…) is not a DM");
        assert!(!replies[0].allow, "d: prefix → deny");
    }
}
