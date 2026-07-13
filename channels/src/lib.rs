use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod discord;
pub mod inbound;
pub mod matrix;
pub mod mattermost;
pub mod ntfy;
pub mod router;
pub mod slack;
pub mod teams;
pub mod telegram;
pub mod terminal;
pub mod webhook;
pub mod wecom;
pub mod whatsapp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Debug)]
pub struct DecisionRequest {
    pub session_id: String,
    pub summary: String,
    pub detail: String,
    pub rule_id: String,
}

#[async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn ask(&self, req: &DecisionRequest, timeout: Duration) -> Decision;
}

/// A normalized inbound approval reply produced by a [`ChannelAdapter`]'s
/// listener. The adapter reports ONLY the platform's facts (who sent it, whether
/// it was a DM, the message id, the echoed correlation nonce, allow/deny). Every
/// trust decision is made downstream by the daemon's authorization gate — the
/// adapter is deliberately unprivileged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundReply {
    /// Adapter id, e.g. `"telegram"`.
    pub platform: String,
    /// Platform-native sender id (namespaced by `platform` for allowlist/dedup).
    pub principal: String,
    /// True only if the platform reports a 1:1 direct message.
    pub is_dm: bool,
    /// The correlation nonce the approver echoed back (from the outbound prompt).
    pub nonce: String,
    /// Platform-native message/interaction id, for at-most-once dedup.
    pub msg_id: String,
    /// The approver's intent: allow (true) or deny (false).
    pub allow: bool,
    /// Optional one-shot callback URL for click feedback (Slack `response_url`).
    /// Poll-based adapters edit the prompt in place instead and leave this `None`.
    pub response_url: Option<String>,
}

/// A bidirectional messaging adapter for the push-model approval flow: `notify`
/// sends the prompt (embedding the correlation nonce) to the approver, and
/// `listen` runs a long-lived task that feeds normalized [`InboundReply`] values
/// into the daemon's authorization gate. A single shared listener per platform
/// avoids competing consumers of one bot's update stream.
///
/// Both methods are best-effort: transient network errors are logged and retried
/// internally, never surfaced as an approval decision (fail-closed lives in the
/// daemon — a missing reply simply lets the park time out to DENY).
#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    /// Stable platform id, e.g. `"telegram"`. Must match the `platform` field the
    /// adapter stamps on every [`InboundReply`] it produces.
    fn platform(&self) -> &'static str;

    /// Send the approval prompt for `req`, embedding `nonce` so the approver's
    /// reply can be correlated back to this exact parked request.
    async fn notify(&self, nonce: &str, req: &DecisionRequest);

    /// Run the inbound listener until `tx` is closed (daemon shutdown). Each
    /// authorized-looking reply is normalized and sent on `tx`; the daemon gate
    /// decides whether it may resolve anything.
    async fn listen(&self, tx: tokio::sync::mpsc::Sender<InboundReply>);

    /// Signal that `nonce` was resolved (a click the daemon accepted), so an
    /// adapter that expires prompts on a timer can cancel the pending rewrite.
    /// Default: no-op — poll-based adapters see the click in their own `listen`
    /// loop and drop the nonce there. Slack has no poll loop (clicks arrive at
    /// the receiver), so it overrides this to keep an answered prompt from later
    /// being relabeled "expired".
    async fn on_resolved(&self, _nonce: &str) {}
}

/// True if `base` is a safe outbound base URL for a notification channel:
/// HTTPS to any host, or HTTP only to a loopback host (for local mock/self-host
/// proxies). Everything else — plaintext to a remote host, non-HTTP schemes, or
/// an unparseable value — is rejected, so a misconfigured `with_base()` cannot
/// send an approval prompt (and the embedded bot token) to an attacker-chosen
/// destination (SSRF / token exfiltration).
pub fn is_safe_base(base: &str) -> bool {
    if let Some(rest) = base.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(authority) = base.strip_prefix("http://") {
        return http_host_is_loopback(authority);
    }
    false
}

/// True if the `host[:port][/path]` authority names a loopback host. The host
/// must end at a port (`:`), path (`/`), or string end so a look-alike like
/// `127.0.0.1.evil.com` is not accepted.
fn http_host_is_loopback(authority: &str) -> bool {
    for h in ["localhost", "127.0.0.1", "[::1]"] {
        if let Some(rest) = authority.strip_prefix(h) {
            if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
                return true;
            }
        }
    }
    false
}

/// `scheme://host` of a URL, dropping path/query/fragment. Webhook-style URLs
/// commonly embed a secret in the path (Slack `hooks.slack.com/services/.../<token>`,
/// Discord `.../webhooks/<id>/<token>`, WeCom `.../send?key=<key>`), so refusal logs
/// must echo only the safe scheme+authority — never the full URL.
pub(crate) fn redact_url(url: &str) -> String {
    match url.find("://") {
        Some(i) => {
            let after = &url[i + 3..];
            let authority = after.split(['/', '?', '#']).next().unwrap_or("");
            // Drop any `user:pass@` userinfo — some webhook URLs carry a credential
            // there, which must not reach a log even in the scheme+host form.
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!("{}://{}", &url[..i], host)
        }
        None => "<redacted>".into(),
    }
}

#[cfg(test)]
mod base_url_tests {
    use super::is_safe_base;

    #[test]
    fn https_any_host_is_allowed() {
        assert!(is_safe_base("https://discord.com/api/v10"));
        assert!(is_safe_base("https://api.telegram.org"));
    }

    #[test]
    fn http_loopback_is_allowed() {
        assert!(is_safe_base("http://127.0.0.1:8080"));
        assert!(is_safe_base("http://localhost:9/mock"));
        assert!(is_safe_base("http://[::1]:1234"));
    }

    #[test]
    fn http_remote_is_rejected() {
        assert!(!is_safe_base("http://evil.com"));
        assert!(!is_safe_base("http://169.254.169.254/latest/meta-data")); // cloud metadata
    }

    #[test]
    fn loopback_lookalike_is_rejected() {
        assert!(!is_safe_base("http://127.0.0.1.evil.com"));
        assert!(!is_safe_base("http://localhostx.evil.com"));
    }

    #[test]
    fn non_http_and_empty_are_rejected() {
        assert!(!is_safe_base("ftp://x"));
        assert!(!is_safe_base("file:///etc/passwd"));
        assert!(!is_safe_base("https://"));
        assert!(!is_safe_base(""));
    }
}
