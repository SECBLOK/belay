//! Microsoft Teams adapter: **notify-only** (Incoming Webhook / MessageCard).
//!
//! On every parked ASK the daemon POSTs a MessageCard to the configured Teams
//! Incoming Webhook `url`, surfacing the prompt in a channel. This adapter CANNOT
//! approve — interactive Teams replies are delivered only to a bot's HTTPS
//! endpoint (Bot Framework), which needs the daemon's future inbound receiver —
//! so [`listen`] returns immediately and approval must come from a two-way
//! channel (Telegram/Discord/…) or the local UI.
//!
//! The correlation nonce is deliberately NOT included: it is not actionable from
//! a Teams channel and could be visible to non-approver channel members.
//!
//! [`listen`]: ChannelAdapter::listen

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;

pub struct TeamsChannel {
    webhook_url: String,
    http: reqwest::Client,
}

impl TeamsChannel {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            http: reqwest::Client::new(),
        }
    }
    /// Override the destination URL (mock/self-host); guarded by `is_safe_base`.
    pub fn with_base(mut self, base: String) -> Self {
        self.webhook_url = base;
        self
    }
}

#[async_trait]
impl ChannelAdapter for TeamsChannel {
    fn platform(&self) -> &'static str {
        "teams"
    }

    async fn notify(&self, _nonce: &str, req: &DecisionRequest) {
        // Fail closed: never POST the prompt to a non-HTTPS destination — a
        // misconfigured webhook URL must not become an SSRF / data-exfil sink.
        // The URL carries a secret, so refusal logs only its scheme+host.
        if !crate::is_safe_base(&self.webhook_url) {
            eprintln!(
                "belay channels: refusing unsafe Teams webhook url: {}",
                crate::redact_url(&self.webhook_url)
            );
            return;
        }
        let text = format!(
            "{}\n\n{}\n\nsession={} rule={}\n\nApprove from a two-way channel or the local UI.",
            req.summary, req.detail, req.session_id, req.rule_id
        );
        let card = json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "Belay approval",
            "themeColor": "D7263D",
            "title": "🛡️ Belay approval",
            "text": text,
        });
        let _ = self.http.post(&self.webhook_url).json(&card).send().await;
    }

    async fn listen(&self, _tx: mpsc::Sender<InboundReply>) {
        // Notify-only: no inbound path. Return immediately so the shared consumer
        // never waits on us; approvals come from a two-way channel or local UI.
    }
}
