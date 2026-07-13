use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;

/// Generic outbound-webhook adapter: **notify-only**. On every parked ASK the
/// daemon fires a single JSON `POST` to the configured `url`, carrying the
/// correlation `nonce` plus the request summary/detail/session/rule so an
/// external system (a bot, a pager, a chatops relay) can surface the prompt.
///
/// This adapter CANNOT approve: it has no inbound path, so [`listen`] returns
/// immediately and never produces an [`InboundReply`]. Approval must arrive via a
/// two-way channel (Telegram/Discord) or the local UI; this webhook only alerts.
///
/// [`listen`]: ChannelAdapter::listen
pub struct WebhookChannel {
    url: String,
    http: reqwest::Client,
}

impl WebhookChannel {
    pub fn new(url: String) -> Self {
        Self {
            url,
            http: reqwest::Client::new(),
        }
    }
    /// Override the destination URL (mock/self-host); guarded by `is_safe_base`.
    pub fn with_base(mut self, base: String) -> Self {
        self.url = base;
        self
    }
}

#[async_trait]
impl ChannelAdapter for WebhookChannel {
    fn platform(&self) -> &'static str {
        "webhook"
    }

    async fn notify(&self, nonce: &str, req: &DecisionRequest) {
        // Fail closed: never POST the prompt to a non-HTTPS remote destination —
        // a misconfigured `url` must not become an SSRF / data-exfil sink.
        if !crate::is_safe_base(&self.url) {
            eprintln!(
                "belay channels: refusing unsafe webhook url: {}",
                crate::redact_url(&self.url)
            );
            return;
        }
        let _ = self
            .http
            .post(&self.url)
            .json(&json!({
                "nonce": nonce,
                "summary": req.summary,
                "detail": req.detail,
                "session": req.session_id,
                "rule": req.rule_id,
            }))
            .send()
            .await;
    }

    async fn listen(&self, _tx: mpsc::Sender<InboundReply>) {
        // Notify-only: no inbound path. Return immediately so the shared consumer
        // never waits on us; approvals come from a two-way channel or local UI.
    }
}
