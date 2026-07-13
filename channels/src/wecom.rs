//! WeCom / 企业微信 (WeChat Work) group-robot adapter: **notify-only**.
//!
//! Posts a markdown message to a WeCom group-robot webhook
//! (`https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=<key>`). This adapter
//! CANNOT approve — interactive WeCom app / Official-Account callbacks arrive over
//! an inbound webhook with AES message encryption + signature verification, which
//! needs the daemon's future inbound receiver — so [`listen`] returns immediately
//! and approval must come from a two-way channel or the local UI.
//!
//! Personal WeChat (weixin) has no official bot API and is intentionally NOT
//! supported. The correlation nonce is not included (not actionable from a WeCom
//! group, and possibly visible to non-approver members).
//!
//! [`listen`]: ChannelAdapter::listen

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;

pub struct WecomChannel {
    webhook_url: String,
    http: reqwest::Client,
}

impl WecomChannel {
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
impl ChannelAdapter for WecomChannel {
    fn platform(&self) -> &'static str {
        "wecom"
    }

    async fn notify(&self, _nonce: &str, req: &DecisionRequest) {
        // Fail closed: never POST to a non-HTTPS destination. The webhook URL
        // carries the robot `key` secret, so refusal logs only its scheme+host.
        if !crate::is_safe_base(&self.webhook_url) {
            eprintln!(
                "belay channels: refusing unsafe WeCom webhook url: {}",
                crate::redact_url(&self.webhook_url)
            );
            return;
        }
        let content = format!(
            "**🛡️ Belay approval**\n{}\n\n{}\nsession={} rule={}\n\nApprove from a two-way channel or the local UI.",
            req.summary, req.detail, req.session_id, req.rule_id
        );
        let body = json!({"msgtype": "markdown", "markdown": {"content": content}});
        let _ = self.http.post(&self.webhook_url).json(&body).send().await;
    }

    async fn listen(&self, _tx: mpsc::Sender<InboundReply>) {
        // Notify-only: no inbound path. Return immediately so the shared consumer
        // never waits on us; approvals come from a two-way channel or local UI.
    }
}
