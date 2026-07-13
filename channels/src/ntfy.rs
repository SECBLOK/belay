//! ntfy.sh push adapter — **notify-only**.
//!
//! ntfy is a fire-and-forget pub/sub push service: the daemon POSTs an approval
//! prompt to a topic and every subscriber's phone/desktop buzzes. There is no
//! interactive reply channel wired here — ntfy *can* carry action buttons, but
//! this adapter deliberately only ALERTS; it cannot APPROVE. Actual approval must
//! come from a two-way channel (Telegram/…) or the local UI.
//!
//! Accordingly [`notify`] is implemented fully and [`listen`] returns immediately
//! (a notify-only adapter has no inbound stream to consume), so it never feeds an
//! [`InboundReply`] into the daemon's authorization gate. The daemon still fails
//! closed: with no reply, the parked request simply times out to DENY.
//!
//! [`notify`]: ChannelAdapter::notify
//! [`listen`]: ChannelAdapter::listen

use crate::{ChannelAdapter, DecisionRequest, InboundReply};
use async_trait::async_trait;
use tokio::sync::mpsc;

pub struct NtfyChannel {
    topic: String,
    token: Option<String>,
    api_base: String,
    http: reqwest::Client,
}

impl NtfyChannel {
    pub fn new(topic: String) -> Self {
        Self {
            topic,
            token: None,
            api_base: "https://ntfy.sh".into(),
            http: reqwest::Client::new(),
        }
    }
    pub fn with_base(mut self, base: String) -> Self {
        self.api_base = base;
        self
    }
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }
    fn url(&self) -> String {
        format!("{}/{}", self.api_base, self.topic)
    }
}

#[async_trait]
impl ChannelAdapter for NtfyChannel {
    fn platform(&self) -> &'static str {
        "ntfy"
    }

    async fn notify(&self, _nonce: &str, req: &DecisionRequest) {
        // Fail closed: never publish the prompt (or the access token) to a
        // non-HTTPS remote base — a misconfigured `with_base()` must not SSRF.
        if !crate::is_safe_base(&self.api_base) {
            eprintln!(
                "belay channels: refusing unsafe ntfy base: {}",
                self.api_base
            );
            return;
        }
        // Notify-only: this is an alert, not an approval prompt. We do NOT ask the
        // recipient to reply with the nonce here — ntfy carries no reply back into
        // the gate, so approval must happen on a two-way channel or the local UI.
        let text = format!(
            "{}\n\n{}\nsession={}",
            req.summary, req.detail, req.session_id
        );
        let mut r = self
            .http
            .post(self.url())
            .header("Title", "Belay approval");
        if let Some(token) = &self.token {
            r = r.header("Authorization", format!("Bearer {token}"));
        }
        let _ = r.body(text).send().await;
    }

    async fn listen(&self, _tx: mpsc::Sender<InboundReply>) {
        // Notify-only adapter: no inbound reply stream. Return immediately so the
        // shared listener set stays healthy; approvals arrive via a two-way
        // channel or the local UI, never through ntfy.
    }
}
