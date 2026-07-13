use crate::{Decision, DecisionRequest, NotificationChannel};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use std::time::Duration;

pub struct Router {
    channels: Vec<Box<dyn NotificationChannel>>,
    timeout: Duration,
    on_timeout: Decision,
}

impl Router {
    pub fn new(
        channels: Vec<Box<dyn NotificationChannel>>,
        timeout: Duration,
        on_timeout: Decision,
    ) -> Self {
        Self {
            channels,
            timeout,
            on_timeout,
        }
    }

    pub async fn escalate(&self, req: &DecisionRequest) -> Decision {
        if self.channels.is_empty() {
            return self.on_timeout.clone();
        }
        let mut futs: FuturesUnordered<_> = self
            .channels
            .iter()
            .map(|c| c.ask(req, self.timeout))
            .collect();
        let race = async {
            while let Some(res) = futs.next().await {
                if matches!(res, Decision::Allow | Decision::Deny) {
                    return res;
                }
            }
            self.on_timeout.clone()
        };
        match tokio::time::timeout(self.timeout, race).await {
            Ok(d) => d,
            Err(_) => self.on_timeout.clone(),
        }
    }
}

pub struct MockChannel {
    responses: std::sync::Mutex<Vec<Decision>>,
}
impl MockChannel {
    pub fn new(responses: Vec<Decision>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses),
        }
    }
}
#[async_trait]
impl NotificationChannel for MockChannel {
    async fn ask(&self, _req: &DecisionRequest, _t: Duration) -> Decision {
        let mut g = self.responses.lock().unwrap();
        if g.is_empty() {
            Decision::Deny
        } else {
            g.remove(0)
        }
    }
}
