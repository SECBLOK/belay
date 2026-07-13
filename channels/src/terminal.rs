use crate::{Decision, DecisionRequest, NotificationChannel};
use async_trait::async_trait;
use std::time::Duration;

type InFn = Box<dyn Fn() -> Option<String> + Send + Sync>;
type OutFn = Box<dyn Fn(&str) + Send + Sync>;

pub struct TerminalChannel {
    input_fn: InFn,
    output_fn: OutFn,
}

impl TerminalChannel {
    pub fn new(input_fn: InFn, output_fn: OutFn) -> Self {
        Self {
            input_fn,
            output_fn,
        }
    }
}

#[async_trait]
impl NotificationChannel for TerminalChannel {
    async fn ask(&self, req: &DecisionRequest, _timeout: Duration) -> Decision {
        (self.output_fn)(&format!(
            "[Belay] {}\n{}\nAllow? [y/N] ",
            req.summary, req.detail
        ));
        let ans = (self.input_fn)().unwrap_or_default();
        match ans.trim().to_lowercase().as_str() {
            "y" | "yes" | "allow" => Decision::Allow,
            _ => Decision::Deny,
        }
    }
}
