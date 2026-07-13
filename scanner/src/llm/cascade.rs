//! Provider cascade: Ollama (offline) -> Anthropic -> OpenAI -> heuristic.
//! Each stage is tried in order; an Err falls through to the next stage.
use crate::llm::{LlmProvider, LlmVerdict};

/// Terminal fallback. Never errors. Returns the fail-closed "keep" verdict so a
/// fully-offline box with no LLM still produces deterministic, safe behavior.
pub struct HeuristicProvider;

#[async_trait::async_trait]
impl LlmProvider for HeuristicProvider {
    async fn judge(&self, _prompt: &str) -> anyhow::Result<LlmVerdict> {
        Ok(LlmVerdict {
            confirmed: true,
            confidence: 1.0,
        })
    }
}

pub struct CascadeProvider {
    stages: Vec<Box<dyn LlmProvider>>,
}

impl CascadeProvider {
    pub fn new(stages: Vec<Box<dyn LlmProvider>>) -> Self {
        Self { stages }
    }
}

#[async_trait::async_trait]
impl LlmProvider for CascadeProvider {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict> {
        let mut last_err = None;
        for stage in &self.stages {
            match stage.judge(prompt).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("empty cascade")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmProvider, LlmVerdict};

    struct Boom;
    #[async_trait::async_trait]
    impl LlmProvider for Boom {
        async fn judge(&self, _p: &str) -> anyhow::Result<LlmVerdict> {
            anyhow::bail!("down")
        }
    }
    struct Ok09;
    #[async_trait::async_trait]
    impl LlmProvider for Ok09 {
        async fn judge(&self, _p: &str) -> anyhow::Result<LlmVerdict> {
            Ok(LlmVerdict {
                confirmed: true,
                confidence: 0.9,
            })
        }
    }

    #[tokio::test]
    async fn falls_through_failed_stages() {
        let c = CascadeProvider::new(vec![Box::new(Boom), Box::new(Boom), Box::new(Ok09)]);
        let v = c.judge("x").await.unwrap();
        assert_eq!(
            v,
            LlmVerdict {
                confirmed: true,
                confidence: 0.9
            }
        );
    }

    #[tokio::test]
    async fn heuristic_terminal_never_errors() {
        let c = CascadeProvider::new(vec![Box::new(Boom), Box::new(HeuristicProvider)]);
        let v = c.judge("x").await.unwrap();
        assert_eq!(
            v,
            LlmVerdict {
                confirmed: true,
                confidence: 1.0
            }
        ); // keep = fail-closed
    }
}
