//! LLM provider trait and the deterministic mock used by parity tests.
use std::collections::HashMap;

pub mod anthropic;
pub mod cascade;
pub mod ollama;
pub mod openai;

#[derive(Debug, Clone, PartialEq)]
pub struct LlmVerdict {
    pub confirmed: bool,
    pub confidence: f64,
}

impl Default for LlmVerdict {
    fn default() -> Self {
        Self {
            confirmed: true,
            confidence: 1.0,
        }
    }
}

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict>;
}

/// Parse `{"confirmed": bool, "confidence": float}` out of a model's free-text
/// reply, tolerating leading/trailing prose around the JSON object. Mirrors the
/// Python judge defaults: confirmed=true, confidence=1.0 when a key is missing.
pub fn parse_verdict(text: &str) -> anyhow::Result<LlmVerdict> {
    let start = text
        .find('{')
        .ok_or_else(|| anyhow::anyhow!("no json object in reply"))?;
    let end = text
        .rfind('}')
        .ok_or_else(|| anyhow::anyhow!("no json object in reply"))?;
    let obj: serde_json::Value = serde_json::from_str(&text[start..=end])?;
    Ok(LlmVerdict {
        confirmed: obj
            .get("confirmed")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        confidence: obj
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0),
    })
}

/// Deterministic provider: prompt -> fixed verdict. Used by every parity test.
pub struct MockProvider {
    pub verdicts: HashMap<String, LlmVerdict>,
    pub default: LlmVerdict,
}

#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict> {
        Ok(self
            .verdicts
            .get(prompt)
            .cloned()
            .unwrap_or_else(|| self.default.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_returns_configured_verdict() {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "p1".to_string(),
            LlmVerdict {
                confirmed: false,
                confidence: 0.9,
            },
        );
        let mock = MockProvider {
            verdicts: m,
            default: LlmVerdict {
                confirmed: true,
                confidence: 1.0,
            },
        };
        assert_eq!(
            mock.judge("p1").await.unwrap(),
            LlmVerdict {
                confirmed: false,
                confidence: 0.9
            }
        );
        assert_eq!(
            mock.judge("other").await.unwrap(),
            LlmVerdict {
                confirmed: true,
                confidence: 1.0
            }
        );
    }
}
