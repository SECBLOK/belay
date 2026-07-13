use crate::llm::{parse_verdict, LlmProvider, LlmVerdict};

pub struct AnthropicProvider {
    http: reqwest::Client,
    api_key: String,
    model: String,
    base: String,
}

impl AnthropicProvider {
    pub fn new(api_key: &str, model: &str, base: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            base: base.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 256,
            "messages": [{ "role": "user", "content": prompt }],
        });
        let resp = self
            .http
            .post(format!("{}/v1/messages", self.base))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = resp.json().await?;
        let text = v["content"][0]["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("anthropic: no text block"))?;
        parse_verdict(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn anthropic_builds_request_and_parses_verdict() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "k"))
            .and(header("anthropic-version", "2023-06-01"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{ "type": "text",
                    "text": "{\"confirmed\": false, \"confidence\": 0.8}" }]
            })))
            .mount(&server)
            .await;

        let p = AnthropicProvider::new("k", "claude-sonnet-4-5", &server.uri());
        let v = p.judge("is this real?").await.unwrap();
        assert_eq!(
            v,
            crate::llm::LlmVerdict {
                confirmed: false,
                confidence: 0.8
            }
        );
    }
}
