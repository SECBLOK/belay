use crate::llm::{parse_verdict, LlmProvider, LlmVerdict};

pub struct OpenAiProvider {
    http: reqwest::Client,
    api_key: String,
    model: String,
    base: String,
}

impl OpenAiProvider {
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
impl LlmProvider for OpenAiProvider {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": prompt }],
        });
        let resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = resp.json().await?;
        let text = v["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("openai: no message content"))?;
        parse_verdict(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn openai_builds_request_and_parses_verdict() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "{\"confirmed\": true, \"confidence\": 0.95}"
                    }
                }]
            })))
            .mount(&server)
            .await;

        let p = OpenAiProvider::new("sk-test", "gpt-4o", &server.uri());
        let v = p.judge("is this real?").await.unwrap();
        assert_eq!(
            v,
            crate::llm::LlmVerdict {
                confirmed: true,
                confidence: 0.95
            }
        );
    }
}
