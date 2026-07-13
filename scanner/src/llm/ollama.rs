use crate::llm::{parse_verdict, LlmProvider, LlmVerdict};

pub struct OllamaProvider {
    http: reqwest::Client,
    model: String,
    base: String,
}

impl OllamaProvider {
    pub fn new(model: &str, base: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            model: model.to_string(),
            base: base.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for OllamaProvider {
    async fn judge(&self, prompt: &str) -> anyhow::Result<LlmVerdict> {
        let body = serde_json::json!({
            "model": self.model,
            "stream": false,
            "messages": [{ "role": "user", "content": prompt }],
        });
        let resp = self
            .http
            .post(format!("{}/api/chat", self.base))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        let v: serde_json::Value = resp.json().await?;
        let text = v["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("ollama: no message content"))?;
        parse_verdict(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn ollama_builds_request_and_parses_verdict() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {
                    "role": "assistant",
                    "content": "{\"confirmed\": false, \"confidence\": 0.6}"
                }
            })))
            .mount(&server)
            .await;

        let p = OllamaProvider::new("llama3", &server.uri());
        let v = p.judge("is this real?").await.unwrap();
        assert_eq!(
            v,
            crate::llm::LlmVerdict {
                confirmed: false,
                confidence: 0.6
            }
        );
    }
}
