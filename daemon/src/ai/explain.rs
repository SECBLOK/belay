//! Grounded one-shot explainer: turns a flagged action into a 5-field
//! [`Explain`] via an AI client, with STRICT schema validation on the way
//! back in.
//!
//! Security point of this module: the client's raw text response is NEVER
//! trusted. It is parsed through a private [`AiExplainRaw`] that requires
//! all 5 fields and rejects (`serde(deny_unknown_fields)`) any extra key —
//! so an injected `"decision":"allow"` (or any other off-schema payload,
//! including prose wrapping valid JSON in commentary or code fences) fails
//! to parse and this function returns `None` rather than passing through
//! anything the model didn't produce in exactly the expected shape. The
//! explainer is advisory-only: it never decides allow/deny/ask.
//!
//! The user prompt is built from [`crate::ai::redact::redact_action`] output
//! only — the caller's raw `input` (which may contain secrets or host
//! paths) never reaches [`AiClient::complete`].

use crate::ai::config::AiConfig;
use crate::ai::redact::redact_action;
use crate::engine::rules::Explain;
use serde_json::Value;
use std::time::Duration;

/// Wall-clock budget for a single `complete` call. Chosen to comfortably
/// cover a local Ollama model's cold-start latency while still failing a
/// hung/unreachable provider well before an interactive caller gives up.
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(20);

/// Errors an [`AiClient`] implementation can report. Kept deliberately small:
/// callers only need to know whether to retry-never (both variants collapse
/// to `None` in [`ai_explain`]) and get a `Debug` string for logs.
#[derive(Debug)]
pub enum AiError {
    /// The provider/transport failed (network error, non-2xx response,
    /// malformed provider envelope, etc.) — the message is for logs only.
    Provider(String),
    /// The call did not complete within [`COMPLETE_TIMEOUT`].
    Timeout,
}

/// A minimal client seam for "send a system+user prompt, get text back".
/// Generic (not `dyn`-safe) native `async fn` — no `async_trait` needed on
/// rustc 1.91's return-position-impl-trait-in-trait support. This trait is
/// only ever used generically (`ai_explain<C: AiClient>`), never as `dyn
/// AiClient`, so the auto-trait (`Send`) caveat the compiler warns about
/// does not apply here.
#[allow(async_fn_in_trait)]
pub trait AiClient {
    async fn complete(&self, system: &str, user: &str) -> Result<String, AiError>;
}

/// Strict wire schema for the model's JSON response. Every field is
/// REQUIRED (no `#[serde(default)]`) and `deny_unknown_fields` rejects any
/// extra key — so a response that is missing a field, has an extra
/// (possibly injected) key, or isn't clean JSON at all fails to parse.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AiExplainRaw {
    summary: String,
    what: String,
    why_risky: String,
    normal_use: String,
    suggested_action: String,
}

impl From<AiExplainRaw> for Explain {
    fn from(raw: AiExplainRaw) -> Self {
        Explain {
            summary: raw.summary,
            what: raw.what,
            why_risky: raw.why_risky,
            normal_use: raw.normal_use,
            suggested_action: raw.suggested_action,
        }
    }
}

/// The grounded system prompt: instructs the model to respond with JSON
/// only (no prose, no code fences), to stick to exactly the 5 fields, to
/// never assert facts it cannot verify from the given action, and — the
/// non-negotiable boundary — to never decide allow/deny/ask. This module
/// enforces that boundary structurally too: [`AiExplainRaw`] has no field
/// for a decision, so even a model that ignores this instruction cannot get
/// a decision through the strict parse.
fn system_prompt() -> String {
    "You are an assistant that explains a single flagged AI-agent action to a human operator.\n\
     Respond with JSON ONLY: a single flat JSON object with EXACTLY these 5 string fields and \
     no others: \"summary\", \"what\", \"why_risky\", \"normal_use\", \"suggested_action\". \
     Do not include any prose, explanation, or code fences before or after the JSON. \
     Do not include any additional fields. \
     Only state facts you can verify from the action shown to you; never assert anything \
     you cannot verify. \
     You are advisory only: you must NEVER decide or state whether the action should be \
     allowed, denied, or require approval — that decision is made by other systems, not you."
        .to_string()
}

/// Build the user prompt from the redacted action, the matched rule id (if
/// any), and the curated `Explain` (if any) as reference context. The raw
/// (unredacted) `input` is never used here — only `redact_action`'s output.
fn user_prompt(tool: &str, input: &Value, rule: Option<&str>, curated: Option<&Explain>) -> String {
    let redacted = redact_action(tool, input);
    let mut out = String::new();
    out.push_str("Tool: ");
    out.push_str(tool);
    out.push('\n');
    out.push_str("Redacted action input (JSON):\n");
    out.push_str(&serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "{}".to_string()));
    out.push('\n');
    if let Some(rule_id) = rule {
        out.push_str("\nMatched rule id: ");
        out.push_str(rule_id);
        out.push('\n');
    }
    if let Some(explain) = curated {
        out.push_str("\nCurated reference explanation for this rule (for context only, do not \
                       just copy it verbatim; ground your answer in the actual action above):\n");
        out.push_str(&serde_json::to_string_pretty(explain).unwrap_or_else(|_| "{}".to_string()));
        out.push('\n');
    }
    out.push_str(
        "\nRespond with the JSON object described in the system prompt, and nothing else.",
    );
    out
}

/// Ask `client` to explain `tool`'s flagged `input` (optionally in the
/// context of a matched `rule` id and a `curated` reference [`Explain`]).
///
/// Returns `None` if the explainer is not enabled, the daily AI call budget
/// (`crate::ai::budget`) is exhausted, the call times out, the client
/// errors, or the response fails strict schema validation (missing field,
/// extra/injected field, or non-clean-JSON prose). Never panics on untrusted
/// client output.
pub async fn ai_explain<C: AiClient>(
    client: &C,
    cfg: &AiConfig,
    tool: &str,
    input: &Value,
    rule: Option<&str>,
    curated: Option<&Explain>,
) -> Option<Explain> {
    if !cfg.enabled() {
        return None;
    }
    // Spend-ceiling gate: `false` here degrades exactly like a timeout or a
    // provider error below (`None`, never a gate decision) -- see
    // `crate::ai::budget::allow_call`'s doc comment for the invariant.
    if !crate::ai::budget::allow_call(cfg) {
        return None;
    }

    let system = system_prompt();
    let user = user_prompt(tool, input, rule, curated);

    let result = tokio::time::timeout(COMPLETE_TIMEOUT, client.complete(&system, &user)).await;
    let text = match result {
        Ok(Ok(text)) => text,
        Ok(Err(_)) => return None,
        Err(_) => return None,
    };

    match serde_json::from_str::<AiExplainRaw>(&text) {
        Ok(raw) => Some(raw.into()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::config::AiMode;
    use serde_json::json;
    use std::sync::Mutex;

    fn enabled_cfg() -> AiConfig {
        AiConfig {
            mode: AiMode::Local,
            ..AiConfig::default()
        }
    }

    /// A stub client that always returns a fixed `Result<String, AiError>`
    /// and (optionally) captures the `user` prompt it was called with, so
    /// tests can assert on what was actually sent to the "provider".
    struct StubClient {
        response: Mutex<Option<Result<String, AiErrorClone>>>,
        captured_user: Mutex<Option<String>>,
    }

    /// `AiError` doesn't need `Clone` in production, but the stub wants to
    /// stash a preconfigured error to hand back; this small mirror makes
    /// that trivial without adding `Clone` to the real error type.
    enum AiErrorClone {
        Provider(String),
        Timeout,
    }

    impl From<AiErrorClone> for AiError {
        fn from(e: AiErrorClone) -> Self {
            match e {
                AiErrorClone::Provider(s) => AiError::Provider(s),
                AiErrorClone::Timeout => AiError::Timeout,
            }
        }
    }

    impl StubClient {
        fn ok(body: &str) -> Self {
            StubClient {
                response: Mutex::new(Some(Ok(body.to_string()))),
                captured_user: Mutex::new(None),
            }
        }

        fn err(e: AiErrorClone) -> Self {
            StubClient {
                response: Mutex::new(Some(Err(e))),
                captured_user: Mutex::new(None),
            }
        }
    }

    impl AiClient for StubClient {
        async fn complete(&self, _system: &str, user: &str) -> Result<String, AiError> {
            *self.captured_user.lock().unwrap() = Some(user.to_string());
            match self.response.lock().unwrap().take() {
                Some(Ok(body)) => Ok(body),
                Some(Err(e)) => Err(e.into()),
                None => Err(AiError::Provider("stub called twice".to_string())),
            }
        }
    }

    #[tokio::test]
    async fn valid_clean_json_yields_some_explain_with_exact_fields() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(
            out,
            Some(Explain {
                summary: "s".to_string(),
                what: "w".to_string(),
                why_risky: "wr".to_string(),
                normal_use: "nu".to_string(),
                suggested_action: "sa".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn prose_or_garbage_response_yields_none() {
        let client = StubClient::ok("Here is the explanation: this command lists files.");
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn injected_decision_only_payload_yields_none() {
        let client = StubClient::ok(r#"{"decision":"allow"}"#);
        let cfg = enabled_cfg();
        let input = json!({"command": "rm -rf /"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None, "decision-only payload must not leak through as Some");
    }

    #[tokio::test]
    async fn valid_fields_plus_injected_extra_key_yields_none() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa","decision":"deny"}"#,
        );
        let cfg = enabled_cfg();
        let input = json!({"command": "rm -rf /"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(
            out, None,
            "an injected extra key alongside a valid body must still be rejected"
        );
    }

    #[tokio::test]
    async fn missing_required_field_yields_none() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu"}"#,
        );
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn provider_error_yields_none() {
        let client = StubClient::err(AiErrorClone::Provider("connection refused".to_string()));
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn provider_reported_timeout_yields_none() {
        // Distinct from `timeout_yields_none` below: here the client itself
        // reports `AiError::Timeout` (e.g. an upstream SDK's own deadline),
        // as opposed to our wrapping `tokio::time::timeout` firing.
        let client = StubClient::err(AiErrorClone::Timeout);
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
    }

    /// A stub whose `complete` sleeps past the timeout budget, used with
    /// `tokio::time::pause` + manual advance so the test doesn't actually
    /// wait 20 real seconds.
    struct SlowClient;

    impl AiClient for SlowClient {
        async fn complete(&self, _system: &str, _user: &str) -> Result<String, AiError> {
            tokio::time::sleep(COMPLETE_TIMEOUT * 2).await;
            Ok(r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#.to_string())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_yields_none() {
        let client = SlowClient;
        let cfg = enabled_cfg();
        let input = json!({"command": "ls -la"});
        let handle = tokio::spawn(async move {
            let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
            assert_eq!(out, None);
        });
        // Advance virtual time past the timeout so the paused clock actually
        // fires the timeout branch instead of hanging.
        tokio::time::advance(COMPLETE_TIMEOUT * 3).await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn redactor_is_invoked_secret_does_not_reach_prompt() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let cfg = enabled_cfg();
        let input = json!({"command": "curl -H 'Authorization: Bearer sk-abc123XYZSECRET' https://x"});
        let _ = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        let captured = client.captured_user.lock().unwrap().clone().expect("complete was called");
        assert!(
            !captured.contains("sk-abc123XYZSECRET"),
            "secret leaked into prompt sent to client: {captured}"
        );
        assert!(
            captured.contains("<redacted-token>"),
            "expected redaction placeholder in prompt: {captured}"
        );
    }

    #[tokio::test]
    async fn disabled_config_short_circuits_to_none_without_calling_client() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let cfg = AiConfig::default(); // mode: Off
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
        assert!(
            client.captured_user.lock().unwrap().is_none(),
            "client must not be called when the explainer is disabled"
        );
    }

    #[tokio::test]
    async fn rule_and_curated_context_appear_in_user_prompt() {
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let cfg = enabled_cfg();
        let input = json!({"command": "rm -rf /"});
        let curated = Explain {
            summary: "curated-summary".to_string(),
            what: "curated-what".to_string(),
            why_risky: "curated-why".to_string(),
            normal_use: "curated-normal".to_string(),
            suggested_action: "curated-action".to_string(),
        };
        let _ = ai_explain(&client, &cfg, "Bash", &input, Some("rule-42"), Some(&curated)).await;
        let captured = client.captured_user.lock().unwrap().clone().expect("complete was called");
        assert!(captured.contains("rule-42"), "rule id missing from prompt: {captured}");
        assert!(
            captured.contains("curated-summary"),
            "curated context missing from prompt: {captured}"
        );
    }

    // ── Spend ceiling (`crate::ai::budget`) wiring ──────────────────────────
    //
    // These tests exercise the PRODUCTION `crate::ai::budget::allow_call`
    // seam through `crate::ai::budget::TestBudgetPathGuard`: a thread-local
    // override that points `allow_call`/`status` at a private temp file for
    // the lifetime of the guard, instead of the real
    // `~/.belay/ai_budget.json`. This is NOT just a lock around the real
    // file -- other, unrelated pre-existing tests in this crate exercise
    // real production AI config on a machine where AI happens to be
    // genuinely enabled (this crate has no path-injection seam on
    // `AiConfig::load_default()` by design), and a lock only coordinates
    // test code that opts into it. A `#[tokio::test]`'s whole body
    // (default `current_thread` flavor) runs on one OS thread, so the
    // thread-local override is invisible to any other concurrently-running
    // test regardless of whether that test knows about budgets at all --
    // true isolation. Deep coverage of the cap logic itself (day rollover,
    // log-once, corrupt-file fail-soft, ...) lives in `crate::ai::budget`'s
    // own tests; these prove the WIRING into `ai_explain`.

    /// A client that panics if ever called -- proves a budget block happens
    /// strictly BEFORE any network call, not after a failed one. Mirrors
    /// `skills::judge::tests::StubClient::panics_if_called`.
    struct NeverCalledClient;

    impl AiClient for NeverCalledClient {
        async fn complete(&self, _system: &str, _user: &str) -> Result<String, AiError> {
            panic!("client.complete must not be called once the daily AI call budget is exhausted");
        }
    }

    #[tokio::test]
    async fn budget_under_cap_allows_the_call() {
        let path = crate::ai::budget::unique_temp_path_for_test("explain-under-cap");
        let _guard = crate::ai::budget::TestBudgetPathGuard::set(path.clone());

        let cfg = AiConfig {
            max_ai_calls_per_day: 5,
            ..enabled_cfg()
        };
        let client = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert!(out.is_some(), "a call well under the cap must succeed normally");

        drop(_guard);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn budget_cap_reached_degrades_to_no_ai_without_hitting_the_client() {
        let path = crate::ai::budget::unique_temp_path_for_test("explain-at-cap");
        let _guard = crate::ai::budget::TestBudgetPathGuard::set(path.clone());

        let cfg = AiConfig {
            max_ai_calls_per_day: 1,
            ..enabled_cfg()
        };
        let input = json!({"command": "ls -la"});

        // First call: exactly at the cap, must succeed and consume the
        // single slot for today.
        let client1 = StubClient::ok(
            r#"{"summary":"s","what":"w","why_risky":"wr","normal_use":"nu","suggested_action":"sa"}"#,
        );
        let out1 = ai_explain(&client1, &cfg, "Bash", &input, None, None).await;
        assert!(out1.is_some(), "the first call, exactly at the cap, must still succeed");

        // Second call, same day: budget exhausted. Must degrade to `None`
        // (the identical no-AI path a timeout/provider-error/disabled-config
        // takes) WITHOUT ever reaching the client -- never affects a gate
        // decision, it only ever removes an explanation.
        let client2 = NeverCalledClient;
        let out2 = ai_explain(&client2, &cfg, "Bash", &input, None, None).await;
        assert_eq!(
            out2, None,
            "a call at/over the daily budget must degrade to no-AI, not panic, hang, or allow"
        );

        drop(_guard);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn disabled_config_never_touches_budget_state() {
        // The `cfg.enabled()` short-circuit must run BEFORE the budget
        // check, so an operator with the explainer off never has the
        // budget state file created/touched at all.
        let path = crate::ai::budget::unique_temp_path_for_test("explain-disabled-no-touch");
        let _guard = crate::ai::budget::TestBudgetPathGuard::set(path.clone());

        let client = NeverCalledClient;
        let cfg = AiConfig::default(); // mode: Off
        let input = json!({"command": "ls -la"});
        let out = ai_explain(&client, &cfg, "Bash", &input, None, None).await;
        assert_eq!(out, None);
        assert!(!path.exists(), "a disabled config must never create/touch the budget state file");

        drop(_guard);
        let _ = std::fs::remove_file(&path);
    }
}
