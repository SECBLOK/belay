//! `AiConfig` — the off-by-default AI explainer's on-disk config shape.
//!
//! Persisted as `~/.belay/ai.json`, following the same fail-soft JSON
//! read pattern as [`crate::host_config::read_json`]: a missing or
//! unparseable file yields the default config (`mode: Off`), never a panic or
//! a hard error. The explainer is fully inert unless an operator opts in by
//! writing `"mode": "local"` or `"mode": "cloud"`.

use serde::{Deserialize, Serialize};

/// The AI explainer's operating mode. Defaults to [`AiMode::Off`] — the
/// feature is inert unless an operator explicitly opts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiMode {
    #[default]
    Off,
    Local,
    Cloud,
}

fn default_provider() -> String {
    "ollama".to_string()
}

/// Cloud providers accepted in `mode: "cloud"` config. Every entry here has a
/// matching arm in `crate::ai::client_rig::RigClient::from_config` that
/// constructs the corresponding rig-core client — kept in sync manually
/// since the two live in different modules for different reasons: this list
/// validates operator input at `from_args` time (reject early, with a
/// message), while `client_rig` re-checks fail-safely at construction time
/// (`None`, no message) because it can be reached from paths (e.g. a
/// hand-edited `ai.json`) that never went through `from_args`.
const KNOWN_CLOUD_PROVIDERS: &[&str] = &[
    "anthropic",
    "openai",
    "gemini",
    "xai",
    "deepseek",
    "mistral",
    "groq",
    "cohere",
    "perplexity",
    "together",
    "openrouter",
    "minimax",
];

fn default_model() -> String {
    "qwen2.5".to_string()
}

/// AI explainer configuration, loaded from `~/.belay/ai.json`.
///
/// All fields are `#[serde(default)]` so a partial (or empty `{}`) config
/// file is still valid — any field the operator omits falls back to its
/// default rather than failing to parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default)]
    pub mode: AiMode,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub cloud_consent: bool,
    /// Per-task override for [`AiTask::Explain`]. `None` (the default) falls
    /// back to the global `model` — see [`AiConfig::model_for`].
    #[serde(default)]
    pub explain_model: Option<String>,
    /// Per-task override for [`AiTask::SkillJudge`]. `None` (the default)
    /// falls back to the global `model` — see [`AiConfig::model_for`].
    #[serde(default)]
    pub skill_judge_model: Option<String>,
    /// Separate opt-in from `mode != Off`: this flag lets the skill-install
    /// meta-filter (daemon/src/skills/judge.rs) actually run. Off by default —
    /// enabling the general explainer does NOT implicitly enable this, because
    /// this feature changes what the operator gets asked about, not just what
    /// text they're shown.
    #[serde(default)]
    pub skill_judge_enabled: bool,
    /// Separate opt-in from `skill_judge_enabled`: lets the SAME LLM
    /// meta-filter also run on the synchronous install-gate path
    /// (`judge_skill_gate` in daemon/src/skills/judge.rs), not just the
    /// async watcher. Off by default and independent of the watcher flag —
    /// an operator can enable the zero-latency async judge without opting
    /// into the latency-on-install synchronous one, or vice versa, because
    /// the gate path sits on the live tool-call critical path and a cold
    /// model changes the operator's install-time experience in a way the
    /// watcher path never does.
    #[serde(default)]
    pub skill_judge_gate_enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            mode: AiMode::default(),
            provider: default_provider(),
            model: default_model(),
            base_url: None,
            cloud_consent: false,
            explain_model: None,
            skill_judge_model: None,
            skill_judge_enabled: false,
            skill_judge_gate_enabled: false,
        }
    }
}

/// A distinct AI-backed task inside the daemon, each of which can be routed
/// to its own model via [`AiConfig::model_for`] (e.g. a small/fast model for
/// the synchronous skill-install gate vs. a larger one for on-demand
/// explanations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiTask {
    Explain,
    SkillJudge,
}

impl AiConfig {
    /// Load the AI config from an explicit path, fail-soft to the default
    /// (`mode: Off`) config if the file is absent or unparseable.
    pub fn load(path: &std::path::Path) -> AiConfig {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => AiConfig::default(),
        }
    }

    /// Load the AI config from its real on-disk location
    /// (`~/.belay/ai.json`), fail-soft to the default config.
    pub fn load_default() -> AiConfig {
        AiConfig::load(&crate::paths::data_dir().join("ai.json"))
    }

    /// Whether the AI explainer is enabled (any mode other than `Off`).
    pub fn enabled(&self) -> bool {
        !matches!(self.mode, AiMode::Off)
    }

    /// Resolve the model name to use for a given [`AiTask`]: the task's
    /// per-task override if set, else the global `model`.
    ///
    /// SECURITY INVARIANT: this returns a model NAME ONLY. It can never
    /// change `provider`, `mode`, `base_url`, or `cloud_consent` — those
    /// stay global and are never per-task. A per-task model override can
    /// therefore never route a task to a different provider, a different
    /// endpoint, or (most importantly) silently flip a local-only task to
    /// cloud: whatever provider/mode/base_url/cloud_consent the operator
    /// configured applies uniformly to every task, no matter which model
    /// name `model_for` resolves to.
    pub fn model_for(&self, task: AiTask) -> &str {
        match task {
            AiTask::Explain => self.explain_model.as_deref().unwrap_or(&self.model),
            AiTask::SkillJudge => self.skill_judge_model.as_deref().unwrap_or(&self.model),
        }
    }

    /// Persist to `path` as JSON, owner-only (0600; defense-in-depth — this
    /// struct itself never carries a secret field, so nothing here is ever
    /// written into `ai.json`. The cloud key resolves from the
    /// `BELAY_AI_KEY` env var or else a separate owner-only (0600) key
    /// file — see [`crate::ai::secret`] — never from this config). Atomic:
    /// write a sibling temp file in the same directory, chmod IT 0600, then
    /// rename over the target — so the real path is never observable at a
    /// looser (umask-default) mode, even momentarily on first creation, and
    /// a crash never leaves a truncated file at `path` (mirrors
    /// `channels_bridge::save_value`).
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist to the real on-disk location (`~/.belay/ai.json`).
    pub fn save_default(&self) -> Result<(), String> {
        self.save(&crate::paths::data_dir().join("ai.json"))
    }

    /// Build a validated `AiConfig` from an untyped args object (the shape the
    /// `set_ai_config` IPC arm receives from the GUI). Every field is optional
    /// and falls back to its default, mirroring [`AiConfig::load`]'s
    /// fail-soft-on-partial-input behavior — EXCEPT the cloud-consent
    /// invariant below, which is a hard validation error, not a silent
    /// fallback: cloud mode sends the flagged action off-box, so silently
    /// downgrading an operator's requested mode would be a privacy surprise,
    /// not a convenience.
    ///
    /// Cloud mode REQUIRES `cloud_consent == true`, and — likewise a hard
    /// error, not a silent fallback — `provider` must be one of
    /// [`KNOWN_CLOUD_PROVIDERS`].
    pub fn from_args(args: &serde_json::Value) -> Result<AiConfig, String> {
        let mode = match args.get("mode").and_then(|v| v.as_str()) {
            None => AiMode::Off,
            Some("off") => AiMode::Off,
            Some("local") => AiMode::Local,
            Some("cloud") => AiMode::Cloud,
            Some(other) => return Err(format!("invalid mode: {other}")),
        };
        let provider = args
            .get("provider")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(default_provider);
        let model = args
            .get("model")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(default_model);
        let base_url = args
            .get("base_url")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let explain_model = args
            .get("explain_model")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let skill_judge_model = args
            .get("skill_judge_model")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let cloud_consent = args
            .get("cloud_consent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let skill_judge_enabled = args
            .get("skill_judge_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let skill_judge_gate_enabled = args
            .get("skill_judge_gate_enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        if mode == AiMode::Cloud && !cloud_consent {
            return Err("cloud mode requires consent".to_string());
        }
        if mode == AiMode::Cloud && !KNOWN_CLOUD_PROVIDERS.contains(&provider.as_str()) {
            return Err(format!("unknown cloud provider: {provider}"));
        }

        Ok(AiConfig {
            mode,
            provider,
            model,
            base_url,
            cloud_consent,
            explain_model,
            skill_judge_model,
            skill_judge_enabled,
            skill_judge_gate_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A unique path under the system temp dir, cleaned up on drop.
    struct TempJsonFile {
        path: std::path::PathBuf,
    }

    impl TempJsonFile {
        fn new(suffix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "belayd-ai-config-test-{}-{}-{}.json",
                std::process::id(),
                suffix,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            TempJsonFile { path }
        }

        fn write(&self, contents: &str) {
            let mut f = std::fs::File::create(&self.path).expect("create temp ai.json");
            f.write_all(contents.as_bytes()).expect("write temp ai.json");
        }
    }

    impl Drop for TempJsonFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn load_missing_file_is_off_and_disabled() {
        let tmp = TempJsonFile::new("missing");
        // Deliberately do not write the file.
        let cfg = AiConfig::load(&tmp.path);
        assert_eq!(cfg.mode, AiMode::Off);
        assert!(!cfg.enabled());
    }

    #[test]
    fn load_local_mode_is_enabled() {
        let tmp = TempJsonFile::new("local");
        tmp.write(r#"{"mode":"local","model":"qwen2.5"}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert_eq!(cfg.mode, AiMode::Local);
        assert_eq!(cfg.model, "qwen2.5");
        assert!(cfg.enabled());
    }

    #[test]
    fn load_unparseable_file_fails_soft_to_off() {
        let tmp = TempJsonFile::new("garbage");
        tmp.write("not json at all {{{");
        let cfg = AiConfig::load(&tmp.path);
        assert_eq!(cfg.mode, AiMode::Off);
        assert!(!cfg.enabled());
    }

    #[test]
    fn load_cloud_mode_with_consent() {
        let tmp = TempJsonFile::new("cloud");
        tmp.write(r#"{"mode":"cloud","provider":"openai","cloud_consent":true}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert_eq!(cfg.mode, AiMode::Cloud);
        assert_eq!(cfg.provider, "openai");
        assert!(cfg.cloud_consent);
        assert!(cfg.enabled());
    }

    #[test]
    fn load_missing_skill_judge_enabled_key_defaults_false() {
        // An old ai.json written before this field existed must still parse,
        // with skill_judge_enabled defaulting to false (additive/backward-compatible).
        let tmp = TempJsonFile::new("no-skill-judge-key");
        tmp.write(r#"{"mode":"local","model":"qwen2.5"}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert!(!cfg.skill_judge_enabled);
    }

    #[test]
    fn load_skill_judge_enabled_true_round_trips() {
        let tmp = TempJsonFile::new("skill-judge-true");
        tmp.write(r#"{"mode":"local","skill_judge_enabled":true}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert!(cfg.skill_judge_enabled);
    }

    #[test]
    fn load_missing_skill_judge_gate_enabled_key_defaults_false() {
        // An old ai.json written before this field existed must still parse,
        // with skill_judge_gate_enabled defaulting to false
        // (additive/backward-compatible), independent of skill_judge_enabled.
        let tmp = TempJsonFile::new("no-skill-judge-gate-key");
        tmp.write(r#"{"mode":"local","skill_judge_enabled":true}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert!(cfg.skill_judge_enabled);
        assert!(!cfg.skill_judge_gate_enabled);
    }

    #[test]
    fn load_skill_judge_gate_enabled_true_round_trips() {
        let tmp = TempJsonFile::new("skill-judge-gate-true");
        tmp.write(r#"{"mode":"local","skill_judge_gate_enabled":true}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert!(cfg.skill_judge_gate_enabled);
        // Independent of the watcher flag, which was never set here.
        assert!(!cfg.skill_judge_enabled);
    }

    #[test]
    fn default_config_has_sensible_provider_and_model() {
        let cfg = AiConfig::default();
        assert_eq!(cfg.provider, "ollama");
        assert_eq!(cfg.model, "qwen2.5");
        assert_eq!(cfg.mode, AiMode::Off);
        assert!(!cfg.enabled());
    }

    // ── Task 1: `AiTask` + per-task model overrides + `model_for` resolver ────

    #[test]
    fn model_for_falls_back_to_global_model_when_overrides_absent() {
        let cfg = AiConfig {
            model: "qwen2.5".into(),
            ..AiConfig::default()
        };
        assert_eq!(cfg.model_for(AiTask::Explain), "qwen2.5");
        assert_eq!(cfg.model_for(AiTask::SkillJudge), "qwen2.5");
    }

    #[test]
    fn model_for_uses_per_task_override_when_set() {
        let cfg = AiConfig {
            model: "qwen2.5".into(),
            explain_model: Some("gemma3:4b".into()),
            skill_judge_model: Some("gemma4:27b".into()),
            ..AiConfig::default()
        };
        assert_eq!(cfg.model_for(AiTask::Explain), "gemma3:4b");
        assert_eq!(cfg.model_for(AiTask::SkillJudge), "gemma4:27b");
    }

    #[test]
    fn load_missing_per_task_model_keys_default_to_global_model() {
        let tmp = TempJsonFile::new("no-per-task-model-keys");
        tmp.write(r#"{"mode":"local","model":"qwen2.5"}"#);
        let cfg = AiConfig::load(&tmp.path);
        assert_eq!(cfg.explain_model, None);
        assert_eq!(cfg.skill_judge_model, None);
        assert_eq!(cfg.model_for(AiTask::Explain), "qwen2.5");
        assert_eq!(cfg.model_for(AiTask::SkillJudge), "qwen2.5");
    }

    #[test]
    fn default_model_is_still_qwen25_unchanged() {
        // Owner decision: recommend-only, no default bump.
        assert_eq!(AiConfig::default().model, "qwen2.5");
    }

    #[test]
    fn from_args_round_trips_per_task_models() {
        let args = serde_json::json!({
            "mode": "local",
            "skill_judge_model": "gemma4:27b"
        });
        let cfg = AiConfig::from_args(&args).unwrap();
        assert_eq!(cfg.skill_judge_model.as_deref(), Some("gemma4:27b"));
        assert_eq!(cfg.explain_model, None);
        assert_eq!(cfg.model_for(AiTask::SkillJudge), "gemma4:27b");
    }

    // ── Task 7: `from_args` validator (owner-gated `set_ai_config` IPC) ───────

    #[test]
    fn from_args_rejects_cloud_without_consent() {
        let args = serde_json::json!({"mode": "cloud", "provider": "openai"});
        let result = AiConfig::from_args(&args);
        assert!(result.is_err(), "cloud without consent must be rejected");
        assert!(result.unwrap_err().to_lowercase().contains("consent"));
    }

    #[test]
    fn from_args_accepts_cloud_with_consent() {
        let args = serde_json::json!({
            "mode": "cloud", "provider": "anthropic", "model": "claude", "cloud_consent": true
        });
        let cfg = AiConfig::from_args(&args).expect("cloud with consent must be accepted");
        assert_eq!(cfg.mode, AiMode::Cloud);
        assert_eq!(cfg.provider, "anthropic");
        assert_eq!(cfg.model, "claude");
        assert!(cfg.cloud_consent);
    }

    #[test]
    fn from_args_accepts_local_without_consent() {
        let args = serde_json::json!({"mode": "local", "model": "qwen2.5"});
        let cfg = AiConfig::from_args(&args).expect("local mode never needs consent");
        assert_eq!(cfg.mode, AiMode::Local);
        assert!(!cfg.cloud_consent);
    }

    #[test]
    fn from_args_accepts_off_and_defaults_missing_fields() {
        let cfg = AiConfig::from_args(&serde_json::json!({})).expect("empty args -> defaults");
        assert_eq!(cfg.mode, AiMode::Off);
        assert_eq!(cfg.provider, "ollama");
        assert_eq!(cfg.model, "qwen2.5");
        assert_eq!(cfg.base_url, None);
        assert!(!cfg.cloud_consent);
    }

    #[test]
    fn from_args_rejects_unknown_mode() {
        let args = serde_json::json!({"mode": "bogus"});
        assert!(AiConfig::from_args(&args).is_err());
    }

    /// Every rig-core-backed cloud provider must be accepted by the
    /// `set_ai_config` validator — this is the exhaustive whitelist that
    /// `client_rig::RigClient::from_config` also matches against (kept in
    /// sync manually since the two live in different modules for different
    /// reasons: this one validates operator input, that one constructs a
    /// rig-core client).
    #[test]
    fn from_args_accepts_all_known_cloud_providers() {
        for provider in [
            "anthropic",
            "openai",
            "gemini",
            "xai",
            "deepseek",
            "mistral",
            "groq",
            "cohere",
            "perplexity",
            "together",
            "openrouter",
            "minimax",
        ] {
            let args = serde_json::json!({
                "mode": "cloud", "provider": provider, "cloud_consent": true
            });
            let cfg = AiConfig::from_args(&args)
                .unwrap_or_else(|e| panic!("provider {provider} should be accepted: {e}"));
            assert_eq!(cfg.provider, provider);
            assert_eq!(cfg.mode, AiMode::Cloud);
        }
    }

    #[test]
    fn from_args_round_trips_skill_judge_enabled() {
        let args = serde_json::json!({"mode": "local", "skill_judge_enabled": true});
        let cfg = AiConfig::from_args(&args).expect("local mode with skill_judge_enabled");
        assert!(cfg.skill_judge_enabled);

        let args_absent = serde_json::json!({"mode": "local"});
        let cfg_absent = AiConfig::from_args(&args_absent).expect("skill_judge_enabled optional");
        assert!(!cfg_absent.skill_judge_enabled, "missing key must default to false");
    }

    #[test]
    fn from_args_round_trips_skill_judge_gate_enabled() {
        let args = serde_json::json!({"mode": "local", "skill_judge_gate_enabled": true});
        let cfg = AiConfig::from_args(&args).expect("local mode with skill_judge_gate_enabled");
        assert!(cfg.skill_judge_gate_enabled);
        assert!(!cfg.skill_judge_enabled, "must not implicitly enable the watcher flag");

        let args_absent = serde_json::json!({"mode": "local"});
        let cfg_absent =
            AiConfig::from_args(&args_absent).expect("skill_judge_gate_enabled optional");
        assert!(!cfg_absent.skill_judge_gate_enabled, "missing key must default to false");
    }

    #[test]
    fn from_args_skill_judge_flags_are_independent() {
        // Watcher on, gate off.
        let cfg = AiConfig::from_args(&serde_json::json!({
            "mode": "local", "skill_judge_enabled": true, "skill_judge_gate_enabled": false
        }))
        .expect("valid args");
        assert!(cfg.skill_judge_enabled);
        assert!(!cfg.skill_judge_gate_enabled);

        // Gate on, watcher off.
        let cfg2 = AiConfig::from_args(&serde_json::json!({
            "mode": "local", "skill_judge_enabled": false, "skill_judge_gate_enabled": true
        }))
        .expect("valid args");
        assert!(!cfg2.skill_judge_enabled);
        assert!(cfg2.skill_judge_gate_enabled);
    }

    #[test]
    fn from_args_rejects_unknown_cloud_provider() {
        let args = serde_json::json!({
            "mode": "cloud", "provider": "bogus", "cloud_consent": true
        });
        let result = AiConfig::from_args(&args);
        assert!(result.is_err(), "unknown cloud provider must be rejected");
        assert!(result.unwrap_err().to_lowercase().contains("provider"));
    }

    // ── Task 7: `save`/`load` round-trip ───────────────────────────────────────

    #[test]
    fn save_load_round_trips_all_fields() {
        let tmp = TempJsonFile::new("save-roundtrip");
        let cfg = AiConfig {
            mode: AiMode::Cloud,
            provider: "openai".to_string(),
            model: "gpt-5".to_string(),
            base_url: Some("https://example.invalid".to_string()),
            cloud_consent: true,
            explain_model: Some("gemma3:4b".to_string()),
            skill_judge_model: Some("gemma4:27b".to_string()),
            skill_judge_enabled: true,
            skill_judge_gate_enabled: true,
        };
        cfg.save(&tmp.path).expect("save must succeed");
        let loaded = AiConfig::load(&tmp.path);
        assert_eq!(loaded, cfg);
    }

    #[test]
    #[cfg(unix)]
    fn save_writes_file_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempJsonFile::new("save-perms");
        let cfg = AiConfig::default();
        cfg.save(&tmp.path).expect("save must succeed");
        let mode = std::fs::metadata(&tmp.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ai.json mode was {mode:o}, expected 600");
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let base = std::env::temp_dir().join(format!(
            "belayd-ai-config-test-parent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let path = base.join("nested").join("ai.json");
        let cfg = AiConfig::default();
        cfg.save(&path).expect("save must create missing parent dirs");
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
