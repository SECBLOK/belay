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
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            mode: AiMode::default(),
            provider: default_provider(),
            model: default_model(),
            base_url: None,
            cloud_consent: false,
        }
    }
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
        let cloud_consent = args
            .get("cloud_consent")
            .and_then(|v| v.as_bool())
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
    fn default_config_has_sensible_provider_and_model() {
        let cfg = AiConfig::default();
        assert_eq!(cfg.provider, "ollama");
        assert_eq!(cfg.model, "qwen2.5");
        assert_eq!(cfg.mode, AiMode::Off);
        assert!(!cfg.enabled());
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
