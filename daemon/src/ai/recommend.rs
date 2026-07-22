//! Per-provider model recommendations — pure data, no network calls and no
//! model discovery. Surfaced read-only via the `get_ai_config` IPC arm (see
//! `crate::ipc`) so the settings UI can suggest sensible `model` /
//! `skill_judge_model` values without the operator having to go look them up.
//!
//! Deliberately NOT a substitute for `AiConfig::model_for`: this module never
//! reads or writes `ai.json`, and nothing here changes what model a request
//! actually uses — it only informs what an operator might choose to set.
//! Unknown / unresearched providers get `None`, never a guess.

/// A suggested "fast" (cheap/latency-sensitive) model and a suggested
/// "judge"-capable model for a given provider, plus a short human-readable
/// note (hardware/pricing/retirement caveats where relevant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelRecommendation {
    pub fast: &'static str,
    pub recommended_judge: &'static str,
    pub note: &'static str,
}

/// Look up the recommended fast/judge model pair for a provider string (the
/// same value stored in `AiConfig::provider`). Returns `None` for any
/// provider not in the researched list below — no guessing, no fallback to a
/// "generic" recommendation.
pub fn recommend_for(provider: &str) -> Option<ModelRecommendation> {
    match provider {
        "ollama" => Some(ModelRecommendation {
            fast: "qwen3:8b",
            recommended_judge: "gemma4:27b",
            note: "gemma4:27b is a capable local judge but needs a GPU or it \
                   blows the 5s gate timeout; CPU-only hosts should stay on \
                   qwen3:8b, or granite4:8b as a CPU-friendly JSON-specialist \
                   alternative.",
        }),
        "anthropic" => Some(ModelRecommendation {
            fast: "claude-haiku-4-5",
            recommended_judge: "claude-sonnet-5",
            note: "Haiku for cheap/fast explanations; Sonnet for the more \
                   demanding judge task.",
        }),
        "openai" => Some(ModelRecommendation {
            fast: "gpt-5-mini",
            recommended_judge: "gpt-5.6-terra",
            note: "gpt-5-mini for cheap/fast explanations; gpt-5.6-terra for \
                   the more demanding judge task.",
        }),
        "gemini" => Some(ModelRecommendation {
            fast: "gemini-3.1-flash-lite",
            recommended_judge: "gemini-3.5-flash",
            note: "gemini-3.1-flash-lite for cheap/fast explanations; \
                   gemini-3.5-flash for the more demanding judge task.",
        }),
        "deepseek" => Some(ModelRecommendation {
            fast: "deepseek-v4-flash",
            recommended_judge: "deepseek-v4-pro",
            note: "Use the v4 model IDs, not the deepseek-chat/deepseek-reasoner \
                   aliases — those were retired 2026-07-24.",
        }),
        "mistral" => Some(ModelRecommendation {
            fast: "mistral-small-latest",
            recommended_judge: "mistral-large-latest",
            note: "mistral-small-latest for cheap/fast explanations; \
                   mistral-large-latest for the more demanding judge task. \
                   Note the current pricing inversion: mistral-medium costs \
                   MORE than mistral-large, so medium is not a cheaper \
                   in-between option.",
        }),
        "groq" => Some(ModelRecommendation {
            fast: "llama-3.1-8b-instant",
            recommended_judge: "llama-3.3-70b-versatile",
            note: "llama-3.1-8b-instant for cheap/fast explanations; \
                   llama-3.3-70b-versatile for the more demanding judge task.",
        }),
        "xai" => Some(ModelRecommendation {
            fast: "grok-4.3",
            recommended_judge: "grok-4.5",
            note: "grok-4.3 for cheap/fast explanations; grok-4.5 for the \
                   more demanding judge task.",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_providers_have_recommendations() {
        for p in [
            "ollama", "anthropic", "openai", "gemini", "deepseek", "mistral", "groq", "xai",
        ] {
            assert!(recommend_for(p).is_some(), "missing rec for {p}");
        }
    }

    #[test]
    fn ollama_note_flags_cpu_vs_gpu() {
        let r = recommend_for("ollama").unwrap();
        assert_eq!(r.fast, "qwen3:8b");
        assert_eq!(r.recommended_judge, "gemma4:27b");
        assert!(r.note.to_lowercase().contains("gpu")); // hardware advisory present
    }

    #[test]
    fn unknown_provider_has_no_recommendation() {
        assert!(recommend_for("cohere").is_none()); // not researched -> no guidance
        assert!(recommend_for("totally-unknown").is_none());
    }

    #[test]
    fn deepseek_uses_v4_ids_not_retired_aliases() {
        let r = recommend_for("deepseek").unwrap();
        assert!(!r.fast.contains("chat") && !r.fast.contains("reasoner"));
        assert!(r.recommended_judge.starts_with("deepseek-v4"));
    }

    #[test]
    fn all_provider_ids_are_distinct_from_fast_to_judge() {
        // Sanity: fast and judge should never be identical (a "recommendation"
        // that suggests the same model for both isn't actually routing).
        for p in [
            "ollama", "anthropic", "openai", "gemini", "deepseek", "mistral", "groq", "xai",
        ] {
            let r = recommend_for(p).unwrap();
            assert_ne!(r.fast, r.recommended_judge, "fast == judge for {p}");
        }
    }
}
