//! Severity-gated LLM judge. Exact port of `scan/meta.py::meta_filter`.
//!
//! Security guarantees (identical to Python):
//! - CRITICAL and HIGH findings are NEVER dropped (FLOOR_SEVERITY = High).
//! - Below the floor, drop only when `!confirmed && confidence >= 0.6`.
//! - Fail-closed: any provider error keeps this finding + all remaining ones unfiltered.
//! - `llm = None` → findings returned unchanged.

use crate::llm::LlmProvider;
use crate::pipeline::FileCache;
use crate::types::{Finding, Severity};

pub const FLOOR_SEVERITY: Severity = Severity::High;
pub const CONFIDENCE_THRESHOLD: f64 = 0.6;

/// Build a confirmation prompt for the LLM.
///
/// Output is byte-identical to `meta.py::_build_prompt` (using `py_name()` for
/// the Severity line so it emits uppercase "HIGH"/"CRITICAL"/… matching Python's
/// `finding.severity.name`).
pub fn build_prompt(finding: &Finding, file_cache: &FileCache) -> String {
    let mut ctx_blocks: Vec<String> = Vec::new();
    for (path, content) in file_cache.iter() {
        if finding.reason.contains(path.as_str()) {
            let snippet: Vec<&str> = content.lines().take(20).collect();
            ctx_blocks.push(format!("File: {}\n{}", path, snippet.join("\n")));
        }
    }
    let context = if ctx_blocks.is_empty() {
        "(no context)".to_string()
    } else {
        ctx_blocks.join("\n\n")
    };
    format!(
        "Security finding for review:\n\
         Rule: {}\n\
         Severity: {}\n\
         Reason: {}\n\n\
         Context:\n{}\n\n\
         Is this a real security issue? \
         Respond with JSON: {{\"confirmed\": true/false, \"confidence\": 0.0-1.0}}",
        finding.rule_id,
        finding.severity.py_name(),
        finding.reason,
        context
    )
}

/// Filter findings using an LLM oracle.
///
/// Gating is identical to `meta.py::meta_filter`:
/// - `llm = None` → return findings unchanged.
/// - `severity >= High` → keep unconditionally (severity floor).
/// - Below the floor → call `llm.judge(&prompt).await`:
///   - `Ok(v)` → drop only when `!v.confirmed && v.confidence >= 0.6`.
///   - `Err(_)` → FAIL-CLOSED: push this finding + all remaining, return immediately.
pub async fn meta_filter(
    findings: Vec<Finding>,
    file_cache: &FileCache,
    llm: Option<&dyn LlmProvider>,
) -> Vec<Finding> {
    let Some(llm) = llm else { return findings };

    let mut result: Vec<Finding> = Vec::with_capacity(findings.len());

    for (idx, finding) in findings.iter().enumerate() {
        // Severity floor: CRITICAL/HIGH are never dropped.
        if finding.severity >= FLOOR_SEVERITY {
            result.push(finding.clone());
            continue;
        }

        // For MEDIUM, LOW, INFO — ask the LLM.
        let prompt = build_prompt(finding, file_cache);
        match llm.judge(&prompt).await {
            Ok(v) => {
                // Drop only if explicitly unconfirmed with sufficient confidence.
                if !v.confirmed && v.confidence >= CONFIDENCE_THRESHOLD {
                    continue; // drop this finding
                }
                result.push(finding.clone());
            }
            Err(_) => {
                // Fail-closed: on any LLM error, keep this finding and every remaining
                // one without further filtering, then return immediately.
                result.push(finding.clone());
                for remaining in findings.iter().skip(idx + 1) {
                    result.push(remaining.clone());
                }
                return result;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests (TDD: written before implementation, run first to confirm failure)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{LlmVerdict, MockProvider};
    use crate::types::{Category, Decision};
    use std::collections::HashMap;

    /// Minimal Finding constructor for judge tests.
    fn f(id: &str, sev: Severity) -> Finding {
        Finding {
            rule_id: id.into(),
            severity: sev,
            category: Category::Recon,
            decision: Decision::Allow,
            reason: id.into(),
            owasp: String::new(),
            atlas: String::new(),
            location: None,
            fix: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: llm = None → all findings returned unchanged
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn none_llm_returns_unchanged() {
        let fs = vec![f("a", Severity::Low), f("b", Severity::Critical)];
        let out = meta_filter(fs.clone(), &FileCache::default(), None).await;
        assert_eq!(out.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Test 2: HIGH and CRITICAL are never dropped even with a "benign" verdict
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn high_and_critical_never_dropped_even_if_benign() {
        let mock = MockProvider {
            verdicts: HashMap::new(),
            default: LlmVerdict {
                confirmed: false,
                confidence: 0.99,
            },
        };
        let fs = vec![f("hi", Severity::High), f("crit", Severity::Critical)];
        let out = meta_filter(fs, &FileCache::default(), Some(&mock)).await;
        assert_eq!(out.len(), 2); // floor protects them
    }

    // -----------------------------------------------------------------------
    // Test 3: LOW, !confirmed, confidence 0.7 (>= 0.6) → dropped
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn low_benign_above_threshold_is_dropped() {
        let mock = MockProvider {
            verdicts: HashMap::new(),
            default: LlmVerdict {
                confirmed: false,
                confidence: 0.7,
            },
        };
        let out = meta_filter(
            vec![f("low", Severity::Low)],
            &FileCache::default(),
            Some(&mock),
        )
        .await;
        assert!(out.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 4: LOW, !confirmed, confidence 0.5 (< 0.6) → kept
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn low_benign_below_threshold_is_kept() {
        let mock = MockProvider {
            verdicts: HashMap::new(),
            default: LlmVerdict {
                confirmed: false,
                confidence: 0.5,
            },
        };
        let out = meta_filter(
            vec![f("low", Severity::Low)],
            &FileCache::default(),
            Some(&mock),
        )
        .await;
        assert_eq!(out.len(), 1); // confidence < 0.6 → not dropped
    }

    // -----------------------------------------------------------------------
    // Test 5: confirmed = true → kept regardless of confidence
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn real_verdict_is_kept() {
        let mock = MockProvider {
            verdicts: HashMap::new(),
            default: LlmVerdict {
                confirmed: true,
                confidence: 0.9,
            },
        };
        let out = meta_filter(
            vec![f("low", Severity::Low)],
            &FileCache::default(),
            Some(&mock),
        )
        .await;
        assert_eq!(out.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Test 6: fail-closed on provider error — keeps this + ALL remaining
    // -----------------------------------------------------------------------

    /// Provider that always returns an error.
    struct ErrProvider;

    #[async_trait::async_trait]
    impl LlmProvider for ErrProvider {
        async fn judge(&self, _prompt: &str) -> anyhow::Result<LlmVerdict> {
            anyhow::bail!("boom")
        }
    }

    #[tokio::test]
    async fn fail_closed_on_provider_error_keeps_all_remaining() {
        let findings = vec![f("low1", Severity::Low), f("low2", Severity::Low)];
        let out = meta_filter(findings, &FileCache::default(), Some(&ErrProvider)).await;
        assert_eq!(out.len(), 2); // both kept: fail-closed
    }
}
