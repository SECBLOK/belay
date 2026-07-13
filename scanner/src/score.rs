//! Provenance-weighted 0-100 scanner score.
//!
//! Faithful port of the deleted Python predecessor's `scan/score.py`.
//!
//! Key parity note: Python `round()` uses round-half-to-even (banker's
//! rounding). Rust `f64::round()` rounds half away from zero.  Both diverge
//! at exact X.5 values, so we implement a dedicated `round_half_to_even`
//! helper to maintain numeric parity.

use std::collections::HashMap;

use crate::types::{Finding, Severity};

/// Output of the score computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreOut {
    pub score: i64,
    pub severity: String,
    pub recommendation: String,
}

/// Base points per severity — mirrors `_BASE_POINTS` in score.py.
fn base_points(sev: Severity) -> f64 {
    match sev {
        Severity::Critical => 50.0,
        Severity::High => 25.0,
        Severity::Medium => 10.0,
        Severity::Low => 5.0,
        Severity::Info => 0.0,
    }
}

/// Diminishing-returns multipliers: 1st, 2nd, 3rd+ occurrence of same rule_id.
const DIMINISHING: [f64; 3] = [1.0, 0.5, 0.25];

const SCRIPT_MULTIPLIER: f64 = 1.3;
const SAFE_MAX: i64 = 20;
const CAUTION_MAX: i64 = 50;

/// Round-half-to-even (banker's rounding) — matches Python's built-in `round()`.
///
/// For values whose fractional part is exactly 0.5 we round to the nearest even
/// integer; for all other values we use standard rounding.
///
/// Examples:
///   round_half_to_even(12.5) == 12  (12 is even)
///   round_half_to_even(13.5) == 14  (14 is even)
///   round_half_to_even( 2.5) ==  2  ( 2 is even)
///   round_half_to_even( 3.5) ==  4  ( 4 is even)
pub fn round_half_to_even(x: f64) -> i64 {
    let floor = x.floor() as i64;
    let frac = x - x.floor();

    // Only the exact-half case needs special treatment.
    if (frac - 0.5).abs() < 1e-10 {
        // Round to the nearest even integer.
        if floor % 2 == 0 {
            floor // floor is even → round down
        } else {
            floor + 1 // floor is odd  → round up to even
        }
    } else {
        x.round() as i64
    }
}

/// Compute a provenance-weighted 0-100 score from `findings`.
///
/// Mirrors `score.py::score` exactly — including iteration order, diminishing
/// returns keyed by `rule_id` first-seen order, and banker's rounding.
pub fn score(findings: &[Finding], has_executable_scripts: bool) -> ScoreOut {
    // Count per rule_id, tracking first-seen order implicitly via insertion.
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut raw: f64 = 0.0;

    for finding in findings {
        let idx = *rule_counts.get(&finding.rule_id).unwrap_or(&0);
        let multiplier = DIMINISHING[idx.min(DIMINISHING.len() - 1)];
        *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        raw += base_points(finding.severity) * multiplier;
    }

    // Apply executable-scripts multiplier only when raw > 0 (mirrors Python).
    if has_executable_scripts && raw > 0.0 {
        raw *= SCRIPT_MULTIPLIER;
    }

    // Clamp then banker-round → final score.
    let clamped = raw.clamp(0.0, 100.0);
    let final_score = round_half_to_even(clamped);

    let (recommendation, severity) = if final_score <= SAFE_MAX {
        ("SAFE", "LOW")
    } else if final_score <= CAUTION_MAX {
        ("CAUTION", "MEDIUM")
    } else {
        ("DO_NOT_INSTALL", "HIGH")
    };

    ScoreOut {
        score: final_score,
        severity: severity.into(),
        recommendation: recommendation.into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Category, Decision, Finding, Severity};

    fn f(rule: &str, sev: Severity) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity: sev,
            category: Category::Rce,
            decision: Decision::Deny,
            reason: "x".into(),
            owasp: "ASI05".into(),
            atlas: "AML".into(),
            location: None,
            fix: String::new(),
        }
    }

    #[test]
    fn banker_rounding_helper_12_5() {
        assert_eq!(round_half_to_even(12.5), 12); // 12 is even
    }

    #[test]
    fn banker_rounding_helper_13_5() {
        assert_eq!(round_half_to_even(13.5), 14); // 14 is even
    }

    #[test]
    fn banker_rounding_helper_2_5() {
        assert_eq!(round_half_to_even(2.5), 2); // 2 is even
    }

    #[test]
    fn banker_rounding_helper_3_5() {
        assert_eq!(round_half_to_even(3.5), 4); // 4 is even
    }

    #[test]
    fn zero_findings_safe() {
        let out = score(&[], false);
        assert_eq!(out.score, 0);
        assert_eq!(out.recommendation, "SAFE");
        assert_eq!(out.severity, "LOW");
    }

    #[test]
    fn single_critical_caution() {
        // score=50 lands exactly on the CAUTION_MAX boundary → CAUTION/MEDIUM
        let out = score(&[f("rce.x", Severity::Critical)], false);
        assert_eq!(out.score, 50);
        assert_eq!(out.recommendation, "CAUTION");
        assert_eq!(out.severity, "MEDIUM");
    }

    #[test]
    fn two_same_critical_diminishing() {
        // 50 * 1.0 + 50 * 0.5 = 75 → DO_NOT_INSTALL / HIGH
        let out = score(
            &[
                f("rce.x", Severity::Critical),
                f("rce.x", Severity::Critical),
            ],
            false,
        );
        assert_eq!(out.score, 75);
        assert_eq!(out.recommendation, "DO_NOT_INSTALL");
        assert_eq!(out.severity, "HIGH");
    }

    #[test]
    fn medium_only_safe() {
        // 10 ≤ 20 (SAFE_MAX) → SAFE/LOW
        let out = score(&[f("x", Severity::Medium)], false);
        assert_eq!(out.score, 10);
        assert_eq!(out.recommendation, "SAFE");
        assert_eq!(out.severity, "LOW");
    }

    #[test]
    fn script_multiplier_applied_when_raw_gt_0() {
        // 1 Critical = 50 raw, * 1.3 = 65 → DO_NOT_INSTALL
        let out = score(&[f("rce.x", Severity::Critical)], true);
        assert_eq!(out.score, 65);
        assert_eq!(out.recommendation, "DO_NOT_INSTALL");
    }

    #[test]
    fn script_multiplier_not_applied_when_raw_0() {
        // Info finding = 0 raw; multiplier must not fire.
        let out = score(&[f("info.x", Severity::Info)], true);
        assert_eq!(out.score, 0);
        assert_eq!(out.recommendation, "SAFE");
    }

    #[test]
    fn clamp_at_100() {
        // Many criticals still clamped to 100.
        let findings: Vec<Finding> = (0..10)
            .map(|i| f(&format!("rule.{i}"), Severity::Critical))
            .collect();
        let out = score(&findings, true);
        assert_eq!(out.score, 100);
    }

    #[test]
    fn different_rules_no_diminishing() {
        // rule_a Critical + rule_b Critical = 50 + 50 = 100, but clamped to 100.
        let out = score(
            &[
                f("rule.a", Severity::Critical),
                f("rule.b", Severity::Critical),
            ],
            false,
        );
        assert_eq!(out.score, 100);
    }
}
