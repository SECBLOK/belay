//! SARIF 2.1.0 emitter for scanner findings.
//!
//! Faithful port of the deleted Python predecessor's `scan/sarif.py`.
//!
//! Rule insertion order is preserved using `indexmap::IndexMap` to match
//! Python's dict insertion-order semantics.

use indexmap::IndexMap;
use serde_json::{json, Value};

use crate::types::{Finding, Severity};

/// Map a Finding severity to a SARIF level string.
///
/// Mirrors `_level()` in sarif.py.
fn level(severity: Severity) -> &'static str {
    // Python: `if severity >= Severity.HIGH → "error"`
    // The Severity enum derives Ord with Info=0 < Low < Medium < High < Critical.
    if severity >= Severity::High {
        "error"
    } else if severity == Severity::Medium {
        "warning"
    } else {
        "note"
    }
}

/// Convert findings to a SARIF 2.1.0 `serde_json::Value`.
///
/// Mirrors `to_sarif()` in sarif.py exactly:
/// - Rules are deduped by first-seen `rule_id` (insertion order preserved).
/// - Each rule entry has `id`, `shortDescription.text`, and `properties`
///   (always present; `owasp`/`atlas` keys added only when non-empty).
/// - Each result has `ruleId`, `level`, `message.text` — no `locations`.
/// - The top-level structure uses `$schema`, `version`, and `runs[0]`.
pub fn to_sarif(findings: &[Finding], tool_version: &str) -> Value {
    // Collect unique rules in first-seen order.
    let mut seen_rules: IndexMap<String, &Finding> = IndexMap::new();
    for f in findings {
        seen_rules.entry(f.rule_id.clone()).or_insert(f);
    }

    // Build rules array.
    let rules: Vec<Value> = seen_rules
        .iter()
        .map(|(rule_id, f)| {
            let mut props = serde_json::Map::new();
            if !f.owasp.is_empty() {
                props.insert("owasp".to_string(), json!(f.owasp));
            }
            if !f.atlas.is_empty() {
                props.insert("atlas".to_string(), json!(f.atlas));
            }
            json!({
                "id": rule_id,
                "shortDescription": { "text": f.reason },
                "properties": props,
            })
        })
        .collect();

    // Build results array — one entry per finding (no dedup here).
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": f.reason },
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "belay",
                        "version": tool_version,
                        "informationUri": "https://github.com/SECBLOK/belay",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    })
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
    fn empty_findings_produces_empty_rules_and_results() {
        let s = to_sarif(&[], "0.1.0");
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "belay");
        assert_eq!(s["runs"][0]["tool"]["driver"]["version"], "0.1.0");
        assert!(s["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(s["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn critical_severity_maps_to_error_level() {
        let s = to_sarif(&[f("rce.x", Severity::Critical)], "0.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn high_severity_maps_to_error_level() {
        let s = to_sarif(&[f("rce.x", Severity::High)], "0.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn medium_severity_maps_to_warning_level() {
        let s = to_sarif(&[f("rce.x", Severity::Medium)], "0.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn low_severity_maps_to_note_level() {
        let s = to_sarif(&[f("rce.x", Severity::Low)], "0.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn info_severity_maps_to_note_level() {
        let s = to_sarif(&[f("rce.x", Severity::Info)], "0.1.0");
        assert_eq!(s["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn duplicate_rule_deduplicated_in_rules_array() {
        // Two findings with same rule_id → only one rules[] entry.
        let findings = vec![
            f("rce.x", Severity::Critical),
            f("rce.x", Severity::Critical),
        ];
        let s = to_sarif(&findings, "0.1.0");
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rule_insertion_order_preserved() {
        // First finding is rce.a, second is rce.b — rules must appear in that order.
        let findings = vec![f("rce.a", Severity::Critical), f("rce.b", Severity::High)];
        let s = to_sarif(&findings, "0.1.0");
        let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["id"], "rce.a");
        assert_eq!(rules[1]["id"], "rce.b");
    }

    #[test]
    fn owasp_and_atlas_present_when_non_empty() {
        let s = to_sarif(&[f("rce.x", Severity::Critical)], "0.1.0");
        let props = &s["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert_eq!(props["owasp"], "ASI05");
        assert_eq!(props["atlas"], "AML");
    }

    #[test]
    fn owasp_and_atlas_omitted_when_empty() {
        let mut finding = f("rce.x", Severity::Critical);
        finding.owasp = String::new();
        finding.atlas = String::new();
        let s = to_sarif(&[finding], "0.1.0");
        let props = &s["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert!(props.get("owasp").is_none());
        assert!(props.get("atlas").is_none());
    }

    #[test]
    fn properties_key_always_present() {
        // Even when owasp/atlas are empty, `properties` key must exist (empty object).
        let mut finding = f("rce.x", Severity::Critical);
        finding.owasp = String::new();
        finding.atlas = String::new();
        let s = to_sarif(&[finding], "0.1.0");
        let props = &s["runs"][0]["tool"]["driver"]["rules"][0]["properties"];
        assert!(props.is_object());
    }

    #[test]
    fn schema_and_version_fields_correct() {
        let s = to_sarif(&[], "1.2.3");
        assert_eq!(
            s["$schema"],
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        );
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["informationUri"],
            "https://github.com/SECBLOK/belay"
        );
    }
}
