//! SARIF 2.1.0 emitter for scanner findings.
//!
//! Faithful port of the deleted Python predecessor's `scan/sarif.py`.
//!
//! Rule insertion order is preserved using `indexmap::IndexMap` to match
//! Python's dict insertion-order semantics.

use indexmap::IndexMap;
use serde_json::{json, Value};

use crate::types::{Category, Finding, Severity};

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

/// Strip a trailing `" [file: <anything>]"` suffix appended by analyzers to
/// `Finding.reason`. Returns the input unchanged if the suffix shape isn't
/// present. Does NOT mutate the source `Finding` — this is a pure projection
/// used only when building the SARIF `message`/`shortDescription` text.
fn strip_file_suffix(reason: &str) -> &str {
    if reason.ends_with(']') {
        if let Some(idx) = reason.rfind(" [file: ") {
            return &reason[..idx];
        }
    }
    reason
}

/// Map a Finding severity to a GitHub code-scanning `security-severity`
/// score string (used in SARIF rule `properties`).
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// Convert a dotted/underscored rule id (e.g. `"taint.cred_to_net"`) into a
/// PascalCase display name (e.g. `"TaintCredToNet"`) for the SARIF rule
/// `name` field.
fn pascal_name(rule_id: &str) -> String {
    rule_id
        .split(['.', '_'])
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Lowercase category name for SARIF rule `properties.category`.
fn category_str(c: Category) -> &'static str {
    match c {
        Category::Secrets => "secrets",
        Category::Egress => "egress",
        Category::Destructive => "destructive",
        Category::Rce => "rce",
        Category::Persistence => "persistence",
        Category::Recon => "recon",
        Category::Tamper => "tamper",
    }
}

/// Normalize a file path into a SARIF-legal `/`-separated URI.
fn normalize_uri(file: &str) -> String {
    file.replace('\\', "/")
}

/// FNV-1a 64-bit hash, hex-formatted, used as a stable `partialFingerprints`
/// value. Pure and deterministic — no external crate needed.
fn fnv1a_hex(s: &str) -> String {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{:016x}", hash)
}

/// Convert findings to a SARIF 2.1.0 `serde_json::Value`.
///
/// Code-scanning-grade emitter (output-shape only — no detection/scoring
/// change):
/// - Rules are deduped by first-seen `rule_id` (insertion order preserved).
/// - Each rule entry has `id`, `name` (PascalCase), `shortDescription.text`,
///   `fullDescription.text`, `helpUri`, `defaultConfiguration.level`, and
///   `properties` (`category`, `security-severity`, plus `owasp`/`atlas`
///   when non-empty). Message text has the ` [file: …]` suffix stripped.
/// - Each result has `ruleId`, `level`, `message.text` (suffix stripped),
///   `locations` (anchored to the finding's file/line, or to `"."` when no
///   location is known — `startLine: 0` is never emitted), and
///   `partialFingerprints.belay/v1` (a line-independent FNV-1a fingerprint).
/// - The run object carries `columnKind: "utf16CodeUnits"`.
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
            let stripped = strip_file_suffix(&f.reason);
            let mut props = serde_json::Map::new();
            props.insert("category".to_string(), json!(category_str(f.category)));
            props.insert(
                "security-severity".to_string(),
                json!(security_severity(f.severity)),
            );
            if !f.owasp.is_empty() {
                props.insert("owasp".to_string(), json!(f.owasp));
            }
            if !f.atlas.is_empty() {
                props.insert("atlas".to_string(), json!(f.atlas));
            }
            json!({
                "id": rule_id,
                "name": pascal_name(rule_id),
                "shortDescription": { "text": stripped },
                "fullDescription": { "text": stripped },
                "helpUri": format!(
                    "https://github.com/SECBLOK/belay/blob/main/docs/rules.md#{}",
                    rule_id
                ),
                "defaultConfiguration": { "level": level(f.severity) },
                "properties": props,
            })
        })
        .collect();

    // Build results array — one entry per finding (no dedup here).
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let stripped = strip_file_suffix(&f.reason);
            let (locations, file_or_empty) = match &f.location {
                Some(loc) if loc.line >= 1 => (
                    json!([{
                        "physicalLocation": {
                            "artifactLocation": { "uri": normalize_uri(&loc.file) },
                            "region": { "startLine": loc.line },
                        }
                    }]),
                    loc.file.clone(),
                ),
                Some(loc) => (
                    // line == 0: file-scoped finding — never emit startLine: 0.
                    json!([{
                        "physicalLocation": {
                            "artifactLocation": { "uri": normalize_uri(&loc.file) },
                        }
                    }]),
                    loc.file.clone(),
                ),
                None => (
                    // No location known: anchor to the scan root, no region.
                    json!([{
                        "physicalLocation": {
                            "artifactLocation": { "uri": "." },
                        }
                    }]),
                    String::new(),
                ),
            };
            let fingerprint = fnv1a_hex(&format!(
                "{}\u{0}{}\u{0}{}",
                f.rule_id, file_or_empty, stripped
            ));
            json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": stripped },
                "locations": locations,
                "partialFingerprints": { "belay/v1": fingerprint },
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
                "columnKind": "utf16CodeUnits",
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
    use crate::types::{Category, Decision, Finding, Location, Severity};

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

    // -----------------------------------------------------------------
    // New tests: strip_file_suffix helper (both branches).
    // -----------------------------------------------------------------

    #[test]
    fn strip_file_suffix_strips_when_present() {
        assert_eq!(
            strip_file_suffix("exec() call detected [file: run.py]"),
            "exec() call detected"
        );
    }

    #[test]
    fn strip_file_suffix_returns_unchanged_when_absent() {
        assert_eq!(
            strip_file_suffix("no suffix here"),
            "no suffix here"
        );
    }

    // -----------------------------------------------------------------
    // New tests: locations, fingerprints, rules-catalog enrichment.
    // -----------------------------------------------------------------

    #[test]
    fn result_has_location_with_region() {
        let mut finding = f("rce.x", Severity::Critical);
        finding.location = Some(Location {
            file: "run.py".into(),
            line: 42,
        });
        let s = to_sarif(&[finding], "0.1.0");
        assert_eq!(
            s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            42
        );
        assert_eq!(
            s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "run.py"
        );
    }

    #[test]
    fn file_scoped_finding_omits_region() {
        let mut finding = f("rce.x", Severity::Critical);
        finding.location = Some(Location {
            file: "run.py".into(),
            line: 0,
        });
        let s = to_sarif(&[finding], "0.1.0");
        let phys = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(phys["artifactLocation"]["uri"], "run.py");
        assert!(phys.get("region").is_none());
    }

    #[test]
    fn no_location_anchors_to_root() {
        let finding = f("rce.x", Severity::Critical); // location: None
        let s = to_sarif(&[finding], "0.1.0");
        let phys = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(phys["artifactLocation"]["uri"], ".");
        assert!(phys.get("region").is_none());
    }

    #[test]
    fn partial_fingerprint_stable_across_line_change() {
        let mut f1 = f("rce.x", Severity::Critical);
        f1.location = Some(Location {
            file: "run.py".into(),
            line: 10,
        });
        let mut f2 = f("rce.x", Severity::Critical);
        f2.location = Some(Location {
            file: "run.py".into(),
            line: 99,
        });
        let s = to_sarif(&[f1, f2], "0.1.0");
        let fp1 = &s["runs"][0]["results"][0]["partialFingerprints"]["belay/v1"];
        let fp2 = &s["runs"][0]["results"][1]["partialFingerprints"]["belay/v1"];
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn partial_fingerprint_distinct_across_files() {
        let mut f1 = f("rce.x", Severity::Critical);
        f1.location = Some(Location {
            file: "a.py".into(),
            line: 10,
        });
        let mut f2 = f("rce.x", Severity::Critical);
        f2.location = Some(Location {
            file: "b.py".into(),
            line: 10,
        });
        let s = to_sarif(&[f1, f2], "0.1.0");
        let fp1 = &s["runs"][0]["results"][0]["partialFingerprints"]["belay/v1"];
        let fp2 = &s["runs"][0]["results"][1]["partialFingerprints"]["belay/v1"];
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn message_strips_file_suffix() {
        let mut finding = f("rce.x", Severity::Critical);
        finding.reason = "exec() call detected [file: run.py]".into();
        let findings = vec![finding];
        let s = to_sarif(&findings, "0.1.0");
        assert_eq!(
            s["runs"][0]["results"][0]["message"]["text"],
            "exec() call detected"
        );
        // Emitting SARIF must not mutate the source Finding.
        assert_eq!(
            findings[0].reason,
            "exec() call detected [file: run.py]"
        );
    }

    #[test]
    fn rule_has_helpuri_and_security_severity() {
        let s = to_sarif(&[f("rce.pipe_to_shell", Severity::Critical)], "0.1.0");
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(
            rule["helpUri"],
            "https://github.com/SECBLOK/belay/blob/main/docs/rules.md#rce.pipe_to_shell"
        );
        assert_eq!(rule["properties"]["security-severity"], "9.0");
        assert_eq!(rule["name"], "RcePipeToShell");
    }

    #[test]
    fn never_emits_startline_zero() {
        let mut finding = f("rce.x", Severity::Critical);
        finding.location = Some(Location {
            file: "run.py".into(),
            line: 0,
        });
        let s = to_sarif(&[finding], "0.1.0");
        let region = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert!(
            region.is_null(),
            "region must be omitted entirely when line == 0, not startLine: 0"
        );
    }
}
