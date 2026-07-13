//! YARA analyzer: scan file-cache contents with bundled (or custom) YARA rules.
//!
//! Mirrors the deleted Python predecessor's `scan/analyzers/yara_scan.py`.
//!
//! The compiled bundled rules are cached in a `OnceLock` so they are only
//! compiled once per process.  When `rules_dir` is `Some(dir)` a fresh compile
//! is done each call (used only in tests / custom-rule mode).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::types::{Category, Decision, Finding, Location, Severity};

// ---------------------------------------------------------------------------
// Bundled rules – compiled once and cached.
// ---------------------------------------------------------------------------

const BUNDLED_RULES: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/yara_rules/agent.yar"));
const CREDENTIAL_RULES: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/yara_rules/credentials.yar"));

static BUNDLED_COMPILED: OnceLock<Rules> = OnceLock::new();

fn get_bundled_rules() -> Option<&'static Rules> {
    Some(BUNDLED_COMPILED.get_or_init(|| {
        let mut compiler = Compiler::new();
        // If compilation fails we still need to return *something* — we return
        // an empty rule set by falling back to `true` (no rules → no matches).
        // The fail-soft path is handled by returning `vec![]` if we cannot
        // compile at all; but `get_or_init` requires a value, so we compile an
        // empty source as the last resort.
        let ok = compiler.add_source(BUNDLED_RULES).is_ok()
            && compiler.add_source(CREDENTIAL_RULES).is_ok();
        if ok {
            compiler.build()
        } else {
            let mut c2 = Compiler::new();
            let _ = c2.add_source("// empty");
            c2.build()
        }
    }))
}

// ---------------------------------------------------------------------------
// Helper: compile all `*.yar` files in a directory.
// ---------------------------------------------------------------------------

fn compile_dir(rules_dir: &Path) -> Option<Rules> {
    let yar_files: Vec<_> = match std::fs::read_dir(rules_dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yar"))
            .collect(),
        Err(_) => return None,
    };
    if yar_files.is_empty() {
        return None;
    }
    let mut compiler = Compiler::new();
    for entry in yar_files {
        let src = match std::fs::read_to_string(entry.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if compiler.add_source(src.as_str()).is_err() {
            return None; // fail-soft: any compile error → no rules
        }
    }
    Some(compiler.build())
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "LOW" => Severity::Low,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Medium,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `file_cache` with YARA rules.
///
/// * `rules_dir = None`  → use the bundled `yara_rules/agent.yar` (cached).
/// * `rules_dir = Some(p)` → compile all `*.yar` files in `p` each call.
///
/// Returns `vec![]` on any compile failure (fail-soft).
pub fn scan_yara(file_cache: &BTreeMap<String, String>, rules_dir: Option<&Path>) -> Vec<Finding> {
    // Obtain compiled rules.
    let rules_owned: Rules;
    let rules: &Rules = match rules_dir {
        None => match get_bundled_rules() {
            Some(r) => r,
            None => return vec![],
        },
        Some(dir) => match compile_dir(dir) {
            Some(r) => {
                rules_owned = r;
                &rules_owned
            }
            None => return vec![],
        },
    };

    let mut scanner = Scanner::new(rules);
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (rel_path, content) in file_cache {
        let scan_result = match scanner.scan(content.as_bytes()) {
            Ok(r) => r,
            Err(_) => continue, // fail-soft per file
        };

        for rule in scan_result.matching_rules() {
            // Extract metadata into a map.
            let meta: BTreeMap<&str, MetaValue<'_>> = rule.metadata().collect();

            // rule_id
            let rule_id = match meta.get("rule_id") {
                Some(MetaValue::String(s)) => s.to_string(),
                _ => format!("yara.{}", rule.identifier()),
            };

            // Dedup
            let key = (rule_id.clone(), rel_path.clone());
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);

            // severity
            let severity = match meta.get("severity") {
                Some(MetaValue::String(s)) => parse_severity(s),
                _ => Severity::Medium,
            };

            // description
            let description = match meta.get("description") {
                Some(MetaValue::String(s)) => s.to_string(),
                _ => rule.identifier().to_string(),
            };

            let decision = if severity >= Severity::High {
                Decision::Deny
            } else {
                Decision::Ask
            };

            findings.push(Finding {
                rule_id,
                severity,
                category: Category::Rce,
                decision,
                reason: format!("YARA match: {} [file: {}]", description, rel_path),
                owasp: "ASI05".to_string(),
                atlas: "AML.CodeExecution".to_string(),
                location: Some(Location {
                    file: rel_path.clone(),
                    line: 1,
                }),
                fix: String::new(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // P1/Task3 (Aegis-derived): the bundled rules must flag leaked credentials by
    // content (key formats / private-key headers), tagged with a secrets.* rule_id.
    #[test]
    fn detects_leaked_credentials() {
        let mut fc = BTreeMap::new();
        fc.insert(
            "config.txt".to_string(),
            "aws_key = AKIAIOSFODNN7EXAMPLE\n-----BEGIN OPENSSH PRIVATE KEY-----\n".to_string(),
        );
        let findings = scan_yara(&fc, None);
        assert!(
            findings.iter().any(|f| f.rule_id.starts_with("secrets.")),
            "expected a secrets.* finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}
