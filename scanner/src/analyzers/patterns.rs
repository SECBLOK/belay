//! Pattern analyzer: apply v1 engine rules over file-cache contents.
//!
//! Mirrors the deleted Python predecessor's `scan/analyzers/patterns.py`:
//! - For each file in the cache (BTreeMap → deterministic order), iterate
//!   non-empty trimmed lines.
//! - Each line becomes a `Bash` ToolCall; all rules in the embedded catalog
//!   are tested against it.
//! - Findings are deduplicated by `(rule_id, rel_path)`.
//! - The `reason` has `" [file: <rel_path>]"` appended.
//! - `location` is set to `{file: rel_path, line: <1-based>}`.
//!
//! The rule catalog is reused from `belayd::engine::rules::RuleSet` —
//! single source of truth; no predicates are re-transcribed here.

use std::collections::{BTreeMap, HashMap, HashSet};

use belayd::engine::rules::RuleSet;
use belayd::engine::types as daemon_types;

use crate::analyzers::fileclass;
use crate::types::{Category, Decision, Finding, Location, Severity};

// ---------------------------------------------------------------------------
// Minimal serde structs for extracting owasp/atlas from catalog.yaml.
// We parse the same embedded YAML (via include_str!) independently so the
// scanner crate owns no duplicate rule logic — only metadata lookup.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CatalogMeta {
    rules: Vec<RuleMeta>,
}

#[derive(serde::Deserialize)]
struct RuleMeta {
    id: String,
    #[serde(default)]
    owasp: String,
    #[serde(default)]
    atlas: String,
}

const CATALOG_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rules/catalog.yaml"
));

/// Build a `HashMap<rule_id → (owasp, atlas)>` from the embedded catalog.
fn build_owasp_atlas_map() -> HashMap<String, (String, String)> {
    let meta: CatalogMeta = serde_yaml::from_str(CATALOG_YAML)
        .expect("catalog.yaml must be valid YAML for owasp/atlas extraction");
    meta.rules
        .into_iter()
        .map(|r| (r.id, (r.owasp, r.atlas)))
        .collect()
}

// ---------------------------------------------------------------------------
// Enum conversions: daemon enums → scanner enums (same variant names, different
// crate namespaces).
// ---------------------------------------------------------------------------

fn conv_sev(s: daemon_types::Severity) -> Severity {
    match s {
        daemon_types::Severity::Info => Severity::Info,
        daemon_types::Severity::Low => Severity::Low,
        daemon_types::Severity::Medium => Severity::Medium,
        daemon_types::Severity::High => Severity::High,
        daemon_types::Severity::Critical => Severity::Critical,
    }
}

fn conv_dec(d: daemon_types::Decision) -> Decision {
    match d {
        daemon_types::Decision::Allow => Decision::Allow,
        daemon_types::Decision::Ask => Decision::Ask,
        daemon_types::Decision::Deny => Decision::Deny,
    }
}

/// Map the lowercase category string from the catalog to `scanner::Category`.
/// Unknown / missing values default to `Category::Rce` (documented deviation).
fn conv_cat(s: &str) -> Category {
    match s {
        "secrets" => Category::Secrets,
        "egress" => Category::Egress,
        "destructive" => Category::Destructive,
        "rce" => Category::Rce,
        "persistence" => Category::Persistence,
        "recon" => Category::Recon,
        "tamper" => Category::Tamper,
        other => {
            // Unknown category from catalog — default to Rce and log.
            eprintln!(
                "[patterns] WARNING: unknown catalog category {:?} — defaulting to Rce",
                other
            );
            Category::Rce
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run v1 engine rules over every line of every file in `file_cache`.
///
/// Each non-empty trimmed line is wrapped in a `Bash` ToolCall and matched
/// against the full embedded rule catalog (reused from `belayd`).
/// Findings are deduplicated by `(rule_id, rel_path)`.
pub fn scan_patterns(file_cache: &BTreeMap<String, String>) -> Vec<Finding> {
    // Load the rule set — embedded catalog never fails; on unexpected error,
    // return empty to fail-soft rather than panic.
    let rs = match RuleSet::load() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[patterns] ERROR: failed to load rule catalog: {}", e);
            return vec![];
        }
    };

    let owasp_atlas = build_owasp_atlas_map();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for (rel_path, content) in file_cache {
        // Context for false-positive control: a `.gitignore` line ".env" is not
        // a credential read, a Dockerfile `pip install` is not an attack, a
        // README mentioning env vars is not a process-env dump. Classify the
        // file once and decide per-rule whether the match is meaningful here.
        let class = fileclass::classify(rel_path);
        if class == fileclass::FileClass::Noise {
            // Ignore files / lockfiles only ever mention paths and deps — never
            // executed. Skip them entirely.
            continue;
        }

        for (line_idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            // 1-based line number
            let line_no = (line_idx + 1) as u32;

            let tc = belayd::engine::types::ToolCall {
                session: "scan".into(),
                tool: "Bash".into(),
                input: serde_json::json!({"command": line}),
            };

            for hit in rs.matches(&tc) {
                // Drop contextual / devops-normal matches that are only
                // meaningful inside an executed script (see `fileclass`).
                if !fileclass::keep_finding(&hit.id, class) {
                    continue;
                }
                let key = (hit.id.clone(), rel_path.clone());
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);

                let (owasp, atlas) = owasp_atlas.get(&hit.id).cloned().unwrap_or_default();

                findings.push(Finding {
                    rule_id: hit.id,
                    severity: conv_sev(hit.severity),
                    category: conv_cat(&hit.category),
                    decision: conv_dec(hit.decision),
                    reason: format!("{} [file: {}]", hit.reason, rel_path),
                    owasp,
                    atlas,
                    location: Some(Location {
                        file: rel_path.clone(),
                        line: line_no,
                    }),
                    fix: String::new(),
                });
            }
        }
    }

    findings
}
