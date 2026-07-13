//! Taint analyzer: heuristic source→sink analysis using regex patterns.
//!
//! Mirrors the deleted Python predecessor's `scan/analyzers/taint.py` exactly:
//! - _SOURCES (case-insensitive): env-var credential access, open(*.pem|key|crt|p12|pfx).
//! - _CRED_SOURCES (case-insensitive): variable name pattern for credential indicators.
//! - _NET_SINKS (case-SENSITIVE): requests/httpx/urllib/socket network calls.
//! - _EXEC_SINKS (case-SENSITIVE): exec/eval/os.system/subprocess calls.
//!
//! Per-file logic: any source line + net sink → taint.cred_to_net or taint.data_to_net;
//! any source line + exec sink → taint.data_to_exec.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{Category, Decision, Finding, Location, Severity};

// ---------------------------------------------------------------------------
// Compiled regex patterns (lazy init, compiled once per process)
//
// ReDoS safety: these patterns use `\w*(KEYWORD)\w*`-style quantifiers that
// would backtrack pathologically under a backtracking engine. They are safe
// here because every pattern is compiled with the `regex` crate, which uses a
// finite automaton with a linear-time `is_match` guarantee — there is no
// catastrophic backtracking regardless of input. The scanner runs on untrusted
// repo contents, so this matters: do NOT port these patterns to a backtracking
// engine (e.g. `fancy_regex`) without anchoring them first.
// ---------------------------------------------------------------------------

struct Patterns {
    sources: Vec<Regex>,
    cred_sources: Regex,
    net_sinks: Vec<Regex>,
    exec_sinks: Vec<Regex>,
}

static PATTERNS: OnceLock<Patterns> = OnceLock::new();

fn get_patterns() -> &'static Patterns {
    PATTERNS.get_or_init(|| {
        // _SOURCES — case-insensitive (prefix with (?i))
        let sources = vec![
            Regex::new(r#"(?i)os\.environ(?:\.get)?\[?["']?(\w*(?:SECRET|TOKEN|KEY|PASSWORD|API|CRED)\w*)["']?\]?"#)
                .expect("sources[0] must compile"),
            Regex::new(r#"(?i)os\.getenv\(["'](\w*(?:SECRET|TOKEN|KEY|PASSWORD|API|CRED)\w*)["']"#)
                .expect("sources[1] must compile"),
            Regex::new(r#"(?i)open\(["'][^"']*\.(pem|key|crt|p12|pfx)["']"#)
                .expect("sources[2] must compile"),
        ];

        // _CRED_SOURCES — case-insensitive
        let cred_sources =
            Regex::new(r"(?i)(SECRET|TOKEN|KEY|PASSWORD|API_KEY|CREDENTIAL)")
                .expect("cred_sources must compile");

        // _NET_SINKS — case-SENSITIVE (no (?i))
        let net_sinks = vec![
            Regex::new(r"requests\.(post|put|patch|get)\(").expect("net_sinks[0]"),
            Regex::new(r"httpx\.(post|put|patch|get)\(").expect("net_sinks[1]"),
            Regex::new(r"urllib\.request\.urlopen\(").expect("net_sinks[2]"),
            Regex::new(r"socket\.send(all)?\(").expect("net_sinks[3]"),
        ];

        // _EXEC_SINKS — case-SENSITIVE (no (?i))
        let exec_sinks = vec![
            Regex::new(r"\bexec\s*\(").expect("exec_sinks[0]"),
            Regex::new(r"\beval\s*\(").expect("exec_sinks[1]"),
            Regex::new(r"os\.system\s*\(").expect("exec_sinks[2]"),
            Regex::new(r"subprocess\.(run|call|Popen)\s*\(").expect("exec_sinks[3]"),
        ];

        Patterns { sources, cred_sources, net_sinks, exec_sinks }
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan all files in `file_cache` for source→sink taint flows.
pub fn scan_taint(file_cache: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pats = get_patterns();

    for (rel, content) in file_cache {
        scan_file(rel, content, pats, &mut findings);
    }

    findings
}

// ---------------------------------------------------------------------------
// Per-file logic (mirrors taint.py `_scan_file`)
// ---------------------------------------------------------------------------

fn scan_file(rel: &str, content: &str, pats: &Patterns, findings: &mut Vec<Finding>) {
    let mut has_cred_source = false;
    let mut has_generic_source = false;
    let mut has_net_sink = false;
    let mut has_exec_sink = false;

    for line in content.lines() {
        // Check sources
        for pattern in &pats.sources {
            if pattern.is_match(line) {
                if pats.cred_sources.is_match(line) {
                    has_cred_source = true;
                } else {
                    has_generic_source = true;
                }
            }
        }
        // Check net sinks
        for pattern in &pats.net_sinks {
            if pattern.is_match(line) {
                has_net_sink = true;
            }
        }
        // Check exec sinks
        for pattern in &pats.exec_sinks {
            if pattern.is_match(line) {
                has_exec_sink = true;
            }
        }
    }

    // Emit findings based on taint combinations (mirrors Python logic exactly)
    if has_cred_source && has_net_sink {
        findings.push(Finding {
            rule_id: "taint.cred_to_net".into(),
            severity: Severity::Critical,
            category: Category::Egress,
            decision: Decision::Deny,
            reason: format!("Credential source flows to network sink [file: {}]", rel),
            owasp: "A02".into(),
            atlas: "AML.DataExfil".into(),
            location: Some(Location {
                file: rel.to_string(),
                line: 1,
            }),
            fix: String::new(),
        });
    } else if has_generic_source && has_net_sink {
        findings.push(Finding {
            rule_id: "taint.data_to_net".into(),
            severity: Severity::High,
            category: Category::Egress,
            decision: Decision::Ask,
            reason: format!("Sensitive source flows to network sink [file: {}]", rel),
            owasp: "A02".into(),
            atlas: "AML.DataExfil".into(),
            location: Some(Location {
                file: rel.to_string(),
                line: 1,
            }),
            fix: String::new(),
        });
    }

    if (has_cred_source || has_generic_source) && has_exec_sink {
        findings.push(Finding {
            rule_id: "taint.data_to_exec".into(),
            severity: Severity::Critical,
            category: Category::Rce,
            decision: Decision::Deny,
            reason: format!("Tainted data flows to code execution sink [file: {}]", rel),
            owasp: "ASI05".into(),
            atlas: "AML.CodeExecution".into(),
            location: Some(Location {
                file: rel.to_string(),
                line: 1,
            }),
            fix: String::new(),
        });
    }
}
