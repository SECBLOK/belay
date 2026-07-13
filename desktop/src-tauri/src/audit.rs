use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRow {
    pub ts: String,
    pub event: String,
    pub session: String,
    pub tool: String,
    #[serde(default)]
    pub input: serde_json::Value,
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub rules: Vec<String>,
    /// Curated severity/category/explanation carried from the daemon verdict
    /// (Explain & Advise). All optional + `#[serde(default)]` so older rows and
    /// the open build (no enrichment) still parse. `explain` is an opaque JSON
    /// object `{summary, what, why_risky, normal_use, suggested_action}`.
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub explain: Option<serde_json::Value>,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
}

/// Parse one NDJSON line into an AuditRow. Blank/garbage lines -> None (never panics).
pub fn parse_audit_line(line: &str) -> Option<AuditRow> {
    let line = line.trim();
    if line.is_empty() { return None; }
    serde_json::from_str::<AuditRow>(line).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_row() {
        let line = r#"{"ts":"2026-06-26T14:00:00Z","event":"gate","session":"s1","tool":"Bash","input":{"command":"rm -rf /"},"verdict":"deny","reason":"destructive","rules":["destructive.rm_rf"],"prev_hash":"a","hash":"b"}"#;
        let row = parse_audit_line(line).expect("should parse");
        assert_eq!(row.tool, "Bash");
        assert_eq!(row.verdict, "deny");
        assert_eq!(row.rules, vec!["destructive.rm_rf".to_string()]);
    }

    #[test]
    fn blank_and_garbage_lines_are_none() {
        assert!(parse_audit_line("   ").is_none());
        assert!(parse_audit_line("not json").is_none());
    }
}
