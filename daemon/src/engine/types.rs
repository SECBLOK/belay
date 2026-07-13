//! Canonical Rust core types — shared contract with the Python engine.
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::engine::rules::Explain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lowercase wire label for a [`Severity`] (matches the serde `rename_all`).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCall {
    pub session: String,
    pub tool: String,
    #[serde(default)]
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: String,
    pub rules: Vec<String>,
    pub severity: Severity,
    /// Id of the winning (most-restrictive) rule — the one whose
    /// category/explain describe this verdict. Kept distinct from
    /// `rules.first()` so the approval card labels the SAME rule its
    /// explanation came from (they can differ on a tie).
    #[serde(default)]
    pub primary_rule: Option<String>,
    /// Category of the winning (most-restrictive) rule, e.g. `destructive`.
    #[serde(default)]
    pub category: Option<String>,
    /// OWASP mapping of the winning rule (previously never surfaced).
    #[serde(default)]
    pub owasp: Option<String>,
    /// MITRE ATLAS mapping of the winning rule.
    #[serde(default)]
    pub atlas: Option<String>,
    /// Curated plain-English explanation of the winning rule (if authored).
    #[serde(default)]
    pub explain: Option<Explain>,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub session: String,
    pub armed: HashSet<String>,
    pub untrusted_ingest: bool,
    pub egress_destinations: Vec<String>,
}

impl SessionState {
    pub fn new(session: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            armed: HashSet::new(),
            untrusted_ingest: false,
            egress_destinations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
        assert_eq!(serde_json::to_string(&Decision::Ask).unwrap(), "\"ask\"");
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
    }

    #[test]
    fn severity_orders_critical_highest() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Info);
    }

    #[test]
    fn session_state_defaults_empty() {
        let s = SessionState::new("s");
        assert!(s.armed.is_empty());
        assert!(!s.untrusted_ingest);
        assert!(s.egress_destinations.is_empty());
    }
}
