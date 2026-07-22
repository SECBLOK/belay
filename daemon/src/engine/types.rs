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

/// A single past verdict with the unix-seconds timestamp it occurred at.
#[derive(Debug, Clone, Copy)]
pub struct VerdictEvent {
    pub decision: Decision,
    pub severity: Severity,
    pub ts: u64,
}

/// Cap on how many [`VerdictEvent`]s a [`SessionState`] retains; oldest are
/// dropped first once the bound is exceeded.
const MAX_VERDICT_HISTORY: usize = 128;

/// Cap on how many resolved paths the dropper detector remembers per session
/// (`downloaded_paths` / `downloaded_execable`). Bounds memory against an
/// adversarial burst of fetches; once full, new paths are simply not recorded
/// (fail-safe — the single-command dropper form never depends on session
/// memory, only the split-across-calls form does).
pub const MAX_DROPPER_PATHS: usize = 256;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub session: String,
    pub armed: HashSet<String>,
    pub untrusted_ingest: bool,
    pub egress_destinations: Vec<String>,
    pub verdict_history: Vec<VerdictEvent>,
    /// Resolved paths that were the write-target of a network fetch
    /// (`curl`/`wget`/…) earlier in this session. Consulted by
    /// `engine::dropper` to catch the split-across-tool-calls form of the
    /// FETCH → chmod → EXEC dropper (fetch in one call, exec in a later one).
    pub downloaded_paths: HashSet<String>,
    /// Subset of `downloaded_paths` that has since had an exec-bit-adding
    /// `chmod` applied. A later *direct* invocation (`./p`) of such a path is
    /// the dropper; an interpreter invocation (`sh p`) needs no exec bit and is
    /// keyed on `downloaded_paths` alone.
    pub downloaded_execable: HashSet<String>,
}

impl SessionState {
    pub fn new(session: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            armed: HashSet::new(),
            untrusted_ingest: false,
            egress_destinations: Vec::new(),
            verdict_history: Vec::new(),
            downloaded_paths: HashSet::new(),
            downloaded_execable: HashSet::new(),
        }
    }

    /// Record a verdict, keeping only the most recent `MAX_VERDICT_HISTORY`
    /// events (oldest dropped first). Purely observational — does not affect
    /// any decision.
    pub fn record_verdict(&mut self, decision: Decision, severity: Severity, now: u64) {
        self.verdict_history.push(VerdictEvent { decision, severity, ts: now });
        if self.verdict_history.len() > MAX_VERDICT_HISTORY {
            let excess = self.verdict_history.len() - MAX_VERDICT_HISTORY;
            self.verdict_history.drain(0..excess);
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
        assert!(s.verdict_history.is_empty());
    }

    #[test]
    fn session_state_records_and_bounds_verdict_history() {
        let mut s = SessionState::new("s");
        for i in 0..200u64 {
            let decision = match i % 3 {
                0 => Decision::Allow,
                1 => Decision::Ask,
                _ => Decision::Deny,
            };
            let severity = match i % 5 {
                0 => Severity::Info,
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            };
            s.record_verdict(decision, severity, i);
        }
        assert_eq!(s.verdict_history.len(), 128);
        // Oldest events (ts 0..=71) were dropped; the retained window is the
        // last 128 verdicts, ts 72..=199.
        assert_eq!(s.verdict_history.first().unwrap().ts, 72);
        assert_eq!(s.verdict_history.last().unwrap().ts, 199);
    }
}
