use serde::{Deserialize, Serialize};

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
    pub fn points(self) -> f64 {
        match self {
            Severity::Critical => 50.0,
            Severity::High => 25.0,
            Severity::Medium => 10.0,
            Severity::Low => 5.0,
            Severity::Info => 0.0,
        }
    }
    /// Matches Python `Severity.name` used by the CLI JSON (`f.severity.name`).
    pub fn py_name(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secrets,
    Egress,
    Destructive,
    Rce,
    Persistence,
    Recon,
    Tamper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: Category,
    pub decision: Decision,
    pub reason: String, // includes the " [file: <rel>]" suffix, byte-identical to Python
    pub owasp: String,
    pub atlas: String,
    #[serde(default)]
    pub location: Option<Location>,
    #[serde(default)]
    pub fix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub score: i64,
    pub severity: String,       // "LOW"|"MEDIUM"|"HIGH"
    pub recommendation: String, // "SAFE"|"CAUTION"|"DO_NOT_INSTALL"
    pub findings: Vec<Finding>,
    pub sarif: serde_json::Value,
    pub source_type: String,
}
