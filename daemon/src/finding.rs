//! Daemon-local detection finding. Mirrors scanner::types::Finding but lives in
//! the daemon to avoid a scanner→daemon→scanner dependency cycle. The scanner
//! crate provides an adapter (host_finding_to_scanner) for unified reporting.
use crate::engine::types::{Decision, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCategory {
    Secrets,
    Egress,
    Destructive,
    Rce,
    Persistence,
    Recon,
    Tamper,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: HostCategory,
    pub decision: Decision,
    pub reason: String,
    pub owasp: String,
    pub atlas: String,
    pub fix: String,
}
