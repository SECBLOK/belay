//! Adapter: convert daemon [`HostFinding`]s to scanner [`Finding`]s for unified reporting.
//!
//! This avoids a dependency cycle by doing a one-way projection at the scanner crate boundary.

use belayd::engine::types::{Decision as DaemonDecision, Severity as DaemonSeverity};
use belayd::finding::{HostCategory, HostFinding};

use crate::types::{Category, Decision, Finding, Severity};

/// Project a daemon [`HostFinding`] into the scanner's [`Finding`] type.
pub fn host_finding_to_scanner(f: HostFinding) -> Finding {
    Finding {
        rule_id: f.rule_id,
        severity: match f.severity {
            DaemonSeverity::Critical => Severity::Critical,
            DaemonSeverity::High => Severity::High,
            DaemonSeverity::Medium => Severity::Medium,
            DaemonSeverity::Low => Severity::Low,
            DaemonSeverity::Info => Severity::Info,
        },
        category: match f.category {
            HostCategory::Secrets => Category::Secrets,
            HostCategory::Egress => Category::Egress,
            HostCategory::Destructive => Category::Destructive,
            HostCategory::Rce => Category::Rce,
            HostCategory::Persistence => Category::Persistence,
            HostCategory::Recon => Category::Recon,
            HostCategory::Tamper => Category::Tamper,
        },
        decision: match f.decision {
            DaemonDecision::Allow => Decision::Allow,
            DaemonDecision::Ask => Decision::Ask,
            DaemonDecision::Deny => Decision::Deny,
        },
        reason: f.reason,
        owasp: f.owasp,
        atlas: f.atlas,
        location: None,
        fix: f.fix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use belayd::engine::types::{Decision as DD, Severity as DS};
    use belayd::finding::HostCategory;

    #[test]
    fn host_finding_critical_maps_to_scanner_critical() {
        let f = HostFinding {
            rule_id: "vuln.nvd_cve".into(),
            severity: DS::Critical,
            decision: DD::Ask,
            category: HostCategory::Recon,
            reason: "CVE-2021-41773 [CISA-KEV]".into(),
            owasp: String::new(),
            atlas: String::new(),
            fix: "upgrade".into(),
        };
        let s = host_finding_to_scanner(f);
        assert_eq!(s.severity, crate::types::Severity::Critical);
        assert_eq!(s.decision, crate::types::Decision::Ask);
        assert_eq!(s.category, crate::types::Category::Recon);
    }
}
