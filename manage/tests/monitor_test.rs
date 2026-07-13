//! Tests for `belay_manage::monitor::render_cycle`.
//!
//! TDD: this file was written BEFORE the implementation.
//!
//! `render_cycle` contract:
//! - Given a slice of `Finding`s, return `(Vec<String>, bool)` where:
//!   - The `Vec<String>` contains one line per finding:
//!     `[ICON] rule_id: reason`
//!     where ICON is "CRITICAL" if severity >= Critical, "HIGH" if >= High,
//!     else "MEDIUM".
//!   - The `bool` is `true` iff any finding has severity >= Critical.
//! - Given an empty slice, return `(vec![], false)`.
//!   The dispatcher (in `src/bin/aidefender.rs`) prints "Posture OK." when the
//!   returned vec is empty.

use belay_manage::monitor::render_cycle;
use scanner::types::{Category, Decision, Finding, Severity};

fn make_finding(rule_id: &str, severity: Severity, reason: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        category: Category::Secrets,
        decision: Decision::Deny,
        reason: reason.to_string(),
        owasp: "A02".to_string(),
        atlas: "AML.Test".to_string(),
        location: None,
        fix: String::new(),
    }
}

// ─── empty slice ─────────────────────────────────────────────────────────────

#[test]
fn render_cycle_empty_returns_no_lines_and_not_critical() {
    let (lines, any_critical) = render_cycle(&[]);
    assert!(
        lines.is_empty(),
        "expected no lines for empty findings, got: {lines:?}"
    );
    assert!(
        !any_critical,
        "expected any_critical=false for empty findings"
    );
}

// ─── single Critical finding ─────────────────────────────────────────────────

#[test]
fn render_cycle_single_critical() {
    let findings = vec![make_finding(
        "posture.ssh_world_readable",
        Severity::Critical,
        "SSH private key is world-readable: /home/user/.ssh/id_rsa",
    )];
    let (lines, any_critical) = render_cycle(&findings);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0],
        "[CRITICAL] posture.ssh_world_readable: SSH private key is world-readable: /home/user/.ssh/id_rsa"
    );
    assert!(
        any_critical,
        "expected any_critical=true for Critical finding"
    );
}

// ─── single High finding ──────────────────────────────────────────────────────

#[test]
fn render_cycle_single_high() {
    let findings = vec![make_finding(
        "posture.env_in_home",
        Severity::High,
        ".env file found in home directory: /home/user/.env",
    )];
    let (lines, any_critical) = render_cycle(&findings);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0],
        "[HIGH] posture.env_in_home: .env file found in home directory: /home/user/.env"
    );
    assert!(
        !any_critical,
        "expected any_critical=false for High-only finding"
    );
}

// ─── single Medium finding ───────────────────────────────────────────────────

#[test]
fn render_cycle_single_medium() {
    let findings = vec![make_finding(
        "posture.medium_rule",
        Severity::Medium,
        "Some medium-severity issue",
    )];
    let (lines, any_critical) = render_cycle(&findings);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0],
        "[MEDIUM] posture.medium_rule: Some medium-severity issue"
    );
    assert!(!any_critical);
}

// ─── mixed Critical + High + Medium ──────────────────────────────────────────

#[test]
fn render_cycle_mixed_findings_order_and_critical_flag() {
    let findings = vec![
        make_finding("rule.medium", Severity::Medium, "medium reason"),
        make_finding("rule.critical", Severity::Critical, "critical reason"),
        make_finding("rule.high", Severity::High, "high reason"),
    ];
    let (lines, any_critical) = render_cycle(&findings);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "[MEDIUM] rule.medium: medium reason");
    assert_eq!(lines[1], "[CRITICAL] rule.critical: critical reason");
    assert_eq!(lines[2], "[HIGH] rule.high: high reason");
    // any_critical is true because there is at least one Critical finding
    assert!(any_critical);
}

// ─── no critical in multi-finding set ────────────────────────────────────────

#[test]
fn render_cycle_no_critical_among_multiple() {
    let findings = vec![
        make_finding("rule.high1", Severity::High, "h1"),
        make_finding("rule.high2", Severity::High, "h2"),
    ];
    let (lines, any_critical) = render_cycle(&findings);
    assert_eq!(lines.len(), 2);
    assert!(!any_critical);
}
