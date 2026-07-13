//! Monitor helpers — Rust port of the deleted Python predecessor's
//! `cli/main.py::monitor_cmd`.
//!
//! The actual loop, sleep, and audit-write logic lives in the `belay`
//! binary (`src/bin/aidefender.rs`) because it needs both `belay_manage`
//! and `belayd` in scope.  This module provides the pure, testable
//! rendering unit that the dispatcher calls on each cycle.
//!
//! NOTE: The Python `DriftMonitor.check` MCP-fingerprint-drift path is NOT
//! invoked by `monitor_cmd` (only `dm.check_posture`), so it is intentionally
//! OUT OF SCOPE here.

use scanner::types::{Finding, Severity};

/// Render one posture-monitor cycle into printable lines.
///
/// For each finding, produces a `[ICON] rule_id: reason` line, where ICON is:
///   - `"CRITICAL"` if `severity >= Critical`
///   - `"HIGH"` if `severity >= High`
///   - `"MEDIUM"` otherwise
///
/// Returns `(lines, any_critical)`:
///   - `lines`: one entry per finding (empty if no findings).
///   - `any_critical`: `true` iff at least one finding has Critical severity.
///
/// The dispatcher prints `"Posture OK."` when `lines` is empty.
pub fn render_cycle(findings: &[Finding]) -> (Vec<String>, bool) {
    let mut lines = Vec::with_capacity(findings.len());
    let mut any_critical = false;

    for f in findings {
        let icon = if f.severity >= Severity::Critical {
            any_critical = true;
            "CRITICAL"
        } else if f.severity >= Severity::High {
            "HIGH"
        } else {
            "MEDIUM"
        };
        lines.push(format!("[{}] {}: {}", icon, f.rule_id, f.reason));
    }

    (lines, any_critical)
}
