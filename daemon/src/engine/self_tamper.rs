//! Compiled-in self-protection backstop.
//!
//! `tamper.agent_config_write` (in `rules/catalog.yaml`) denies *direct* writes
//! to Belay's own artifacts by matching the protected path string in the
//! tool call. Two gaps remain that a catalog rule cannot close:
//!
//!  1. **Indirection** — `git apply <patch>` / `git am` / `patch` modify a
//!     protected file WITHOUT naming it, so no path string is present to match.
//!  2. **Self-disable** — anything expressed only in the YAML can itself be
//!     weakened by editing the YAML.
//!
//! This module is the un-disableable backstop: it is compiled into the binary
//! and consulted by [`crate::engine::decide::decide`] regardless of the catalog
//! contents. It returns synthetic [`RuleHit`]s that the dev-toolchain allowlist
//! is forbidden to downgrade.

use crate::engine::rules::RuleHit;
use crate::engine::types::{Decision, Severity, ToolCall};
use crate::service::is_self_tamper;
use std::sync::OnceLock;

/// Matches a Bash command that applies opaque external content — at the start of
/// the command or after a `;`/`&`/`|` separator, with optional `sudo`:
/// `git apply`, `git am`, or `patch`. These can write arbitrary (including
/// protected) files without naming them, so they are surfaced for human review.
fn opaque_write_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:git\s+(?:apply|am)|patch)\b")
            .expect("opaque-write regex is valid")
    })
}

fn hit(id: &str, decision: Decision, severity: Severity, reason: &str) -> RuleHit {
    RuleHit {
        id: id.to_string(),
        category: "tamper".to_string(),
        severity,
        decision,
        reason: reason.to_string(),
        sink: false,
        arms: None,
        ingest: false,
        owasp: None,
        atlas: None,
        explain: None,
    }
}

/// Synthetic self-protection hits for a tool call (empty when none apply):
///  - a direct `Write`/`Edit` to a Belay-protected artifact → **Deny**;
///  - a `Bash` command applying opaque external content → **Ask** (human review,
///    because it could modify a protected file without naming it).
pub fn self_tamper_hits(tc: &ToolCall) -> Vec<RuleHit> {
    match tc.tool.as_str() {
        "Write" | "Edit" => {
            let path = tc
                .input
                .get("file_path")
                .or_else(|| tc.input.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_self_tamper(path) {
                return vec![hit(
                    "tamper.self_protect",
                    Decision::Deny,
                    Severity::Critical,
                    "direct write to a Belay-protected file",
                )];
            }
        }
        "Bash" => {
            let cmd = tc
                .input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if opaque_write_re().is_match(cmd) {
                return vec![hit(
                    "tamper.indirect_write",
                    Decision::Ask,
                    Severity::High,
                    "applies opaque external content (could modify a protected file without naming it)",
                )];
            }
        }
        _ => {}
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tc(tool: &str, input: serde_json::Value) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: tool.into(),
            input,
        }
    }

    #[test]
    fn direct_write_to_protected_file_is_deny() {
        for path in [
            "/home/u/project/rules/catalog.yaml",
            "/home/u/.belay/audit.ndjson",
            "/usr/local/bin/belayd",
        ] {
            let hits = self_tamper_hits(&tc("Write", json!({ "file_path": path })));
            assert_eq!(hits.len(), 1, "{path}");
            assert_eq!(hits[0].id, "tamper.self_protect");
            assert_eq!(hits[0].decision, Decision::Deny);
        }
        // Edit is gated identically.
        let hits = self_tamper_hits(&tc("Edit", json!({"file_path": "/p/rules/catalog.yaml"})));
        assert_eq!(hits[0].decision, Decision::Deny);
    }

    #[test]
    fn ordinary_write_is_not_self_tamper() {
        let hits = self_tamper_hits(&tc("Write", json!({"file_path": "/p/src/main.rs"})));
        assert!(hits.is_empty());
    }

    #[test]
    fn opaque_write_commands_are_ask() {
        // The exact indirection that bypassed the path-string deny, plus siblings.
        for cmd in [
            "git apply /tmp/x.patch",
            "git am < series.mbox",
            "patch -p1 < change.diff",
            "echo hi && git apply x.patch",
            "sudo patch -p0 -i z.diff",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "{cmd}");
            assert_eq!(hits[0].id, "tamper.indirect_write", "{cmd}");
            assert_eq!(hits[0].decision, Decision::Ask, "{cmd}");
        }
    }

    #[test]
    fn benign_git_and_lookalikes_are_not_flagged() {
        for cmd in [
            "git status",
            "git commit -m x",
            "git checkout main",
            "npm run patch-release", // 'patch' only as a substring, not the command
            "echo 'git apply' is a phrase",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(hits.is_empty(), "must not flag: {cmd} -> {hits:?}");
        }
    }
}
