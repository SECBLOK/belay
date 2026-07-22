//! Conservative-v1 entry scanner for MCP-server config writes.
//!
//! [`scan_entry`] takes one already-diffed [`McpServerEntry`] (see
//! `skills::gate::detect_mcp_config_write`, which decides WHICH entries
//! changed) and turns it into a gating [`Verdict`]. Several independent
//! signals are folded together most-restrictive-wins (Deny > Ask > Allow,
//! ties broken by severity) so a `http://` entry that is ALSO "remote" still
//! surfaces as the more specific/severe "insecure transport" finding rather
//! than the generic "new remote server" one.
//!
//! Deliberately conservative: an ordinary local `{"command": "...", "args":
//! [...]}` server with no remote/secret/dangerous-flag signal returns a
//! silent Allow — no alert fatigue for the common case.
use std::net::IpAddr;

use serde_json::json;

use crate::engine::decide::decide;
use crate::engine::rules::RuleSet;
use crate::engine::types::{Decision, Severity, SessionState, ToolCall, Verdict};
use crate::observe::secrets::scan_secret_bytes;
use crate::skills::mcp_config::McpServerEntry;

/// Scan one changed MCP server entry and return a gating [`Verdict`]. Never
/// panics: a `RuleSet::load()` failure just skips the command-through-engine
/// signal (fail-soft) rather than propagating an error.
pub fn scan_entry(e: &McpServerEntry) -> Verdict {
    let mut best = allow_verdict();

    // Signal 1: fold the launch command+args through the existing rule engine
    // so an obviously-dangerous command (e.g. one matching an existing
    // destructive/egress rule) is caught the same way a Bash tool call would be.
    if let Some(command) = &e.command {
        if let Ok(rs) = RuleSet::load() {
            let full = if e.args.is_empty() {
                command.clone()
            } else {
                format!("{command} {}", e.args.join(" "))
            };
            let tc = ToolCall {
                session: "mcp-scan".into(),
                tool: "Bash".into(),
                input: json!({ "command": full }),
            };
            let mut st = SessionState::new("mcp-scan");
            best = fold_most_restrictive(best, decide(&rs, &tc, &mut st));
        }
    }

    let is_remote = e.url.is_some() || e.transport.is_some();

    // Signal 2: any remote (url/transport) entry is at least worth a look.
    if is_remote {
        best = fold_most_restrictive(best, remote_verdict(e));
    }

    // Signal 3: insecure transport — plaintext http:// or a raw IP literal host.
    if is_insecure(e) {
        best = fold_most_restrictive(best, insecure_verdict());
    }

    // Signal 4: a known-dangerous flag in the command/args/env values.
    if has_dangerous_flag(e) {
        best = fold_most_restrictive(best, dangerous_flag_verdict());
    }

    // Signal 5: secret-shaped value in args/env. Remote + secret is the ONLY
    // Deny in this scanner (credentials handed to a server outside our
    // control); stdio-only + secret is just worth a look (Ask).
    if has_secret_shaped_value(e) {
        let secret_verdict = if is_remote { secret_remote_deny_verdict() } else { secret_stdio_ask_verdict() };
        best = fold_most_restrictive(best, secret_verdict);
    }

    best
}

fn rank(d: Decision) -> u8 {
    match d {
        Decision::Deny => 2,
        Decision::Ask => 1,
        Decision::Allow => 0,
    }
}

/// Fold `candidate` into the running `best`, keeping whichever is more
/// restrictive: higher decision rank wins outright; on a decision tie, higher
/// severity wins (so e.g. an Ask/High "insecure transport" signal beats an
/// Ask/Medium "new remote server" signal instead of the first-seen signal
/// silently winning). A tie on both rank and severity keeps `best`.
fn fold_most_restrictive(best: Verdict, candidate: Verdict) -> Verdict {
    if (rank(candidate.decision), candidate.severity) > (rank(best.decision), best.severity) {
        candidate
    } else {
        best
    }
}

fn allow_verdict() -> Verdict {
    Verdict {
        decision: Decision::Allow,
        reason: String::new(),
        rules: vec![],
        severity: Severity::Info,
        primary_rule: None,
        category: None,
        owasp: None,
        atlas: None,
        explain: None,
    }
}

fn remote_verdict(e: &McpServerEntry) -> Verdict {
    let host = e.url.as_deref().and_then(host_of).unwrap_or_else(|| "unknown host".into());
    Verdict {
        decision: Decision::Ask,
        reason: format!("new remote MCP server ({host})"),
        rules: vec!["mcp.install.review".into()],
        severity: Severity::Medium,
        primary_rule: Some("mcp.install.review".into()),
        category: Some("tamper".into()),
        owasp: None,
        atlas: None,
        explain: None,
    }
}

fn insecure_verdict() -> Verdict {
    Verdict {
        decision: Decision::Ask,
        reason: "insecure MCP transport".into(),
        rules: vec!["mcp.install.review".into()],
        severity: Severity::High,
        primary_rule: Some("mcp.install.review".into()),
        category: Some("tamper".into()),
        owasp: None,
        atlas: None,
        explain: None,
    }
}

fn dangerous_flag_verdict() -> Verdict {
    Verdict {
        decision: Decision::Ask,
        reason: "MCP server launch carries a dangerous flag".into(),
        rules: vec!["mcp.install.review".into()],
        severity: Severity::High,
        primary_rule: Some("mcp.install.review".into()),
        category: Some("tamper".into()),
        owasp: None,
        atlas: None,
        explain: None,
    }
}

fn secret_remote_deny_verdict() -> Verdict {
    Verdict {
        decision: Decision::Deny,
        reason: "credential embedded in remote MCP entry".into(),
        rules: vec!["mcp.install.blocked".into()],
        severity: Severity::Critical,
        primary_rule: Some("mcp.install.blocked".into()),
        category: Some("tamper".into()),
        owasp: None,
        atlas: None,
        explain: None,
    }
}

fn secret_stdio_ask_verdict() -> Verdict {
    Verdict {
        decision: Decision::Ask,
        reason: "credential-shaped value in local MCP server config".into(),
        rules: vec!["mcp.install.review".into()],
        severity: Severity::Medium,
        primary_rule: Some("mcp.install.review".into()),
        category: Some("tamper".into()),
        owasp: None,
        atlas: None,
        explain: None,
    }
}

/// `true` if `url` starts with `http://` (case-insensitively) or its host is
/// a raw IPv4/IPv6 literal. `false` (never insecure) if there's no url at
/// all — stdio-only entries have no transport to judge.
fn is_insecure(e: &McpServerEntry) -> bool {
    let Some(url) = &e.url else { return false };
    if url.get(..7).map(|s| s.eq_ignore_ascii_case("http://")).unwrap_or(false) {
        return true;
    }
    match host_of(url) {
        Some(host) => host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().is_ok(),
        None => false,
    }
}

/// Best-effort host extraction from a URL string: no new deps, so this is a
/// small manual parse rather than pulling in the `url` crate. Strips the
/// scheme, any userinfo, the path/query/fragment, and a trailing port.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_and_rest = after_scheme.split(['/', '?', '#']).next().unwrap_or(after_scheme);
    let host_port = host_and_rest.rsplit('@').next().unwrap_or(host_and_rest);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 literal in brackets, e.g. `[::1]:8080`.
        format!("[{}", rest.split(']').next().unwrap_or(rest))
    } else {
        host_port.split(':').next().unwrap_or(host_port).to_string()
    };
    if host.is_empty() { None } else { Some(host) }
}

const DANGEROUS_FLAGS: [&str; 3] = ["--dangerously-skip-permissions", "--no-sandbox", "--allow-all"];

/// `true` if `command`, any `args` entry, or any `env` VALUE contains one of
/// [`DANGEROUS_FLAGS`], or if `env.NODE_OPTIONS` contains `--require`.
fn has_dangerous_flag(e: &McpServerEntry) -> bool {
    let mut haystacks: Vec<&str> = Vec::new();
    if let Some(c) = &e.command {
        haystacks.push(c.as_str());
    }
    haystacks.extend(e.args.iter().map(String::as_str));
    haystacks.extend(e.env.values().map(String::as_str));
    if haystacks.iter().any(|h| DANGEROUS_FLAGS.iter().any(|f| h.contains(f))) {
        return true;
    }
    e.env.get("NODE_OPTIONS").map(|v| v.contains("--require")).unwrap_or(false)
}

/// `true` if [`scan_secret_bytes`] flags anything in the concatenated `args`
/// values + `env` VALUES (never keys — an env var literally named `TOKEN` or
/// `API_KEY` is normal and not itself a finding).
fn has_secret_shaped_value(e: &McpServerEntry) -> bool {
    let mut buf = String::new();
    for a in &e.args {
        buf.push_str(a);
        buf.push('\n');
    }
    for v in e.env.values() {
        buf.push_str(v);
        buf.push('\n');
    }
    !scan_secret_bytes(buf.as_bytes()).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn entry(name: &str) -> McpServerEntry {
        McpServerEntry {
            name: name.into(),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            url: None,
            transport: None,
        }
    }

    #[test]
    fn ordinary_local_command_is_silent_allow() {
        let mut e = entry("local");
        e.command = Some("node".into());
        e.args = vec!["server.js".into()];
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.rules.is_empty());
    }

    #[test]
    fn remote_https_entry_asks_medium() {
        let mut e = entry("remote");
        e.url = Some("https://h.example/".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Ask);
        assert_eq!(v.severity, Severity::Medium);
        assert!(v.rules.iter().any(|r| r == "mcp.install.review"));
    }

    #[test]
    fn http_entry_asks_high_not_medium() {
        let mut e = entry("insecure");
        e.url = Some("http://h.example/".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Ask);
        assert_eq!(v.severity, Severity::High, "insecure-transport signal must win the tie over the generic remote signal");
    }

    #[test]
    fn raw_ip_literal_host_is_insecure() {
        let mut e = entry("rawip");
        e.url = Some("https://203.0.113.5:9443/mcp".into());
        assert!(is_insecure(&e));
    }

    #[test]
    fn secret_in_remote_env_value_denies() {
        let mut e = entry("remote");
        e.url = Some("https://h.example/".into());
        e.env.insert("TOKEN".into(), "AKIAIOSFODNN7EXAMPLE".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Deny);
        assert!(v.rules.iter().any(|r| r == "mcp.install.blocked"));
    }

    #[test]
    fn secret_in_stdio_only_env_value_asks_not_denies() {
        let mut e = entry("local");
        e.command = Some("node".into());
        e.env.insert("TOKEN".into(), "AKIAIOSFODNN7EXAMPLE".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn secret_shaped_env_key_alone_is_not_a_finding() {
        // The KEY "API_KEY" is a completely ordinary env var name; only the
        // VALUE shape matters.
        let mut e = entry("local");
        e.command = Some("node".into());
        e.env.insert("API_KEY".into(), "not-secret-shaped".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn dangerous_flag_in_args_asks_high() {
        let mut e = entry("local");
        e.command = Some("claude".into());
        e.args = vec!["--dangerously-skip-permissions".into()];
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Ask);
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn node_options_require_flag_asks() {
        let mut e = entry("local");
        e.command = Some("node".into());
        e.env.insert("NODE_OPTIONS".into(), "--require ./evil.js".into());
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn dangerous_launch_command_caught_via_engine_fold() {
        let mut e = entry("local");
        e.command = Some("rm".into());
        e.args = vec!["-rf".into(), "/".into()];
        let v = scan_entry(&e);
        assert_eq!(v.decision, Decision::Deny, "rm -rf / must be caught by the folded-in engine decide()");
    }
}
