//! Protect/unprotect agent wiring — Phase 12 Task 3.
//!
//! Ports the deleted Python predecessor's `wire/proxy_wire.py` protect/unprotect
//! dispatch and the `protect`/`unprotect` CLI subcommands from its `cli/main.py`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::detect::{find_agents, find_claude_code, DetectedAgent};
use crate::wire::{install, restore, rewrite_to_proxy, uninstall};

const PROXY: [&str; 2] = ["belay", "mcp-proxy"];

/// Decide the absolute hook-binary path from an optional `$BELAY_BIN`
/// override and the process's current-exe path. Pure (no env/fs) so it is fully
/// unit-testable.
///
/// Returns `Some` ONLY when the result is an absolute path. A relative path — or
/// a bare name like `belay` — returns `None`, because the hook command runs
/// from the AGENT's environment (e.g. Claude Code) where `belay` is almost
/// never on `$PATH`: a bare `"belay hook …"` fails with
/// `/bin/sh: belay: not found` and NO tool call is ever gated or recorded
/// (the Live Feed stays empty). The guard makes callers refuse rather than
/// silently install a hook that can never fire.
fn resolve_hook_exe(env_override: Option<String>, current_exe: Option<PathBuf>) -> Option<String> {
    if let Some(val) = env_override {
        if PathBuf::from(&val).is_absolute() {
            return Some(val);
        }
    }
    let p = current_exe?;
    p.is_absolute().then(|| p.to_string_lossy().into_owned())
}

/// Absolute path to the `belay` binary to embed in installed agent hooks.
/// Prefers an absolute `$BELAY_BIN`, else the canonicalized current exe.
/// `None` when neither yields an absolute path (see [`resolve_hook_exe`]).
fn belay_exe() -> Option<String> {
    let env_override = std::env::var("BELAY_BIN").ok();
    let current = std::env::current_exe()
        .ok()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p));
    resolve_hook_exe(env_override, current)
}

/// Build a hook command string: the (double-quoted, so paths with spaces work)
/// binary path followed by `hook <phase>`.
fn hook_command(exe: &str, phase: &str) -> String {
    format!("\"{exe}\" hook {phase}")
}

/// Mirror Python `protect(agent)` from proxy_wire.py.
///
/// Returns `Err` (and installs NOTHING) for a hook agent when no absolute
/// binary path can be resolved — installing a bare hook would fail silently at
/// the agent's runtime, so we refuse loudly instead.
pub fn protect(agent: &DetectedAgent) -> Result<(), String> {
    match agent.interception.as_str() {
        "hook" => {
            let exe = belay_exe().ok_or_else(|| {
                "could not resolve an absolute path to the belay binary; \
                 refusing to install a bare hook that would fail at the agent's \
                 runtime with \"belay: not found\". Set $BELAY_BIN to \
                 the absolute binary path and retry."
                    .to_string()
            })?;
            let pre = hook_command(&exe, "pretooluse");
            let post = hook_command(&exe, "posttooluse");
            let mut refused = false;
            for p in &agent.settings_paths {
                if !install(Path::new(p), &pre, &post) {
                    refused = true;
                }
            }
            if refused {
                Err(format!(
                    "refused to modify an existing settings file for '{}' that is not \
                     valid JSON — nothing was changed (fix or remove the file and retry)",
                    agent.name
                ))
            } else {
                Ok(())
            }
        }
        "mcp-proxy" => {
            // Honest result: rewrite_to_proxy returns whether the file ends up
            // routed through the proxy. If NOTHING got protected (no servers, or
            // an unparseable config we refused to touch), report failure instead
            // of a silent success the GUI would show as "Protected".
            let mut any = false;
            for p in &agent.mcp_config_paths {
                any |= rewrite_to_proxy(Path::new(p), &PROXY);
            }
            if any {
                Ok(())
            } else {
                Err(format!(
                    "no MCP servers were found to route through the proxy for '{}'; \
                     nothing was changed (add an MCP server first, or this agent may \
                     need a different protection method)",
                    agent.name
                ))
            }
        }
        // Hermes uses its native pre_tool_call hook (YAML config + consent
        // allowlist) — see hermes.rs. Wire our gate in; propagate real errors.
        "hermes-hook" => {
            let exe = belay_exe().ok_or_else(|| {
                "could not resolve an absolute path to the belay binary; set \
                 $BELAY_BIN to the absolute binary path and retry."
                    .to_string()
            })?;
            let config = agent.settings_paths.first().ok_or_else(|| {
                "hermes config path is unknown; cannot install the hook".to_string()
            })?;
            crate::hermes::install_hermes_hook(Path::new(config), &exe)
        }
        // Cursor's native pre-tool gate (~/.cursor/hooks.json) — see gates.rs.
        "cursor-hook" => {
            let exe = belay_exe().ok_or_else(|| {
                "could not resolve an absolute path to the belay binary; set \
                 $BELAY_BIN to the absolute binary path and retry."
                    .to_string()
            })?;
            let hooks = agent
                .settings_paths
                .first()
                .ok_or_else(|| "cursor hooks.json path is unknown".to_string())?;
            crate::gates::install_cursor_hook(Path::new(hooks), &exe)
        }
        // OpenClaw's native exec-approvals policy (tightening only).
        "exec-policy" => {
            let ea = agent
                .settings_paths
                .first()
                .ok_or_else(|| "openclaw exec-approvals path is unknown".to_string())?;
            crate::gates::install_openclaw_policy(Path::new(ea))
        }
        // opencode native plugin (permission.ask -> belay gate).
        "opencode-plugin" => {
            let exe = belay_exe().ok_or_else(|| {
                "could not resolve an absolute path to the belay binary; set \
                 $BELAY_BIN to the absolute binary path and retry."
                    .to_string()
            })?;
            let dir = agent
                .settings_paths
                .first()
                .ok_or_else(|| "opencode plugin dir is unknown".to_string())?;
            crate::gates::install_opencode_plugin(Path::new(dir), &exe)
        }
        _ => Ok(()),
    }
}

/// Mirror Python `unprotect(agent)` from proxy_wire.py.
pub fn unprotect(agent: &DetectedAgent) {
    match agent.interception.as_str() {
        "hook" => {
            for p in &agent.settings_paths {
                uninstall(Path::new(p));
            }
        }
        "mcp-proxy" => {
            for p in &agent.mcp_config_paths {
                restore(Path::new(p));
            }
        }
        "hermes-hook" => {
            if let Some(config) = agent.settings_paths.first() {
                crate::hermes::uninstall_hermes_hook(Path::new(config));
            }
        }
        "cursor-hook" => {
            if let Some(p) = agent.settings_paths.first() {
                crate::gates::uninstall_cursor_hook(Path::new(p));
            }
        }
        "exec-policy" => {
            if let Some(p) = agent.settings_paths.first() {
                crate::gates::uninstall_openclaw_policy(Path::new(p));
            }
        }
        "opencode-plugin" => {
            if let Some(p) = agent.settings_paths.first() {
                crate::gates::uninstall_opencode_plugin(Path::new(p));
            }
        }
        _ => {}
    }
}

/// CLI: `belay protect <agent> [--observe]`
///
/// Mirrors Python `protect` command in cli/main.py.
pub fn run_protect(agent_name: &str, observe: bool, home: Option<&str>) -> ExitCode {
    let agents = find_agents(home);
    let mut matched: Vec<DetectedAgent> = agents
        .into_iter()
        .filter(|a| a.name == agent_name)
        .collect();
    if matched.is_empty() {
        // Fallback: try claude-code specifically (may have no settings yet)
        match find_claude_code(home) {
            Some(a) if !a.settings_paths.is_empty() => matched.push(a),
            _ => {
                eprintln!("Agent '{}' not found or has no settings", agent_name);
                return ExitCode::FAILURE;
            }
        }
    }
    for a in &matched {
        if let Err(e) = protect(a) {
            eprintln!("Failed to protect '{}': {}", agent_name, e);
            return ExitCode::FAILURE;
        }
    }
    let mode = if observe { "observe" } else { "enforce" };
    println!("Protecting {} (mode={})", agent_name, mode);
    ExitCode::SUCCESS
}

/// CLI: `belay unprotect <agent>`
///
/// Mirrors Python `unprotect` command in cli/main.py.
pub fn run_unprotect(agent_name: &str, home: Option<&str>) -> ExitCode {
    let agents = find_agents(home);
    let mut matched: Vec<DetectedAgent> = agents
        .into_iter()
        .filter(|a| a.name == agent_name)
        .collect();
    if matched.is_empty() {
        if let Some(a) = find_claude_code(home) {
            matched.push(a);
        }
    }
    for a in &matched {
        unprotect(a);
    }
    println!("Unprotected.");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_hook_exe_requires_absolute_path() {
        // Absolute current exe → used.
        assert_eq!(
            resolve_hook_exe(None, Some(PathBuf::from("/usr/bin/belay"))),
            Some("/usr/bin/belay".to_string())
        );
        // Relative current exe, no override → None (the guard refuses).
        assert_eq!(
            resolve_hook_exe(None, Some(PathBuf::from("belay"))),
            None
        );
        assert_eq!(
            resolve_hook_exe(None, Some(PathBuf::from("target/debug/belay"))),
            None
        );
        // No current exe and no override → None.
        assert_eq!(resolve_hook_exe(None, None), None);
        // Absolute override wins even when current exe is relative.
        assert_eq!(
            resolve_hook_exe(
                Some("/opt/ad/belay".to_string()),
                Some(PathBuf::from("belay"))
            ),
            Some("/opt/ad/belay".to_string())
        );
        // Relative override is ignored; falls through to the absolute current exe.
        assert_eq!(
            resolve_hook_exe(
                Some("belay".to_string()),
                Some(PathBuf::from("/usr/bin/belay"))
            ),
            Some("/usr/bin/belay".to_string())
        );
        // Relative override AND relative current exe → None.
        assert_eq!(
            resolve_hook_exe(
                Some("belay".to_string()),
                Some(PathBuf::from("rel/belay"))
            ),
            None
        );
    }

    #[test]
    fn protect_refuses_hook_without_absolute_path() {
        // A hook agent whose binary can't be resolved must NOT install a bare
        // hook — protect() returns Err so run_protect can fail loudly.
        // We exercise the guard via resolve_hook_exe (protect() uses it): a
        // relative-only resolution yields None → the ok_or_else Err branch.
        assert!(resolve_hook_exe(None, Some(PathBuf::from("belay"))).is_none());
    }

    #[test]
    fn hook_command_uses_absolute_quoted_path() {
        let cmd = hook_command("/opt/belay/bin/belay", "pretooluse");
        assert_eq!(cmd, "\"/opt/belay/bin/belay\" hook pretooluse");
        // Quoting lets paths with spaces survive the shell.
        let spaced = hook_command("/home/a b/belay", "posttooluse");
        assert_eq!(spaced, "\"/home/a b/belay\" hook posttooluse");
        // Not the bare name that fails with "belay: not found".
        assert!(!cmd.starts_with("belay "));
    }
}
