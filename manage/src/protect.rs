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
            return Some(strip_verbatim_prefix(&val));
        }
    }
    let p = current_exe?;
    p.is_absolute()
        .then(|| strip_verbatim_prefix(&p.to_string_lossy()))
}

/// Removes Windows' extended-length (`\\?\`) path prefix.
///
/// `std::fs::canonicalize` on Windows returns a VERBATIM path —
/// `\\?\C:\Program Files\Belay\belay.exe` — and that form is not executable
/// through a shell. `cmd.exe` parses the leading `\\` as a UNC network path and
/// fails with "The system cannot find the path specified"; PowerShell and most
/// process launchers reject it too.
///
/// The consequence is the exact failure this module's [`resolve_hook_exe`] doc
/// already warns about for the bare-`belay` case, and it is silent: the agent
/// runs the hook, the hook cannot start, the tool call proceeds UNGATED, and
/// nothing is recorded. A Windows install would report no detections at all
/// while appearing to be protected.
///
/// Stripping is safe on every platform and for both the `\\?\C:\…` (drive) and
/// `\\?\UNC\server\share` (network) forms — the latter is rewritten back to a
/// real `\\server\share` UNC path rather than being left as a broken literal.
/// A no-op on paths that carry no prefix, and on Unix.
fn strip_verbatim_prefix(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    p.to_string()
}

/// True when `path` is a Cargo-built **test harness** rather than a real
/// `belay` executable.
///
/// # Why this exists
///
/// [`belay_exe`] falls back to `std::env::current_exe()`. Under `cargo test`
/// that is the libtest harness for the crate being tested, not `belay`. The
/// post-install probe in [`self_test_hook`] then runs the command it just
/// built - `sh -c '"<harness>" hook pretooluse'` - and libtest reads `hook`
/// and `pretooluse` as test-name filters, so the harness RE-RUNS THE TEST
/// SUITE. Those tests reach `protect()` again and each spawns another probe.
///
/// The branching factor is greater than one and every generation lives until
/// [`SELF_TEST_TIMEOUT`], so the process count grows without bound: an
/// observed `cargo test --workspace` on this repo reached ~2000 live
/// processes spawning at ~220/sec and had to be broken by removing the exec
/// bit from the harness binary. Killing generations does not work, because
/// each one forks its successors before it dies.
///
/// # The tell
///
/// Cargo names test binaries `<crate>-<hash>` and puts them in
/// `target/<profile>/deps/`. Requiring BOTH signals keeps this precise:
/// neither fires on a shipped `/usr/local/bin/belay`, nor on
/// `cargo run --bin belay` (`target/<profile>/belay` - no hash, not in
/// `deps/`), so a real install is never skipped.
fn looks_like_cargo_test_binary(path: &str) -> bool {
    let p = Path::new(path);
    let in_deps = p
        .parent()
        .and_then(|d| d.file_name())
        .is_some_and(|n| n == "deps");
    let hash_suffixed = p
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.rsplit_once('-'))
        .is_some_and(|(_, suffix)| {
            (8..=32).contains(&suffix.len()) && suffix.chars().all(|c| c.is_ascii_hexdigit())
        });
    in_deps && hash_suffixed
}

/// The binary path out of a command built by [`hook_command`] - the leading
/// double-quoted segment of `"<exe>" hook <phase>`.
///
/// `None` for any other shape (a hand-written shell snippet, for instance),
/// which callers treat as "no path to vet" rather than as a refusal.
fn hook_command_exe(pre_cmd: &str) -> Option<&str> {
    pre_cmd.strip_prefix('"')?.split('"').next()
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

/// How long the post-install self-test waits for the hook to answer before
/// giving up. Generous: a cold-start binary on a loaded machine is slow, and a
/// false "your hook is broken" is worse than a slow install.
const SELF_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Runs the freshly-installed hook command and checks it actually answers.
///
/// # Why this exists
///
/// A hook can install perfectly and still be unable to RUN, and that failure is
/// invisible from every direction: the agent invokes it, the process never
/// starts, the tool call proceeds ungated, nothing is recorded, and the UI
/// still reports the agent as protected. A broken hook and a quiet day look
/// identical.
///
/// That is not hypothetical. Belay v0.1.14 on Windows embedded the verbatim
/// (`\\?\C:\…`) path that `canonicalize` returns, which no shell can execute,
/// so every Windows install silently gated nothing until a user reported it.
/// No engine test could have caught it, because the engine was never invoked.
/// [`resolve_hook_exe`] already refuses the shapes it can prove are broken;
/// this catches the ones it cannot.
///
/// # Faithful by construction
///
/// The command is run THROUGH A SHELL (`cmd /C` on Windows, `sh -c` elsewhere)
/// because that is how the agent runs it, and a path that a shell rejects but
/// `Command::new` would happily accept is precisely the bug class in question.
/// Testing it any other way would have passed on the broken Windows build.
///
/// The probe payload is deliberately innocuous so the gate answers `allow`
/// immediately and never parks an approval; this must not leave a prompt
/// waiting on a messaging channel at install time.
fn self_test_hook(pre_cmd: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    // Refuse to EXECUTE a Cargo test harness. `protect()` pre-checks this and
    // reports it accurately, so reaching here means a caller did not - and the
    // consequence is a fork bomb, not a bad message, so the primitive refuses
    // on its own rather than trusting every present and future caller to.
    // See `looks_like_cargo_test_binary` for the failure it prevents.
    if let Some(exe) = hook_command_exe(pre_cmd) {
        if looks_like_cargo_test_binary(exe) {
            return Err(format!(
                "refused to run the self-test: {exe} is a Cargo test harness, not a \
                 belay binary; executing it would re-enter the test suite recursively"
            ));
        }
    }

    let (shell, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") };
    let mut child = Command::new(shell)
        .arg(flag)
        .arg(pre_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start the hook via {shell}: {e}"))?;

    // A benign call: allowed instantly, so this never parks.
    let probe = serde_json::json!({
        "session_id": "belay-install-self-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "true" },
    })
    .to_string();
    if let Some(mut stdin) = child.stdin.take() {
        // Ignore a write error: a hook that died before reading stdin shows up
        // as a bad/missing answer below, which is the message we want to give.
        let _ = stdin.write_all(probe.as_bytes());
    } // dropped here -> EOF, so a well-behaved one-shot hook exits

    // Wait with a bound. A hook that hangs is as broken as one that fails, and
    // must not wedge `belay protect` forever.
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut out = String::new();
        if let Some(mut so) = child.stdout.take() {
            let _ = so.read_to_string(&mut out);
        }
        let status = child.wait();
        let _ = tx.send((out, status));
    });
    let (out, status) = rx.recv_timeout(SELF_TEST_TIMEOUT).map_err(|_| {
        format!(
            "the hook did not answer within {}s",
            SELF_TEST_TIMEOUT.as_secs()
        )
    })?;
    let _ = handle.join();

    let code = status.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
    let v: serde_json::Value = serde_json::from_str(out.trim()).map_err(|_| {
        let shown: String = out.trim().chars().take(200).collect();
        if shown.is_empty() {
            format!("the hook produced no output (exit code {code})")
        } else {
            format!("the hook did not answer with JSON (exit code {code}): {shown}")
        }
    })?;
    v.get("hookSpecificOutput")
        .and_then(|h| h.get("permissionDecision"))
        .and_then(serde_json::Value::as_str)
        .map(|_| ())
        .ok_or_else(|| format!("the hook answered without a permission decision: {v}"))
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
            // Claude Code MERGES hooks from EVERY settings file it loads (user
            // ~/.claude/settings.json, settings.local.json, and the project
            // .claude/settings.json). A belay hook present in more than one fires
            // multiple times per tool call - duplicate approval prompts. So install
            // into exactly ONE canonical file (the first / highest-precedence path)
            // and strip any belay hook from the rest, so the gate fires exactly once
            // regardless of prior state (idempotent across re-runs).
            match agent.settings_paths.split_first() {
                None => Ok(()),
                Some((primary, rest)) => {
                    for p in rest {
                        uninstall(Path::new(p));
                    }
                    if install(Path::new(primary), &pre, &post) {
                        // Verify the hook we just wrote can actually run. NOT
                        // fatal: the hook is installed and may well work
                        // (a sandbox with no shell, an antivirus holding the
                        // binary, a transient failure), and tearing down a
                        // possibly-good install over a failed probe would be
                        // worse than the uncertainty. But it must be LOUD:
                        // the whole point is that this failure is otherwise
                        // indistinguishable from silence.
                        if looks_like_cargo_test_binary(&exe) {
                            // Not a pass and not a failure: the probe was never
                            // run. Saying so plainly beats both the loud
                            // "may be UNGATED" warning (wrong - this is a test
                            // run, not a broken install) and silence (which
                            // would imply the hook was verified).
                            eprintln!(
                                "[belay] note: skipping the hook self-test for '{}' - the \
                                 resolved binary {exe} is a Cargo test harness, not a belay \
                                 binary. Nothing was verified. Set $BELAY_BIN to a real \
                                 binary to exercise the probe.",
                                agent.name
                            );
                        } else if let Err(why) = self_test_hook(&pre) {
                            eprintln!(
                                "[belay] WARNING: installed the hook for '{}', but the \
                                 self-test could not confirm it runs: {why}\n\
                                 [belay] Until this is resolved, tool calls for this agent \
                                 may proceed UNGATED while the UI reports it as protected.\n\
                                 [belay] Hook command: {pre}\n\
                                 [belay] See docs/TROUBLESHOOTING.md \
                                 (\"Belay never prompts, never blocks\").",
                                agent.name
                            );
                        }
                        Ok(())
                    } else {
                        Err(format!(
                            "refused to modify an existing settings file for '{}' that is not \
                             valid JSON — nothing was changed (fix or remove the file and retry)",
                            agent.name
                        ))
                    }
                }
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
        // Detected-but-unsupported agents (currently `config-policy`: gemini,
        // goose). There is no interception path for these and none is planned —
        // they are detected so `belay detect` output is complete, not because
        // Belay can gate them.
        //
        // This returns Ok because "nothing to do" is not an error, but the
        // CALLER must not report success: see `run_protect`, which checks
        // `is_interceptable` and tells the user plainly. Reporting "Protecting
        // gemini (mode=enforce)" after a no-op is worse than not supporting the
        // agent at all — it tells someone they are covered when they are not.
        _ => Ok(()),
    }
}

/// True if Belay has a real interception path for this agent.
///
/// `protect()`'s catch-all returns `Ok(())` for anything else, so this is what
/// distinguishes "wired up" from "silently did nothing".
pub fn is_interceptable(agent: &DetectedAgent) -> bool {
    matches!(
        agent.interception.as_str(),
        "hook" | "mcp-proxy" | "hermes-hook" | "cursor-hook" | "exec-policy" | "opencode-plugin"
    )
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
    // Report per agent what actually happened. An agent with no interception
    // path must never be reported as protected.
    let mode = if observe { "observe" } else { "enforce" };
    let (wired, skipped): (Vec<_>, Vec<_>) = matched.iter().partition(|a| is_interceptable(a));

    for a in &skipped {
        eprintln!(
            "NOT protecting '{}': Belay has no interception path for it \
             (detected as '{}'). It is detected for reporting only; \
             `belay protect` cannot gate this agent.",
            a.name, a.interception
        );
    }

    if wired.is_empty() {
        // Nothing was wired. Exiting SUCCESS here is what previously told users
        // they were covered when they were not.
        return ExitCode::FAILURE;
    }

    for a in &wired {
        println!("Protecting {} (mode={})", a.name, mode);
    }
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

    fn agent_with(interception: &str) -> DetectedAgent {
        DetectedAgent {
            name: "test-agent".to_string(),
            settings_paths: vec![],
            risky_flags: vec![],
            interception: interception.to_string(),
            mcp_config_paths: vec![],
            mcp_servers: vec![],
            skills: vec![],
            protected: false,
        }
    }

    /// Every interception string that `protect()` actually has an arm for must
    /// be reported as interceptable, and anything reaching the catch-all must
    /// not be. If someone adds a new `protect()` arm without adding it here,
    /// `belay protect` would silently claim to have wired an agent it skipped —
    /// which is the exact defect this function exists to prevent.
    #[test]
    fn is_interceptable_matches_the_arms_protect_actually_has() {
        for wired in [
            "hook",
            "mcp-proxy",
            "hermes-hook",
            "cursor-hook",
            "exec-policy",
            "opencode-plugin",
        ] {
            assert!(
                is_interceptable(&agent_with(wired)),
                "{wired} has a protect() arm"
            );
        }
    }

    /// `config-policy` is gemini and goose. They are detected for reporting
    /// only; `protect()` falls through to its no-op catch-all. Reporting them
    /// as protected told users they were covered when they were not.
    #[test]
    fn config_policy_agents_are_not_interceptable() {
        assert!(
            !is_interceptable(&agent_with("config-policy")),
            "gemini/goose must never be reported as protected"
        );
        // A future unknown mechanism must also fail closed rather than being
        // assumed wired.
        assert!(!is_interceptable(&agent_with("some-future-mechanism")));
    }

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

    /// Windows `canonicalize` returns a verbatim (`\\?\`) path, which no shell
    /// can execute. Installing that as the hook command produces a Windows
    /// install that looks protected and gates nothing — reported live on
    /// v0.1.14 as "no alerts at all".
    #[test]
    fn a_verbatim_windows_path_is_normalised_for_the_hook() {
        // Drive form.
        assert_eq!(
            strip_verbatim_prefix(r"\\?\C:\Program Files\Belay\belay.exe"),
            r"C:\Program Files\Belay\belay.exe"
        );
        // UNC form becomes a real UNC path, not a broken literal.
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\server\share\belay.exe"),
            r"\\server\share\belay.exe"
        );
        // No-ops.
        assert_eq!(strip_verbatim_prefix(r"C:\Belay\belay.exe"), r"C:\Belay\belay.exe");
        assert_eq!(strip_verbatim_prefix("/usr/local/bin/belay"), "/usr/local/bin/belay");

        // End to end through the resolver, which is what protect() calls.
        // Windows-only: the resolver gates on `Path::is_absolute`, and a
        // `C:\`-rooted path is absolute on Windows but NOT on Unix, so this
        // half can only be asserted where it actually runs.
        #[cfg(windows)]
        {
            let got = resolve_hook_exe(
                None,
                Some(PathBuf::from(r"\\?\C:\Program Files\Belay\belay.exe")),
            );
            assert_eq!(got.as_deref(), Some(r"C:\Program Files\Belay\belay.exe"));

            // And through the env override, which takes the other branch.
            let got = resolve_hook_exe(Some(r"\\?\C:\tools\belay.exe".to_string()), None);
            assert_eq!(got.as_deref(), Some(r"C:\tools\belay.exe"));
        }
    }

    /// The self-test must FAIL for a hook that cannot execute. This is the
    /// whole point: `resolve_hook_exe` already rejects the shapes it can prove
    /// broken, and this catches the rest: a path that looks fine and is not.
    ///
    /// The Windows verbatim-path bug is the motivating case, and it is
    /// reproduced here in the form that matters: a shell being handed a command
    /// it cannot run. On Unix a `\\?\C:\…` path is simply a missing file, which
    /// exercises the identical failure path (shell starts, command does not).
    #[test]
    fn the_self_test_fails_for_a_hook_that_cannot_execute() {
        let broken = hook_command(r"\\?\C:\Program Files\Belay\belay.exe", "pretooluse");
        let err = self_test_hook(&broken).expect_err("a non-executable hook must fail the probe");
        assert!(!err.is_empty(), "failure must carry a reason");

        // A path that does not exist at all, same expectation.
        let missing = hook_command("/nonexistent/belay-does-not-exist", "pretooluse");
        assert!(self_test_hook(&missing).is_err());
    }

    /// And it must PASS for a hook that answers properly, or it would cry wolf
    /// on every install. Uses a stub that emits the real hook wire format, so
    /// the assertion is about the contract rather than about our binary being
    /// built in this test run.
    #[test]
    fn the_self_test_passes_for_a_hook_that_answers() {
        // A shell one-liner standing in for the hook: consumes stdin and emits
        // the PreToolUse allow payload the agent expects.
        let ok = if cfg!(windows) {
            r#"echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}"#
                .to_string()
        } else {
            r#"cat >/dev/null; printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'"#
                .to_string()
        };
        assert!(self_test_hook(&ok).is_ok(), "a well-behaved hook must pass");
    }

    /// A hook that starts, but answers with something that is not a decision,
    /// is broken too: silence and garbage are equally unusable.
    #[test]
    fn the_self_test_rejects_a_non_answer() {
        let empty = if cfg!(windows) { "cd ." } else { "cat >/dev/null" };
        assert!(
            self_test_hook(empty).is_err(),
            "no output must not count as a pass"
        );
        let garbage = if cfg!(windows) { "echo hello" } else { "printf hello" };
        assert!(self_test_hook(garbage).is_err(), "non-JSON must not pass");
        let wrong_shape = if cfg!(windows) {
            r#"echo {"ok":true}"#.to_string()
        } else {
            r#"printf '%s' '{"ok":true}'"#.to_string()
        };
        assert!(
            self_test_hook(&wrong_shape).is_err(),
            "JSON without a permission decision must not pass"
        );
    }

    /// The regression guard for the fork bomb.
    ///
    /// Before this, `cargo test` resolved `belay_exe()` to the libtest harness
    /// and the probe shelled out to it; the harness treated `hook pretooluse`
    /// as test filters, re-ran the suite, and each generation spawned more.
    /// The probe must now REFUSE rather than execute.
    #[test]
    fn the_self_test_refuses_to_execute_a_cargo_test_harness() {
        let harness = "/home/u/proj/target/debug/deps/belay_manage-e943c5c5ada314bf";
        let cmd = hook_command(harness, "pretooluse");
        let err = self_test_hook(&cmd).expect_err("must refuse a test harness");

        // Refused, not merely "ran and failed" - the distinction is the whole
        // fix, so assert on the reason rather than just on is_err().
        assert!(
            err.contains("refused to run the self-test"),
            "must report a refusal, got: {err}"
        );
        assert!(err.contains(harness), "reason must name the path, got: {err}");
    }

    #[test]
    fn test_harness_paths_are_recognised_and_real_binaries_are_not() {
        // Cargo test binaries: in `deps/` AND hash-suffixed.
        assert!(looks_like_cargo_test_binary(
            "/p/target/debug/deps/belay_manage-e943c5c5ada314bf"
        ));
        assert!(looks_like_cargo_test_binary(
            "/p/target/release/deps/protect-0123456789abcdef"
        ));

        // Real binaries must never be skipped - a false positive here silently
        // disables the probe on a genuine install, which is the bug the probe
        // exists to catch.
        assert!(!looks_like_cargo_test_binary("/usr/local/bin/belay"));
        assert!(!looks_like_cargo_test_binary("/p/target/release/belay"));
        assert!(!looks_like_cargo_test_binary("/p/target/debug/belay"));
        assert!(!looks_like_cargo_test_binary(r"C:\Program Files\Belay\belay.exe"));

        // Each signal alone is not enough.
        assert!(
            !looks_like_cargo_test_binary("/p/target/debug/deps/belay"),
            "in deps/ but not hash-suffixed"
        );
        assert!(
            !looks_like_cargo_test_binary("/opt/belay-0123456789abcdef"),
            "hash-suffixed but not in deps/"
        );

        // A hyphenated real name must not read as a hash.
        assert!(!looks_like_cargo_test_binary("/p/target/debug/deps/belay-hook"));
    }

    #[test]
    fn hook_command_exe_extracts_the_quoted_path_only() {
        assert_eq!(
            hook_command_exe(&hook_command("/usr/local/bin/belay", "pretooluse")),
            Some("/usr/local/bin/belay")
        );
        assert_eq!(
            hook_command_exe(&hook_command("/opt/my belay/belay", "posttooluse")),
            Some("/opt/my belay/belay"),
            "a path with spaces survives, which is why hook_command quotes it"
        );
        // Shapes with no leading quoted path yield None, so the existing
        // shell-snippet probes in these tests stay unaffected by the guard.
        assert_eq!(hook_command_exe("cat >/dev/null; printf hi"), None);
        assert_eq!(hook_command_exe(""), None);
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

    #[test]
    fn protect_hook_installs_into_one_file_and_dedups_the_rest() {
        // Regression: protect() used to install the belay hook into EVERY settings
        // file, and Claude Code merges hooks from all of them -> the gate fired
        // multiple times per tool call (duplicate approval prompts). It must install
        // into exactly ONE file and strip belay from the rest.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("settings.json");
        let secondary = tmp.path().join("settings.local.json");
        // Pre-seed the SECONDARY with a belay hook (the already-duplicated state);
        // primary starts as an empty object.
        let pre = hook_command("/usr/local/bin/belay", "pretooluse");
        let post = hook_command("/usr/local/bin/belay", "posttooluse");
        assert!(install(&secondary, &pre, &post));
        std::fs::write(&primary, "{}").unwrap();

        let agent = DetectedAgent {
            name: "claude-code".into(),
            settings_paths: vec![
                primary.to_string_lossy().into_owned(),
                secondary.to_string_lossy().into_owned(),
            ],
            risky_flags: vec![],
            interception: "hook".into(),
            mcp_config_paths: vec![],
            mcp_servers: vec![],
            skills: vec![],
            protected: false,
        };
        protect(&agent).expect("protect should succeed");

        let has_hook =
            |p: &std::path::Path| std::fs::read_to_string(p).unwrap().contains("hook pretooluse");
        assert!(has_hook(&primary), "primary must carry the belay hook");
        assert!(
            !has_hook(&secondary),
            "secondary must be stripped (no duplicate)"
        );
    }
}
