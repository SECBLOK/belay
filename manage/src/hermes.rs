//! Hermes agent hook wiring.
//!
//! Hermes (NousResearch/hermes-agent) has a native, config-declared, ENFORCING
//! hook system that is a near-exact analogue of Claude Code's `PreToolUse`: a
//! `hooks:` block in `~/.hermes/config.yaml` whose `pre_tool_call` entries each
//! run a shell `command`; the command receives the tool call as JSON on stdin
//! and can DENY it by printing `{"decision":"block","reason":...}` on stdout
//! (verified against hermes `agent/shell_hooks.py::_parse_response` +
//! `model_tools.py` enforcement — the tool is never dispatched on a block).
//!
//! A hook only FIRES once its `(event, command)` pair is present in the consent
//! allowlist `~/.hermes/shell-hooks-allowlist.json`
//! (`agent/shell_hooks.py::_is_allowlisted`). So "protected" means BOTH the
//! config hook AND the allowlist consent are present — either alone does
//! nothing. Belay therefore protects hermes the way it protects
//! claude-code (wire in its own gate), NOT by rewriting `mcp_servers`: hermes's
//! config is YAML with no standard `mcpServers` block, and an mcp-proxy rewrite
//! could not gate hermes's dangerous BUILT-IN tools (terminal, write_file, …)
//! anyway. The hook fires on every tool call, so coverage is strictly broader.
//!
//! Comment safety: hermes configs are large and heavily commented. We NEVER do
//! a whole-file YAML round-trip (serde_yaml drops comments). We only ever append
//! a clearly-delimited managed block to a config that has no `hooks:` key, write
//! a fresh block to an empty config, or refuse (returning an actionable error)
//! when a `hooks:` block already exists — and we never overwrite a config we
//! could not parse.

use std::path::{Path, PathBuf};

use serde_json::{json, Value as JsonValue};

/// The hermes hook event Belay gates on.
const HOOK_EVENT: &str = "pre_tool_call";
/// Substring that marks a hook command as Belay's (matches `wire.rs`).
const MARKER: &str = "belay";
/// Delimiters around the managed block we append/write, so uninstall can strip
/// it back out without disturbing the rest of a commented config.
const BEGIN: &str = "# >>> Belay managed hook (do not edit inside) >>>";
const END: &str = "# <<< Belay managed hook <<<";

// ── path resolution ───────────────────────────────────────────────────────────

/// Hermes's home directory. When `home` is `Some` (tests / `--home`) it is used
/// verbatim so behaviour is deterministic; when `None` (production) `$HERMES_HOME`
/// wins over `$HOME/.hermes`, mirroring hermes's own `get_hermes_home()`.
pub fn hermes_dir(home: Option<&str>) -> PathBuf {
    match home {
        Some(h) => Path::new(h).join(".hermes"),
        None => match std::env::var("HERMES_HOME") {
            Ok(v) if !v.is_empty() => PathBuf::from(v),
            _ => {
                let h = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                Path::new(&h).join(".hermes")
            }
        },
    }
}

/// Hermes's live config file (`<hermes_dir>/config.yaml`).
pub fn config_path(home: Option<&str>) -> PathBuf {
    hermes_dir(home).join("config.yaml")
}

/// Consent allowlist path (`<hermes_dir>/shell-hooks-allowlist.json`).
fn allowlist_path_for(config: &Path) -> PathBuf {
    config
        .parent()
        .map(|d| d.join("shell-hooks-allowlist.json"))
        .unwrap_or_else(|| PathBuf::from("shell-hooks-allowlist.json"))
}

/// The exact hook command string Belay installs and matches on. Hermes runs
/// it via `shlex.split` + `shell=False`, so the double-quoted absolute path
/// survives as `argv[0]` even with spaces. `exe` must be an absolute path.
pub fn hook_command(exe: &str) -> String {
    format!("\"{exe}\" hook hermes-pretool")
}

// ── RFC3339 (no chrono dep; mirrors daemon host_config::rfc3339_utc) ───────────

fn rfc3339_utc(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mtime_iso(command: &str) -> Option<String> {
    // hermes stores this only to warn on drift; best-effort, never fatal.
    // `command` is `"<exe>" hook hermes-pretool` — extract the quoted exe path
    // (the old `trim_matches('"')` only stripped the leading quote, leaving the
    // embedded quote + trailing args, so this never resolved).
    let exe = command.split('"').nth(1).unwrap_or_else(|| command.trim());
    let meta = std::fs::metadata(exe).ok()?;
    let mtime = meta.modified().ok()?;
    let secs = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(rfc3339_utc(secs))
}

// ── config parsing helpers ────────────────────────────────────────────────────

/// Outcome of reading a config for wiring: `MissingOrEmpty` is safe to write a
/// fresh block into; `Parsed` carries the structure; `Unparseable` means the
/// file exists with content we could not parse — we MUST NOT touch it.
enum Cfg {
    MissingOrEmpty,
    Parsed(serde_yaml::Value),
    Unparseable,
}

fn read_cfg(path: &Path) -> Cfg {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Cfg::MissingOrEmpty,
    };
    if text.trim().is_empty() {
        return Cfg::MissingOrEmpty;
    }
    match serde_yaml::from_str::<serde_yaml::Value>(&text) {
        Ok(serde_yaml::Value::Null) => Cfg::MissingOrEmpty,
        // An empty flow map `{}` (hermes's reset/default state — and exactly what
        // the mcp-proxy no-op left on disk) must be REPLACED with a fresh block,
        // not appended to: `{}\nhooks:` is two root nodes and won't parse.
        Ok(serde_yaml::Value::Mapping(m)) if m.is_empty() => Cfg::MissingOrEmpty,
        Ok(v @ serde_yaml::Value::Mapping(_)) => Cfg::Parsed(v),
        // A valid but NON-mapping root (top-level sequence/scalar) — appending a
        // `hooks:` mapping after it would yield two root nodes (invalid YAML), so
        // refuse rather than corrupt it.
        Ok(_) => Cfg::Unparseable,
        Err(_) => Cfg::Unparseable,
    }
}

/// True if the parsed config's `hooks.pre_tool_call` list has any entry whose
/// `command` contains the Belay marker.
fn value_has_belay_hook(v: &serde_yaml::Value) -> bool {
    v.get("hooks")
        .and_then(|h| h.get(HOOK_EVENT))
        .and_then(|e| e.as_sequence())
        .map(|seq| {
            seq.iter().any(|item| {
                item.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains(MARKER))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn value_has_hooks_key(v: &serde_yaml::Value) -> bool {
    matches!(v, serde_yaml::Value::Mapping(m) if m.contains_key(serde_yaml::Value::String("hooks".into())))
}

/// Render the managed hooks block (delimited, comment-annotated). `command` is
/// emitted through serde_yaml so quoting is always valid YAML.
fn managed_block(command: &str) -> String {
    // Build just the `hooks:` subtree and serialize it — serde_yaml emits a
    // top-level `hooks:` mapping we can drop in as-is.
    let entry = json!({
        "hooks": { HOOK_EVENT: [ { "command": command, "timeout": 10 } ] }
    });
    let yaml = serde_yaml::to_string(&entry).unwrap_or_else(|_| {
        // Extremely defensive fallback: hand-format with a single-quoted scalar.
        let esc = command.replace('\'', "''");
        format!("hooks:\n  {HOOK_EVENT}:\n  - command: '{esc}'\n    timeout: 10\n")
    });
    format!(
        "{BEGIN}\n\
         # Gates every hermes tool call through the local Belay daemon; a\n\
         # denied call is blocked before it runs. Remove with:\n\
         #   belay unprotect hermes\n\
         {yaml}{END}\n"
    )
}

// ── allowlist (consent) ───────────────────────────────────────────────────────

/// Insert/refresh the consent entry so the hook actually fires in non-TTY
/// (gateway/cron) runs. Schema mirrors hermes `_record_approval`.
fn add_allowlist_entry(path: &Path, command: &str) -> Result<(), String> {
    let mut data: JsonValue = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => {
            serde_json::from_str(&t).unwrap_or_else(|_| json!({ "approvals": [] }))
        }
        _ => json!({ "approvals": [] }),
    };
    let entry = json!({
        "event": HOOK_EVENT,
        "command": command,
        "approved_at": rfc3339_utc(now_secs()),
        "script_mtime_at_approval": mtime_iso(command),
    });
    match data.get_mut("approvals").and_then(|a| a.as_array_mut()) {
        Some(arr) => {
            // Replace any stale entry for the same (event, command).
            arr.retain(|e| {
                !(e.get("event").and_then(|x| x.as_str()) == Some(HOOK_EVENT)
                    && e.get("command").and_then(|x| x.as_str()) == Some(command))
            });
            arr.push(entry);
        }
        None => {
            data = json!({ "approvals": [entry] });
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    crate::wire::atomic_write(path, text.as_bytes()).map_err(|e| e.to_string())
}

fn remove_allowlist_entries(path: &Path) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut data: JsonValue = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Some(arr) = data.get_mut("approvals").and_then(|a| a.as_array_mut()) {
        arr.retain(|e| {
            !e.get("command")
                .and_then(|x| x.as_str())
                .map(|c| c.contains(MARKER))
                .unwrap_or(false)
        });
    }
    if let Ok(t) = serde_json::to_string_pretty(&data) {
        let _ = std::fs::write(path, t);
    }
}

#[cfg(test)]
fn is_allowlisted(path: &Path, command: &str) -> bool {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let data: JsonValue = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    data.get("approvals")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter().any(|e| {
                e.get("event").and_then(|x| x.as_str()) == Some(HOOK_EVENT)
                    && e.get("command").and_then(|x| x.as_str()) == Some(command)
            })
        })
        .unwrap_or(false)
}

// ── public API ────────────────────────────────────────────────────────────────

/// True when hermes protection is ACTIVE: the Belay hook is present in
/// `config.yaml` AND its consent entry is in the allowlist (so it will fire).
/// Used by `detect::compute_protected` for the `"hermes-hook"` interception.
pub fn hermes_protected(config: &Path) -> bool {
    let cfg_has = match read_cfg(config) {
        Cfg::Parsed(v) => value_has_belay_hook(&v),
        _ => false,
    };
    if !cfg_has {
        return false;
    }
    // Consent must also exist (any allowlisted pre_tool_call command carrying
    // the marker), else the hook silently never fires.
    let allow = allowlist_path_for(config);
    match std::fs::read_to_string(&allow)
        .ok()
        .and_then(|t| serde_json::from_str::<JsonValue>(&t).ok())
    {
        Some(v) => v
            .get("approvals")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter().any(|e| {
                    e.get("event").and_then(|x| x.as_str()) == Some(HOOK_EVENT)
                        && e.get("command")
                            .and_then(|x| x.as_str())
                            .map(|c| c.contains(MARKER))
                            .unwrap_or(false)
                })
            })
            .unwrap_or(false),
        None => false,
    }
}

/// Install Belay's `pre_tool_call` hook into hermes's config + allowlist.
///
/// `exe` must be an absolute path to the `belay` binary. Returns `Err`
/// (having written nothing to the config) when the config exists but cannot be
/// parsed, or already defines its own `hooks:` block we won't rewrite.
pub fn install_hermes_hook(config: &Path, exe: &str) -> Result<(), String> {
    let command = hook_command(exe);
    let allow = allowlist_path_for(config);

    match read_cfg(config) {
        Cfg::Unparseable => {
            return Err(format!(
                "refusing to modify {}: it exists but is not valid YAML — \
                 Belay will not overwrite a config it cannot parse. Fix or \
                 remove the file and retry.",
                config.display()
            ));
        }
        Cfg::Parsed(v) if value_has_belay_hook(&v) => {
            // Config already wired; just make sure consent is present.
            return add_allowlist_entry(&allow, &command);
        }
        Cfg::Parsed(v) if value_has_hooks_key(&v) => {
            return Err(format!(
                "hermes config {} already defines a `hooks:` block. Belay \
                 won't rewrite it automatically (to avoid disturbing your \
                 config/comments). Add this under `hooks.pre_tool_call:` yourself:\n\
                 \x20   - command: {command}\n\
                 \x20     timeout: 10\n\
                 then run `belay protect hermes` again to register consent.",
                config.display()
            ));
        }
        Cfg::MissingOrEmpty => {
            backup_if_absent(config);
            write_fresh(config, &command)?;
        }
        Cfg::Parsed(_) => {
            // Non-empty config, no `hooks:` key: append the managed block,
            // preserving every existing line and comment.
            backup_if_absent(config);
            append_block(config, &command)?;
        }
    }
    add_allowlist_entry(&allow, &command)
}

/// Remove Belay's hook from hermes's config (the delimited managed block)
/// and its consent entries. Comment-safe: strips only the managed region.
pub fn uninstall_hermes_hook(config: &Path) {
    if let Ok(text) = std::fs::read_to_string(config) {
        if let Some(stripped) = strip_managed_block(&text) {
            let _ = std::fs::write(config, stripped);
        }
        // If no managed markers are present (e.g. a hand-added hook), we leave
        // the config untouched and rely on removing consent below so the hook
        // can no longer fire.
    }
    remove_allowlist_entries(&allowlist_path_for(config));
}

// ── config writers ────────────────────────────────────────────────────────────

fn backup_if_absent(config: &Path) {
    let backup = PathBuf::from(format!("{}.belay-backup", config.to_string_lossy()));
    if !backup.exists() {
        if let Ok(orig) = std::fs::read(config) {
            let _ = std::fs::write(&backup, orig);
        } else {
            // No original to back up (missing file) — record an empty marker so
            // a later restore knows the config was Belay-created.
            let _ = std::fs::write(&backup, b"");
        }
    }
}

fn write_fresh(config: &Path, command: &str) -> Result<(), String> {
    if let Some(dir) = config.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    crate::wire::atomic_write(config, managed_block(command).as_bytes()).map_err(|e| e.to_string())
}

fn append_block(config: &Path, command: &str) -> Result<(), String> {
    let mut text = std::fs::read_to_string(config).map_err(|e| e.to_string())?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push('\n');
    text.push_str(&managed_block(command));
    crate::wire::atomic_write(config, text.as_bytes()).map_err(|e| e.to_string())
}

/// Remove the delimited managed block (inclusive) plus one blank separator line
/// immediately before it, if present. Returns `None` when no block exists.
fn strip_managed_block(text: &str) -> Option<String> {
    let begin = text.find(BEGIN)?;
    let end_rel = text[begin..].find(END)?;
    let end = begin + end_rel + END.len();
    let mut start = begin;
    let mut stop = end;
    if text[stop..].starts_with('\n') {
        stop += 1;
    }
    // Trim one preceding blank line (the separator `append_block` inserts).
    if text[..start].ends_with("\n\n") {
        start -= 1;
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    out.push_str(&text[stop..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const EXE: &str = "/opt/belay/belay";

    fn cmd() -> String {
        hook_command(EXE)
    }

    #[test]
    fn install_into_empty_config_writes_block_and_consent() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        fs::write(&cfg, "{}").unwrap();

        install_hermes_hook(&cfg, EXE).unwrap();

        assert!(hermes_protected(&cfg), "should be active after install");
        let text = fs::read_to_string(&cfg).unwrap();
        assert!(text.contains(BEGIN) && text.contains(END));
        assert!(text.contains("hook hermes-pretool"));
        let allow = dir.path().join("shell-hooks-allowlist.json");
        assert!(is_allowlisted(&allow, &cmd()));
    }

    #[test]
    fn install_appends_and_preserves_existing_comments() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        let original = "# my hermes config\nmodel:\n  name: gpt-5   # a comment\n";
        fs::write(&cfg, original).unwrap();

        install_hermes_hook(&cfg, EXE).unwrap();

        let text = fs::read_to_string(&cfg).unwrap();
        assert!(text.contains("# my hermes config"));
        assert!(text.contains("name: gpt-5   # a comment"));
        assert!(text.contains(BEGIN));
        assert!(hermes_protected(&cfg));
    }

    #[test]
    fn refuses_existing_hooks_block_without_clobbering() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        let original = "hooks:\n  pre_tool_call:\n    - command: /usr/bin/mine\n";
        fs::write(&cfg, original).unwrap();

        let err = install_hermes_hook(&cfg, EXE).unwrap_err();
        assert!(err.contains("already defines"), "got: {err}");
        assert_eq!(fs::read_to_string(&cfg).unwrap(), original);
        assert!(!hermes_protected(&cfg));
    }

    #[test]
    fn refuses_unparseable_config_without_clobbering() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        let original = "model: [unclosed\n  : : :\n";
        fs::write(&cfg, original).unwrap();

        let err = install_hermes_hook(&cfg, EXE).unwrap_err();
        assert!(err.contains("not valid YAML"), "got: {err}");
        assert_eq!(fs::read_to_string(&cfg).unwrap(), original);
    }

    #[test]
    fn refuses_non_mapping_yaml_root_without_clobbering() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        // A valid YAML doc whose root is a sequence, not a mapping.
        let original = "- one\n- two\n";
        fs::write(&cfg, original).unwrap();
        let err = install_hermes_hook(&cfg, EXE).unwrap_err();
        assert!(err.contains("not valid YAML"), "got: {err}");
        assert_eq!(fs::read_to_string(&cfg).unwrap(), original);
        assert!(!hermes_protected(&cfg));
    }

    #[test]
    fn install_is_idempotent() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        fs::write(&cfg, "model:\n  name: x\n").unwrap();

        install_hermes_hook(&cfg, EXE).unwrap();
        let after_first = fs::read_to_string(&cfg).unwrap();
        install_hermes_hook(&cfg, EXE).unwrap();
        let after_second = fs::read_to_string(&cfg).unwrap();

        assert_eq!(after_first, after_second, "second install must be a no-op");
        assert_eq!(after_second.matches(BEGIN).count(), 1);
    }

    #[test]
    fn uninstall_strips_block_and_consent_restoring_original() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        let original = "# header\nmodel:\n  name: x\n";
        fs::write(&cfg, original).unwrap();

        install_hermes_hook(&cfg, EXE).unwrap();
        assert!(hermes_protected(&cfg));

        uninstall_hermes_hook(&cfg);
        assert!(!hermes_protected(&cfg));
        let text = fs::read_to_string(&cfg).unwrap();
        assert!(!text.contains(BEGIN) && !text.contains(END));
        assert_eq!(text, original);
        let allow = dir.path().join("shell-hooks-allowlist.json");
        assert!(!is_allowlisted(&allow, &cmd()));
    }

    #[test]
    fn protected_requires_both_config_and_consent() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        fs::write(&cfg, "{}").unwrap();
        backup_if_absent(&cfg);
        write_fresh(&cfg, &cmd()).unwrap();
        assert!(
            !hermes_protected(&cfg),
            "config hook without consent must NOT read as protected"
        );
        add_allowlist_entry(&allowlist_path_for(&cfg), &cmd()).unwrap();
        assert!(hermes_protected(&cfg));
    }
}
