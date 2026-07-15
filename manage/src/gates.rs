//! Native-gate wiring for agents whose correct interception is NOT the
//! Claude-style JSON hook (`wire.rs`) or hermes's YAML hook (`hermes.rs`):
//!
//! - **cursor**  → Cursor Hooks (`~/.cursor/hooks.json`): a real pre-tool gate
//!   (`beforeShellExecution`/`beforeMCPExecution`/`beforeReadFile`) that can
//!   `deny`. Supersedes the old mcp-proxy classification, which missed Cursor's
//!   built-in shell/edit tools and url MCP servers entirely.
//! - **openclaw** → exec-approvals policy (`~/.openclaw/exec-approvals.json`):
//!   OpenClaw's native host-exec gate. Belay tightens the policy (effective
//!   policy is the STRICTER of config and this file, so tightening always wins).
//!   The old mcp-proxy classification no-oped (OpenClaw nests servers under
//!   `mcp.servers`, not top-level `mcpServers`).
//! - **opencode** → a native plugin (`~/.config/opencode/plugin/belay.ts`)
//!   implementing `permission.ask`, routed through `belay gate`.
//!
//! All writers embed a `belay` marker so `detect::compute_protected` can
//! tell whether protection is actually in place, and back up any pre-existing
//! file to `<path>.belay-backup` before writing.

use std::path::Path;

use serde_json::{json, Value};

const MARKER: &str = "belay";

fn backup_if_absent(path: &Path) {
    let backup = format!("{}.belay-backup", path.to_string_lossy());
    let backup = Path::new(&backup);
    if !backup.exists() {
        if let Ok(orig) = std::fs::read(path) {
            let _ = std::fs::write(backup, orig);
        }
    }
}

fn load_json_or_empty(path: &Path) -> Option<Value> {
    // None => file exists but is unparseable (caller must refuse to clobber).
    match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => serde_json::from_str(&t).ok(),
        _ => Some(json!({})),
    }
}

fn write_pretty(path: &Path, v: &Value) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    // Atomic temp-then-rename so a crash mid-write can't corrupt the config.
    crate::wire::atomic_write(path, text.as_bytes()).map_err(|e| e.to_string())
}

fn cmd_has_marker(e: &Value) -> bool {
    e.get("command")
        .and_then(|c| c.as_str())
        .map(|c| c.contains(MARKER))
        .unwrap_or(false)
}

// ── Cursor ────────────────────────────────────────────────────────────────────

/// Cursor hook events Belay gates. `beforeShellExecution` is the primary
/// control (built-in terminal); `beforeMCPExecution` supersedes the mcp-proxy;
/// `beforeReadFile` guards secret exfiltration.
const CURSOR_EVENTS: [&str; 3] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
];

/// The hook command Cursor runs (reads JSON on stdin, prints a permission
/// decision on stdout). Cursor uses `shell:false`-style argv, so the quoted
/// absolute path survives.
pub fn cursor_hook_command(exe: &str) -> String {
    format!("\"{exe}\" hook cursor-pre")
}

/// True only when the PRIMARY control (`beforeShellExecution` — arbitrary shell
/// execution, the highest-risk surface) is gated through Belay. Requiring
/// the shell hook specifically (not "any of the three events") means a
/// partially-wired or hand-edited `hooks.json` — e.g. one where only the
/// non-`failClosed` `beforeReadFile` carries our marker — does NOT read as
/// protected while shell exec is unguarded. `install_cursor_hook` always writes
/// all three, so a full install satisfies this.
pub fn cursor_protected(hooks_json: &Path) -> bool {
    let v = match std::fs::read_to_string(hooks_json)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    {
        Some(v) => v,
        None => return false,
    };
    v.get("hooks")
        .and_then(|h| h.get("beforeShellExecution"))
        .and_then(|a| a.as_array())
        .map(|a| a.iter().any(cmd_has_marker))
        .unwrap_or(false)
}

/// Install Belay into Cursor's hooks.json. Merges into an existing JSON
/// (Cursor hooks.json is plain JSON, no comments), refuses to clobber an
/// unparseable file, and is idempotent.
pub fn install_cursor_hook(hooks_json: &Path, exe: &str) -> Result<(), String> {
    let command = cursor_hook_command(exe);
    let mut v = load_json_or_empty(hooks_json).ok_or_else(|| {
        format!(
            "refusing to modify {}: not valid JSON",
            hooks_json.display()
        )
    })?;
    backup_if_absent(hooks_json);

    if !v.is_object() {
        v = json!({});
    }
    v["version"] = json!(1);
    if !v["hooks"].is_object() {
        v["hooks"] = json!({});
    }
    for ev in CURSOR_EVENTS {
        // The exec/tool events fail CLOSED (block) if our gate crashes/times out.
        // beforeReadFile is deliberately left fail-OPEN: a daemon hiccup should
        // not brick every file the agent reads (reads are lower-risk than exec).
        // Net: a crash blocks shell/MCP but still allows reads until recovery.
        let fail_closed = ev != "beforeReadFile";
        let entry = if fail_closed {
            json!({ "command": command, "failClosed": true })
        } else {
            json!({ "command": command })
        };
        match v["hooks"].get_mut(ev).and_then(|a| a.as_array_mut()) {
            Some(a) => {
                if !a.iter().any(cmd_has_marker) {
                    a.push(entry);
                }
            }
            None => {
                v["hooks"][ev] = json!([entry]);
            }
        }
    }
    write_pretty(hooks_json, &v)
}

/// Remove Belay's entries from Cursor's hooks.json (keeps the user's own).
pub fn uninstall_cursor_hook(hooks_json: &Path) {
    let mut v = match std::fs::read_to_string(hooks_json)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    {
        Some(v) => v,
        None => return,
    };
    if let Some(hooks) = v.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        for ev in CURSOR_EVENTS {
            if let Some(arr) = hooks.get_mut(ev).and_then(|a| a.as_array_mut()) {
                arr.retain(|e| !cmd_has_marker(e));
            }
        }
    }
    let _ = write_pretty(hooks_json, &v);
}

// ── OpenClaw (exec-approvals policy) ───────────────────────────────────────────

/// True if Belay's managed exec-approvals policy is present.
pub fn openclaw_protected(exec_approvals: &Path) -> bool {
    std::fs::read_to_string(exec_approvals)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| {
            v.get("defaults")
                .and_then(|d| d.get("belay_managed"))
                .and_then(|m| m.as_bool())
        })
        .unwrap_or(false)
}

/// The four keys that flip OpenClaw's exec gate to default-deny + fail-closed:
/// allowlist mode, ask on an allowlist miss, deny when a prompt can't be
/// delivered, and never silently auto-allow skill binaries.
fn tighten_exec_policy(obj: &mut serde_json::Map<String, Value>) {
    obj.insert("security".into(), json!("allowlist"));
    obj.insert("ask".into(), json!("on-miss"));
    obj.insert("askFallback".into(), json!("deny"));
    obj.insert("autoAllowSkills".into(), json!(false));
}

/// Write a strict Belay-managed exec-approvals policy (tightening only -
/// OpenClaw takes the stricter of config and this file). Tightens `defaults`
/// AND every existing per-agent block (per-agent policy OVERRIDES defaults in
/// OpenClaw, so a looser `agents.<id>` would otherwise bypass us). Refuses to
/// clobber an unparseable file; the original is restored from backup on uninstall.
pub fn install_openclaw_policy(exec_approvals: &Path) -> Result<(), String> {
    let mut v = load_json_or_empty(exec_approvals).ok_or_else(|| {
        format!(
            "refusing to modify {}: not valid JSON",
            exec_approvals.display()
        )
    })?;
    backup_if_absent(exec_approvals);
    if !v.is_object() {
        v = json!({});
    }
    v["version"] = json!(1);
    // MERGE our tightening keys into any existing `defaults` (default-deny with
    // an allowlist and fail-closed fallback; `belay_managed` is our detection
    // marker). A wholesale replace would drop other keys OpenClaw may store.
    if !v.get("defaults").map(|d| d.is_object()).unwrap_or(false) {
        v["defaults"] = json!({});
    }
    let d = v["defaults"].as_object_mut().unwrap();
    tighten_exec_policy(d);
    d.insert("belay_managed".into(), json!(true));
    if !v.get("agents").map(|a| a.is_object()).unwrap_or(false) {
        v["agents"] = json!({});
    }
    // Close the per-agent bypass: a pre-existing `agents.<id>` with a looser
    // security mode overrides our tightened defaults, so apply the same
    // tightening to each existing per-agent block. Other per-agent keys (e.g. a
    // custom allowlist) are preserved.
    if let Some(agents) = v["agents"].as_object_mut() {
        for entry in agents.values_mut() {
            if let Some(obj) = entry.as_object_mut() {
                tighten_exec_policy(obj);
            }
        }
    }
    write_pretty(exec_approvals, &v)
}

/// Restore the pre-Belay exec-approvals file (from backup), else drop the
/// managed marker so it no longer reads as protected.
pub fn uninstall_openclaw_policy(exec_approvals: &Path) {
    let backup = format!("{}.belay-backup", exec_approvals.to_string_lossy());
    if let Ok(orig) = std::fs::read(&backup) {
        let _ = std::fs::write(exec_approvals, orig);
        return;
    }
    if let Some(mut v) = std::fs::read_to_string(exec_approvals)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    {
        if let Some(d) = v.get_mut("defaults").and_then(|d| d.as_object_mut()) {
            d.remove("belay_managed");
        }
        let _ = write_pretty(exec_approvals, &v);
    }
}

/// OpenClaw risky-config flags (the real ones — the old `full-host` string was a
/// phantom that never existed in OpenClaw). Reads `openclaw.json` JSON.
pub fn openclaw_risky_flags(openclaw_json: &Path) -> Vec<String> {
    let v = match std::fs::read_to_string(openclaw_json)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    {
        Some(v) => v,
        None => return vec![],
    };
    let exec = v.get("tools").and_then(|t| t.get("exec"));
    let mut flags = vec![];
    let sec = exec
        .and_then(|e| e.get("security").or_else(|| e.get("mode")))
        .and_then(|s| s.as_str());
    if sec == Some("full") {
        flags.push("exec.security=full".to_string());
    }
    if exec.and_then(|e| e.get("ask")).and_then(|s| s.as_str()) == Some("off") {
        flags.push("exec.ask=off".to_string());
    }
    match exec.and_then(|e| e.get("host")).and_then(|s| s.as_str()) {
        Some("gateway") | Some("node") => flags.push("exec.host=host".to_string()),
        _ => {}
    }
    if exec
        .and_then(|e| e.get("autoAllowSkills"))
        .and_then(|b| b.as_bool())
        == Some(true)
    {
        flags.push("autoAllowSkills=true".to_string());
    }
    flags
}

// ── opencode (native plugin) ───────────────────────────────────────────────────

/// Minimal opencode plugin: routes every approval through `belay gate` and
/// denies when the daemon says deny. Fail-open (never bricks opencode). `{EXE}`
/// is substituted with the absolute binary path at install time.
const OPENCODE_PLUGIN_TS: &str = r#"// Belay (managed) — routes opencode tool approvals through the local
// Belay daemon; a denied call is blocked. Remove with `belay unprotect opencode`.
import { spawnSync } from "node:child_process"
const BELAY = "{EXE}"
export const belay = async () => ({
  "permission.ask": async (input, output) => {
    try {
      const payload = JSON.stringify({
        tool_name: input?.type ?? input?.tool ?? "tool",
        tool_input: input,
        session_id: input?.sessionID ?? "opencode",
      })
      const r = spawnSync(BELAY, ["gate"], { input: payload, encoding: "utf8" })
      const out = JSON.parse(r.stdout || "{}")
      const dec = out?.hookSpecificOutput?.permissionDecision
      if (dec === "deny") output.status = "deny"
    } catch (_) {
      // fail-open: never block opencode because our gate errored
    }
  },
})
"#;

fn opencode_plugin_file(plugin_dir: &Path) -> std::path::PathBuf {
    plugin_dir.join("belay.ts")
}

/// True if Belay's opencode plugin is installed.
pub fn opencode_protected(plugin_dir: &Path) -> bool {
    std::fs::read_to_string(opencode_plugin_file(plugin_dir))
        .map(|t| t.contains(MARKER))
        .unwrap_or(false)
}

/// Install the Belay opencode plugin (`<config>/plugin/belay.ts`).
pub fn install_opencode_plugin(plugin_dir: &Path, exe: &str) -> Result<(), String> {
    std::fs::create_dir_all(plugin_dir).map_err(|e| e.to_string())?;
    let contents = OPENCODE_PLUGIN_TS.replace("{EXE}", exe);
    crate::wire::atomic_write(&opencode_plugin_file(plugin_dir), contents.as_bytes())
        .map_err(|e| e.to_string())
}

/// Remove the Belay opencode plugin.
pub fn uninstall_opencode_plugin(plugin_dir: &Path) {
    let f = opencode_plugin_file(plugin_dir);
    if std::fs::read_to_string(&f)
        .map(|t| t.contains(MARKER))
        .unwrap_or(false)
    {
        let _ = std::fs::remove_file(&f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const EXE: &str = "/opt/belay/belay";

    #[test]
    fn cursor_install_detect_uninstall() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join("hooks.json");
        assert!(!cursor_protected(&hooks));
        install_cursor_hook(&hooks, EXE).unwrap();
        assert!(cursor_protected(&hooks));
        let v: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["hooks"]["beforeShellExecution"][0]["failClosed"], true);
        install_cursor_hook(&hooks, EXE).unwrap();
        let v2: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
        assert_eq!(
            v2["hooks"]["beforeShellExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        uninstall_cursor_hook(&hooks);
        assert!(!cursor_protected(&hooks));
    }

    #[test]
    fn cursor_preserves_users_own_hook() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join("hooks.json");
        fs::write(
            &hooks,
            r#"{"version":1,"hooks":{"beforeShellExecution":[{"command":"/usr/bin/mine"}]}}"#,
        )
        .unwrap();
        install_cursor_hook(&hooks, EXE).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["beforeShellExecution"].as_array().unwrap().len(),
            2
        );
        uninstall_cursor_hook(&hooks);
        let v2: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
        assert_eq!(
            v2["hooks"]["beforeShellExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            v2["hooks"]["beforeShellExecution"][0]["command"],
            "/usr/bin/mine"
        );
    }

    #[test]
    fn cursor_refuses_unparseable() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join("hooks.json");
        fs::write(&hooks, "not json {{{").unwrap();
        assert!(install_cursor_hook(&hooks, EXE).is_err());
        assert_eq!(fs::read_to_string(&hooks).unwrap(), "not json {{{");
    }

    #[test]
    fn openclaw_policy_install_detect_uninstall() {
        let dir = tempdir().unwrap();
        let ea = dir.path().join("exec-approvals.json");
        assert!(!openclaw_protected(&ea));
        install_openclaw_policy(&ea).unwrap();
        assert!(openclaw_protected(&ea));
        let v: Value = serde_json::from_str(&fs::read_to_string(&ea).unwrap()).unwrap();
        assert_eq!(v["defaults"]["security"], "allowlist");
        assert_eq!(v["defaults"]["askFallback"], "deny");
        uninstall_openclaw_policy(&ea);
        assert!(!openclaw_protected(&ea));
    }

    #[test]
    fn openclaw_policy_restores_original_from_backup() {
        let dir = tempdir().unwrap();
        let ea = dir.path().join("exec-approvals.json");
        let orig = r#"{"version":1,"defaults":{"security":"full"},"agents":{"main":{}}}"#;
        fs::write(&ea, orig).unwrap();
        install_openclaw_policy(&ea).unwrap();
        assert!(openclaw_protected(&ea));
        uninstall_openclaw_policy(&ea);
        assert_eq!(fs::read_to_string(&ea).unwrap(), orig);
    }

    #[test]
    fn openclaw_policy_merges_and_preserves_other_defaults_keys() {
        let dir = tempdir().unwrap();
        let ea = dir.path().join("exec-approvals.json");
        // A pre-existing config with an unrelated key under `defaults`.
        fs::write(
            &ea,
            r#"{"defaults":{"timeoutSec":30,"security":"full"},"agents":{"main":{"x":1}}}"#,
        )
        .unwrap();
        install_openclaw_policy(&ea).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&ea).unwrap()).unwrap();
        // Our tightening keys applied...
        assert_eq!(v["defaults"]["security"], "allowlist");
        assert_eq!(v["defaults"]["belay_managed"], true);
        // ...without dropping the unrelated key or the agents block.
        assert_eq!(v["defaults"]["timeoutSec"], 30);
        assert_eq!(v["agents"]["main"]["x"], 1);
    }

    #[test]
    fn openclaw_policy_tightens_preexisting_per_agent_override() {
        let dir = tempdir().unwrap();
        let ea = dir.path().join("exec-approvals.json");
        // A per-agent block that overrides defaults with a wide-open policy -
        // this is the bypass we must close - plus an unrelated key to preserve.
        fs::write(
            &ea,
            r#"{"agents":{"evil":{"security":"full","ask":"off","note":"keep"}}}"#,
        )
        .unwrap();
        install_openclaw_policy(&ea).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&ea).unwrap()).unwrap();
        // The per-agent override is tightened to match our default-deny policy...
        assert_eq!(v["agents"]["evil"]["security"], "allowlist");
        assert_eq!(v["agents"]["evil"]["ask"], "on-miss");
        assert_eq!(v["agents"]["evil"]["askFallback"], "deny");
        // ...while unrelated per-agent keys survive.
        assert_eq!(v["agents"]["evil"]["note"], "keep");
    }

    #[test]
    fn openclaw_risky_flags_detects_real_keys() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("openclaw.json");
        fs::write(&cfg, r#"{"tools":{"exec":{"security":"full","ask":"off","host":"gateway","autoAllowSkills":true}}}"#).unwrap();
        let flags = openclaw_risky_flags(&cfg);
        assert!(flags.contains(&"exec.security=full".to_string()));
        assert!(flags.contains(&"exec.ask=off".to_string()));
        assert!(flags.contains(&"exec.host=host".to_string()));
        assert!(flags.contains(&"autoAllowSkills=true".to_string()));
    }

    #[test]
    fn opencode_plugin_install_detect_uninstall() {
        let dir = tempdir().unwrap();
        let plugdir = dir.path().join("plugin");
        assert!(!opencode_protected(&plugdir));
        install_opencode_plugin(&plugdir, EXE).unwrap();
        assert!(opencode_protected(&plugdir));
        let ts = fs::read_to_string(plugdir.join("belay.ts")).unwrap();
        assert!(ts.contains(EXE) && ts.contains("permission.ask"));
        uninstall_opencode_plugin(&plugdir);
        assert!(!opencode_protected(&plugdir));
    }
}
