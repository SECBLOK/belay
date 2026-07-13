//! Agent detection module — Phase 12 Task 2.
//!
//! Ports the deleted Python predecessor's `detect/registry.py` + `detect.py` + all 8 agent
//! detectors to Rust. Detector order matches the Python registry exactly:
//! claude_code, codex, cline, roo, cursor, gemini, goose, openclaw, hermes.
//!
//! Public API surface used by posture.rs and the `detect` CLI subcommand:
//!   - `DetectedAgent` struct
//!   - `find_agents(home: Option<&str>) -> Vec<DetectedAgent>`
//!   - `py_list_repr(v: &[String]) -> String`
//!   - `run(home: Option<&str>) -> ExitCode`

use std::path::Path;
use std::process::ExitCode;

// ─────────────────────────────────────────────────────────────────────────────
// Data types
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a detected AI agent on the host.
///
/// Mirrors the Python `detect.detect.DetectedAgent` dataclass.
pub struct DetectedAgent {
    /// Display name of the agent (e.g. "claude-code").
    pub name: String,
    /// Paths to the agent's settings/config files (may be empty).
    pub settings_paths: Vec<String>,
    /// Risky CLI flags found in the agent configuration.
    pub risky_flags: Vec<String>,
    /// Interception mode string ("hook" / "mcp-proxy" / "config-policy").
    pub interception: String,
    /// Paths to MCP config files associated with this agent.
    pub mcp_config_paths: Vec<String>,
    /// Names of MCP servers configured for this agent (parsed from its config
    /// files' `mcpServers`/`servers` objects). Sorted and deduplicated.
    pub mcp_servers: Vec<String>,
    /// Names of installed skills for this agent (currently claude-code only,
    /// from `~/.claude/skills/<name>/`). Sorted.
    pub skills: Vec<String>,
    /// Whether Belay protection is currently wired into this agent (the
    /// `belay` hook is installed, or its MCP config is rewritten to the
    /// proxy). Computed by `find_agents`; `false` for config-policy agents.
    pub protected: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: enumerate MCP server names + skill names
// ─────────────────────────────────────────────────────────────────────────────

/// Extract MCP server names from a set of JSON config files. Looks for a
/// top-level `mcpServers` (Claude/Cursor/Cline/Roo style) or `servers` object
/// and collects its keys. Result is sorted and deduplicated; unreadable or
/// non-JSON files (e.g. a TOML config) are skipped (best-effort, never panics).
fn mcp_server_names(paths: &[String]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut names: BTreeSet<String> = BTreeSet::new();
    for p in paths {
        let data: serde_json::Value = match std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(v) => v,
            None => continue,
        };
        for key in ["mcpServers", "servers"] {
            if let Some(obj) = data.get(key).and_then(|v| v.as_object()) {
                for name in obj.keys() {
                    names.insert(name.clone());
                }
            }
        }
    }
    names.into_iter().collect()
}

/// List the immediate subdirectory names of `dir` (e.g. installed skills),
/// sorted. A missing/unreadable directory yields an empty list.
fn subdir_names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: is Belay protection currently wired into an agent?
// ─────────────────────────────────────────────────────────────────────────────

/// True if a hook-agent settings file has a Belay hook installed — any
/// `hooks.{PreToolUse,PostToolUse}[].hooks[].command` containing "belay".
/// Mirrors the marker `wire::install` writes (and `has_belay` checks).
fn settings_has_belay_hook(path: &str) -> bool {
    let data: serde_json::Value = match std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => return false,
    };
    let hooks = match data.get("hooks").and_then(|v| v.as_object()) {
        Some(h) => h,
        None => return false,
    };
    for event in ["PreToolUse", "PostToolUse"] {
        if let Some(arr) = hooks.get(event).and_then(|v| v.as_array()) {
            for m in arr {
                if let Some(inner) = m.get("hooks").and_then(|v| v.as_array()) {
                    for h in inner {
                        if h.get("command")
                            .and_then(|v| v.as_str())
                            .map(|c| c.contains("belay"))
                            .unwrap_or(false)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// True if an MCP config file has a server rewritten to the Belay proxy —
/// any `mcpServers`/`servers` entry whose `command` contains "belay".
fn mcp_config_has_proxy(path: &str) -> bool {
    let data: serde_json::Value = match std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => return false,
    };
    for key in ["mcpServers", "servers"] {
        if let Some(obj) = data.get(key).and_then(|v| v.as_object()) {
            for server in obj.values() {
                if server
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(|c| c.contains("belay"))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Whether Belay protection is currently active for an agent, based on its
/// interception mode. config-policy agents have no in-place wiring, so `false`.
fn compute_protected(agent: &DetectedAgent) -> bool {
    match agent.interception.as_str() {
        "hook" => agent
            .settings_paths
            .iter()
            .any(|p| settings_has_belay_hook(p)),
        "mcp-proxy" => agent
            .mcp_config_paths
            .iter()
            .any(|p| mcp_config_has_proxy(p)),
        // Hermes has a native YAML `hooks:` block + a consent allowlist; the
        // check (config hook AND allowlisted) lives in the hermes module.
        "hermes-hook" => agent
            .settings_paths
            .first()
            .map(|p| crate::hermes::hermes_protected(Path::new(p)))
            .unwrap_or(false),
        // Native-gate agents (see gates.rs): settings_paths[0] is the file/dir
        // Belay wires into (cursor hooks.json, openclaw exec-approvals.json,
        // opencode plugin dir).
        "cursor-hook" => agent
            .settings_paths
            .first()
            .map(|p| crate::gates::cursor_protected(Path::new(p)))
            .unwrap_or(false),
        "exec-policy" => agent
            .settings_paths
            .first()
            .map(|p| crate::gates::openclaw_protected(Path::new(p)))
            .unwrap_or(false),
        "opencode-plugin" => agent
            .settings_paths
            .first()
            .map(|p| crate::gates::opencode_protected(Path::new(p)))
            .unwrap_or(false),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Python list repr
// ─────────────────────────────────────────────────────────────────────────────

/// Format a `&[String]` exactly as Python's `repr(list)`:
/// `['a', 'b']` (single quotes, comma+space).
/// An empty slice → `[]`.  A single element → `['x']`.
///
/// Used for BOTH the `detect` CLI output (`settings=`, `risky=`) AND the
/// posture `agent_risky_flags` reason string so both match Python's f-string.
pub fn py_list_repr(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let inner: Vec<String> = items.iter().map(|s| format!("'{}'", s)).collect();
    format!("[{}]", inner.join(", "))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: resolve home directory
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_home(home: Option<&str>) -> String {
    match home {
        Some(h) => h.to_owned(),
        None => std::env::var("HOME").unwrap_or_else(|_| ".".into()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: which(cmd) — search $PATH for an executable
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if `cmd` is found as an executable file in any `$PATH` component.
/// Mirrors Python's `shutil.which(cmd) is not None`.
fn which(cmd: &str) -> bool {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(cmd);
        if candidate.is_file() {
            // Check that the file has at least one execute bit set.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&candidate) {
                    if meta.permissions().mode() & 0o111 != 0 {
                        return true;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: Python truthiness for JSON values
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror Python's `if data.get(key):` truthiness for JSON values.
/// A value is truthy if it is: `true` (bool), non-zero number, non-empty string,
/// non-empty array/object.  `null`, `false`, `0`, `""`, `[]`, `{}` are falsy.
fn is_truthy(val: Option<&serde_json::Value>) -> bool {
    match val {
        None => false,
        Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(a)) => !a.is_empty(),
        Some(serde_json::Value::Object(o)) => !o.is_empty(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 1: claude-code  (mirrors detect.py::find_claude_code)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `find_claude_code(home)` in the deleted Python predecessor's `detect/detect.py`.
///
/// Detection: `~/.claude` dir exists OR `claude` binary on PATH.
/// Settings candidates:
///   - `~/.claude/settings.json`
///   - `~/.claude/settings.local.json`
///   - `$CWD/.claude/settings.json`
///
/// Risky flags (appended once per file, multiple flags possible per file):
///   - `"bypassPermissions"` if top-level `defaultMode == "bypassPermissions"`
///   - `"bypassPermissions"` if `permissions.defaultMode == "bypassPermissions"`
///   - `"enableAllProjectMcpServers"` if that key is truthy
pub fn find_claude_code(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let cdir = Path::new(&home_str).join(".claude");

    let on_path = which("claude");
    if !cdir.is_dir() && !on_path {
        return None;
    }

    // Collect existing settings paths
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let candidates = [
        cdir.join("settings.json"),
        cdir.join("settings.local.json"),
        cwd.join(".claude").join("settings.json"),
    ];
    let paths: Vec<String> = candidates
        .iter()
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    let mut flags: Vec<String> = Vec::new();
    for p in &paths {
        let data: serde_json::Value = match std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(v) => v,
            None => continue,
        };
        if data.get("defaultMode").and_then(|v| v.as_str()) == Some("bypassPermissions") {
            flags.push("bypassPermissions".to_string());
        }
        if data
            .get("permissions")
            .and_then(|p| p.get("defaultMode"))
            .and_then(|v| v.as_str())
            == Some("bypassPermissions")
        {
            flags.push("bypassPermissions".to_string());
        }
        if is_truthy(data.get("enableAllProjectMcpServers")) {
            flags.push("enableAllProjectMcpServers".to_string());
        }
        // "MiniMax Code" is not a standalone agent — it's Claude Code repointed
        // at a MiniMax endpoint via the env block. Flag the source-code egress
        // (China endpoint minimaxi.com is a distinct jurisdiction concern).
        if let Some(env) = data.get("env") {
            let base = env
                .get("ANTHROPIC_BASE_URL")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let model = env
                .get("ANTHROPIC_MODEL")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if base.contains("minimaxi.com") {
                flags.push("model-endpoint=minimax-cn".to_string());
            } else if base.contains("minimax.io") || model.starts_with("MiniMax-") {
                flags.push("model-endpoint=minimax".to_string());
            }
        }
    }

    // MCP servers live in ~/.claude.json (and project .mcp.json / settings),
    // not the settings files alone; skills are subdirs of ~/.claude/skills/.
    let mcp_sources: Vec<String> = [
        Path::new(&home_str).join(".claude.json"),
        cdir.join(".mcp.json"),
        cdir.join("settings.json"),
        cdir.join("settings.local.json"),
    ]
    .iter()
    .filter(|p| p.is_file())
    .map(|p| p.to_string_lossy().into_owned())
    .collect();
    let mcp_servers = mcp_server_names(&mcp_sources);
    let skills = subdir_names(&cdir.join("skills"));

    Some(DetectedAgent {
        name: "claude-code".to_string(),
        settings_paths: paths,
        risky_flags: flags,
        interception: "hook".to_string(),
        mcp_config_paths: mcp_sources,
        mcp_servers,
        skills,
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 2: codex  (mirrors agents/codex.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/codex.py::find(home)`.
///
/// Detection: `~/.codex` dir exists.
/// Config: `~/.codex/config.toml` if it exists.
/// Risky flags:
///   - `"danger-full-access"` if that string appears anywhere in config.toml
///   - `"approval_policy=never"` if `approval_policy = "never"` appears
///
/// Interception: "hook".
pub fn find_codex(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".codex");
    if !d.is_dir() {
        return None;
    }

    // Risky-flag scan reads the TOML config as text (still config.toml).
    let config_path = d.join("config.toml");
    let mut flags: Vec<String> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&config_path) {
        if text.contains("danger-full-access") {
            flags.push("danger-full-access".to_string());
        }
        if text.contains(r#"approval_policy = "never""#) {
            flags.push("approval_policy=never".to_string());
        }
    }

    // Codex has a Claude-Code-style hook engine, but hooks are declared in a
    // SEPARATE JSON file `~/.codex/hooks.json` — NOT config.toml (which is TOML).
    // Writing Claude-shaped JSON hooks into config.toml would corrupt it (the
    // hermes-class data-loss bug). Codex's hooks.json uses the same
    // {hooks:{PreToolUse:[{matcher,hooks:[{command}]}]}} schema `wire::install`
    // already produces, so we wire (and read protection) there.
    // NOTE: codex marks a newly-added hook "needs review" until the user trusts
    // it at startup — enforcement is pending until then.
    let hooks_json = d.join("hooks.json").to_string_lossy().into_owned();

    Some(DetectedAgent {
        name: "codex".to_string(),
        settings_paths: vec![hooks_json],
        risky_flags: flags,
        interception: "hook".to_string(),
        // codex MCP servers live under [mcp_servers] in TOML; the JSON mcp-proxy
        // rewriter can't handle TOML, so don't point it at config.toml.
        mcp_config_paths: vec![],
        mcp_servers: vec![],
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 3: cline  (mirrors agents/cline.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/cline.py::find(home)`.
///
/// Detection: `~/.cline` dir exists OR
///            `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev` dir.
/// Interception: "mcp-proxy". No risky flags (empty settings_paths).
pub fn find_cline(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".cline");
    let vs_storage = Path::new(&home_str)
        .join(".config")
        .join("Code")
        .join("User")
        .join("globalStorage")
        .join("saoudrizwan.claude-dev");

    if !d.is_dir() && !vs_storage.is_dir() {
        return None;
    }

    let candidates = [
        d.join("mcp.json"),
        vs_storage.join("cline_mcp_settings.json"),
    ];
    let cfg: Vec<String> = candidates
        .iter()
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    Some(DetectedAgent {
        name: "cline".to_string(),
        settings_paths: vec![],
        risky_flags: vec![],
        interception: "mcp-proxy".to_string(),
        mcp_config_paths: cfg.clone(),
        mcp_servers: mcp_server_names(&cfg),
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 4: roo  (mirrors agents/roo.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/roo.py::find(home)`.
///
/// Detection: `~/.roo` dir exists OR
///            `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline`.
/// Interception: "mcp-proxy". No risky flags.
pub fn find_roo(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".roo");
    let vs_storage = Path::new(&home_str)
        .join(".config")
        .join("Code")
        .join("User")
        .join("globalStorage")
        .join("rooveterinaryinc.roo-cline");

    if !d.is_dir() && !vs_storage.is_dir() {
        return None;
    }

    let candidates = [d.join("mcp.json"), vs_storage.join("mcp_settings.json")];
    let cfg: Vec<String> = candidates
        .iter()
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    Some(DetectedAgent {
        name: "roo".to_string(),
        settings_paths: vec![],
        risky_flags: vec![],
        interception: "mcp-proxy".to_string(),
        mcp_config_paths: cfg.clone(),
        mcp_servers: mcp_server_names(&cfg),
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 5: cursor  (mirrors agents/cursor.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/cursor.py::find(home)`.
///
/// Detection: `~/.cursor` dir exists.
/// MCP config: `~/.cursor/mcp.json` if it exists.
/// Interception: "mcp-proxy". No risky flags.
pub fn find_cursor(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".cursor");
    if !d.is_dir() {
        return None;
    }

    // Cursor's built-in shell/edit/read tools are NOT MCP servers, so the old
    // mcp-proxy classification missed the primary risk (and url MCP servers).
    // Cursor Hooks (~/.cursor/hooks.json) is a native pre-tool gate that can
    // `deny` beforeShellExecution/beforeMCPExecution/beforeReadFile — see gates.rs.
    let hooks_json = d.join("hooks.json").to_string_lossy().into_owned();

    Some(DetectedAgent {
        name: "cursor".to_string(),
        settings_paths: vec![hooks_json],
        risky_flags: vec![],
        interception: "cursor-hook".to_string(),
        mcp_config_paths: vec![],
        mcp_servers: vec![],
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 6: gemini  (mirrors agents/gemini.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/gemini.py::find(home)`.
///
/// Detection: `~/.gemini` dir exists.
/// MCP config: `~/.gemini/settings.json` if it exists.
/// Interception: "config-policy". No risky flags.
pub fn find_gemini(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".gemini");
    if !d.is_dir() {
        return None;
    }

    let settings = d.join("settings.json");
    let cfg: Vec<String> = if settings.is_file() {
        vec![settings.to_string_lossy().into_owned()]
    } else {
        vec![]
    };

    Some(DetectedAgent {
        name: "gemini".to_string(),
        settings_paths: vec![],
        risky_flags: vec![],
        interception: "config-policy".to_string(),
        mcp_config_paths: cfg.clone(),
        mcp_servers: mcp_server_names(&cfg),
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 7: goose  (mirrors agents/goose.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/goose.py::find(home)`.
///
/// Detection: `~/.config/goose` dir exists.
/// MCP config: `~/.config/goose/config.yaml` if it exists.
/// Interception: "config-policy". No risky flags.
pub fn find_goose(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let d = Path::new(&home_str).join(".config").join("goose");
    if !d.is_dir() {
        return None;
    }

    let config = d.join("config.yaml");
    let cfg: Vec<String> = if config.is_file() {
        vec![config.to_string_lossy().into_owned()]
    } else {
        vec![]
    };

    Some(DetectedAgent {
        name: "goose".to_string(),
        settings_paths: vec![],
        risky_flags: vec![],
        interception: "config-policy".to_string(),
        mcp_config_paths: cfg.clone(),
        mcp_servers: mcp_server_names(&cfg),
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 8: openclaw  (mirrors agents/openclaw.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/openclaw.py::find(home)`.
///
/// Detection: `~/.openclaw` dir exists.
/// Config: `~/.openclaw/openclaw.json` if it exists.
/// Risky flags: `"full-host"` if that string appears in openclaw.json.
/// Interception: "mcp-proxy".
pub fn find_openclaw(home: Option<&str>) -> Option<DetectedAgent> {
    // Honor $OPENCLAW_STATE_DIR (falls back to ~/.openclaw) when no explicit
    // override is given, so we detect relocated installs.
    let d = match home {
        Some(h) => Path::new(h).join(".openclaw"),
        None => match std::env::var("OPENCLAW_STATE_DIR") {
            Ok(v) if !v.is_empty() => Path::new(&v).to_path_buf(),
            _ => Path::new(&resolve_home(None)).join(".openclaw"),
        },
    };
    if !d.is_dir() {
        return None;
    }

    // Real risky flags parsed from openclaw.json (the old `full-host` string was
    // a phantom that never existed in OpenClaw's config surface).
    let openclaw_json = d.join("openclaw.json");
    let flags = crate::gates::openclaw_risky_flags(&openclaw_json);

    // OpenClaw is protected via its native exec-approvals gate — NOT mcp-proxy
    // (its MCP servers nest under `mcp.servers`, which the top-level rewriter
    // never saw, and exec is the real risk surface). settings_paths carries the
    // policy file Belay tightens.
    let exec_approvals = d.join("exec-approvals.json").to_string_lossy().into_owned();

    Some(DetectedAgent {
        name: "openclaw".to_string(),
        settings_paths: vec![exec_approvals],
        risky_flags: flags,
        interception: "exec-policy".to_string(),
        mcp_config_paths: vec![],
        mcp_servers: vec![],
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 9: hermes  (mirrors agents/hermes.py::find)
// ─────────────────────────────────────────────────────────────────────────────

/// Port of `agents/hermes.py::find(home)`.
///
/// Detection: `~/.hermes` dir exists.
/// Config: `~/.hermes/config.yaml` if it exists.
/// Risky flags: `"full-host"` if that string appears in config.yaml.
/// Interception: "mcp-proxy".
pub fn find_hermes(home: Option<&str>) -> Option<DetectedAgent> {
    // Honor $HERMES_HOME (hermes's own get_hermes_home()) when no explicit
    // override is given, so we detect/wire the config the agent actually loads.
    let d = crate::hermes::hermes_dir(home);
    if !d.is_dir() {
        return None;
    }

    let config_file = d.join("config.yaml");
    let config_str = config_file.to_string_lossy().into_owned();

    // Risky-flag scan is a plain text search, so it works on hermes's YAML.
    let mut flags: Vec<String> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&config_file) {
        if text.contains("full-host") {
            flags.push("full-host".to_string());
        }
    }

    // Hermes is protected via its NATIVE pre_tool_call hook (see hermes.rs), not
    // an mcp-proxy rewrite: its config is YAML with no standard mcpServers block,
    // and the hook gates every built-in tool too. settings_paths carries the
    // config file we wire the hook into (protect/compute_protected read it).
    Some(DetectedAgent {
        name: "hermes".to_string(),
        settings_paths: vec![config_str],
        risky_flags: flags,
        interception: "hermes-hook".to_string(),
        mcp_config_paths: vec![],
        mcp_servers: vec![],
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 10: antigravity  (Google Antigravity — agent-first dev platform)
// ─────────────────────────────────────────────────────────────────────────────

/// Detect Google Antigravity. It shares the `~/.gemini/` base with the legacy
/// Gemini CLI, so we disambiguate via the antigravity-specific subdirs (or the
/// dedicated IDE dir). MCP config is standard JSON `mcpServers`, so command
/// servers are proxy-wrappable via the existing mcp-proxy machinery. (Antigravity
/// also ships a native permission engine; auto-writing those Deny rules is
/// deferred — the on-disk settings schema is not yet verified.)
pub fn find_antigravity(home: Option<&str>) -> Option<DetectedAgent> {
    let home_str = resolve_home(home);
    let gemini = Path::new(&home_str).join(".gemini");
    let ide = Path::new(&home_str).join(".antigravity-ide");
    let is_antigravity = ide.is_dir()
        || gemini.join("antigravity-cli").is_dir()
        || gemini.join("antigravity-ide").is_dir()
        || gemini.join("antigravity").is_dir();
    if !is_antigravity {
        return None;
    }

    let mcp_cfg = gemini.join("config").join("mcp_config.json");
    let cfg: Vec<String> = if mcp_cfg.is_file() {
        vec![mcp_cfg.to_string_lossy().into_owned()]
    } else {
        vec![]
    };

    Some(DetectedAgent {
        name: "antigravity".to_string(),
        settings_paths: vec![],
        risky_flags: vec![],
        interception: "mcp-proxy".to_string(),
        mcp_config_paths: cfg.clone(),
        mcp_servers: mcp_server_names(&cfg),
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector 11: opencode  (SST/anomalyco open-source terminal coding agent)
// ─────────────────────────────────────────────────────────────────────────────

/// Detect opencode via its config dir (`~/.config/opencode` or
/// `$XDG_CONFIG_HOME/opencode`). Protected via a native plugin at
/// `<cfgdir>/plugin/belay.ts` (permission.ask -> `belay gate`).
pub fn find_opencode(home: Option<&str>) -> Option<DetectedAgent> {
    let cfgdir = if let Some(h) = home {
        Path::new(h).join(".config").join("opencode")
    } else {
        match std::env::var("XDG_CONFIG_HOME") {
            Ok(v) if !v.is_empty() => Path::new(&v).join("opencode"),
            _ => Path::new(&resolve_home(None))
                .join(".config")
                .join("opencode"),
        }
    };
    let has_cfg = cfgdir.is_dir()
        || ["opencode.json", "opencode.jsonc", "config.json"]
            .iter()
            .any(|f| cfgdir.join(f).is_file());
    if !has_cfg {
        return None;
    }

    let plugin_dir = cfgdir.join("plugin").to_string_lossy().into_owned();

    Some(DetectedAgent {
        name: "opencode".to_string(),
        settings_paths: vec![plugin_dir],
        risky_flags: vec![],
        interception: "opencode-plugin".to_string(),
        mcp_config_paths: vec![],
        mcp_servers: vec![],
        skills: vec![],
        protected: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry: find_agents  (mirrors detect/registry.py::find_agents)
// ─────────────────────────────────────────────────────────────────────────────

/// Discover all installed AI agents on the host.
///
/// Runs detectors in the exact order specified by the Python registry:
/// claude_code → codex → cline → roo → cursor → gemini → goose → openclaw → hermes.
/// Non-None results are collected in order.
///
/// `home`: `None` means use `$HOME`; `Some(path)` overrides (for tests and
/// the `--home` CLI flag).
pub fn find_agents(home: Option<&str>) -> Vec<DetectedAgent> {
    let mut out: Vec<DetectedAgent> = Vec::new();

    type Detector = fn(Option<&str>) -> Option<DetectedAgent>;
    let detectors: Vec<Detector> = vec![
        find_claude_code,
        find_codex,
        find_cline,
        find_roo,
        find_cursor,
        find_gemini,
        find_goose,
        find_openclaw,
        find_hermes,
        find_antigravity,
        find_opencode,
    ];

    for detect_fn in &detectors {
        if let Some(agent) = detect_fn(home) {
            out.push(agent);
        }
    }

    // Single post-pass: mark which agents already have Belay protection
    // wired in, so callers (the GUI banner, the Agents tab) can distinguish
    // "detected" from "detected and protected".
    for agent in &mut out {
        agent.protected = compute_protected(agent);
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI: detect subcommand  (mirrors cli/main.py::detect)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the `detect` CLI subcommand and return an ExitCode.
///
/// Output (matches Python exactly):
///   - No agents → `No supported AI agents detected.`
///   - Per agent → `• {name}  settings={settings_repr}  risky={risky_repr}`
///     where `settings_repr` and `risky_repr` are `py_list_repr(...)`.
pub fn run(home: Option<&str>) -> ExitCode {
    let agents = find_agents(home);
    if agents.is_empty() {
        println!("No supported AI agents detected.");
    } else {
        for a in &agents {
            println!(
                "\u{2022} {}  settings={}  risky={}",
                a.name,
                py_list_repr(&a.settings_paths),
                py_list_repr(&a.risky_flags),
            );
        }
    }
    ExitCode::SUCCESS
}
