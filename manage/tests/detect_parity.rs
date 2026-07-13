//! Parity test: Rust `find_agents` / detect rendering must produce the same
//! output as the Python `belay detect` CLI for the same synthetic home.
//!
//! The Python package is deleted, so the expected detect/posture lines are now
//! reconstructed from the format captured from the Python CLI (pre-deletion)
//! with the per-run tmp path substituted in. The load-bearing cross-language
//! facts — agent names, ordering (claude-code, codex, cursor), the risky-flag
//! lists (`['bypassPermissions']`, `['danger-full-access']`), and the
//! single-quote Python list repr — are preserved verbatim.
//!
//! Scenarios:
//!   1. Planted home with claude-code (bypassPermissions), codex
//!      (danger-full-access), and cursor dir → detect output matches golden.
//!   2. Clean home → Rust finds no planted agents.
//!   3. Posture parity: risky-agent home → `agent_risky_flags` findings match
//!      the captured Python lines.

use std::fs;
use std::path::Path;

use belay_manage::detect::{find_agents, py_list_repr};

// ─── Helper: plant a synthetic home ─────────────────────────────────────────

/// Plant a synthetic home with:
///   - ~/.claude/settings.json  {"defaultMode":"bypassPermissions"}
///   - ~/.codex/config.toml     with `danger-full-access`
///   - ~/.cursor/mcp.json       empty JSON
fn plant_detect_home(base: &Path) {
    let claude_dir = base.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"defaultMode":"bypassPermissions"}"#,
    )
    .unwrap();

    let codex_dir = base.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    fs::write(codex_dir.join("config.toml"), "danger-full-access = true\n").unwrap();

    let cursor_dir = base.join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    fs::write(cursor_dir.join("mcp.json"), "{}").unwrap();
}

/// Golden `belay detect` lines for the planted home, with `{home}` standing
/// in for the per-run tmp path. Mostly captured from the Python CLI (pre-deletion),
/// EXCEPT codex/cursor: `settings=` now reflects the file Belay wires
/// protection into — codex `~/.codex/hooks.json` (JSON hooks, not the TOML
/// config) and cursor `~/.cursor/hooks.json` (native Cursor Hooks, not mcp-proxy).
/// This is an intentional correctness divergence from the old Python behaviour.
fn golden_detect_lines(home: &Path) -> Vec<String> {
    let h = home.to_str().unwrap();
    vec![
        format!("\u{2022} claude-code  settings=['{h}/.claude/settings.json']  risky=['bypassPermissions']"),
        format!("\u{2022} codex  settings=['{h}/.codex/hooks.json']  risky=['danger-full-access']"),
        format!("\u{2022} cursor  settings=['{h}/.cursor/hooks.json']  risky=[]"),
    ]
}

// ─── Helper: format DetectedAgent → detect output line ───────────────────────

fn agent_to_detect_line(a: &belay_manage::detect::DetectedAgent) -> String {
    format!(
        "\u{2022} {}  settings={}  risky={}",
        a.name,
        py_list_repr(&a.settings_paths),
        py_list_repr(&a.risky_flags),
    )
}

// ─── Test 1: planted home — detect parity vs golden ──────────────────────────

#[test]
fn detect_parity_planted_home() {
    let tmp = tempfile::tempdir().unwrap();
    plant_detect_home(tmp.path());

    let rust_agents = find_agents(Some(tmp.path().to_str().unwrap()));
    let rust_lines: Vec<String> = rust_agents.iter().map(agent_to_detect_line).collect();
    let golden = golden_detect_lines(tmp.path());

    assert!(
        !rust_agents.is_empty(),
        "expected at least one Rust agent in planted home"
    );

    assert_eq!(
        rust_lines,
        golden,
        "Rust detect output differs from Python golden!\n\nRust:\n{}\n\nGolden:\n{}",
        rust_lines.join("\n"),
        golden.join("\n")
    );
}

// ─── Test 2: clean home — no planted agents ──────────────────────────────────

#[test]
fn detect_parity_clean_home() {
    let tmp = tempfile::tempdir().unwrap();
    // No agent dirs planted under this synthetic HOME. The codex/cursor agents
    // are detected ONLY via their config dirs (~/.codex, ~/.cursor), so with an
    // empty home they must be absent. (claude-code may still appear if `claude`
    // is on the system PATH — that is environment-driven, matching the Python
    // detector, which also probed PATH, so it is not asserted here.)
    let rust_agents = find_agents(Some(tmp.path().to_str().unwrap()));
    assert!(
        !rust_agents
            .iter()
            .any(|a| a.name == "codex" || a.name == "cursor"),
        "clean synthetic home must not detect config-dir-only agents, got: {:?}",
        rust_agents.iter().map(|a| &a.name).collect::<Vec<_>>()
    );
}

// ─── Test 3: py_list_repr unit checks ────────────────────────────────────────

#[test]
fn py_list_repr_empty() {
    assert_eq!(py_list_repr(&[]), "[]");
}

#[test]
fn py_list_repr_single() {
    assert_eq!(
        py_list_repr(&["bypassPermissions".to_string()]),
        "['bypassPermissions']"
    );
}

#[test]
fn py_list_repr_multi() {
    assert_eq!(
        py_list_repr(&[
            "bypassPermissions".to_string(),
            "enableAllProjectMcpServers".to_string()
        ]),
        "['bypassPermissions', 'enableAllProjectMcpServers']"
    );
}

// ─── Test 4: detect rendering matches Python golden (non-empty branch) ───────

#[test]
fn detect_run_output_matches_golden() {
    let tmp = tempfile::tempdir().unwrap();
    plant_detect_home(tmp.path());

    let rust_agents = find_agents(Some(tmp.path().to_str().unwrap()));
    let rust_lines: Vec<String> = if rust_agents.is_empty() {
        vec!["No supported AI agents detected.".to_string()]
    } else {
        rust_agents.iter().map(agent_to_detect_line).collect()
    };

    assert_eq!(
        rust_lines,
        golden_detect_lines(tmp.path()),
        "detect rendering differs from Python golden!\n\nRust:\n{}",
        rust_lines.join("\n")
    );
}

// ─── Test 6: claude-code MCP servers + skills enumeration ────────────────────

#[test]
fn claude_mcp_servers_and_skills_enumerated() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let claude = home.join(".claude");
    // Two installed skills (subdirs) and two MCP servers (~/.claude.json).
    fs::create_dir_all(claude.join("skills").join("beta")).unwrap();
    fs::create_dir_all(claude.join("skills").join("alpha")).unwrap();
    fs::write(claude.join("settings.json"), "{}").unwrap();
    fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"srv-two":{},"srv-one":{}}}"#,
    )
    .unwrap();

    let agents = find_agents(Some(home.to_str().unwrap()));
    let claude_agent = agents
        .iter()
        .find(|a| a.name == "claude-code")
        .expect("claude-code should be detected via ~/.claude");

    // Both lists are sorted, deduped.
    assert_eq!(claude_agent.mcp_servers, vec!["srv-one", "srv-two"]);
    assert_eq!(claude_agent.skills, vec!["alpha", "beta"]);
}

// ─── Test 7: protected flag reflects the installed Belay hook ───────────────

#[test]
fn claude_protected_reflects_belay_hook() {
    // Unprotected: settings.json with no belay hook → protected == false.
    let tmp = tempfile::tempdir().unwrap();
    let claude = tmp.path().join(".claude");
    fs::create_dir_all(&claude).unwrap();
    fs::write(claude.join("settings.json"), r#"{"hooks":{}}"#).unwrap();
    let agents = find_agents(Some(tmp.path().to_str().unwrap()));
    let a = agents.iter().find(|a| a.name == "claude-code").unwrap();
    assert!(!a.protected, "no belay hook ⇒ not protected");

    // Protected: a PreToolUse hook whose command runs `belay` → protected.
    let tmp2 = tempfile::tempdir().unwrap();
    let claude2 = tmp2.path().join(".claude");
    fs::create_dir_all(&claude2).unwrap();
    fs::write(
        claude2.join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"belay hook pretooluse"}]}]}}"#,
    )
    .unwrap();
    let agents2 = find_agents(Some(tmp2.path().to_str().unwrap()));
    let a2 = agents2.iter().find(|a| a.name == "claude-code").unwrap();
    assert!(a2.protected, "belay hook present ⇒ protected");
}

// ─── Test 5: posture agent_risky_flags parity vs golden ──────────────────────

#[test]
fn posture_agent_risky_flags_parity() {
    use belay_manage::posture::check_posture;

    let tmp = tempfile::tempdir().unwrap();
    plant_detect_home(tmp.path());

    let rust_findings = check_posture(Some(tmp.path()));
    let rust_flag_lines: Vec<String> = rust_findings
        .iter()
        .filter(|f| f.rule_id == "posture.agent_risky_flags")
        .map(|f| format!("[HIGH] {}: {}", f.rule_id, f.reason))
        .collect();

    // Golden `agent_risky_flags` lines captured from `posture --home` (pre-deletion).
    let golden = vec![
        "[HIGH] posture.agent_risky_flags: Agent 'claude-code' has risky flags: ['bypassPermissions']".to_string(),
        "[HIGH] posture.agent_risky_flags: Agent 'codex' has risky flags: ['danger-full-access']".to_string(),
    ];

    assert_eq!(
        rust_flag_lines,
        golden,
        "posture agent_risky_flags differ from Python golden!\n\nRust:\n{}\n\nGolden:\n{}",
        rust_flag_lines.join("\n"),
        golden.join("\n")
    );
}
