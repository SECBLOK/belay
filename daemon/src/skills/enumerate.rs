//! Discover installed agent skills on disk. Foundation for the Phase-2 triggers.
use std::path::{Path, PathBuf};

use crate::skills::mcp_config::McpConfigFormat;

pub struct InstalledSkill { pub agent: String, pub name: String, pub manifest: PathBuf }

/// One known MCP-server config file location for a detected agent.
pub struct McpConfig { pub agent: String, pub path: PathBuf, pub format: McpConfigFormat }

/// Skill roots per agent, rooted at `home` (testable). Extend as agents are confirmed.
pub fn skill_roots_in(home: &Path) -> Vec<(String, PathBuf)> {
    vec![
        ("claude".into(), home.join(".claude/skills")),
        ("cursor".into(), home.join(".cursor/skills")),
        ("codex".into(),  home.join(".codex/skills")),
    ]
}

pub fn skill_roots() -> Vec<(String, PathBuf)> {
    skill_roots_in(&crate::skills::home_dir())
}

/// Walk each root for `<skill>/SKILL.md` (or `skill.md`), bounded + fail-soft.
pub fn enumerate_skills_in(roots: &[(String, PathBuf)]) -> Vec<InstalledSkill> {
    let mut out = Vec::new();
    for (agent, root) in roots {
        if !root.is_dir() { continue; }
        for entry in walkdir::WalkDir::new(root).max_depth(3).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() { continue; }
            let p = entry.path();
            let is_manifest = p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case("skill.md"))
                .unwrap_or(false);
            if !is_manifest { continue; }
            let name = p.parent().and_then(|d| d.file_name()).and_then(|n| n.to_str())
                .unwrap_or("unknown").to_string();
            out.push(InstalledSkill { agent: agent.clone(), name, manifest: p.to_path_buf() });
        }
    }
    out
}

pub fn enumerate_skills() -> Vec<InstalledSkill> { enumerate_skills_in(&skill_roots()) }

/// Known MCP-server config file paths, rooted at `home` (testable). v1 scope
/// covers the Claude family only (see [`McpConfigFormat`]): Claude Code's
/// per-user `~/.claude.json` and Claude Desktop's config. `.mcp.json` is
/// project-scoped (lives under a repo, not under `home`), so it is
/// deliberately NOT included here — a scanner that wants it matches by
/// basename against project trees instead.
///
/// Fail-soft: a path whose file doesn't (yet) exist on disk is still
/// returned unconditionally — callers that care about existence check it
/// themselves, mirroring [`skill_roots_in`].
pub fn mcp_config_paths_in(home: &Path) -> Vec<McpConfig> {
    vec![
        McpConfig {
            agent: "claude".into(),
            path: home.join(".claude.json"),
            format: McpConfigFormat::ClaudeUser,
        },
        McpConfig {
            agent: "claude-desktop".into(),
            path: claude_desktop_config_path(home),
            format: McpConfigFormat::ClaudeDesktop,
        },
    ]
}

pub fn mcp_config_paths() -> Vec<McpConfig> {
    mcp_config_paths_in(&crate::skills::home_dir())
}

/// Claude Desktop's config path, platform-branched like
/// [`crate::skills::home_dir`]: macOS uses `Library/Application Support`,
/// Windows prefers `%APPDATA%` (falling back to `home\AppData\Roaming` if
/// unset), and everything else (Linux etc.) is a best-effort XDG-style guess
/// under `~/.config` — Claude Desktop isn't officially supported there, but
/// this keeps the lookup harmless (a non-existent path) rather than absent.
fn claude_desktop_config_path(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/Claude/claude_desktop_config.json")
    }
    #[cfg(windows)]
    {
        match std::env::var("APPDATA") {
            Ok(appdata) => PathBuf::from(appdata).join("Claude").join("claude_desktop_config.json"),
            Err(_) => home.join("AppData").join("Roaming").join("Claude").join("claude_desktop_config.json"),
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        home.join(".config/Claude/claude_desktop_config.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roots_include_claude_skills() {
        let home = std::path::Path::new("/home/u");
        let roots = skill_roots_in(home);
        assert!(roots.iter().any(|(a, p)| a == "claude" && p.ends_with(".claude/skills")));
    }
    #[test]
    fn mcp_config_paths_include_claude_user_and_desktop() {
        let home = std::path::Path::new("/home/u");
        let paths = mcp_config_paths_in(home);
        assert!(paths.iter().any(|c| c.agent == "claude"
            && c.format == McpConfigFormat::ClaudeUser
            && c.path.ends_with(".claude.json")));
        assert!(paths
            .iter()
            .any(|c| c.agent == "claude-desktop" && c.format == McpConfigFormat::ClaudeDesktop));
    }

    #[test]
    fn enumerate_finds_planted_skill_and_ignores_missing_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(".claude/skills");
        std::fs::create_dir_all(root.join("greeter")).unwrap();
        std::fs::write(root.join("greeter/SKILL.md"), "---\nname: greeter\n---\nhi").unwrap();
        let roots = vec![
            ("claude".to_string(), root.clone()),
            ("cursor".to_string(), tmp.path().join(".cursor/skills")), // missing -> skipped
        ];
        let found = enumerate_skills_in(&roots);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "greeter");
        assert_eq!(found[0].agent, "claude");
    }
}
