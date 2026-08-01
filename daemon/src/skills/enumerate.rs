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
///
/// `follow_links(true)` is load-bearing, not a convenience. Plugin managers and
/// the marketplace install skills by symlinking them into `~/.claude/skills/`
/// rather than copying, so on a normally-provisioned machine the large majority
/// of installed skills are links. `walkdir` does not descend a symlinked
/// directory by default, so without this the walk sees the link itself, decides
/// it is not a file, and moves on: those skills are never enumerated, never
/// scanned, never gated. Measured on one real install, 37 of 147 reachable
/// `SKILL.md` manifests were visible before this and 147 after. A malicious
/// symlinked skill was therefore invisible to every caller of this function.
pub fn enumerate_skills_in(roots: &[(String, PathBuf)]) -> Vec<InstalledSkill> {
    let mut out = Vec::new();
    for (agent, root) in roots {
        if !root.is_dir() { continue; }
        for entry in walkdir::WalkDir::new(root).max_depth(3).follow_links(true).into_iter().filter_map(|e| e.ok()) {
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

use crate::skills::sweep::{ItemKind, SkipReason, Skipped};

/// Enumeration plus what it could NOT reach.
pub struct SkillScan {
    pub found: Vec<InstalledSkill>,
    pub skipped: Vec<Skipped>,
}

/// Map a `walkdir` error to a closed reason. `walkdir` wraps the io error, and
/// a `None` path means the failure was at the root of the walk.
fn reason_for(e: &walkdir::Error) -> SkipReason {
    match e.io_error().map(|io| io.kind()) {
        Some(std::io::ErrorKind::PermissionDenied) => SkipReason::PermissionDenied,
        Some(std::io::ErrorKind::NotFound) => SkipReason::NotFound,
        _ if e.loop_ancestor().is_some() => SkipReason::SymlinkLoop,
        _ => SkipReason::Unreadable,
    }
}

/// Same walk as [`enumerate_skills_in`], but reporting what it could not read
/// instead of dropping it. The two are kept side by side rather than merged:
/// the install gate calls the original and only wants the findings. They must
/// stay in lockstep on WHAT they traverse, though - a skill one of them cannot
/// see is a hole in whichever is blind - so both follow links.
pub fn enumerate_skills_scanned_in(roots: &[(String, PathBuf)]) -> SkillScan {
    let mut found = Vec::new();
    let mut skipped = Vec::new();

    for (agent, root) in roots {
        if !root.is_dir() {
            // Previously a silent `continue`. A root that is absent or
            // unreadable is exactly the case that made "clean" and "never
            // looked" indistinguishable.
            skipped.push(Skipped {
                kind: ItemKind::Skill,
                agent: agent.clone(),
                path: root.display().to_string(),
                reason: SkipReason::RootMissing,
                detail: String::new(),
            });
            continue;
        }
        // `follow_links(true)` for the same reason as `enumerate_skills_in`:
        // most installed skills are symlinks, and an unfollowed link is an
        // unscanned skill. It also turns two failure modes into reportable
        // ones instead of invisible ones: a dangling link surfaces as
        // `NotFound` and a symlink cycle as `SymlinkLoop` (see `reason_for`),
        // where an unfollowed link produced no entry and no skip at all.
        for res in walkdir::WalkDir::new(root).max_depth(3).follow_links(true) {
            let entry = match res {
                Ok(e) => e,
                Err(e) => {
                    // Previously discarded by `filter_map(|e| e.ok())`.
                    skipped.push(Skipped {
                        kind: ItemKind::Skill,
                        agent: agent.clone(),
                        path: e.path().map(|p| p.display().to_string()).unwrap_or_default(),
                        reason: reason_for(&e),
                        detail: e.to_string(),
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let p = entry.path();
            let is_manifest = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case("skill.md"))
                .unwrap_or(false);
            if !is_manifest {
                continue;
            }
            let name = p
                .parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            found.push(InstalledSkill {
                agent: agent.clone(),
                name,
                manifest: p.to_path_buf(),
            });
        }
    }

    SkillScan { found, skipped }
}

pub fn enumerate_skills_scanned() -> SkillScan {
    enumerate_skills_scanned_in(&skill_roots())
}

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

    use crate::skills::sweep::{ItemKind, SkipReason};

    /// A root that does not exist must be REPORTED, not silently skipped.
    /// Silence here is what makes "no findings" and "never looked" identical.
    #[test]
    fn a_missing_root_is_reported_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let roots = vec![("codex".to_string(), dir.path().join("does-not-exist"))];

        let scan = enumerate_skills_scanned_in(&roots);

        assert!(scan.found.is_empty());
        assert_eq!(scan.skipped.len(), 1, "the missing root must be reported");
        assert_eq!(scan.skipped[0].reason, SkipReason::RootMissing);
        assert_eq!(scan.skipped[0].agent, "codex");
        assert_eq!(scan.skipped[0].kind, ItemKind::Skill);
    }

    /// A readable root with a real skill still enumerates it, and reports
    /// nothing skipped. The happy path must not acquire false positives.
    #[test]
    fn a_readable_root_enumerates_and_reports_no_skips() {
        let dir = tempfile::tempdir().unwrap();
        let sk = dir.path().join("pdf-tools");
        std::fs::create_dir_all(&sk).unwrap();
        std::fs::write(sk.join("SKILL.md"), "# pdf tools").unwrap();
        let roots = vec![("claude".to_string(), dir.path().to_path_buf())];

        let scan = enumerate_skills_scanned_in(&roots);

        assert_eq!(scan.found.len(), 1);
        assert_eq!(scan.found[0].name, "pdf-tools");
        assert!(scan.skipped.is_empty(), "nothing was unreachable");
    }

    /// An unreadable subdirectory must surface as PermissionDenied, made real
    /// with chmod rather than mocked: mocking the error tests the mock.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_subdir_is_reported_as_permission_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("SKILL.md"), "# x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let roots = vec![("claude".to_string(), dir.path().to_path_buf())];
        let scan = enumerate_skills_scanned_in(&roots);

        // Restore before asserting so a failure cannot leave an undeletable dir.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));

        assert!(
            scan.skipped.iter().any(|s| s.reason == SkipReason::PermissionDenied),
            "an unreadable dir must be reported, got: {:?}",
            scan.skipped
        );
    }

    /// A skill installed as a SYMLINK into the root must be enumerated.
    ///
    /// This is how plugin managers and the marketplace actually install
    /// skills, so before `follow_links(true)` the majority of a real machine's
    /// skills were invisible to the scanner. Both enumerators are asserted:
    /// the install gate reads the first, the sweep reads the second, and a
    /// skill that only one of them can see is a hole in whichever is blind.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_skill_is_enumerated_by_both_walkers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        std::fs::create_dir_all(&root).unwrap();

        // The skill lives OUTSIDE the root, exactly as a plugin cache does.
        let real = dir.path().join("elsewhere/pdf-tools");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("SKILL.md"), "# pdf tools").unwrap();
        std::os::unix::fs::symlink(&real, root.join("pdf-tools")).unwrap();

        let roots = vec![("claude".to_string(), root)];

        let old = enumerate_skills_in(&roots);
        assert_eq!(old.len(), 1, "symlinked skill missed by enumerate_skills_in");
        assert_eq!(old[0].name, "pdf-tools");

        let scan = enumerate_skills_scanned_in(&roots);
        assert_eq!(
            scan.found.len(),
            1,
            "symlinked skill missed by enumerate_skills_scanned_in"
        );
        assert_eq!(scan.found[0].name, "pdf-tools");
    }

    /// Following links means cycles are now reachable, so they must be
    /// REPORTED rather than silently truncating the walk. `walkdir` yields an
    /// error carrying a `loop_ancestor` for this, which `reason_for` maps to
    /// `SymlinkLoop`; the walk must survive it and still return the real skill
    /// sitting next to the cycle.
    #[cfg(unix)]
    #[test]
    fn a_symlink_cycle_is_reported_and_does_not_abort_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        let good = root.join("good");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(good.join("SKILL.md"), "# good").unwrap();

        // `skills/loop/back` points back at `skills/`, so descending it
        // revisits an ancestor.
        let cycle = root.join("loop");
        std::fs::create_dir_all(&cycle).unwrap();
        std::os::unix::fs::symlink(&root, cycle.join("back")).unwrap();

        let roots = vec![("claude".to_string(), root)];
        let scan = enumerate_skills_scanned_in(&roots);

        assert!(
            scan.found.iter().any(|s| s.name == "good"),
            "the cycle must not cost us the sibling skill, got: {:?}",
            scan.found.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        assert!(
            scan.skipped.iter().any(|s| s.reason == SkipReason::SymlinkLoop),
            "the cycle must be reported, got: {:?}",
            scan.skipped
        );
    }

    /// A dangling symlink is a skill we cannot read, which is a coverage gap,
    /// not a clean result. Unfollowed it produced neither a finding nor a
    /// skip; followed it must produce a skip.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_reported_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), root.join("ghost")).unwrap();

        let roots = vec![("claude".to_string(), root)];
        let scan = enumerate_skills_scanned_in(&roots);

        assert!(scan.found.is_empty());
        assert_eq!(
            scan.skipped.len(),
            1,
            "the unreadable link must be reported, got: {:?}",
            scan.skipped
        );
        assert_eq!(scan.skipped[0].reason, SkipReason::NotFound);
    }

    /// The original API is unchanged. The install gate depends on it.
    #[test]
    fn the_original_enumerator_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let sk = dir.path().join("a");
        std::fs::create_dir_all(&sk).unwrap();
        std::fs::write(sk.join("SKILL.md"), "# a").unwrap();
        let roots = vec![("claude".to_string(), dir.path().to_path_buf())];

        let old = enumerate_skills_in(&roots);
        let new = enumerate_skills_scanned_in(&roots);

        assert_eq!(old.len(), new.found.len());
        assert_eq!(old[0].name, new.found[0].name);
    }
}
