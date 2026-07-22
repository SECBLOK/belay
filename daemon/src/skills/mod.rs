use std::path::Path;

pub mod enumerate;
pub mod gate;
/// LLM meta-filter over borderline (Caution) skillscan verdicts. Opt-in via
/// the `ai` cargo feature (off by default) — see `daemon/src/ai/config.rs`'s
/// `AiConfig.skill_judge_enabled` for the runtime opt-in on top of that.
#[cfg(feature = "ai")]
pub mod judge;
pub mod mcp_config;
pub mod mcp_scan;
pub mod summary;
pub mod watch;

pub use summary::{skills_summary, skills_summary_in, skills_summary_json, SkillSummary};

/// The current user's home directory, cross-platform: `USERPROFILE` on
/// Windows, `HOME` on Unix. Fails soft to `.` rather than panicking — never
/// the security-critical path (worst case, skill-root matching under `.`
/// simply misses).
pub fn home_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::path::PathBuf::from(std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into()))
    }
    #[cfg(unix)]
    {
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
    }
}

/// Guards every test in the crate that mutates the process-global `HOME`
/// (Unix) / `USERPROFILE` (Windows) env var consumed by [`home_dir`], so
/// they — and any test that reads a `HOME`-derived path such as
/// [`home_dir`] or `host_config::belay_dir`/`quarantine_dir` — can't race
/// each other under cargo's default parallel test execution. `HOME` is a
/// single process-wide value; two tests mutating (or reading, mid-mutation)
/// it concurrently on different threads can observe each other's temp dir
/// and intermittently fail with spurious "unknown id" / "not trusted" /
/// wrong-decision errors. Every `#[test]` that calls `std::env::set_var`
/// on this var, or that depends on it staying stable for the test's
/// duration, must hold this lock first. Poisoning is ignored
/// (`unwrap_or_else(PoisonError::into_inner)`) so one test's panic while
/// holding the lock doesn't cascade into every subsequent test failing too.
#[cfg(test)]
pub(crate) static HOME_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Operator re-approval: snapshot the skill's CURRENT manifest as its approved
/// baseline (moving the baseline on purpose — the "yes, this update is fine"
/// action behind `belay skill-approve`). Returns the baseline permission list.
/// Errors if the dir has no parseable `SKILL.md` manifest.
pub fn approve(dir: &Path) -> Result<Vec<String>, String> {
    let m = skillscan::scan_skill(dir)
        .manifest
        .ok_or_else(|| format!("skill at {} has no parseable SKILL.md manifest", dir.display()))?;
    crate::host_config::set_skill_baseline(dir, &m, "operator_approve")?;
    Ok(m.permissions)
}

#[cfg(test)]
mod tests {
    #[test]
    fn approve_sets_operator_baseline_and_returns_perms() {
        let _home_guard = crate::skills::HOME_ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        let dir = tmp.path().join("proj/.claude/skills/appr");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"),
            "---\nname: appr\ndescription: d\npermissions: [read]\nallowed-tools: [Read]\n---\n# Hi").unwrap();
        let perms = crate::skills::approve(&dir).expect("approve");
        assert!(perms.iter().any(|p| p == "read"));
        assert!(crate::host_config::skill_baseline(&dir).is_some());
    }

    #[test]
    fn approve_errs_without_a_manifest() {
        let _home_guard = crate::skills::HOME_ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        let dir = tmp.path().join("proj/.claude/skills/nomani");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "no frontmatter here").unwrap();
        assert!(crate::skills::approve(&dir).is_err());
    }
}
