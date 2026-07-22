//! Skills summary assembler — pairs each enumerated installed skill with its
//! current scan verdict and baseline-drift state. This is the queryable
//! surface the GUI (Tauri `list_skills` command) renders; no scanning
//! machinery lives here, only the join between `enumerate`, `skillscan`, and
//! `host_config`'s baseline store.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;

use crate::host_config;
use crate::skills::enumerate::{enumerate_skills_in, skill_roots, InstalledSkill};

/// One row of the skills summary. Wire form: `recommendation` and `severity`
/// use skillscan's own lowercase enum strings (`"safe"|"caution"|"donotinstall"`,
/// `"low"|"medium"|"high"|"critical"`); `drift` is one of
/// `"unbaselined" | "clean" | "drifted"`.
#[derive(Debug, Serialize)]
pub struct SkillSummary {
    pub agent: String,
    pub name: String,
    pub path: String,
    pub recommendation: skillscan::finding::Recommendation,
    pub severity: Option<skillscan::finding::Severity>,
    pub finding_count: usize,
    pub drift: String,
}

/// Assemble the summary from a caller-supplied set of skill roots (testable
/// seam, mirrors [`enumerate_skills_in`]).
pub fn skills_summary_in(roots: &[(String, PathBuf)]) -> Vec<SkillSummary> {
    enumerate_skills_in(roots).into_iter().map(summarize_one).collect()
}

/// Assemble the summary over the real, per-agent skill roots under the
/// current user's home directory.
pub fn skills_summary() -> Vec<SkillSummary> {
    skills_summary_in(&skill_roots())
}

/// Scan one enumerated skill and join its verdict with baseline-drift state.
/// Fail-soft by construction: `skillscan::scan_skill` never panics (a missing
/// or unparseable manifest simply yields an empty, `Safe` result), so a skill
/// that can't be meaningfully scanned still appears here with its enumerated
/// agent/name and a best-effort (empty) verdict rather than being dropped.
fn summarize_one(skill: InstalledSkill) -> SkillSummary {
    let dir = skill
        .manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| skill.manifest.clone());

    let result = skillscan::scan_skill(&dir);
    let severity = result.findings.iter().max_by_key(|f| f.severity).map(|f| f.severity);

    let drift = match host_config::skill_baseline_content_hash(&dir) {
        None => "unbaselined",
        Some(baseline) if host_config::skill_content_hash(&dir) == baseline => "clean",
        Some(_) => "drifted",
    };

    SkillSummary {
        agent: skill.agent,
        name: skill.name,
        path: dir.to_string_lossy().into_owned(),
        recommendation: result.recommendation,
        severity,
        finding_count: result.findings.len(),
        drift: drift.to_string(),
    }
}

/// JSON form of [`skills_summary`] for the Tauri `list_skills` command.
/// Fail-soft: an unexpected serialization failure yields `[]` rather than
/// propagating (mirrors `host_config::list_quarantine`'s Value-returning
/// shape — the GUI surface never errors on a read).
pub fn skills_summary_json() -> serde_json::Value {
    serde_json::to_value(skills_summary()).unwrap_or(json!([]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plant_skill(home: &std::path::Path, agent: &str, name: &str, body: &str) -> PathBuf {
        let dir = home.join(format!(".{agent}/skills/{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), body).unwrap();
        dir
    }

    #[test]
    fn summary_over_unbaselined_benign_skill() {
        let tmp = tempfile::tempdir().unwrap();
        plant_skill(
            tmp.path(),
            "claude",
            "greeter",
            "---\nname: greeter\ndescription: says hi\n---\n# Body\nhello",
        );
        let roots = vec![("claude".to_string(), tmp.path().join(".claude/skills"))];
        let out = skills_summary_in(&roots);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent, "claude");
        assert_eq!(out[0].name, "greeter");
        assert_eq!(out[0].drift, "unbaselined");
        assert_eq!(out[0].recommendation, skillscan::finding::Recommendation::Safe);
    }

    #[test]
    fn summary_reports_clean_then_drifted_against_a_baseline() {
        let _home_guard =
            crate::skills::HOME_ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());

        let dir = plant_skill(
            tmp.path(),
            "claude",
            "tool",
            "---\nname: tool\ndescription: d\n---\n# Body\nv1",
        );
        let m = skillscan::scan_skill(&dir).manifest.expect("manifest parses");
        host_config::set_skill_baseline(&dir, &m, "auto_clean_scan").expect("set baseline");

        let roots = vec![("claude".to_string(), tmp.path().join(".claude/skills"))];

        let clean = skills_summary_in(&roots);
        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].drift, "clean");

        // Change the body -> content hash no longer matches the baseline.
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: tool\ndescription: d\n---\n# Body\nv2 changed",
        )
        .unwrap();

        let drifted = skills_summary_in(&roots);
        assert_eq!(drifted.len(), 1);
        assert_eq!(drifted[0].drift, "drifted");
    }

    #[test]
    fn skills_summary_json_serializes_expected_shape() {
        let tmp = tempfile::tempdir().unwrap();
        plant_skill(
            tmp.path(),
            "claude",
            "greeter",
            "---\nname: greeter\ndescription: says hi\n---\n# Body\nhello",
        );
        let roots = vec![("claude".to_string(), tmp.path().join(".claude/skills"))];
        let v = serde_json::to_value(skills_summary_in(&roots)).unwrap();
        assert_eq!(v[0]["agent"], "claude");
        assert_eq!(v[0]["name"], "greeter");
        assert_eq!(v[0]["drift"], "unbaselined");
        assert_eq!(v[0]["recommendation"], "safe");
        assert!(v[0]["severity"].is_null());
        assert_eq!(v[0]["finding_count"], 0);
    }
}
