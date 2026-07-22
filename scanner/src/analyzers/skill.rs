//! Adapter: run the `skillscan` leaf crate over a scanned skill directory and
//! map its findings into scanner `Finding`s. No-op when the tree has no
//! `SKILL.md`/`skill.md` manifest.
//!
//! Analyzers in this crate receive a `FileCache` (relative-path → decoded
//! text), not a filesystem root, so this does NOT call `skillscan::scan_skill`
//! (which walks a `Path` itself). Instead it locates the manifest entry
//! already present in the cache and calls the lower-level
//! `skillscan::scan_skill_source(skill_md, files)`, which is exactly what
//! `scan_skill` does internally after its own directory walk.

use crate::pipeline::FileCache;
use crate::types::{Category, Decision, Finding, Location, Severity};

/// Scan a `FileCache` for a skill manifest and run every `skillscan` detector
/// against it, mapping the results into scanner `Finding`s.
///
/// No-op (returns `vec![]`) when the cache carries no `SKILL.md`/`skill.md`
/// entry — a benign, non-skill repo is unaffected.
pub fn scan_skills(cache: &FileCache) -> Vec<Finding> {
    // Find EVERY skill manifest (basename SKILL.md/skill.md) and scan each one's
    // OWN directory subtree independently — so an unrelated repo tree is never
    // attributed to a single skill, and sibling skills are each scanned.
    let manifests: Vec<String> = cache
        .keys()
        .filter(|k| k.rsplit('/').next().unwrap_or(k).eq_ignore_ascii_case("skill.md"))
        .cloned()
        .collect();
    let mut out = Vec::new();
    for md_key in &manifests {
        // Directory prefix of this manifest ("" for a root-level SKILL.md).
        let dir = match md_key.rsplit_once('/') {
            Some((d, _)) => format!("{d}/"),
            None => String::new(),
        };
        let skill_md = cache.get(md_key).cloned().unwrap_or_default();
        // Only files under this manifest's own directory (excluding the manifest
        // itself and any nested skill's manifest).
        let files: Vec<(String, Vec<u8>)> = cache
            .iter()
            .filter(|(k, _)| *k != md_key && k.starts_with(&dir))
            .filter(|(k, _)| !manifests.iter().any(|m| m == *k))
            .map(|(k, v)| (k.clone(), v.clone().into_bytes()))
            .collect();
        let result = skillscan::scan_skill_source(&skill_md, &files);
        out.extend(result.findings.into_iter().map(|f| map_finding(f, md_key)));
    }
    out
}

/// Map one skillscan `SkillFinding` into a scanner `Finding`.
///
/// Mirrors the `reason`/`location` `[file: <rel>]` suffix convention used by
/// `analyzers::malware::scan_malware_yara` and
/// `analyzers::meta_mcp::scan_mcp_metadata`. `default_file` (the manifest's
/// own cache key) is used when a detector didn't pinpoint a specific
/// in-skill file (e.g. `leastpriv::detect`'s findings all carry
/// `location: None` — the diff is against the whole manifest, not one line).
///
/// Severity maps 1:1 (skillscan has no `Info` tier). Decision follows the
/// scanner's severity-driven convention (mirrors `malware.rs`: Critical/High
/// are always `Deny`): Critical|High -> Deny, Medium -> Ask, Low -> Allow.
/// Category is `Tamper` for every skillscan finding — skillscan's detectors
/// (least-privilege drift, prompt injection, tool poisoning, rug-pull,
/// snooping, SSRF, refusal-suppression, trigger phrases) all describe an
/// agent skill attempting to manipulate or exceed its declared behavior,
/// the same class `meta_mcp::scan_mcp_metadata` buckets under `Tamper` for
/// its own (narrower) tool-poisoning detections.
fn map_finding(sf: skillscan::finding::SkillFinding, default_file: &str) -> Finding {
    let severity = match sf.severity {
        skillscan::finding::Severity::Critical => Severity::Critical,
        skillscan::finding::Severity::High => Severity::High,
        skillscan::finding::Severity::Medium => Severity::Medium,
        skillscan::finding::Severity::Low => Severity::Low,
    };
    let decision = match sf.severity {
        skillscan::finding::Severity::Critical | skillscan::finding::Severity::High => {
            Decision::Deny
        }
        skillscan::finding::Severity::Medium => Decision::Ask,
        skillscan::finding::Severity::Low => Decision::Allow,
    };

    let (file, line) = match sf.location {
        Some(loc) => (loc.file, loc.start_line),
        None => (default_file.to_string(), 1),
    };

    Finding {
        rule_id: sf.id,
        severity,
        category: Category::Tamper,
        decision,
        reason: format!("{} [file: {}]", sf.message, file),
        owasp: String::new(),
        atlas: String::new(),
        location: Some(Location { file, line }),
        fix: sf.remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(entries: &[(&str, &str)]) -> FileCache {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_manifest_is_noop() {
        let c = cache(&[("readme.txt", "hi")]);
        assert!(scan_skills(&c).is_empty());
    }

    #[test]
    fn underdeclared_capability_is_flagged() {
        let c = cache(&[
            ("SKILL.md", "---\nname: x\nallowed-tools: [Read]\n---\n# body\n"),
            ("run.py", "import socket\nsocket.socket()\n"),
        ]);
        let findings = scan_skills(&c);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "skill.lp.underdeclared")
            .expect("expected skill.lp.underdeclared finding");
        // ADVISORY, not blocking. An undeclared capability is declaration
        // hygiene rather than evidence of malice: plenty of honest skills use a
        // capability they forgot to list, so blocking on it was a large false
        // positive source. feb470c deliberately set this to Low in the detector
        // (skillscan/src/detect/leastpriv.rs), and skillscan's own tests assert
        // Low. This assertion still said High/Deny and was simply never updated.
        // Low maps to Decision::Allow by the severity->decision table above.
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.decision, Decision::Allow);
        assert_eq!(f.category, Category::Tamper);
        assert!(f.reason.contains("[file: SKILL.md]"), "reason: {}", f.reason);
    }

    #[test]
    fn manifest_lookup_is_case_insensitive_and_nested() {
        let c = cache(&[
            (
                "sub/skill.md",
                "---\nname: x\nallowed-tools: [Read]\n---\n# body\n",
            ),
            ("sub/run.py", "import socket\nsocket.socket()\n"),
        ]);
        assert!(!scan_skills(&c).is_empty());
    }

    #[test]
    fn files_are_scoped_to_manifest_directory() {
        // A skill under skills/foo/ must NOT ingest an unrelated sibling file.
        let c = cache(&[
            ("skills/foo/SKILL.md", "---\nname: foo\nallowed-tools: [Read]\n---\n# foo\n"),
            ("skills/foo/run.py", "print(1)"),
            ("unrelated/big.py", "import socket\nsocket.socket()\n"),
        ]);
        let findings = scan_skills(&c);
        // The socket call is in an UNRELATED dir, so no underdeclared-network finding.
        assert!(findings.iter().all(|f| f.rule_id != "skill.lp.underdeclared"),
            "unrelated file must not be attributed to the skill, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>());
    }
}
