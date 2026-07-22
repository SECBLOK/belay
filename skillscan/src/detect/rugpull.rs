//! Rug-Pull (RP1-3). Ported from SkillSpector `mcp_rug_pull.py`. `diff_manifests`
//! needs a stored baseline (wired in Phase 2) so it is NOT in `ALL`; the RP1
//! unpinned-external-ref check needs no baseline and runs on every scan.
//!
//! NOTE on RP1: the reference pattern used `(?!...)` negative lookahead to
//! express "not followed by a pin marker". The `regex` crate this leaf crate
//! depends on deliberately does not support lookaround (it guarantees
//! linear-time matching), so that pattern fails at `Regex::new(..)` --
//! confirmed by compiling it standalone: "look-around, including look-ahead
//! and look-behind, is not supported". The three rules below express the same
//! "unpinned invocation" semantics -- flag npx/uvx/pip-install/docker-run
//! references that carry no version or digest pin -- using only supported
//! regex features (a consuming match followed by a whitespace/end-of-text
//! check, instead of a negative lookahead).
use std::collections::HashSet;
use crate::detect::{run_rules, text_surfaces, Rule};
use crate::finding::{Severity, SkillFinding};
use crate::manifest::Manifest;
use crate::SkillContext;

fn perms_set(m: &Manifest) -> HashSet<String> {
    m.permissions.iter().chain(m.allowed_tools.iter()).map(|s| s.trim().to_ascii_lowercase()).collect()
}

pub fn diff_manifests(old: &Manifest, new: &Manifest) -> Vec<SkillFinding> {
    let mut out = Vec::new();
    let (o, n) = (perms_set(old), perms_set(new));
    let added: Vec<&String> = n.difference(&o).collect();
    if !added.is_empty() {
        out.push(SkillFinding {
            id: "skill.rp.perm_expansion".into(), category: "rug_pull".into(), severity: Severity::Medium,
            confidence: 0.9, location: None,
            message: format!("Manifest gained permissions vs the approved baseline: {added:?}"),
            remediation: "Re-review the skill; permission growth is a rug-pull signal.".into(),
            tags: vec!["RP2".into(), "ASI16".into()] });
    }
    if old.triggers != new.triggers || old.description != new.description {
        out.push(SkillFinding {
            id: "skill.rp.manifest_change".into(), category: "rug_pull".into(), severity: Severity::Low,
            confidence: 0.6, location: None,
            message: "Triggers or description changed vs the approved baseline.".into(),
            remediation: "Confirm the change is intentional.".into(),
            tags: vec!["RP3".into(), "ASI16".into()] });
    }
    out
}

const RULES: &[Rule] = &[
    Rule { id: "skill.rp.unpinned_ref", category: "rug_pull", sev: Severity::Low, conf: 0.7, origin: "RP1",
        pattern: r"(?m)\b(npx|uvx)\s+[^\s@]+(?:\s|$)",
        message: "Uses an unpinned external reference (npx/pip/docker without a pinned version).",
        remediation: "Pin the version (@x.y.z, ==x.y.z, or @sha256:...)." },
    Rule { id: "skill.rp.unpinned_ref", category: "rug_pull", sev: Severity::Low, conf: 0.7, origin: "RP1",
        pattern: r"(?i)pip\s+install\s+[a-z][a-z0-9._\-\[\]]*(\s|$|>=|<=|~=|!=|>|<)",
        message: "Uses an unpinned external reference (npx/pip/docker without a pinned version).",
        remediation: "Pin the version (@x.y.z, ==x.y.z, or @sha256:...)." },
    Rule { id: "skill.rp.unpinned_ref", category: "rug_pull", sev: Severity::Low, conf: 0.7, origin: "RP1",
        pattern: r"(?m)\bdocker\s+run\s+[^\s@]+(?:\s|$)",
        message: "Uses an unpinned external reference (npx/pip/docker without a pinned version).",
        remediation: "Pin the version (@x.y.z, ==x.y.z, or @sha256:...)." },
];

pub fn detect(ctx: &SkillContext) -> Vec<SkillFinding> {
    run_rules(RULES, &text_surfaces(ctx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::build_context;

    fn m(perms: &[&str]) -> Manifest {
        Manifest { permissions: perms.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn permission_expansion_flagged() {
        let fs = diff_manifests(&m(&["read"]), &m(&["read", "network", "shell"]));
        assert!(fs.iter().any(|f| f.id == "skill.rp.perm_expansion"));
    }
    #[test]
    fn no_change_is_clean() { assert!(diff_manifests(&m(&["read"]), &m(&["read"])).is_empty()); }
    #[test]
    fn unpinned_pip_install_flagged_in_scan() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"pip install requests".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }

    // Extra coverage for the rewritten (non-lookaround) RP1 patterns: prove
    // pinned refs across all three command families stay clean, and that
    // npx/docker unpinned refs are caught too (the brief's given test only
    // exercises pip).
    #[test]
    fn pinned_pip_install_is_clean() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"pip install requests==2.31.0".to_vec())]);
        assert!(!detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }
    #[test]
    fn unpinned_npx_flagged() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"npx cowsay hi".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }
    #[test]
    fn pinned_npx_is_clean() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"npx cowsay@1.5.0 hi".to_vec())]);
        assert!(!detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }
    #[test]
    fn unpinned_docker_run_flagged() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"docker run alpine:latest echo hi".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }
    #[test]
    fn pinned_docker_run_is_clean() {
        let ctx = build_context("---\nname: x\n---\nb", &[("s.sh".into(), b"docker run alpine@sha256:abcd1234ef echo hi".to_vec())]);
        assert!(!detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }

    #[test]
    fn pip_range_operator_is_unpinned() {
        let ctx = build_context("---\nname: x\n---\n", &[("s.sh".into(), b"pip install requests>=2.0".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.rp.unpinned_ref"));
    }

    #[test]
    fn pip_exact_pin_is_clean() {
        let ctx = build_context("---\nname: x\n---\n", &[("s.sh".into(), b"pip install requests==2.31.0".to_vec())]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.rp.unpinned_ref"));
    }

    #[test]
    fn pip_requirements_file_is_clean() {
        let ctx = build_context("---\nname: x\n---\n", &[("s.sh".into(), b"pip install -r requirements.txt".to_vec())]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.rp.unpinned_ref"));
    }
}
