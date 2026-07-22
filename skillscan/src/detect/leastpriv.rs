//! Least-Privilege (LP1-4): diff the manifest's DECLARED capabilities against the
//! scripts' OBSERVED capabilities. Ported from SkillSpector `mcp_least_privilege.py`.

use crate::capabilities::{declared_caps, observed_caps};
use crate::finding::{Severity, SkillFinding};
use crate::SkillContext;

fn mk(id: &str, sev: Severity, conf: f32, msg: String, origin: &str) -> SkillFinding {
    SkillFinding { id: id.into(), category: "least_privilege".into(), severity: sev, confidence: conf,
        location: None, message: msg, remediation: "Declare exactly the capabilities the code uses.".into(),
        tags: vec![origin.into()] }
}

pub fn detect(ctx: &SkillContext) -> Vec<SkillFinding> {
    let Some(m) = ctx.manifest.as_ref() else { return vec![] };
    let (declared, wildcard) = declared_caps(m);
    let observed = observed_caps(&ctx.files);
    let mut out = Vec::new();

    if wildcard {
        out.push(mk("skill.lp.wildcard", Severity::Medium, 0.9,
            "Manifest grants a wildcard permission (*/all/full/any).".into(), "LP2"));
    }
    let has_decl = !m.allowed_tools.is_empty() || !m.permissions.is_empty();
    if !has_decl && !observed.is_empty() {
        out.push(mk("skill.lp.missing_decl", Severity::Low, 0.8,
            "Scripts use capabilities but the manifest declares no permissions.".into(), "LP3"));
    }
    if !wildcard {
        for cap in observed.difference(&declared) {
            out.push(mk("skill.lp.underdeclared", Severity::Low, 0.9,
                format!("Code uses capability {cap:?} not declared in the manifest."), "LP1"));
        }
    }
    // LP4 only when scripts exist to compare against (and no wildcard). A
    // scriptless skill (pure prompt/Markdown) legitimately declares agent tools
    // it uses directly, so "declared but not seen in scripts" is not a signal.
    if !wildcard && !ctx.files.is_empty() {
        for cap in declared.difference(&observed) {
            out.push(mk("skill.lp.overdeclared", Severity::Low, 0.6,
                format!("Manifest declares capability {cap:?} the code never uses (pre-staging signal)."), "LP4"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_context;

    #[test]
    fn underdeclared_network_is_low() {
        let md = "---\nname: x\nallowed-tools: [read]\n---\nbody";
        let ctx = build_context(md, &[("r.py".into(), b"import requests\nrequests.get('http://x')".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.lp.underdeclared" && f.severity == crate::finding::Severity::Low));
    }

    #[test]
    fn wildcard_permission_is_flagged() {
        let md = "---\nname: x\nallowed-tools: ['*']\n---\nbody";
        assert!(detect(&build_context(md, &[])).iter().any(|f| f.id == "skill.lp.wildcard"));
    }

    #[test]
    fn benign_declared_match_is_clean() {
        let md = "---\nname: x\nallowed-tools: [network]\n---\nbody";
        let ctx = build_context(md, &[("r.py".into(), b"import requests\nrequests.get('http://x')".to_vec())]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.lp.underdeclared"));
    }

    #[test]
    fn declared_bash_covering_subprocess_is_not_underdeclared() {
        let md = "---\nname: x\nallowed-tools: [Bash]\n---\nbody";
        let ctx = build_context(md, &[("r.py".into(), b"import subprocess\nsubprocess.run(['ls'])".to_vec())]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.lp.underdeclared"),
            "declaring Bash must cover a subprocess call (no false underdeclared)");
    }

    #[test]
    fn scriptless_skill_has_no_overdeclared_noise() {
        let md = "---\nname: x\nallowed-tools: [Read, Write]\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.lp.overdeclared"),
            "scriptless skill must not emit overdeclared findings");
    }
}
