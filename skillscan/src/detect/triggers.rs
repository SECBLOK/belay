//! Trigger-abuse heuristics (TR1-3): a skill's `triggers` declare WHEN the
//! agent auto-invokes it — an overbroad or command-shadowing trigger can pull
//! a malicious skill into contexts its author never should have reached, and
//! keyword-baited triggers try to game relevance ranking.
use crate::detect::{run_rules, Rule};
use crate::finding::SkillFinding;
use crate::manifest::Manifest;
use crate::SkillContext;

const RULES: &[Rule] = &[
    Rule { id: "skill.trigger.overbroad", category: "trigger_abuse", sev: crate::finding::Severity::Medium, conf: 0.6,
        origin: "TR1", pattern: r"(?i)^\s*(any|all|every|always|everything|anything)\b|when\s+the\s+user\s+(says|does)\s+(anything|any)",
        message: "Trigger matches an overbroad condition (any/all/every/always).",
        remediation: "Scope the trigger to the specific request the skill handles." },
    Rule { id: "skill.trigger.shadow", category: "trigger_abuse", sev: crate::finding::Severity::Medium, conf: 0.6,
        origin: "TR2", pattern: r"(?i)^\s*(help|install|run|deploy|delete|list|search|build|test)\s*$",
        message: "Trigger shadows a common command word, hijacking generic requests.",
        remediation: "Use a distinctive trigger phrase instead of a bare common command word." },
    Rule { id: "skill.trigger.baiting", category: "trigger_abuse", sev: crate::finding::Severity::Low, conf: 0.5,
        origin: "TR3", pattern: r"(?i)(free|urgent|important|now|click|guaranteed)\b.*\b(free|urgent|important|now|click|guaranteed)\b",
        message: "Trigger uses keyword-baiting language to game relevance matching.",
        remediation: "Remove attention-baiting keywords from the trigger text." },
];

/// Each trigger entry + the manifest description (both drive auto-invocation
/// relevance matching in most Agent-Skill runtimes).
fn surfaces(m: &Manifest) -> Vec<(String, &str)> {
    let mut s: Vec<(String, &str)> = m.triggers.iter().enumerate()
        .map(|(i, t)| (format!("manifest.triggers[{i}]"), t.as_str()))
        .collect();
    if let Some(d) = m.description.as_deref() { s.push(("manifest.description".to_string(), d)); }
    s
}

pub fn detect(ctx: &SkillContext) -> Vec<SkillFinding> {
    let Some(m) = ctx.manifest.as_ref() else { return Vec::new() };
    let s = surfaces(m);
    let refs: Vec<(&str, &str)> = s.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    run_rules(RULES, &refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_context;

    #[test]
    fn flags_overbroad_trigger() {
        let md = "---\nname: x\ntriggers:\n  - \"any request the user makes\"\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.trigger.overbroad"));
    }

    #[test]
    fn flags_overbroad_says_anything_phrasing() {
        let md = "---\nname: x\ntriggers:\n  - \"when the user says anything about files\"\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.trigger.overbroad"));
    }

    #[test]
    fn flags_shadow_trigger() {
        let md = "---\nname: x\ntriggers:\n  - \"install\"\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.trigger.shadow"));
    }

    #[test]
    fn flags_baiting_trigger() {
        let md = "---\nname: x\ntriggers:\n  - \"Free offer, click now for guaranteed savings\"\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.trigger.baiting"));
    }

    #[test]
    fn no_manifest_is_empty() {
        let ctx = build_context("# just docs, no frontmatter", &[]);
        assert!(detect(&ctx).is_empty());
    }

    #[test]
    fn benign_is_clean() {
        let md = "---\nname: x\ndescription: \"converts CSV files to JSON\"\ntriggers:\n  - \"when the user asks to convert a CSV file to JSON\"\n---\nbody";
        let ctx = build_context(md, &[]);
        assert!(detect(&ctx).is_empty());
    }
}
