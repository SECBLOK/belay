//! Agent-config snooping (AS1-3): a skill reading another agent's config, MCP
//! config, or peer skills. Ported from SkillSpector `static_patterns_agent_snooping.py`.
use crate::detect::{run_rules, text_surfaces, Rule};
use crate::finding::{SkillFinding, Severity};
use crate::SkillContext;

const RULES: &[Rule] = &[
    Rule { id: "skill.snoop.agent_config", category: "agent_snooping", sev: Severity::High, conf: 0.85,
        origin: "AS1", pattern: r"(?i)(open|read|cat|load|listdir|glob|pathlib|os\.(path|walk)|with\s+open)[^\n]{0,50}\.(claude|codex|gemini|cursor|aider)/",
        message: "Reads another agent's config directory.", remediation: "Skills must not read agent config dirs." },
    Rule { id: "skill.snoop.mcp_config", category: "agent_snooping", sev: Severity::High, conf: 0.85,
        origin: "AS2", pattern: r"(?i)(open|read|cat|load|parse|json\.load)[^\n]{0,50}(mcp\.json|claude_desktop_config\.json)",
        message: "Reads MCP server configuration.", remediation: "Skills must not read MCP config." },
    Rule { id: "skill.snoop.skill_enum", category: "agent_snooping", sev: Severity::Medium, conf: 0.7,
        origin: "AS3", pattern: r"(?i)(listdir|glob|walk|readdir|scandir|os\.walk|\bls\s)[^\n]{0,40}/skills/|open\s*\([^)]*/skills/",
        message: "Enumerates or reads peer skills.", remediation: "Skills must not read other skills." },
];

pub fn detect(ctx: &SkillContext) -> Vec<SkillFinding> { run_rules(RULES, &text_surfaces(ctx)) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_context;
    #[test]
    fn flags_claude_config_read() {
        let ctx = build_context("---\nname: x\n---\nb",
            &[("r.py".into(), b"open('/home/u/.claude/config.json').read()".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.snoop.agent_config"));
    }
    #[test]
    fn benign_is_clean() {
        let ctx = build_context("---\nname: x\n---\nb", &[("r.py".into(), b"print('hi')".to_vec())]);
        assert!(detect(&ctx).is_empty());
    }
    #[test]
    fn documenting_skill_md_does_not_trip_enum() {
        let ctx = build_context("---\nname: x\n---\nSee SKILL.md above for details.", &[]);
        assert!(detect(&ctx).iter().all(|f| f.id != "skill.snoop.skill_enum"));
    }
}
