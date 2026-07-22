//! Parse an Agent-Skill `SKILL.md`: split YAML frontmatter from the Markdown
//! body and extract the manifest fields skillscan reasons about. `allowed-tools`
//! accepts either a YAML list or a comma-separated string (Agent Skills standard).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter { pub name: String, pub description: String }

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub triggers: Vec<String>,
    pub permissions: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub parameters: Vec<Parameter>,
}

/// Split `---\n...\n---\n` frontmatter from the body. Returns `(None, whole)`
/// when there is no leading frontmatter fence OR the opening fence is never
/// closed. The closer is the FIRST subsequent line whose content is exactly
/// `---` (a trailing CR is ignored), so mixed line endings and a `---` rule in
/// the body both split correctly.
pub fn split_frontmatter(skill_md: &str) -> (Option<&str>, &str) {
    let s = skill_md.strip_prefix('\u{feff}').unwrap_or(skill_md);
    let rest = match s.strip_prefix("---\n").or_else(|| s.strip_prefix("---\r\n")) {
        Some(r) => r,
        None => return (None, s),
    };
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed == "---" {
            return (Some(&rest[..offset]), &rest[offset + line.len()..]);
        }
        offset += line.len();
    }
    (None, s)
}

#[derive(Deserialize)]
struct RawManifest {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)] triggers: Vec<String>,
    #[serde(default)] permissions: Vec<String>,
    #[serde(default, rename = "allowed-tools")] allowed_tools: Option<ToolsField>,
    #[serde(default)] parameters: Vec<RawParam>,
}

#[derive(Deserialize)]
struct RawParam { name: String, #[serde(default)] description: String }

#[derive(Deserialize)]
#[serde(untagged)]
enum ToolsField { List(Vec<String>), CommaString(String) }

impl ToolsField {
    fn into_vec(self) -> Vec<String> {
        match self {
            ToolsField::List(v) => v,
            ToolsField::CommaString(s) =>
                s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
        }
    }
}

pub fn parse_manifest(skill_md: &str) -> Option<Manifest> {
    let (fm, _body) = split_frontmatter(skill_md);
    let fm = fm?;
    let raw: RawManifest = serde_yaml::from_str(fm).ok()?;
    Some(Manifest {
        name: raw.name,
        description: raw.description,
        triggers: raw.triggers,
        permissions: raw.permissions,
        allowed_tools: raw.allowed_tools.map(ToolsField::into_vec).unwrap_or_default(),
        parameters: raw.parameters.into_iter()
            .map(|p| Parameter { name: p.name, description: p.description }).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKILL: &str = "---\nname: demo\ndescription: does a thing\nallowed-tools: [read, write]\npermissions:\n  - net\ntriggers:\n  - when the user says hi\n---\n# Body\nhello\n";

    #[test]
    fn parses_frontmatter_fields() {
        let m = parse_manifest(SKILL).unwrap();
        assert_eq!(m.name.as_deref(), Some("demo"));
        assert_eq!(m.allowed_tools, vec!["read", "write"]);
        assert_eq!(m.permissions, vec!["net"]);
        assert_eq!(m.triggers.len(), 1);
    }

    #[test]
    fn allowed_tools_accepts_comma_string() {
        let src = "---\nname: x\nallowed-tools: read, write, exec\n---\nbody";
        let m = parse_manifest(src).unwrap();
        assert_eq!(m.allowed_tools, vec!["read", "write", "exec"]);
    }

    #[test]
    fn no_frontmatter_returns_none() {
        assert!(parse_manifest("# just a doc\nno frontmatter").is_none());
    }

    #[test]
    fn invalid_yaml_returns_none() {
        assert!(parse_manifest("---\n: : : bad\n---\nbody").is_none());
    }

    #[test]
    fn split_frontmatter_returns_body() {
        let (fm, body) = split_frontmatter(SKILL);
        assert!(fm.unwrap().contains("name: demo"));
        assert!(body.contains("hello"));
    }

    #[test]
    fn parses_parameters() {
        let src = "---\nname: x\nparameters:\n  - name: url\n    description: the target\n---\nbody";
        let m = parse_manifest(src).unwrap();
        assert_eq!(m.parameters.len(), 1);
        assert_eq!(m.parameters[0].name, "url");
        assert_eq!(m.parameters[0].description, "the target");
    }

    #[test]
    fn parses_crlf_frontmatter() {
        let src = "---\r\nname: x\r\nallowed-tools: [read]\r\n---\r\nbody";
        let m = parse_manifest(src).unwrap();
        assert_eq!(m.name.as_deref(), Some("x"));
        assert_eq!(m.allowed_tools, vec!["read"]);
    }

    #[test]
    fn earliest_closing_fence_wins() {
        let src = "---\nname: x\n---\nintro\n---\nmore";
        let (fm, body) = split_frontmatter(src);
        assert!(fm.unwrap().contains("name: x"));
        assert!(body.starts_with("intro"));
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let m = Manifest {
            name: Some("x".into()),
            description: Some("d".into()),
            triggers: vec!["t".into()],
            permissions: vec!["read".into()],
            allowed_tools: vec!["Read".into()],
            parameters: vec![Parameter { name: "p".into(), description: "pd".into() }],
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }
}
