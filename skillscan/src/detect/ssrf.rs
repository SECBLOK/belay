//! SSRF heuristics (SSRF1-3): scripts that reach cloud metadata endpoints,
//! internal/loopback networks, or build a request target from untrusted
//! input. Surfaces = bundled script files only (SKILL.md body is prose, not
//! executed code, so it is out of scope for this family).
use crate::detect::{run_rules, Rule};
use crate::finding::{Severity, SkillFinding};
use crate::SkillContext;

const RULES: &[Rule] = &[
    Rule { id: "skill.ssrf.cloud_metadata", category: "ssrf", sev: Severity::Critical, conf: 0.9,
        origin: "SSRF1", pattern: r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
        message: "Script reaches a cloud instance-metadata endpoint.",
        remediation: "Do not request cloud instance-metadata endpoints from skill scripts." },
    Rule { id: "skill.ssrf.internal_net", category: "ssrf", sev: Severity::Medium, conf: 0.6,
        origin: "SSRF2", pattern: r"(?i)https?://(127\.\d|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|0\.0\.0\.0)",
        message: "Script reaches a loopback or private-network address.",
        remediation: "Do not target internal/private network addresses from skill scripts." },
    Rule { id: "skill.ssrf.dynamic_target", category: "ssrf", sev: Severity::Medium, conf: 0.5,
        origin: "SSRF3", pattern: r"(?i)(requests\.(get|post)|urlopen|fetch)\s*\([^)]*(input\(|argv|os\.environ|getenv|request\.(args|form|json|params))",
        message: "Request target is built from untrusted/user-controlled input.",
        remediation: "Validate and allowlist request targets before making outbound requests." },
];

pub fn detect(ctx: &SkillContext) -> Vec<SkillFinding> {
    let surfaces: Vec<(&str, &str)> = ctx.files.iter().map(|f| (f.path.as_str(), f.text.as_str())).collect();
    run_rules(RULES, &surfaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_context;

    #[test]
    fn flags_cloud_metadata_ip() {
        let ctx = build_context("---\nname: x\n---\nbody",
            &[("r.py".into(), b"requests.get('http://169.254.169.254/latest/meta-data/')".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.ssrf.cloud_metadata"));
    }

    #[test]
    fn flags_internal_network_url() {
        let ctx = build_context("---\nname: x\n---\nbody",
            &[("r.py".into(), b"requests.get('http://127.0.0.1:8080/admin')".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.ssrf.internal_net"));
    }

    #[test]
    fn flags_dynamic_target_from_env() {
        let ctx = build_context("---\nname: x\n---\nbody",
            &[("r.py".into(), b"requests.get(os.environ['TARGET_URL'])".to_vec())]);
        assert!(detect(&ctx).iter().any(|f| f.id == "skill.ssrf.dynamic_target"));
    }

    #[test]
    fn ignores_body_and_only_scans_scripts() {
        // The tell-tale metadata IP lives in the body, not in any bundled file:
        // this family's surfaces must be scripts only, so no finding should fire.
        let ctx = build_context(
            "---\nname: x\n---\nSee 169.254.169.254 for details.",
            &[("r.py".into(), b"print('hello')".to_vec())],
        );
        assert!(detect(&ctx).is_empty());
    }

    #[test]
    fn benign_static_external_url_is_clean() {
        let ctx = build_context("---\nname: x\n---\nbody",
            &[("r.py".into(), b"requests.get('https://api.example.com/data')".to_vec())]);
        assert!(detect(&ctx).is_empty());
    }
}
