//! Detector registry. Every detector shares `fn(&SkillContext) -> Vec<SkillFinding>`.
pub mod antirefusal;
pub mod coverage;
pub mod injection;
pub mod leastpriv;
pub mod patterns;
pub mod rugpull;
pub mod snooping;
pub mod ssrf;
pub mod toolpoison;
pub mod triggers;

use crate::{finding::SkillFinding, SkillContext};
use regex::Regex;

pub type Detector = fn(&SkillContext) -> Vec<SkillFinding>;

/// All static detectors run by `scan_skill_source`. Later tasks append here.
/// `rugpull::diff_manifests` is intentionally NOT here: it needs a stored
/// baseline (wired in Phase 2), unlike `rugpull::detect` (RP1 only).
pub const ALL: &[Detector] = &[leastpriv::detect, snooping::detect, injection::detect, toolpoison::detect, triggers::detect, antirefusal::detect, ssrf::detect, patterns::detect, rugpull::detect, coverage::detect];

pub struct Rule {
    pub id: &'static str, pub category: &'static str, pub sev: crate::finding::Severity,
    pub conf: f32, pub origin: &'static str, pub pattern: &'static str,
    pub message: &'static str, pub remediation: &'static str,
}

/// Run `rules` over each `(surface_name, text)`; emit a finding at the first match
/// per (rule, surface) with the 1-based line number.
pub fn run_rules(rules: &[Rule], surfaces: &[(&str, &str)]) -> Vec<SkillFinding> {
    let mut out = Vec::new();
    for r in rules {
        let re = Regex::new(r.pattern).expect("static rule regex compiles");
        for (name, text) in surfaces {
            if let Some(mch) = re.find(text) {
                let line = text[..mch.start()].bytes().filter(|&b| b == b'\n').count() as u32 + 1;
                out.push(SkillFinding {
                    id: r.id.into(), category: r.category.into(), severity: r.sev, confidence: r.conf,
                    location: Some(crate::finding::Location { file: name.to_string(), start_line: line, end_line: line }),
                    message: r.message.into(), remediation: r.remediation.into(), tags: vec![r.origin.into()],
                });
            }
        }
    }
    out
}

/// The default surfaces: SKILL.md body + each script file.
pub fn text_surfaces(ctx: &SkillContext) -> Vec<(&str, &str)> {
    let mut s: Vec<(&str, &str)> = vec![("SKILL.md", ctx.body.as_str())];
    s.extend(ctx.files.iter().map(|f| (f.path.as_str(), f.text.as_str())));
    s
}
