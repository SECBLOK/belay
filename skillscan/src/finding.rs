//! Finding, severity, and recommendation types for skillscan. Kept crate-local
//! (no Belay dependency); the scanner adapter maps these into scanner findings.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Recommendation { Safe, Caution, DoNotInstall }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location { pub file: String, pub start_line: u32, pub end_line: u32 }

#[derive(Debug, Clone, Serialize)]
pub struct SkillFinding {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: f32,
    pub location: Option<Location>,
    pub message: String,
    pub remediation: String,
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn finding_constructs() {
        let f = SkillFinding {
            id: "skill.lp.underdeclared".into(),
            category: "least_privilege".into(),
            severity: Severity::High,
            confidence: 0.9,
            location: Some(Location { file: "s.py".into(), start_line: 1, end_line: 1 }),
            message: "m".into(),
            remediation: "r".into(),
            tags: vec!["LP1".into()],
        };
        assert_eq!(f.severity, Severity::High);
    }
}
