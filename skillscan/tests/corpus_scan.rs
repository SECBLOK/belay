use std::path::Path;
use skillscan::finding::Recommendation;

#[test]
fn benign_skill_is_safe() {
    let r = skillscan::scan_skill(Path::new("tests/corpus/benign/hello_skill"));
    assert_eq!(r.recommendation, Recommendation::Safe,
        "benign should be Safe, got {:?} / {} findings", r.recommendation, r.findings.len());
}

#[test]
fn underdeclared_net_skill_flags_lp() {
    // skill.lp.underdeclared is Low (declaration hygiene, not malice): the
    // actual dangerous USE of a capability is caught by the real capability
    // detectors, so this LP-only fixture correctly stays Safe on its own.
    let r = skillscan::scan_skill(Path::new("tests/corpus/malicious/underdeclared_net_skill"));
    assert!(r.findings.iter().any(|f| f.id == "skill.lp.underdeclared"));
    assert_eq!(r.recommendation, Recommendation::Safe);
}

#[test]
fn snooping_skill_flags_snoop() {
    let r = skillscan::scan_skill(Path::new("tests/corpus/malicious/snooping_claude_config_skill"));
    assert!(r.findings.iter().any(|f| f.category == "agent_snooping"));
}
