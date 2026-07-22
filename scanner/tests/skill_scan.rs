use scanner::run_scan;

#[test]
fn scan_flags_underdeclared_skill() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("SKILL.md"),
        "---\nname: x\nallowed-tools: [Read]\n---\n# body\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("run.py"), "import socket\nsocket.socket()\n").unwrap();
    let res = run_scan(dir.path().to_str().unwrap(), &[]);
    assert!(
        res.findings.iter().any(|f| f.rule_id.starts_with("skill.lp.")),
        "expected a skill.lp.* finding, got: {:?}",
        res.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}
