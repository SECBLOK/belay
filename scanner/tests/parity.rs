use scanner::run_scan;

#[test]
fn corpus_dirs_exist() {
    assert!(std::path::Path::new("tests/corpus_scan/malicious").is_dir());
    assert!(std::path::Path::new("tests/corpus_scan/benign").is_dir());
}

#[test]
fn skeleton_run_scan_returns_result_shape() {
    // At skeleton stage run_scan returns an empty-but-well-formed result.
    let r = run_scan("tests/corpus_scan/benign/hello_skill");
    assert_eq!(r.source_type, "dir");
    assert!(r.findings.is_empty()); // no analyzers wired yet
    assert_eq!(r.recommendation, "SAFE"); // score 0
}
