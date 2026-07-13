//! End-to-end corpus parity: Rust scanner CLI vs committed golden table.
//!
//! NOTE (post Phase-10 cutover): `belay scan` shells this same Rust binary,
//! and (Phase 13) the Python package has been DELETED. The expected
//! score / recommendation / finding set per corpus dir is now a committed golden
//! table captured from the deleted Python predecessor's `aidefender scan` CLI before deletion. This
//! test verifies CLI plumbing (exit-code + JSON passthrough) against that golden.

#[path = "common/mod.rs"]
mod common;
use common::{diff_findings, run_rust_cli};
use scanner::types::{Category, Decision, Finding, Severity};

/// Build a golden `Finding` keyed only on (rule_id, severity, reason) — the
/// other fields are defaulted to match `run_rust_cli`'s minimal mapping (which
/// `diff_findings` ignores).
fn gf(rule: &str, sev: Severity, reason: &str) -> Finding {
    Finding {
        rule_id: rule.into(),
        severity: sev,
        category: Category::Rce,
        decision: Decision::Allow,
        reason: reason.into(),
        owasp: String::new(),
        atlas: String::new(),
        location: None,
        fix: String::new(),
    }
}

/// Golden table captured from the deleted Python predecessor's `aidefender scan <dir> --format json` (pre-deletion):
/// (corpus subdir, score, recommendation, findings).
fn golden_table() -> Vec<(&'static str, i64, &'static str, Vec<Finding>)> {
    vec![
        (
            "malicious/decode_exec",
            100,
            "DO_NOT_INSTALL",
            vec![
                gf("ast.exec", Severity::Critical, "exec() call detected [file: run.py]"),
                gf(
                    "yara.b64_exec",
                    Severity::Critical,
                    "YARA match: Detects base64 decode piped to execution [file: run.py]",
                ),
            ],
        ),
        (
            // The CRITICAL taint flow (credentials → network) carries the verdict.
            // `yara.sensitive_env` is intentionally filtered here: a bare env read
            // in source code is the same signal that false-flagged every official
            // server, and the real exfiltration is already caught by taint.
            // Score = 50 (taint, CRITICAL) × 1.3 (executable scripts) = 65.
            "malicious/exfil_server",
            65,
            "DO_NOT_INSTALL",
            vec![gf(
                "taint.cred_to_net",
                Severity::Critical,
                "Credential source flows to network sink [file: server.py]",
            )],
        ),
        (
            "malicious/pipe_skill",
            100,
            "DO_NOT_INSTALL",
            vec![
                gf(
                    "rce.pipe_to_shell",
                    Severity::Critical,
                    "downloads and pipes to an interpreter [file: SKILL.md]",
                ),
                gf(
                    "yara.pipe_to_shell",
                    Severity::Critical,
                    "YARA match: Detects piping download to shell interpreter [file: SKILL.md]",
                ),
            ],
        ),
        (
            // MCP tool poisoning: a hidden instruction inside a tool description.
            // Previously a FALSE NEGATIVE (the meta_mcp analyzer existed but was
            // never wired into the scan); now detected. Critical injection (50) +
            // High hidden-unicode (25) = 75 → DO_NOT_INSTALL.
            "malicious/poison_tool",
            75,
            "DO_NOT_INSTALL",
            vec![
                gf(
                    "mcp.hidden_unicode",
                    Severity::High,
                    "hidden unicode in 'get_weather' [file: tools.json]",
                ),
                gf(
                    "mcp.tool_poisoning",
                    Severity::Critical,
                    "injection text in 'get_weather' [file: tools.json]",
                ),
            ],
        ),
        ("benign/hello_skill", 0, "SAFE", vec![]),
        ("benign/util_lib", 0, "SAFE", vec![]),
        // Regression guard for the official-repo false-positive bug: a typical
        // public repo (README mentioning `.env`/`pip install`, a Dockerfile that
        // installs deps, CI reading secrets, a `*_test.go` with a fake token, a
        // `script/lint` curl|sh dev installer, a sample `schema.sql` with DROP
        // TABLE, a `.gitignore` listing `.env`) must NOT be flagged. Every one of
        // these used to fire HIGH/CRITICAL and force DO_NOT_INSTALL.
        ("benign/official_like", 0, "SAFE", vec![]),
    ]
}

/// Comprehensive gate: every corpus dir's Rust CLI output must match the golden.
#[test]
fn e2e_corpus_parity() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut tested = 0usize;

    for (rel, score, rec, findings) in golden_table() {
        let dir = std::path::Path::new(manifest)
            .join("tests/corpus_scan")
            .join(rel);
        if !dir.is_dir() {
            continue;
        }
        let rs = run_rust_cli(dir.to_str().unwrap());

        assert_eq!(
            rs.score, score,
            "score mismatch for {rel}  rust={} golden={score}",
            rs.score
        );
        assert_eq!(
            rs.recommendation, rec,
            "recommendation mismatch for {rel}  rust={} golden={rec}",
            rs.recommendation
        );

        let diffs = diff_findings(&rs.findings, &findings);
        assert!(
            diffs.is_empty(),
            "finding diffs for {rel}:\n{}",
            diffs.join("\n")
        );

        tested += 1;
    }

    assert!(tested >= 2, "expected at least 2 corpus dirs, got {tested}");
}

/// Binary exits 1 when score > 50.
#[test]
fn cli_exit_code_on_high_score() {
    let manifest = env!("CARGO_MANIFEST_DIR");

    // malicious/decode_exec has score=100 → exit 1
    let malicious = std::path::Path::new(manifest).join("tests/corpus_scan/malicious/decode_exec");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_scanner"))
        .args(["scan", malicious.to_str().unwrap(), "--format", "json"])
        .current_dir(manifest)
        .status()
        .expect("failed to spawn scanner binary");

    assert_eq!(
        status.code(),
        Some(1),
        "expected exit 1 for high-score target, got {:?}",
        status.code()
    );

    // benign/util_lib has score=0 → exit 0
    let benign = std::path::Path::new(manifest).join("tests/corpus_scan/benign/util_lib");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_scanner"))
        .args(["scan", benign.to_str().unwrap(), "--format", "json"])
        .current_dir(manifest)
        .status()
        .expect("failed to spawn scanner binary");

    assert_eq!(
        status.code(),
        Some(0),
        "expected exit 0 for benign target, got {:?}",
        status.code()
    );
}
