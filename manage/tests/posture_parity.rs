//! Parity test: Rust `check_posture` must produce the same output as the
//! deleted Python predecessor's `aidefender posture --home <tmp>` CLI for the
//! same synthetic home directory.
//!
//! The Python package is deleted, so the expected `[ICON] rule_id: reason` lines
//! are reconstructed from the format captured from the Python CLI (pre-deletion)
//! with the per-run tmp path substituted in. The load-bearing cross-language
//! facts — rule ids, severities, ordering, the *duplicate* ssh finding, and the
//! exact message text — are preserved verbatim from the captured golden.
//!
//! Two scenarios:
//!   1. Planted home: world-readable `~/.ssh/id_rsa`, a `~/.env` file, and a
//!      `~/.claude/x.json` containing `"host": "0.0.0.0"`.
//!   2. Clean home: none of the above → Rust finds nothing (Python printed
//!      "Posture OK: no issues found.").

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use belay_manage::posture::check_posture;
use scanner::types::Severity;

/// Plant a synthetic "dangerous" home directory.
fn plant_home(base: &Path) {
    // 1. world-readable SSH key
    let ssh_dir = base.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let key_path = ssh_dir.join("id_rsa");
    fs::write(&key_path, "FAKE PRIVATE KEY").unwrap();
    // set permissions to 0644 (world-readable)
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

    // 2. .env in home
    fs::write(base.join(".env"), "SECRET=hunter2").unwrap();

    // 3. MCP config with 0.0.0.0 binding
    let claude_dir = base.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("x.json"),
        r#"{ "host": "0.0.0.0", "port": 9999 }"#,
    )
    .unwrap();
}

/// Golden `posture` lines captured from the Python CLI for the planted home
/// (pre-deletion), with `{home}` standing in for the per-run tmp path. The
/// id_rsa key produces TWO ssh findings (exact `id_rsa` pattern + `id_*`
/// wildcard), matching Python.
fn golden_planted_lines(home: &Path) -> Vec<String> {
    let h = home.to_str().unwrap();
    vec![
        format!("[CRITICAL] posture.ssh_world_readable: SSH private key is world-readable: {h}/.ssh/id_rsa"),
        format!("[CRITICAL] posture.ssh_world_readable: SSH private key is world-readable: {h}/.ssh/id_rsa"),
        format!("[HIGH] posture.env_in_home: .env file found in home directory: {h}/.env"),
        format!("[CRITICAL] posture.mcp_bound_all_interfaces: MCP server config binds to 0.0.0.0: {h}/.claude/x.json"),
    ]
}

/// Convert a Rust finding to the `[ICON] rule_id: reason` format the Python CLI
/// prints, so we can diff against the captured golden line-by-line.
fn finding_to_line(f: &scanner::types::Finding) -> String {
    let icon = if f.severity >= Severity::Critical {
        "CRITICAL"
    } else if f.severity >= Severity::High {
        "HIGH"
    } else {
        "MEDIUM"
    };
    format!("[{}] {}: {}", icon, f.rule_id, f.reason)
}

// ─── Test 1: planted home ────────────────────────────────────────────────────

#[test]
fn posture_parity_planted_home() {
    let tmp = tempfile::tempdir().unwrap();
    plant_home(tmp.path());

    let rust_findings = check_posture(Some(tmp.path()));
    let rust_lines: Vec<String> = rust_findings.iter().map(finding_to_line).collect();
    let golden = golden_planted_lines(tmp.path());

    assert!(
        !rust_findings.is_empty(),
        "expected at least one Rust finding in planted home"
    );

    assert_eq!(
        rust_lines,
        golden,
        "Rust posture output differs from Python golden!\n\nRust:\n{}\n\nGolden:\n{}",
        rust_lines.join("\n"),
        golden.join("\n")
    );
}

// ─── Test 2: clean home ──────────────────────────────────────────────────────

#[test]
fn posture_parity_clean_home() {
    let tmp = tempfile::tempdir().unwrap();
    // No files planted → everything clean. Python printed "Posture OK: no issues
    // found."; Rust must produce zero findings.
    let rust_findings = check_posture(Some(tmp.path()));
    assert!(
        rust_findings.is_empty(),
        "expected no Rust findings in clean home, got: {:?}",
        rust_findings
    );
}

// ─── Test 3: unit-check SSH duplicate behaviour ──────────────────────────────

/// Verify that id_rsa matches BOTH the exact pattern AND the wildcard `id_*`,
/// so two findings are emitted (one per matching pattern) — matching Python.
#[test]
fn posture_ssh_id_rsa_emits_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let ssh_dir = tmp.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();
    let key_path = ssh_dir.join("id_rsa");
    fs::write(&key_path, "KEY").unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

    let findings = check_posture(Some(tmp.path()));
    let ssh_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "posture.ssh_world_readable")
        .collect();

    // id_rsa matches both "id_rsa" pattern and "id_*" pattern → 2 findings.
    assert_eq!(
        ssh_findings.len(),
        2,
        "expected 2 ssh findings for id_rsa (exact + wildcard), got: {:?}",
        ssh_findings
    );
}
