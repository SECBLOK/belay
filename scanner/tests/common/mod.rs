use scanner::types::{Finding, ScanResult};
use std::process::Command;

// NOTE: the former `run_python_oracle` helper (which shelled out to
// `.venv/bin/python -m aidefender.cli.main scan ...`) was removed as part of the
// Python-package deletion. The corpus parity tests now compare the Rust scanner
// against committed golden finding sets captured from that oracle pre-deletion
// (see `patterns.rs` / `ast_taint.rs`).

/// Shell out to the compiled Rust scanner binary and parse its JSON output.
///
/// Uses `env!("CARGO_BIN_EXE_scanner")` so cargo test always uses the
/// freshly-built binary for the current test run.
#[allow(dead_code)]
pub fn run_rust_cli(target: &str) -> ScanResult {
    let output = Command::new(env!("CARGO_BIN_EXE_scanner"))
        .args(["scan", target, "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to spawn scanner binary");

    // Parse raw JSON — same shape as Python oracle.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let raw: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!(
            "scanner CLI JSON parse failed for {target}: {e}\nstatus={}\nstdout={stdout}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));

    let score = raw["score"].as_i64().unwrap_or(0);
    let severity = raw["severity"].as_str().unwrap_or("LOW").to_string();
    let recommendation = raw["recommendation"].as_str().unwrap_or("SAFE").to_string();

    let findings: Vec<Finding> = raw["findings"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|f| {
            let sev_str = f["severity"].as_str().unwrap_or("info");
            let severity = match sev_str.to_uppercase().as_str() {
                "CRITICAL" => scanner::types::Severity::Critical,
                "HIGH" => scanner::types::Severity::High,
                "MEDIUM" => scanner::types::Severity::Medium,
                "LOW" => scanner::types::Severity::Low,
                _ => scanner::types::Severity::Info,
            };
            Finding {
                rule_id: f["rule_id"].as_str().unwrap_or("unknown").to_string(),
                severity,
                category: scanner::types::Category::Rce,
                decision: scanner::types::Decision::Allow,
                reason: f["reason"].as_str().unwrap_or("").to_string(),
                owasp: String::new(),
                atlas: String::new(),
                location: None,
                fix: String::new(),
            }
        })
        .collect();

    ScanResult {
        score,
        severity,
        recommendation,
        findings,
        sarif: serde_json::json!({}),
        source_type: "dir".into(),
    }
}

/// Compute human-readable mismatches between Rust and Python finding sets,
/// keyed on `(rule_id, severity, reason)`.
///
/// Returns a `Vec<String>` where each entry describes one discrepancy.
/// An empty vec means the two sets are identical on those three fields.
#[allow(dead_code)]
pub fn diff_findings(rust: &[Finding], py: &[Finding]) -> Vec<String> {
    use std::collections::HashSet;

    let key = |f: &Finding| -> (String, String, String) {
        (
            f.rule_id.clone(),
            f.severity.py_name().to_string(),
            f.reason.clone(),
        )
    };

    let rust_keys: HashSet<_> = rust.iter().map(key).collect();
    let py_keys: HashSet<_> = py.iter().map(key).collect();

    let mut diffs = Vec::new();

    for k in rust_keys.difference(&py_keys) {
        diffs.push(format!(
            "RUST_ONLY   rule={} sev={} reason={:?}",
            k.0, k.1, k.2
        ));
    }
    for k in py_keys.difference(&rust_keys) {
        diffs.push(format!(
            "PYTHON_ONLY rule={} sev={} reason={:?}",
            k.0, k.1, k.2
        ));
    }

    diffs.sort();
    diffs
}
