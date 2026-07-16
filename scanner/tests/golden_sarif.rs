//! Golden-file SARIF parity tests for Task 7.
//!
//! ## Design deviations from the original brief
//!
//! The brief originally called for a `golden_sarif_equals_python` test over
//! `malicious/decode_exec`. That corpus dir produces findings via the `ast`
//! and `yara` analyzers, which are deferred to Tasks 4/5 (those crates are too
//! heavy for the current disk). The non-empty golden test is therefore deferred
//! until after Tasks 4/5 land.
//!
//! Instead we test with `benign/util_lib`, which produces **zero findings** in
//! both Python and Rust — identical empty-findings SARIF validates the full
//! end-to-end structure faithfully.

use scanner::sarif::to_sarif;
use scanner::score::score;
use scanner::types::{Category, Decision, Finding, Severity};

fn f(rule: &str, sev: Severity) -> Finding {
    Finding {
        rule_id: rule.into(),
        severity: sev,
        category: Category::Rce,
        decision: Decision::Deny,
        reason: "x".into(),
        owasp: "ASI05".into(),
        atlas: "AML".into(),
        location: None,
        fix: String::new(),
    }
}

// ---------------------------------------------------------------------------
// score tests (from brief)
// ---------------------------------------------------------------------------

/// Two Critical findings with the same rule_id trigger diminishing returns:
/// 50 * 1.0 + 50 * 0.5 = 75 → DO_NOT_INSTALL / HIGH.
#[test]
fn score_thresholds_and_diminishing() {
    let out = score(
        &[
            f("rce.x", Severity::Critical),
            f("rce.x", Severity::Critical),
        ],
        false,
    );
    assert_eq!(out.recommendation, "DO_NOT_INSTALL");
    assert_eq!(out.score, 75);
    assert_eq!(out.severity, "HIGH");
}

/// Banker's rounding regression test.
///
/// The score point structure (Critical=50, High=25, …) makes it difficult to
/// land on an exact X.5 raw score through normal findings. We therefore test
/// the `round_half_to_even` helper directly; see the unit tests inside
/// `score.rs` for the four canonical banker's-rounding cases (12.5→12,
/// 13.5→14, 2.5→2, 3.5→4).
///
/// This integration-level test confirms the helper is callable from outside
/// the module (pub visibility) and returns the expected banker's result.
#[test]
fn bankers_rounding_regression() {
    use scanner::score::round_half_to_even;
    // Canonical banker's rounding cases — these diverge from std f64::round().
    assert_eq!(round_half_to_even(12.5), 12); // even floor wins
    assert_eq!(round_half_to_even(13.5), 14); // even ceiling wins
    assert_eq!(round_half_to_even(2.5), 2); // even floor wins
    assert_eq!(round_half_to_even(3.5), 4); // even ceiling wins
                                            // Non-half cases round normally.
    assert_eq!(round_half_to_even(3.6), 4);
    assert_eq!(round_half_to_even(3.4), 3);
}

// ---------------------------------------------------------------------------
// sarif tests (from brief)
// ---------------------------------------------------------------------------

/// Structural shape matches what the Python oracle emits.
#[test]
fn sarif_structure_matches_python() {
    let s = to_sarif(&[f("rce.pipe_to_shell", Severity::Critical)], "0.1.0");
    assert_eq!(s["version"], "2.1.0");
    assert_eq!(s["runs"][0]["results"][0]["ruleId"], "rce.pipe_to_shell");
    assert_eq!(s["runs"][0]["results"][0]["level"], "error");
    assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "belay");
    assert_eq!(s["runs"][0]["tool"]["driver"]["version"], "0.1.0");
    assert_eq!(
        s["runs"][0]["tool"]["driver"]["informationUri"],
        "https://github.com/SECBLOK/belay"
    );
}

// ---------------------------------------------------------------------------
// Golden-file test: benign/util_lib (empty findings, both Python and Rust)
// ---------------------------------------------------------------------------

/// End-to-end SARIF golden parity for `benign/util_lib`.
///
/// Both the (now-deleted) Python CLI and Rust `run_scan` produce zero findings
/// for this corpus dir, so the SARIF output is structurally identical. The
/// committed `fixtures/python_sarif_benign.json` was captured from the Python
/// scanner CLI (sarif format) over this corpus dir before the Python package was
/// removed, and is the committed parity oracle.
#[test]
fn golden_sarif_equals_benign_python() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo_root = std::path::Path::new(manifest)
        .parent()
        .expect("scanner crate must live inside the repo");
    let corpus = repo_root.join("scanner/tests/corpus_scan/benign/util_lib");

    // The committed golden fixture (captured from the Python CLI pre-deletion) is
    // the parity oracle now that the Python package is gone — no live Python.
    let golden_json = include_str!("fixtures/python_sarif_benign.json");
    let golden: serde_json::Value = serde_json::from_str(golden_json)
        .expect("fixtures/python_sarif_benign.json must be valid JSON");

    // Run the Rust scanner on the same corpus dir.
    let result = scanner::run_scan(corpus.to_str().unwrap(), &[]);
    let rust_sarif = result.sarif;

    assert_eq!(
        rust_sarif,
        golden,
        "Rust SARIF for benign/util_lib must match Python golden.\n\
         Rust:   {}\n\
         Python: {}",
        serde_json::to_string_pretty(&rust_sarif).unwrap_or_default(),
        serde_json::to_string_pretty(&golden).unwrap_or_default(),
    );
}

// ---------------------------------------------------------------------------
// Golden-file test: malicious/decode_exec (non-empty findings)
// ---------------------------------------------------------------------------

/// End-to-end SARIF golden parity for `malicious/decode_exec`.
///
/// Two findings: ast.exec (CRITICAL) and yara.b64_exec (CRITICAL).
/// The committed `fixtures/python_sarif_malicious.json` was captured from the
/// Python scanner CLI (sarif format) over this corpus dir before the Python
/// package was removed, and is the committed parity oracle.
///
/// Rule order: Rust uses fixed merge order patterns→ast→taint→yara.
/// Python LangGraph may vary. For decode_exec both emit ast.exec first,
/// yara.b64_exec second — matching. If order diverges for other corpora,
/// we compare rule/result MULTISETs (sorted) rather than asserting array order.
#[test]
fn golden_sarif_equals_malicious_python() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo_root = std::path::Path::new(manifest)
        .parent()
        .expect("scanner crate must live inside the repo");
    let corpus = repo_root.join("scanner/tests/corpus_scan/malicious/decode_exec");

    // The committed golden fixture (captured from the Python CLI pre-deletion) is
    // the parity oracle now that the Python package is gone — no live Python.
    let golden_json = include_str!("fixtures/python_sarif_malicious.json");
    let golden: serde_json::Value = serde_json::from_str(golden_json)
        .expect("fixtures/python_sarif_malicious.json must be valid JSON");

    // Run the Rust scanner on the same corpus dir.
    let result = scanner::run_scan(corpus.to_str().unwrap(), &[]);
    let rust_sarif = result.sarif;

    // Compare rule arrays as sorted multisets to handle potential order differences.
    // (Rust: fixed order patterns→ast→taint→yara; Python: LangGraph parallel merge.)
    let rust_rules = {
        let mut r: Vec<serde_json::Value> = rust_sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        r.sort_by_key(|v| v["id"].as_str().unwrap_or("").to_string());
        r
    };
    let golden_rules = {
        let mut r: Vec<serde_json::Value> = golden["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        r.sort_by_key(|v| v["id"].as_str().unwrap_or("").to_string());
        r
    };
    assert_eq!(
        rust_rules,
        golden_rules,
        "SARIF rules multiset mismatch for malicious/decode_exec.\nRust:   {}\nPython: {}",
        serde_json::to_string_pretty(&serde_json::json!(rust_rules)).unwrap_or_default(),
        serde_json::to_string_pretty(&serde_json::json!(golden_rules)).unwrap_or_default(),
    );

    // Compare results as sorted multisets too.
    let rust_results = {
        let mut r: Vec<serde_json::Value> = rust_sarif["runs"][0]["results"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        r.sort_by_key(|v| v["ruleId"].as_str().unwrap_or("").to_string());
        r
    };
    let golden_results = {
        let mut r: Vec<serde_json::Value> = golden["runs"][0]["results"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        r.sort_by_key(|v| v["ruleId"].as_str().unwrap_or("").to_string());
        r
    };
    assert_eq!(
        rust_results,
        golden_results,
        "SARIF results multiset mismatch for malicious/decode_exec.\nRust:   {}\nPython: {}",
        serde_json::to_string_pretty(&serde_json::json!(rust_results)).unwrap_or_default(),
        serde_json::to_string_pretty(&serde_json::json!(golden_results)).unwrap_or_default(),
    );
}
