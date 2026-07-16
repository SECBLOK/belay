//! End-to-end LLM scan parity test (Phase 11 Task 5).
//!
//! Oracle: the Phase-10 Rust deterministic scan (`pipeline::run_scan`).
//!
//! DEVIATION NOTE: The plan's `scripts/dump_python_scan.py` was designed to run
//! the Python deterministic pipeline as an oracle.  That pipeline was DELETED in
//! Phase 10 Task 9 (`scan/resolve.py`, `scan/context.py`, the Python analyzers,
//! and the deterministic nodes in `scan/graph.py`).  Phase 10 already locked
//! Rust↔Python parity on the deterministic finding fields (analyzers + score +
//! sarif, byte-verified).  Therefore we use the Phase-10 Rust deterministic scan
//! itself as the oracle for Task 5.  Task 5's real job is to verify the NEW
//! LLM-integration delta: gating + recompute.

use std::collections::HashMap;
use std::sync::Arc;

use scanner::{
    context::build_context,
    default_analyzers,
    judge::FLOOR_SEVERITY,
    llm::{LlmVerdict, MockProvider},
    pipeline::{run_scan, run_scan_with_llm, FileCache},
    score::score,
    types::{Category, Decision, Finding, Severity},
};

/// Corpus directories under `scanner/tests/corpus_scan/`.
const CORPUS_DIRS: &[&str] = &[
    "tests/corpus_scan/malicious/decode_exec",
    "tests/corpus_scan/malicious/exfil_server",
    "tests/corpus_scan/malicious/pipe_skill",
    "tests/corpus_scan/malicious/poison_tool",
    "tests/corpus_scan/benign/hello_skill",
    "tests/corpus_scan/benign/util_lib",
];

// ---------------------------------------------------------------------------
// keep-all: MockProvider conf=0.5 (< 0.6 threshold) → judge keeps everything
// ---------------------------------------------------------------------------

/// For each corpus dir: run_scan_with_llm(mock_conf_0.5) == run_scan baseline.
///
/// Proves the LLM layer is transparent when no finding is dropped.
#[tokio::test]
async fn keep_all_equals_deterministic_baseline() {
    let mock05 = MockProvider {
        verdicts: HashMap::new(),
        default: LlmVerdict {
            confirmed: false,
            confidence: 0.5,
        },
    };

    for dir in CORPUS_DIRS {
        let base = run_scan(dir, default_analyzers(), &[])
            .await
            .unwrap_or_else(|e| panic!("run_scan failed for {dir}: {e}"));

        let keep = run_scan_with_llm(dir, default_analyzers(), Some(&mock05), &[])
            .await
            .unwrap_or_else(|e| panic!("run_scan_with_llm failed for {dir}: {e}"));

        assert_eq!(
            keep.findings, base.findings,
            "keep-all findings mismatch for {dir}"
        );
        assert_eq!(keep.score, base.score, "keep-all score mismatch for {dir}");
    }
}

// ---------------------------------------------------------------------------
// drop-low: MockProvider conf=0.7 (>= 0.6) → judge drops all severity < HIGH
// ---------------------------------------------------------------------------

/// For each corpus dir:
/// 1. `drop.findings` == HIGH+ findings from baseline.
/// 2. Removed set == exactly the severity-`< HIGH` findings (the gated set).
/// 3. `drop.score` is recomputed consistently over the surviving findings.
#[tokio::test]
async fn drop_low_gates_exactly_sub_high_severity() {
    let mock07 = MockProvider {
        verdicts: HashMap::new(),
        default: LlmVerdict {
            confirmed: false,
            confidence: 0.7,
        },
    };

    for dir in CORPUS_DIRS {
        let base = run_scan(dir, default_analyzers(), &[])
            .await
            .unwrap_or_else(|e| panic!("run_scan failed for {dir}: {e}"));

        let drop = run_scan_with_llm(dir, default_analyzers(), Some(&mock07), &[])
            .await
            .unwrap_or_else(|e| panic!("run_scan_with_llm failed for {dir}: {e}"));

        // --- assertion 1: surviving findings == HIGH/CRITICAL from baseline ---
        let expected_surviving: Vec<_> = base
            .findings
            .iter()
            .filter(|f| f.severity >= FLOOR_SEVERITY)
            .cloned()
            .collect();

        assert_eq!(
            drop.findings, expected_surviving,
            "drop-low survivors mismatch for {dir}"
        );

        // --- assertion 2: removed set == exactly severity-< HIGH findings ---
        let expected_removed: Vec<_> = base
            .findings
            .iter()
            .filter(|f| f.severity < FLOOR_SEVERITY)
            .cloned()
            .collect();

        let actual_removed: Vec<_> = base
            .findings
            .iter()
            .filter(|f| !drop.findings.contains(f))
            .cloned()
            .collect();

        assert_eq!(
            actual_removed, expected_removed,
            "drop-low removed-set mismatch for {dir}"
        );

        // --- assertion 3: drop.score recomputed over survivors ---
        let resolved_dir = std::path::Path::new(dir)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(dir));
        let ctx = build_context(&resolved_dir);
        let expected_score = score(&expected_surviving, ctx.has_executable_scripts).score;

        assert_eq!(
            drop.score, expected_score,
            "drop-low score mismatch for {dir}: got {} expected {}",
            drop.score, expected_score
        );
    }
}

// ---------------------------------------------------------------------------
// synthetic-medium: non-vacuous gating proof — the mock analyzer injects a
// Medium finding that is provably dropped end-to-end by meta_filter.
// ---------------------------------------------------------------------------

/// Constructs an analyzer vec = default_analyzers() + a mock that always emits
/// one `Severity::Medium` finding with rule_id "test.synthetic_medium".
fn analyzers_with_synthetic_medium() -> Vec<scanner::pipeline::Analyzer> {
    let mut analyzers = default_analyzers();
    analyzers.push(Arc::new(|_c: &FileCache| {
        vec![Finding {
            rule_id: "test.synthetic_medium".into(),
            severity: Severity::Medium,
            category: Category::Recon,
            decision: Decision::Allow,
            reason: "synthetic medium for gating test".into(),
            owasp: String::new(),
            atlas: String::new(),
            location: None,
            fix: String::new(),
        }]
    }));
    analyzers
}

/// Non-vacuous gating proof using one real corpus dir (exfil_server → CRITICAL + HIGH).
///
/// 1. baseline (`run_scan` with mock analyzer) includes the synthetic Medium finding.
/// 2. keep-all (`MockProvider conf=0.5`): all baseline findings kept (Medium is NOT dropped).
/// 3. drop-low (`MockProvider conf=0.7`): Medium is dropped; removed set is exactly
///    `["test.synthetic_medium"]` (NON-EMPTY); surviving HIGH/CRITICAL findings remain;
///    recomputed score equals score over survivors only.
///
/// This test proves the severity-gate actually fires end-to-end.
#[tokio::test]
async fn drop_low_synthetic_medium_is_actually_dropped() {
    let dir = "tests/corpus_scan/malicious/exfil_server";

    // --- baseline: includes the synthetic Medium finding ---
    let base = run_scan(dir, analyzers_with_synthetic_medium(), &[])
        .await
        .unwrap_or_else(|e| panic!("run_scan failed for {dir}: {e}"));

    // Sanity: the synthetic Medium must actually be present in the baseline.
    assert!(
        base.findings
            .iter()
            .any(|f| f.rule_id == "test.synthetic_medium"),
        "synthetic medium finding missing from baseline — mock analyzer did not fire"
    );

    // Sanity: there must also be HIGH/CRITICAL findings (so survivors are non-empty).
    assert!(
        base.findings.iter().any(|f| f.severity >= FLOOR_SEVERITY),
        "no HIGH/CRITICAL findings in {dir} — corpus may have changed"
    );

    // --- keep-all: MockProvider conf=0.5 (< 0.6) → judge keeps everything ---
    let mock05 = MockProvider {
        verdicts: HashMap::new(),
        default: LlmVerdict {
            confirmed: false,
            confidence: 0.5,
        },
    };
    let keep = run_scan_with_llm(dir, analyzers_with_synthetic_medium(), Some(&mock05), &[])
        .await
        .unwrap_or_else(|e| panic!("run_scan_with_llm (keep) failed for {dir}: {e}"));

    assert_eq!(
        keep.findings, base.findings,
        "keep-all findings mismatch for {dir} — Medium should be kept at conf=0.5"
    );
    assert_eq!(keep.score, base.score, "keep-all score mismatch for {dir}");

    // --- drop-low: MockProvider conf=0.7 (>= 0.6) → Medium is gated and dropped ---
    let mock07 = MockProvider {
        verdicts: HashMap::new(),
        default: LlmVerdict {
            confirmed: false,
            confidence: 0.7,
        },
    };
    let drop = run_scan_with_llm(dir, analyzers_with_synthetic_medium(), Some(&mock07), &[])
        .await
        .unwrap_or_else(|e| panic!("run_scan_with_llm (drop) failed for {dir}: {e}"));

    // Assertion 1: synthetic Medium finding is absent from survivors.
    assert!(
        !drop
            .findings
            .iter()
            .any(|f| f.rule_id == "test.synthetic_medium"),
        "test.synthetic_medium was NOT dropped by the severity gate — gate did not fire!"
    );

    // Assertion 2: removed set is exactly ["test.synthetic_medium"] — NON-EMPTY.
    let removed: Vec<_> = base
        .findings
        .iter()
        .filter(|f| !drop.findings.contains(f))
        .collect();

    assert_eq!(
        removed.len(),
        1,
        "expected exactly 1 removed finding; got {}: {:?}",
        removed.len(),
        removed.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    assert_eq!(
        removed[0].rule_id, "test.synthetic_medium",
        "removed finding is not the synthetic medium"
    );

    // Assertion 3: surviving findings == HIGH/CRITICAL from baseline (no Medium).
    let expected_survivors: Vec<_> = base
        .findings
        .iter()
        .filter(|f| f.severity >= FLOOR_SEVERITY)
        .cloned()
        .collect();

    assert_eq!(
        drop.findings, expected_survivors,
        "drop-low survivors mismatch for {dir}"
    );

    // Assertion 4: drop.score recomputed over survivors only (lower than base.score).
    let resolved_dir = std::path::Path::new(dir)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(dir));
    let ctx = build_context(&resolved_dir);
    let expected_score = score(&expected_survivors, ctx.has_executable_scripts).score;

    assert_eq!(
        drop.score, expected_score,
        "drop-low score mismatch for {dir}: got {} expected {}",
        drop.score, expected_score
    );

    // Assertion 5: drop.score < base.score (Medium was contributing points).
    assert!(
        drop.score < base.score,
        "drop.score ({}) should be strictly less than base.score ({}) after removing Medium",
        drop.score,
        base.score
    );
}
