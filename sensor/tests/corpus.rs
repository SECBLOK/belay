/// Parity gate: every BAD case from tests/corpus/cases.py must NOT be allowed by the Rust sensor.
///
/// The corpus is exported to sensor/tests/corpus.json by the Python build step.
/// Each entry has: tool, params (object), expected ("deny"|"ask").
/// Parity requirement: Rust must NOT return "allow" for any BAD case
/// (i.e. it must return "deny" or "ask", matching or exceeding severity).
use serde::Deserialize;
use serde_json::Value;
use std::fs;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod sensor;

#[derive(Debug, Deserialize)]
struct CorpusCase {
    tool: String,
    params: Value,
    expected: String,
}

#[test]
fn corpus_parity() {
    let corpus_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus.json");
    let raw = fs::read_to_string(corpus_path).expect("corpus.json not found");
    let cases: Vec<CorpusCase> = serde_json::from_str(&raw).expect("valid JSON corpus");

    let mut passed = 0;
    let mut failed = Vec::new();

    for case in &cases {
        let (rust_decision, _reason) = sensor::decide(&case.tool, &case.params);
        // Parity: Rust must never ALLOW something the Python engine blocks
        if rust_decision == "allow" {
            failed.push(format!(
                "FAIL: tool={} params={} expected={} rust=allow",
                case.tool, case.params, case.expected
            ));
        } else {
            passed += 1;
        }
    }

    if !failed.is_empty() {
        panic!(
            "Corpus parity failed ({}/{} passed):\n{}",
            passed,
            cases.len(),
            failed.join("\n")
        );
    }

    println!("Corpus parity: {}/{} cases passed", passed, cases.len());
}
