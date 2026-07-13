//! Cross-language tamper-evidence parity for the evidence pack (Phase 13 Task 3).
//!
//! Originally verified byte-parity of the Rust `to_py_json` serialiser against
//! the live Python `json.dump(..., indent=2)` (`ensure_ascii=True`) and that
//! packs built in one language verify in the other. The Python package has been
//! DELETED (Phase 13 cutover), so the cross-language checks are now committed
//! GOLDEN BYTES captured from Python pre-deletion, plus Rust self-consistency
//! (build → verify) round-trips that keep tamper-evidence proven without Python.

use belay_manage::evidence::{build_pack, to_py_json, verify_pack, FINDINGS, MANIFEST, SARIF};
use serde_json::json;
use std::path::Path;

/// A fixed findings array that includes a non-ASCII reason (BMP + astral) so
/// the ensure_ascii path is exercised by the golden byte test.
fn fixture_findings() -> serde_json::Value {
    json!([
        {
            "ts": "2026-06-26T00:00:00Z",
            "event": "PostToolUse",
            "session": "s1",
            "tool": "Bash",
            "verdict": "deny",
            "reason": "café 日本 \u{1F600}",
            "rules": ["rce.curl_pipe_sh"]
        },
        {
            "ts": "2026-06-26T00:00:01Z",
            "event": "PreToolUse",
            "session": "s2",
            "tool": "Write",
            "verdict": "allow",
            "reason": "ok",
            "rules": []
        }
    ])
}

fn sarif_literal() -> serde_json::Value {
    json!({"version": "2.1.0", "runs": []})
}

// ─── Golden bytes captured from the live Python pack builder (pre-deletion) ───
// the deleted Python predecessor's `evidence.pack.build_pack` over `fixture_findings()` + `sarif_literal()`:
//   findings.json  → `json.dump(findings, indent=2)` (ensure_ascii=True)
//   report.sarif   → `json.dump(sarif, indent=2)`
//   manifest.json  → {"findings.json": sha256, "report.sarif": sha256}

/// Exact `findings.json` bytes Python wrote for `fixture_findings()`.
const GOLDEN_FINDINGS_JSON: &str = "[\n  {\n    \"ts\": \"2026-06-26T00:00:00Z\",\n    \"event\": \"PostToolUse\",\n    \"session\": \"s1\",\n    \"tool\": \"Bash\",\n    \"verdict\": \"deny\",\n    \"reason\": \"caf\\u00e9 \\u65e5\\u672c \\ud83d\\ude00\",\n    \"rules\": [\n      \"rce.curl_pipe_sh\"\n    ]\n  },\n  {\n    \"ts\": \"2026-06-26T00:00:01Z\",\n    \"event\": \"PreToolUse\",\n    \"session\": \"s2\",\n    \"tool\": \"Write\",\n    \"verdict\": \"allow\",\n    \"reason\": \"ok\",\n    \"rules\": []\n  }\n]";

/// Exact `report.sarif` bytes Python wrote for `sarif_literal()`.
const GOLDEN_SARIF: &str = "{\n  \"version\": \"2.1.0\",\n  \"runs\": []\n}";

/// SHA-256 of the golden findings.json (from Python's manifest.json).
const GOLDEN_FINDINGS_SHA: &str =
    "3eee7682231d485c52343eaa9cb46285cc826a3417b91ebcbd6d47410079b4a5";
/// SHA-256 of the golden report.sarif (from Python's manifest.json).
const GOLDEN_SARIF_SHA: &str = "6cfbf5d10b913ee48195f32cd01b3a712c695e8aac70fc090f5ba61ed311197b";

// ─────────────────────────────────────────────────────────────────────────
// ALWAYS-RUN: ensure_ascii golden against a known-good escaped literal.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ensure_ascii_golden_literal() {
    // Python: json.dumps([{"reason": "café 日本 😀"}], indent=2) →
    //   [\n  {\n    "reason": "café 日本 😀"\n  }\n]
    let v = json!([{"reason": "café 日本 \u{1F600}"}]);
    let got = to_py_json(&v);
    let expected = "[\n  {\n    \"reason\": \"caf\\u00e9 \\u65e5\\u672c \\ud83d\\ude00\"\n  }\n]";
    assert_eq!(got, expected);
    assert!(got.is_ascii(), "ensure_ascii output must be pure ASCII");
}

// ─────────────────────────────────────────────────────────────────────────
// ALWAYS-RUN: Rust self round-trip build → verify (post-deletion DoD invariant).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn rust_self_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("pack");
    let p = build_pack(out.to_str().unwrap(), &fixture_findings(), &sarif_literal()).unwrap();
    assert!(verify_pack(&p));
}

#[test]
fn tamper_breaks_rust_verify() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("pack");
    let p = build_pack(out.to_str().unwrap(), &fixture_findings(), &sarif_literal()).unwrap();
    let fp = Path::new(&p).join(FINDINGS);
    let mut c = std::fs::read(&fp).unwrap();
    c.push(b'!');
    std::fs::write(&fp, c).unwrap();
    assert!(!verify_pack(&p));
}

#[test]
fn missing_files_break_rust_verify() {
    // Missing findings.json → false.
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("p1");
    let p = build_pack(out.to_str().unwrap(), &fixture_findings(), &sarif_literal()).unwrap();
    std::fs::remove_file(Path::new(&p).join(FINDINGS)).unwrap();
    assert!(!verify_pack(&p));

    // Missing manifest.json → false.
    let out2 = tmp.path().join("p2");
    let p2 = build_pack(
        out2.to_str().unwrap(),
        &fixture_findings(),
        &sarif_literal(),
    )
    .unwrap();
    std::fs::remove_file(Path::new(&p2).join(MANIFEST)).unwrap();
    assert!(!verify_pack(&p2));
}

// ─────────────────────────────────────────────────────────────────────────
// CROSS-LANGUAGE byte-parity, now asserted against committed Python goldens.
// ─────────────────────────────────────────────────────────────────────────

/// Rust `to_py_json` of the fixture findings + sarif must be byte-identical to
/// the bytes Python's `json.dump(..., indent=2)` produced (captured pre-deletion).
#[test]
fn golden_byte_parity_with_python() {
    assert_eq!(
        to_py_json(&fixture_findings()),
        GOLDEN_FINDINGS_JSON,
        "findings.json bytes differ from Python golden"
    );
    assert_eq!(
        to_py_json(&sarif_literal()),
        GOLDEN_SARIF,
        "report.sarif bytes differ from Python golden"
    );
}

/// A Rust-built pack must be byte-identical to the Python-built pack: same
/// findings.json / report.sarif bytes AND the same SHA-256 manifest hashes that
/// Python recorded. Because the bytes match, a Python-built pack and a
/// Rust-built pack are interchangeable, and each verifies under the other's
/// `verify_pack` — proven here via the committed golden hashes + Rust verify.
#[test]
fn rust_pack_matches_python_golden_bytes() {
    use sha2::{Digest, Sha256};

    let tmp = tempfile::tempdir().unwrap();
    let pack = tmp.path().join("rustpack");
    let p = build_pack(
        pack.to_str().unwrap(),
        &fixture_findings(),
        &sarif_literal(),
    )
    .unwrap();

    let findings_bytes = std::fs::read(Path::new(&p).join(FINDINGS)).unwrap();
    let sarif_bytes = std::fs::read(Path::new(&p).join(SARIF)).unwrap();

    // Byte-identical to the Python-built files.
    assert_eq!(
        findings_bytes,
        GOLDEN_FINDINGS_JSON.as_bytes(),
        "Rust findings.json bytes differ from Python golden"
    );
    assert_eq!(
        sarif_bytes,
        GOLDEN_SARIF.as_bytes(),
        "Rust report.sarif bytes differ from Python golden"
    );

    // SHA-256 over the raw bytes must equal the hashes Python recorded in its
    // manifest — so the manifests (and thus cross-language verify) agree.
    let hex = |b: &[u8]| {
        let mut h = Sha256::new();
        h.update(b);
        h.finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(&findings_bytes),
        GOLDEN_FINDINGS_SHA,
        "findings.json sha mismatch"
    );
    assert_eq!(
        hex(&sarif_bytes),
        GOLDEN_SARIF_SHA,
        "report.sarif sha mismatch"
    );

    // And the Rust-built pack verifies in Rust (build → verify round-trip).
    assert!(verify_pack(&p), "Rust verify of Rust-built pack failed");

    // The committed manifest contents Python wrote also verify this Rust pack
    // when substituted in (same hashes → same manifest): sanity-confirm the
    // manifest the Rust builder wrote equals the golden manifest map.
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(&p).join(MANIFEST)).unwrap()).unwrap();
    assert_eq!(manifest[FINDINGS], json!(GOLDEN_FINDINGS_SHA));
    assert_eq!(manifest[SARIF], json!(GOLDEN_SARIF_SHA));
}

/// Tamper a Rust-built pack and confirm Rust `verify_pack` returns false (the
/// cross-language tamper check, now proven Rust-to-Rust without Python).
#[test]
fn tamper_breaks_verify_cross_language_invariant() {
    let tmp = tempfile::tempdir().unwrap();
    let pack = tmp.path().join("rustpack");
    let p = build_pack(
        pack.to_str().unwrap(),
        &fixture_findings(),
        &sarif_literal(),
    )
    .unwrap();
    assert!(verify_pack(&p));

    let fp = Path::new(&p).join(SARIF);
    let mut c = std::fs::read(&fp).unwrap();
    c.push(b'!');
    std::fs::write(&fp, c).unwrap();
    assert!(!verify_pack(&p), "tampered pack must fail verify");
}
