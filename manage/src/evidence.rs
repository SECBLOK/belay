//! Tamper-evident evidence packs with a SHA-256 manifest (Phase 13 Task 3).
//!
//! Port of the deleted Python predecessor's `evidence/pack.py`. A pack directory holds exactly
//! four files:
//!   - `findings.json`  - JSON array of AuditRow dicts.
//!   - `report.sarif`   - literal `{"version": "2.1.0", "runs": []}`.
//!   - `sweeps.json`    - agent-surface sweep history (Task 6), an opaque
//!     `serde_json::Value` this crate does not interpret.
//!   - `manifest.json`  - `{"findings.json": <sha256hex>, "report.sarif": <sha256hex>,
//!     "sweeps.json": <sha256hex>}`.
//!
//! **Byte-parity with Python `json.dump(obj, f, indent=2)` is mandatory** because
//! the manifest hashes the RAW FILE BYTES. Any byte difference between the Rust
//! and Python serialisations breaks cross-language `verify`. To match Python we:
//!   - use 2-space indent (`serde_json::to_string_pretty`),
//!   - write with NO trailing newline (`std::fs::write`, never `writeln!`),
//!   - preserve exact key order (serde_json `preserve_order` is on),
//!   - apply an `ensure_ascii` post-pass: Python `json.dump` defaults to
//!     `ensure_ascii=True`, escaping every non-ASCII scalar to `\uXXXX`
//!     (UTF-16, surrogate pairs for astral chars). serde_json does NOT, so we
//!     post-process the pretty string ourselves.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub const MANIFEST: &str = "manifest.json";
pub const FINDINGS: &str = "findings.json";
pub const SARIF: &str = "report.sarif";
pub const SWEEPS: &str = "sweeps.json";

/// SHA-256 of a file's RAW BYTES (read in 64KiB chunks), lowercase hex.
/// Mirrors Python `_sha256_file`.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Serialise `v` to bytes byte-identical to Python `json.dump(v, f, indent=2)`
/// with the default `ensure_ascii=True`.
///
/// `serde_json::to_string_pretty` already gives 2-space indent + no trailing
/// newline + (with `preserve_order`) the same key order. The remaining gap is
/// `ensure_ascii`: we escape every non-ASCII scalar in the pretty string to
/// `\uXXXX`, using UTF-16 surrogate pairs for code points above U+FFFF —
/// exactly what CPython's encoder emits. The structural/indent characters are
/// all ASCII, so escaping every non-ASCII char in the whole serialised string
/// is safe and matches Python's per-string-value escaping.
pub fn to_py_json(v: &serde_json::Value) -> String {
    let pretty = serde_json::to_string_pretty(v).expect("serde_json pretty");
    ensure_ascii(&pretty)
}

/// Escape every non-ASCII scalar to `\uXXXX` (UTF-16, surrogate pairs for
/// astral code points), matching CPython's `ensure_ascii=True`.
fn ensure_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if (ch as u32) < 0x80 {
            out.push(ch);
        } else {
            let mut units = [0u16; 2];
            for u in ch.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    out
}

/// Write `findings` + `sarif` + `sweeps` to `out_dir` and create a SHA-256
/// manifest over all three files (the manifest excludes itself). Returns
/// `out_dir`.
///
/// `findings` is expected to be a JSON array (the output of
/// `audit_reader::to_findings`); `sarif` the literal
/// `{"version":"2.1.0","runs":[]}`; `sweeps` the agent-surface sweep history
/// (this crate takes it as an opaque `serde_json::Value` so `manage` does not
/// need a dependency on `belayd`, where the sweep types live). Mirrors Python
/// `build_pack`, extended with sweep history (Task 6).
pub fn build_pack(
    out_dir: &str,
    findings: &serde_json::Value,
    sarif: &serde_json::Value,
    sweeps: &serde_json::Value,
) -> std::io::Result<String> {
    std::fs::create_dir_all(out_dir)?;

    let dir = Path::new(out_dir);
    let findings_path = dir.join(FINDINGS);
    let sarif_path = dir.join(SARIF);
    let sweeps_path = dir.join(SWEEPS);
    let manifest_path = dir.join(MANIFEST);

    // NO trailing newline — std::fs::write writes exactly these bytes.
    std::fs::write(&findings_path, to_py_json(findings))?;
    std::fs::write(&sarif_path, to_py_json(sarif))?;
    std::fs::write(&sweeps_path, to_py_json(sweeps))?;

    // Manifest key order: findings.json, report.sarif, then sweeps.json
    // (preserve_order is on). Appending rather than inserting keeps the first
    // two entries byte-identical to a pre-sweeps manifest.
    let mut manifest = serde_json::Map::new();
    manifest.insert(
        FINDINGS.to_string(),
        serde_json::Value::String(sha256_file(&findings_path)?),
    );
    manifest.insert(
        SARIF.to_string(),
        serde_json::Value::String(sha256_file(&sarif_path)?),
    );
    manifest.insert(
        SWEEPS.to_string(),
        serde_json::Value::String(sha256_file(&sweeps_path)?),
    );
    let manifest = serde_json::Value::Object(manifest);

    std::fs::write(&manifest_path, to_py_json(&manifest))?;

    Ok(out_dir.to_string())
}

/// Recompute SHA-256 for every file listed in the manifest and compare.
/// Missing manifest → false; missing listed file → false; hash mismatch → false.
/// Does NOT re-hash the manifest and does NOT check for extra files.
/// Mirrors Python `verify_pack`.
pub fn verify_pack(pack_dir: &str) -> bool {
    let dir = Path::new(pack_dir);
    let manifest_path = dir.join(MANIFEST);
    if !manifest_path.exists() {
        return false;
    }

    let manifest: serde_json::Value = match std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => return false,
    };

    let obj = match manifest.as_object() {
        Some(o) => o,
        None => return false,
    };

    for (filename, expected) in obj {
        let expected = match expected.as_str() {
            Some(e) => e,
            None => return false,
        };
        let file_path = dir.join(filename);
        if !file_path.exists() {
            return false;
        }
        match sha256_file(&file_path) {
            Ok(h) if h == expected => {}
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ensure_ascii_escapes_bmp_and_astral() {
        // BMP chars (café 日本) → \uXXXX; astral emoji → surrogate pair.
        assert_eq!(ensure_ascii("café"), "caf\\u00e9");
        assert_eq!(ensure_ascii("日本"), "\\u65e5\\u672c");
        // U+1F600 GRINNING FACE → surrogate pair d83d de00.
        assert_eq!(ensure_ascii("\u{1F600}"), "\\ud83d\\ude00");
        // ASCII is untouched.
        assert_eq!(ensure_ascii("plain ascii {}[]:,"), "plain ascii {}[]:,");
    }

    #[test]
    fn to_py_json_sarif_literal() {
        let sarif = json!({"version": "2.1.0", "runs": []});
        // 2-space indent, version before runs, no trailing newline.
        assert_eq!(
            to_py_json(&sarif),
            "{\n  \"version\": \"2.1.0\",\n  \"runs\": []\n}"
        );
    }

    #[test]
    fn to_py_json_non_ascii_value() {
        let v = json!([{"reason": "café 日本"}]);
        let s = to_py_json(&v);
        // The non-ASCII reason must be \u-escaped; no raw multibyte bytes remain.
        assert!(s.contains("caf\\u00e9 \\u65e5\\u672c"));
        assert!(s.is_ascii(), "output must be pure ASCII");
    }

    #[test]
    fn build_then_verify_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("pack");
        let findings = json!([{"ts": "t", "reason": "café 日本", "rules": []}]);
        let sarif = json!({"version": "2.1.0", "runs": []});
        let p = build_pack(out.to_str().unwrap(), &findings, &sarif, &json!([])).unwrap();
        assert!(verify_pack(&p));
    }

    #[test]
    fn tamper_breaks_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("pack");
        let findings = json!([{"ts": "t"}]);
        let sarif = json!({"version": "2.1.0", "runs": []});
        let p = build_pack(out.to_str().unwrap(), &findings, &sarif, &json!([])).unwrap();
        // Append a byte to findings.json.
        let fp = std::path::Path::new(&p).join(FINDINGS);
        let mut content = std::fs::read(&fp).unwrap();
        content.push(b'x');
        std::fs::write(&fp, content).unwrap();
        assert!(!verify_pack(&p));
    }

    #[test]
    fn missing_findings_breaks_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("pack");
        let findings = json!([]);
        let sarif = json!({"version": "2.1.0", "runs": []});
        let p = build_pack(out.to_str().unwrap(), &findings, &sarif, &json!([])).unwrap();
        std::fs::remove_file(std::path::Path::new(&p).join(FINDINGS)).unwrap();
        assert!(!verify_pack(&p));
    }

    #[test]
    fn missing_manifest_breaks_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("pack");
        let findings = json!([]);
        let sarif = json!({"version": "2.1.0", "runs": []});
        let p = build_pack(out.to_str().unwrap(), &findings, &sarif, &json!([])).unwrap();
        std::fs::remove_file(std::path::Path::new(&p).join(MANIFEST)).unwrap();
        assert!(!verify_pack(&p));
    }
}
