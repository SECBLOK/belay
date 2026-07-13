//! Tamper-evident hash-chained NDJSON audit log.
//! hash = sha256_hex(prev_hash + canonical_json(row_without_hash)).
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Canonical JSON: object keys sorted recursively, no insignificant whitespace.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

fn strip_hash(v: &Value) -> Value {
    let mut map: Map<String, Value> = v.as_object().cloned().unwrap_or_default();
    map.remove("hash");
    Value::Object(map)
}

pub fn row_hash(prev_hash: &str, row_without_hash: &Value) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(canonical_json(row_without_hash).as_bytes());
    format!("{:x}", h.finalize())
}

pub struct AuditWriter {
    file: File,
    prev_hash: String,
    path: String,
}

impl AuditWriter {
    /// Open (or create) the audit log and resume its hash chain.
    ///
    /// Integrity model: each row's `hash` chains over the prior `hash`, so any
    /// in-place edit of a past row is detectable (see `tamper_is_detected`). The
    /// genesis row starts from an empty `prev_hash`, which is NOT externally
    /// anchored — an attacker who can rewrite the *entire* file (truncation or
    /// full rollback) can forge a self-consistent chain. This is the inherent
    /// limit of any unanchored hash chain. Where rollback-resistance matters,
    /// anchor the latest hash off-host via the append-only `push` path
    /// (`belay push` ships rows to a remote ingest endpoint).
    pub fn open(path: &str) -> io::Result<AuditWriter> {
        let prev_hash = last_hash(path).unwrap_or_default();
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditWriter {
            file,
            prev_hash,
            path: path.to_string(),
        })
    }

    pub fn append(&mut self, mut row: Value) -> io::Result<()> {
        let obj = row
            .as_object_mut()
            .expect("audit row must be a JSON object");
        obj.insert("prev_hash".into(), Value::String(self.prev_hash.clone()));
        let body = strip_hash(&row);
        let hash = row_hash(&self.prev_hash, &body);
        row.as_object_mut()
            .unwrap()
            .insert("hash".into(), Value::String(hash.clone()));
        writeln!(self.file, "{}", row)?;
        self.file.flush()?;
        self.prev_hash = hash;
        let _ = &self.path;
        Ok(())
    }
}

fn last_hash(path: &str) -> Option<String> {
    let f = File::open(path).ok()?;
    let mut last = None;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            last = v.get("hash").and_then(|h| h.as_str()).map(String::from);
        }
    }
    last
}

/// Read the last `n` audit rows, oldest-first.
///
/// Mirrors Python `SessionStore.recent(n)`:
///   - missing file → empty vec
///   - else: read file, keep the LAST `n` non-blank parseable lines, preserving
///     original (oldest-first) order.
///
/// Blank/whitespace-only lines are skipped; rare un-parseable lines are skipped
/// rather than panicking.
pub fn recent(path: &str, n: usize) -> Vec<Value> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut rows: Vec<Value> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            rows.push(v);
        }
    }
    if rows.len() > n {
        let start = rows.len() - n;
        rows.drain(0..start);
    }
    rows
}

/// Walk the chain; Ok(count) if intact, Err(reason) on the first broken link.
pub fn verify_chain(path: &str) -> Result<usize, String> {
    let f = File::open(path).map_err(|e| e.to_string())?;
    let mut prev = String::new();
    let mut n = 0usize;
    for (i, line) in BufReader::new(f).lines().map_while(Result::ok).enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line).map_err(|e| format!("row {i}: {e}"))?;
        let stored = row.get("hash").and_then(|h| h.as_str()).unwrap_or("");
        let row_prev = row.get("prev_hash").and_then(|h| h.as_str()).unwrap_or("");
        if row_prev != prev {
            return Err(format!("row {i}: prev_hash mismatch"));
        }
        let expect = row_hash(&prev, &strip_hash(&row));
        if expect != stored {
            return Err(format!("row {i}: hash mismatch (tampered)"));
        }
        prev = stored.to_string();
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_is_deterministic_and_chains() {
        let r1 = json!({"event": "PreToolUse", "verdict": "deny"});
        let h1 = row_hash("", &r1);
        let h1b = row_hash("", &json!({"verdict": "deny", "event": "PreToolUse"}));
        assert_eq!(h1, h1b, "canonicalization must ignore key order");
        let r2 = json!({"event": "PreToolUse", "verdict": "allow"});
        let h2 = row_hash(&h1, &r2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn append_then_verify_ok() {
        let dir = std::env::temp_dir().join(format!("aud-{}.ndjson", std::process::id()));
        let p = dir.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let mut w = AuditWriter::open(p).unwrap();
        w.append(json!({"event": "a", "verdict": "allow"})).unwrap();
        w.append(json!({"event": "b", "verdict": "deny"})).unwrap();
        assert_eq!(verify_chain(p).unwrap(), 2);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn tamper_is_detected() {
        let p = std::env::temp_dir().join(format!("aud-tamper-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let mut w = AuditWriter::open(p).unwrap();
        w.append(json!({"event": "a", "verdict": "allow"})).unwrap();
        w.append(json!({"event": "b", "verdict": "deny"})).unwrap();
        // flip a verdict in place, leaving its stored hash stale
        let content = std::fs::read_to_string(p)
            .unwrap()
            .replace("\"deny\"", "\"allow\"");
        std::fs::write(p, content).unwrap();
        assert!(verify_chain(p).is_err());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn recent_missing_file_is_empty() {
        let p =
            std::env::temp_dir().join(format!("aud-recent-missing-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        assert_eq!(recent(p, 20), Vec::<Value>::new());
    }

    #[test]
    fn recent_fewer_than_n_returns_all_in_order() {
        let p = std::env::temp_dir().join(format!("aud-recent-few-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(p, "{\"i\":1}\n{\"i\":2}\n").unwrap();
        let rows = recent(p, 20);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["i"], json!(1));
        assert_eq!(rows[1]["i"], json!(2));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn recent_more_than_n_keeps_last_n_oldest_first() {
        let p = std::env::temp_dir().join(format!("aud-recent-many-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let mut s = String::new();
        for i in 0..10 {
            s.push_str(&format!("{{\"i\":{i}}}\n"));
        }
        std::fs::write(p, s).unwrap();
        let rows = recent(p, 3);
        assert_eq!(rows.len(), 3);
        // last 3, oldest-first: 7, 8, 9
        assert_eq!(rows[0]["i"], json!(7));
        assert_eq!(rows[1]["i"], json!(8));
        assert_eq!(rows[2]["i"], json!(9));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn recent_skips_blank_lines() {
        let p =
            std::env::temp_dir().join(format!("aud-recent-blank-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(p, "{\"i\":1}\n\n   \n{\"i\":2}\n").unwrap();
        let rows = recent(p, 20);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["i"], json!(1));
        assert_eq!(rows[1]["i"], json!(2));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn cross_language_golden_hash_nonascii() {
        // Must equal the Python store._row_hash("", {...}) for the same row — locks
        // Rust/Python canonical-JSON parity on non-ASCII content.
        let h = row_hash("", &serde_json::json!({"event":"café","verdict":"deny"}));
        assert_eq!(
            h,
            "c8aeae3c31d58ec2984b48de25f2b1abe8e8323923ff9ac535044129401118d1"
        );
    }
}
