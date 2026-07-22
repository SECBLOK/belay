//! Tamper-evident hash-chained NDJSON audit log.
//! hash = sha256_hex(prev_hash + canonical_json(row_without_hash)).
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};

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

/// Bytes read per backward scan step when locating the audit log's last row.
/// Sized comfortably larger than a typical audit row so the common case (a
/// healthy, uncorrupted log) resolves in a single read regardless of how
/// many prior rows the file holds; doubled on each retry (see `last_hash`)
/// only when the trailing content forces a wider look-back.
const TAIL_SCAN_CHUNK: u64 = 4096;

/// Find the `hash` of the last row in the audit log — WITHOUT reading the
/// whole file.
///
/// The audit log only ever grows, so re-reading it in full on every append
/// (the previous implementation, `std::fs::read_to_string` + a forward scan)
/// made every hook call pay O(audit-log size), growing unbounded over a
/// project's lifetime. This instead reads backward from EOF in growing
/// chunks (starting at `TAIL_SCAN_CHUNK`, doubling on each retry, capped at
/// the file's length) until it finds the last non-blank line that parses as
/// JSON — resolving in one bounded read for a healthy log, independent of
/// total file size.
///
/// Semantics are preserved byte-for-byte with the old forward scan on every
/// realistic input:
///   - a blank/whitespace-only trailing line is skipped, never treated as
///     "the last row" (same as before);
///   - a line that fails to parse as JSON (e.g. a partial/corrupted write
///     from a crash mid-`writeln!`) is skipped too, falling back to the
///     previous valid row's hash — this never panics and never fabricates a
///     hash for a broken row, so a corrupt tail can only make the *next*
///     append's `prev_hash` point at the last known-good row (detectable via
///     `verify_chain` if the corrupt row is later repaired in place), never
///     silently mint a wrong link;
///   - an empty file returns `None`, same as before.
///
/// One intentional, documented divergence: the old code used
/// `BufReader::lines()`, whose iterator silently stops at the *first* line
/// that isn't valid UTF-8 — a non-UTF-8 line anywhere in the file could hide
/// every row written after it, even fully valid ones (a latent bug in the
/// old code, not a feature worth preserving). This implementation instead
/// treats an invalid-UTF-8 line as just another corrupt line to skip over
/// (via `String::from_utf8_lossy`, which never panics), so it can only ever
/// look further *back*, never silently drop rows that come *after* garbage.
/// This cannot change behavior on any file this module itself writes (every
/// row `append()` writes is valid UTF-8 JSON); it only matters for a
/// hand-corrupted or foreign-tool-written file with binary garbage embedded
/// mid-stream.
fn last_hash(path: &str) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }

    let mut window = TAIL_SCAN_CHUNK.min(len);
    loop {
        let start = len - window;
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut buf = vec![0u8; window as usize];
        f.read_exact(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf);
        // A trailing '\n' does not itself start a new (empty) line — matches
        // `BufRead::lines()`, which never yields a phantom final "" entry for
        // content that ends with a newline.
        let mut rest: &str = text.strip_suffix('\n').unwrap_or(&text);

        loop {
            match rest.rfind('\n') {
                Some(idx) => {
                    // Bounded on both sides (a '\n' just before it, and
                    // either EOF or an already-resolved boundary just after
                    // it): a real, trustworthy line.
                    let candidate = &rest[idx + 1..];
                    let line = candidate.strip_suffix('\r').unwrap_or(candidate);
                    if !line.trim().is_empty() {
                        if let Ok(v) = serde_json::from_str::<Value>(line) {
                            return v.get("hash").and_then(|h| h.as_str()).map(String::from);
                        }
                    }
                    rest = &rest[..idx];
                }
                None => {
                    // No '\n' left in this window. `rest` is only a genuine
                    // first line if this window already reached byte 0 of
                    // the file; otherwise it may be the tail end of a longer
                    // line that starts earlier than we've read, so leave it
                    // unresolved and grow the window instead of guessing.
                    if start == 0 {
                        let line = rest.strip_suffix('\r').unwrap_or(rest);
                        if !line.trim().is_empty() {
                            if let Ok(v) = serde_json::from_str::<Value>(line) {
                                return v.get("hash").and_then(|h| h.as_str()).map(String::from);
                            }
                        }
                    }
                    break;
                }
            }
        }

        if start == 0 {
            // Scanned the whole file; no non-blank, JSON-parseable row exists.
            return None;
        }
        window = window.saturating_mul(2).min(len);
    }
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

    // --- last_hash: tail-scan correctness + edge cases -------------------

    #[test]
    fn last_hash_missing_file_is_none() {
        let p = std::env::temp_dir().join(format!("aud-lh-missing-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        assert_eq!(last_hash(p), None);
    }

    #[test]
    fn last_hash_empty_file_is_none() {
        let p = std::env::temp_dir().join(format!("aud-lh-empty-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(p, "").unwrap();
        assert_eq!(last_hash(p), None);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_single_line_no_trailing_newline() {
        let p = std::env::temp_dir().join(format!("aud-lh-single-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(p, r#"{"event":"a","verdict":"allow","hash":"deadbeef"}"#).unwrap();
        assert_eq!(last_hash(p), Some("deadbeef".to_string()));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_single_line_with_trailing_newline() {
        let p =
            std::env::temp_dir().join(format!("aud-lh-single-nl-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(
            p,
            "{\"event\":\"a\",\"verdict\":\"allow\",\"hash\":\"deadbeef\"}\n",
        )
        .unwrap();
        assert_eq!(last_hash(p), Some("deadbeef".to_string()));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_falls_back_past_corrupt_trailing_line() {
        let p = std::env::temp_dir().join(format!("aud-lh-corrupt-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        // Two valid rows, then a line truncated mid-write (as a crash during
        // `writeln!` would leave it behind) — no closing brace, no trailing
        // newline.
        let content = "{\"event\":\"a\",\"verdict\":\"allow\",\"hash\":\"aaa1\"}\n\
                        {\"event\":\"b\",\"verdict\":\"deny\",\"hash\":\"bbb2\"}\n\
                        {\"event\":\"c\",\"verdict\":\"deny\",\"hash\":\"ccc";
        std::fs::write(p, content).unwrap();
        // Must fall back to the last COMPLETE row's hash — never panic, never
        // silently drop to None when a good row exists, never fabricate a
        // hash out of the corrupt tail.
        assert_eq!(last_hash(p), Some("bbb2".to_string()));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_wholly_corrupt_file_is_none() {
        let p =
            std::env::temp_dir().join(format!("aud-lh-allcorrupt-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        std::fs::write(p, "not json at all\nstill not json\n").unwrap();
        assert_eq!(last_hash(p), None);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_matches_full_scan_on_large_file() {
        // Oracle: the ORIGINAL full-file-read implementation this module used
        // to ship, kept here only as a correctness reference for the new
        // tail-scan `last_hash`. Any divergence here means the chain-hash
        // semantics changed — which must never happen.
        fn reference_last_hash_full_scan(path: &str) -> Option<String> {
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

        let p = std::env::temp_dir().join(format!("aud-lh-large-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let mut w = AuditWriter::open(p).unwrap();
            for i in 0..12_000 {
                w.append(json!({"event": "hook/pretooluse", "i": i, "verdict": "allow"}))
                    .unwrap();
            }
        }

        let expected = reference_last_hash_full_scan(p);
        assert!(expected.is_some(), "fixture must have a parseable last row");

        let t0 = std::time::Instant::now();
        let got = last_hash(p);
        let elapsed = t0.elapsed();

        assert_eq!(
            got, expected,
            "tail-scan last_hash must match a full forward scan byte-for-byte"
        );
        // Regression tripwire, not a microbenchmark: a single tail scan over
        // a 12k-row (several-hundred-KB) log should read only a few KB from
        // the end. 50ms leaves generous margin for a loaded CI box while
        // still catching an accidental reversion to an O(file size) scan.
        assert!(
            elapsed.as_millis() < 50,
            "last_hash on a 12k-row log took {elapsed:?}, expected well under 50ms"
        );

        std::fs::remove_file(p).ok();
    }

    #[test]
    fn audit_append_latency_stays_bounded_with_large_log() {
        // Latency guard (roadmap item ③): the decision+audit-append path
        // (`AuditWriter::open`, which calls `last_hash`, followed by one
        // `append`) must stay fast even against a large pre-existing audit
        // log — this is the property that stops a growing audit log from
        // ever eating into the calling framework's hook deadline (Claude
        // Code's PreToolUse hook timeout defaults to 600,000ms; this bound
        // is a much tighter self-imposed regression tripwire, not that
        // ceiling). 50ms is chosen with wide margin so CI noise can't flake
        // it, while still being far below what the OLD O(audit-log-size)
        // full-file-read implementation would take at this row count.
        let p =
            std::env::temp_dir().join(format!("aud-lh-latency-{}.ndjson", std::process::id()));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let mut w = AuditWriter::open(p).unwrap();
            for i in 0..15_000 {
                w.append(json!({"event": "hook/pretooluse", "i": i, "verdict": "allow"}))
                    .unwrap();
            }
        }

        let t0 = std::time::Instant::now();
        let mut w = AuditWriter::open(p).unwrap();
        w.append(json!({"event": "hook/pretooluse", "i": 15_000, "verdict": "deny"}))
            .unwrap();
        let elapsed = t0.elapsed();

        assert!(
            elapsed.as_millis() < 50,
            "AuditWriter::open+append against a 15k-row log took {elapsed:?}, \
             expected well under 50ms (audit-log size must not grow this cost)"
        );

        std::fs::remove_file(p).ok();
    }

    // --- last_hash: chunk-doubling regression coverage --------------------
    //
    // Every test above this point resolves in `last_hash`'s FIRST read: the
    // last row always sits inside the initial `TAIL_SCAN_CHUNK` (4096-byte)
    // window, so the `window = window.saturating_mul(2).min(len)` retry loop
    // never actually executes more than once end-to-end. That loop is the
    // load-bearing part of this whole change — it's what lets `last_hash`
    // stay correct on a corrupt/oversized tail instead of just being fast on
    // the happy path. These tests force it to run, repeatedly in one case,
    // and pin its output against a reference oracle.

    /// Reference oracle mirroring the OLD full-file forward-scan `last_hash`
    /// this module used to ship (see `reference_last_hash_full_scan` above
    /// for the same oracle used by the large-file happy-path test). Used by
    /// the chunk-doubling tests below to assert byte-for-byte parity with
    /// the new tail-scan implementation on inputs that force backward
    /// window growth.
    fn reference_last_hash(path: &str) -> Option<String> {
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

    #[test]
    fn last_hash_multi_doubling_past_corrupt_raw_tail() {
        // ~50 valid rows, then a raw (non-`AuditWriter`, bypassing the hash
        // chain entirely) append of newline-free, non-JSON garbage several
        // multiples of TAIL_SCAN_CHUNK long. The very first backward window
        // (and several after it) lands entirely inside the garbage with no
        // '\n' in sight, forcing `window` to double past 4096 more than once
        // before it ever reaches the boundary separating garbage from the
        // last real row.
        let p = std::env::temp_dir().join(format!(
            "aud-lh-doubling-corrupt-{}.ndjson",
            std::process::id()
        ));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let mut w = AuditWriter::open(p).unwrap();
            for i in 0..50 {
                w.append(json!({"event": "hook/pretooluse", "i": i, "verdict": "allow"}))
                    .unwrap();
            }
        }

        // Raw-append, bypassing AuditWriter entirely: no newline, not JSON.
        let garbage_len = (TAIL_SCAN_CHUNK as usize) * 5; // ~20KB, several chunks
        let garbage: Vec<u8> = vec![b'X'; garbage_len];
        {
            let mut f = OpenOptions::new().append(true).open(p).unwrap();
            f.write_all(&garbage).unwrap();
        }

        let expected = reference_last_hash(p);
        assert!(
            expected.is_some(),
            "fixture must still have a parseable last row after the corrupt raw append"
        );
        assert_eq!(
            last_hash(p),
            expected,
            "last_hash must skip the multi-chunk corrupt raw tail and return the last \
             valid row's hash, matching a full forward scan"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_resolves_legitimate_row_larger_than_one_chunk() {
        // A perfectly legitimate last row (written normally via
        // `AuditWriter`, not corrupted) whose JSON alone exceeds one
        // TAIL_SCAN_CHUNK — e.g. a big `explain`/reason payload. This is the
        // "healthy log, just a big row" case: `last_hash` must still grow
        // its window to resolve it correctly, not just in the corrupt-tail
        // case.
        let p = std::env::temp_dir().join(format!(
            "aud-lh-doubling-bigrow-{}.ndjson",
            std::process::id()
        ));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let mut w = AuditWriter::open(p).unwrap();
            for i in 0..10 {
                w.append(json!({"event": "hook/pretooluse", "i": i, "verdict": "allow"}))
                    .unwrap();
            }
            let big_explain = "x".repeat((TAIL_SCAN_CHUNK as usize) + 2000);
            w.append(
                json!({"event": "hook/pretooluse", "verdict": "deny", "explain": big_explain}),
            )
            .unwrap();
        }

        let expected = reference_last_hash(p);
        assert!(expected.is_some(), "fixture must have a parseable last row");
        assert_eq!(
            last_hash(p),
            expected,
            "last_hash must resolve a legitimate oversized last row via window growth"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_skips_multiple_trailing_blank_lines() {
        let p = std::env::temp_dir().join(format!(
            "aud-lh-doubling-blanks-{}.ndjson",
            std::process::id()
        ));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let mut w = AuditWriter::open(p).unwrap();
            for i in 0..5 {
                w.append(json!({"event": "hook/pretooluse", "i": i, "verdict": "allow"}))
                    .unwrap();
            }
        }
        // Several trailing blank / whitespace-only lines after the last
        // valid row (blank, spaces-only, tab-only, mixed, blank again).
        {
            let mut f = OpenOptions::new().append(true).open(p).unwrap();
            f.write_all(b"\n   \n\t\n \t \n\n").unwrap();
        }

        let expected = reference_last_hash(p);
        assert!(expected.is_some(), "fixture must have a parseable last row");
        assert_eq!(
            last_hash(p),
            expected,
            "last_hash must skip multiple trailing blank/whitespace-only lines"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_returns_newest_row_past_non_utf8_mid_file_line() {
        // valid row A, then a raw line that is not valid UTF-8 at all
        // (never written by this module, but could appear in a
        // hand-corrupted or foreign-tool-appended file), then valid row B.
        let p = std::env::temp_dir().join(format!(
            "aud-lh-doubling-nonutf8-{}.ndjson",
            std::process::id()
        ));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"{\"event\":\"a\",\"verdict\":\"allow\",\"hash\":\"aaa1\"}");
        bytes.push(b'\n');
        bytes.extend_from_slice(&[0xFF, 0xFE, 0x80, 0x81]); // never valid UTF-8
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"event\":\"b\",\"verdict\":\"deny\",\"hash\":\"bbb2\"}");
        bytes.push(b'\n');
        std::fs::write(p, &bytes).unwrap();

        // Sanity check pinning the OLD algorithm's documented blind spot
        // (see the doc comment on `last_hash` above): `BufReader::lines()`,
        // driven through `.map_while(Result::ok)`, returns an Err on the
        // non-UTF-8 line and PERMANENTLY STOPS right there — so the old
        // full-scan reference silently returns row A's hash and never even
        // sees row B, despite B being perfectly valid.
        assert_eq!(
            reference_last_hash(p),
            Some("aaa1".to_string()),
            "sanity check: the OLD forward-scan algorithm stops at the non-UTF-8 line"
        );

        // The new tail-scan `last_hash` reads backward from EOF and finds
        // row B directly — it never needs to look past the non-UTF-8 line
        // at all. Strictly safer than the old behavior; this divergence can
        // only ever be observed on a hand-corrupted or foreign-tool-written
        // file, since nothing this module writes is ever non-UTF-8.
        assert_eq!(
            last_hash(p),
            Some("bbb2".to_string()),
            "last_hash must see the newest valid row even past a non-UTF-8 mid-file line"
        );

        std::fs::remove_file(p).ok();
    }

    #[test]
    fn last_hash_giant_single_line_no_newlines_terminates_fast() {
        // ~2MB, single line, no '\n' anywhere, not JSON. Every backward
        // window from 4096 up through the full file length finds no
        // newline at all, so this exercises doubling all the way out to
        // `start == 0` with zero resolution along the way — the true worst
        // case for the retry loop. Must still terminate quickly and return
        // `None`, never panic or hang.
        let p = std::env::temp_dir().join(format!(
            "aud-lh-doubling-giant-{}.ndjson",
            std::process::id()
        ));
        let p = p.to_str().unwrap();
        let _ = std::fs::remove_file(p);

        let garbage: Vec<u8> = vec![b'X'; 2_000_000];
        std::fs::write(p, &garbage).unwrap();

        let t0 = std::time::Instant::now();
        let got = last_hash(p);
        let elapsed = t0.elapsed();

        assert_eq!(got, None);
        assert!(
            elapsed.as_millis() < 1000,
            "last_hash on a 2MB single-line non-JSON file took {elapsed:?}, expected well \
             under 1s (no hang on the all-the-way-to-start==0 doubling path)"
        );

        std::fs::remove_file(p).ok();
    }
}
