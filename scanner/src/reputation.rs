//! Hash-based reputation lookup with an on-disk JSON cache.
//!
//! **Hash-only by default** — file contents are never uploaded anywhere.
//! Only the SHA-256 hex digest is transmitted (or stored).
//!
//! Cache schema (pretty JSON):
//! ```json
//! {
//!   "<sha256hex>": { "malicious": bool, "source": "vt", "vendors": u32 }
//! }
//! ```
//!
//! Network calls (VirusTotal `/api/v3/files/{hash}`) are fail-soft and are
//! **not** unit-tested here — only the cache read/write round-trip is tested.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationResult {
    pub malicious: bool,
    pub source: String,
    pub vendors: u32,
}

// ── Cache I/O (internal) ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct CacheFile(HashMap<String, ReputationResult>);

impl CacheFile {
    /// Load the cache from `path`.  Returns an empty cache on any error
    /// (fail-soft — a missing or corrupted cache is not fatal).
    fn load(path: &Path) -> Self {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Self::default(),
        };
        serde_json::from_slice(&data).unwrap_or_default()
    }

    /// Persist the cache to `path` as pretty JSON.  Errors are silently
    /// discarded (fail-soft).
    fn save(&self, path: &Path) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            // Write to a temp file in the same directory then rename for
            // atomicity, falling back to a direct write if that fails.
            let parent = path.parent().unwrap_or(Path::new("."));
            match tempfile::NamedTempFile::new_in(parent) {
                Ok(mut tmp) => {
                    use std::io::Write as _;
                    if tmp.write_all(json.as_bytes()).is_ok() {
                        let _ = tmp.persist(path);
                    }
                }
                Err(_) => {
                    let _ = std::fs::write(path, json.as_bytes());
                }
            }
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Look up `sha256_hex` in the on-disk cache at `cache_path`.
///
/// Returns `None` if the cache file does not exist, cannot be parsed, or does
/// not contain an entry for `sha256_hex`.
pub fn lookup_cached(sha256_hex: &str, cache_path: &Path) -> Option<ReputationResult> {
    let cache = CacheFile::load(cache_path);
    cache.0.get(sha256_hex).cloned()
}

/// Store a `ReputationResult` for `sha256_hex` in the on-disk cache at
/// `cache_path`.  Errors are silently discarded (fail-soft).
pub fn store_cached(sha256_hex: &str, r: &ReputationResult, cache_path: &Path) {
    let mut cache = CacheFile::load(cache_path);
    cache.0.insert(sha256_hex.to_owned(), r.clone());
    cache.save(cache_path);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trips_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("rep_cache.json");

        let sha256 = "a".repeat(64); // fake but valid-length hex string

        // Nothing in cache yet.
        assert!(lookup_cached(&sha256, &cache_path).is_none());

        // Store a verdict.
        let verdict = ReputationResult {
            malicious: true,
            source: "vt".to_owned(),
            vendors: 7,
        };
        store_cached(&sha256, &verdict, &cache_path);

        // Read it back.
        let result = lookup_cached(&sha256, &cache_path).unwrap();
        assert!(result.malicious);
        assert_eq!(result.vendors, 7);
        assert_eq!(result.source, "vt");

        // A different hash returns None.
        assert!(lookup_cached("b".repeat(64).as_str(), &cache_path).is_none());
    }
}
