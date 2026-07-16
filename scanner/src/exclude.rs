//! Shared path-exclude glob matching for `belay scan --exclude`.
//!
//! Used by the byte-level malware pass (`analyzers::malware::scan_malware_pass`)
//! and by `run_scan` / `pipeline::run_scan(_with_llm)` (which filter the
//! `FileCache` before the text analyzers run). This is the principled AV
//! pattern: let the operator exclude known-good paths (e.g. the scanner's own
//! signature database) from being scanned as content. It is deliberately NOT
//! an extension-based skip — excluding a file type globally (e.g. every
//! `.yar`) is a signature-evasion hole, since an attacker can simply rename
//! `malware.bin` to `payload.yar` and it would never be scanned. `--exclude`
//! only hides paths the operator explicitly names.
//!
//! Patterns are matched against the path relative to the scan root, using
//! forward slashes (mirrors how `Finding::location.file` paths are keyed
//! throughout the scanner, and how `context::build_context`'s `FileCache` keys
//! its entries).

use std::collections::BTreeMap;

use globset::{Glob, GlobSet, GlobSetBuilder};

/// Compile `patterns` (each a glob like `"rules/malware/**"` or an exact
/// relative path like `"scanner/src/analyzers/malware.rs"`) into a `GlobSet`.
///
/// Returns `None` when `patterns` is empty or none of them compile to a valid
/// glob — callers treat `None` as "nothing excluded". Invalid individual
/// patterns are skipped rather than erroring out (fail-soft, consistent with
/// the rest of the scan pipeline, which never aborts a scan over bad input).
pub fn build_globset(patterns: &[String]) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut any = false;
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
            any = true;
        }
    }
    if !any {
        return None;
    }
    builder.build().ok()
}

/// Drop every entry of `file_cache` whose (forward-slash, root-relative) key
/// matches one of `excludes`. No-op when `excludes` is empty or compiles to
/// no valid pattern.
///
/// Shared by `lib.rs::run_scan` and `pipeline::run_scan`/`run_scan_with_llm`
/// so the text analyzers (patterns/ast/taint/yara/meta_mcp), which all read
/// from `FileCache`, honor the same `--exclude` list as the byte-level
/// malware pass.
pub fn filter_file_cache(file_cache: &mut BTreeMap<String, String>, excludes: &[String]) {
    if excludes.is_empty() {
        return;
    }
    if let Some(globset) = build_globset(excludes) {
        file_cache.retain(|rel_path, _| !globset.is_match(rel_path.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_patterns_yield_no_globset() {
        assert!(build_globset(&[]).is_none());
    }

    #[test]
    fn matches_glob_pattern() {
        let gs = build_globset(&["rules/malware/**".to_owned()]).unwrap();
        assert!(gs.is_match("rules/malware/belay-baseline.yar"));
        assert!(!gs.is_match("scanner/src/lib.rs"));
    }

    #[test]
    fn matches_exact_path_pattern() {
        let gs = build_globset(&["scanner/src/analyzers/malware.rs".to_owned()]).unwrap();
        assert!(gs.is_match("scanner/src/analyzers/malware.rs"));
        assert!(!gs.is_match("scanner/src/analyzers/other.rs"));
    }

    /// An unparseable glob (unterminated character class) must not poison the
    /// whole exclude list — the other, valid pattern still applies.
    #[test]
    fn invalid_pattern_is_skipped_not_fatal() {
        let gs = build_globset(&["[".to_owned(), "ok/**".to_owned()]).unwrap();
        assert!(gs.is_match("ok/thing.txt"));
    }

    #[test]
    fn filter_file_cache_drops_matching_and_keeps_rest() {
        let mut cache: BTreeMap<String, String> = BTreeMap::new();
        cache.insert("rules/malware/belay-baseline.yar".to_owned(), "x".into());
        cache.insert("scanner/src/lib.rs".to_owned(), "y".into());

        filter_file_cache(&mut cache, &["rules/malware/**".to_owned()]);

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("scanner/src/lib.rs"));
    }

    #[test]
    fn filter_file_cache_is_noop_with_no_excludes() {
        let mut cache: BTreeMap<String, String> = BTreeMap::new();
        cache.insert("a.rs".to_owned(), "x".into());
        filter_file_cache(&mut cache, &[]);
        assert_eq!(cache.len(), 1);
    }
}
