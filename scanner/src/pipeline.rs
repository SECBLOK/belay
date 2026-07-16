//! Async tokio fan-out/fan-in scan pipeline.
//!
//! Reimplements the Python LangGraph parallel analyzer fan-out
//! (`scan/graph.py`: `context → [patterns, ast, taint, yara] → score`)
//! as concurrent `tokio::task::spawn_blocking` tasks whose `Vec<Finding>`
//! results are concatenated **in analyzer registration order**.
//!
//! Coexists with the synchronous `lib.rs::run_scan`; this entry point is
//! `scanner::pipeline::run_scan` (async).  Task 5 will reconcile the two.

use std::sync::Arc;

use anyhow::Result;

use crate::types::{Finding, ScanResult};

/// File cache type — forward-declared so `Analyzer` closures can reference it
/// without importing `BTreeMap` at every call site.
///
/// SARIF parity note: `Context.file_cache` is `BTreeMap<String, String>`.
pub type FileCache = std::collections::BTreeMap<String, String>;

/// A synchronous, CPU-bound analyzer function.
///
/// Each analyzer receives a shared reference to the `FileCache` and returns
/// its slice of `Finding`s.  Wrapped in `Arc` so callers can clone handles
/// cheaply before `spawn_blocking` moves them into worker threads.
pub type Analyzer = Arc<dyn Fn(&FileCache) -> Vec<Finding> + Send + Sync>;

// ---------------------------------------------------------------------------
// fan_out
// ---------------------------------------------------------------------------

/// Dispatch `analyzers` concurrently using `tokio::task::spawn_blocking`.
///
/// Results are concatenated **in analyzer registration order** (operator.add
/// semantics), regardless of task completion order.  A panicking analyzer
/// contributes nothing and never aborts the scan.
pub async fn fan_out(file_cache: FileCache, analyzers: Vec<Analyzer>) -> Vec<Finding> {
    // Share the file cache across tasks — cheap clone via Arc<BTreeMap>.
    let shared = Arc::new(file_cache);

    // Spawn one blocking task per analyzer, collecting `JoinHandle`s IN ORDER.
    let handles: Vec<_> = analyzers
        .into_iter()
        .map(|analyzer| {
            let cache = Arc::clone(&shared);
            tokio::task::spawn_blocking(move || analyzer(&cache))
        })
        .collect();

    // Await handles IN ORDER and append results.
    let mut findings: Vec<Finding> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(mut batch) => findings.append(&mut batch),
            Err(_join_err) => {
                // Panicking analyzer: log nothing, contribute nothing, keep going.
            }
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// run_scan  (async pipeline entry-point)
// ---------------------------------------------------------------------------

/// Async pipeline: resolve → build_context → fan_out → score → to_sarif → ScanResult.
///
/// Accepts an explicit `analyzers` list for testability and future LLM
/// augmentation.
///
/// SARIF tool version is `crate::TOOL_VERSION` ("0.1.0") — shared with lib.rs
/// to avoid duplication (Phase 11 Task 5 dedup: the duplicate `const TOOL_VERSION`
/// that was previously in this file has been removed; it is now imported from
/// `crate::TOOL_VERSION` which is `pub(crate)` in lib.rs).
///
/// `excludes`: glob patterns (relative to the resolved scan root) dropped from
/// both the `FileCache` fed to `analyzers` and the byte-level malware pass.
/// See `crate::exclude` for the matching semantics.
pub async fn run_scan(
    input_path: &str,
    analyzers: Vec<Analyzer>,
    excludes: &[String],
) -> Result<ScanResult> {
    use crate::{context, resolve, sarif, score, TOOL_VERSION};

    // resolve() determines the canonical local path and source type.
    let (path, source_type) = resolve::resolve(input_path)?;

    // build_context walks the resolved directory (returns Context, not Result).
    let mut ctx = context::build_context(&path);

    // Drop excluded paths before any analyzer sees them.
    crate::exclude::filter_file_cache(&mut ctx.file_cache, excludes);

    // Fan out analyzers concurrently; results merged in registration order.
    let mut findings = fan_out(ctx.file_cache, analyzers).await;

    // Central false-positive control (see `analyzers::fileclass` and
    // `lib.rs::run_scan`): drop devops-normal matches outside executed scripts.
    findings.retain(|f| {
        crate::analyzers::fileclass::relevant(
            &f.rule_id,
            f.location.as_ref().map(|l| l.file.as_str()),
        )
    });

    // Byte-level malware pass (raw filesystem bytes off the resolved scan
    // root; not a FileCache analyzer, see
    // `analyzers::malware::scan_malware_pass` docs). Merged in after the
    // devops-noise filter above on purpose: that filter is for benign
    // mentions of shell patterns outside runtime files, not for genuine
    // malware signatures/YARA matches.
    findings.extend(crate::analyzers::malware::scan_malware_pass(&path, excludes));

    // Score findings.
    let score_out = score::score(&findings, ctx.has_executable_scripts);

    // Emit SARIF.
    let sarif_val = sarif::to_sarif(&findings, TOOL_VERSION);

    // Serialize SourceType to its lowercase serde name (mirrors lib.rs::run_scan).
    let source_type_str = match source_type {
        resolve::SourceType::Git => "git",
        resolve::SourceType::Url => "url",
        resolve::SourceType::Zip => "zip",
        resolve::SourceType::Dir => "dir",
        resolve::SourceType::File => "file",
    };

    Ok(ScanResult {
        score: score_out.score,
        severity: score_out.severity,
        recommendation: score_out.recommendation,
        findings,
        sarif: sarif_val,
        source_type: source_type_str.into(),
    })
}

// ---------------------------------------------------------------------------
// run_scan_with_llm  (LLM-augmented pipeline entry-point)
// ---------------------------------------------------------------------------

/// Async pipeline with LLM severity gating:
/// resolve → build_context → fan_out → meta_filter → score → to_sarif → ScanResult.
///
/// The `llm` parameter is forwarded to `judge::meta_filter`:
/// - `None`        → findings returned unchanged (identical to `run_scan`).
/// - `Some(llm)`   → severity-`< HIGH` findings are individually confirmed;
///   those the LLM considers benign (confidence ≥ 0.6) are dropped.
///
/// SARIF tool version is `crate::TOOL_VERSION` ("0.1.0") for SARIF parity.
///
/// `excludes`: same glob-exclude list as `run_scan` (see `crate::exclude`).
pub async fn run_scan_with_llm(
    input_path: &str,
    analyzers: Vec<Analyzer>,
    llm: Option<&dyn crate::llm::LlmProvider>,
    excludes: &[String],
) -> Result<ScanResult> {
    use crate::{context, judge, resolve, sarif, score, TOOL_VERSION};

    // resolve() determines the canonical local path and source type.
    let (path, source_type) = resolve::resolve(input_path)?;

    // build_context walks the resolved directory (returns Context, not Result).
    let mut ctx = context::build_context(&path);

    // Drop excluded paths before any analyzer sees them. Filtered once, in
    // place, so both the fan_out feed below and the `judge::meta_filter` call
    // (which reads `ctx.file_cache` again for LLM context) see the same
    // reduced set.
    crate::exclude::filter_file_cache(&mut ctx.file_cache, excludes);

    // Fan out analyzers concurrently; results merged in registration order.
    let mut raw_findings = fan_out(ctx.file_cache.clone(), analyzers).await;

    // Central false-positive control before the LLM pass (see
    // `analyzers::fileclass`): drop devops-normal matches outside executed
    // scripts so the LLM only adjudicates plausibly-real findings.
    raw_findings.retain(|f| {
        crate::analyzers::fileclass::relevant(
            &f.rule_id,
            f.location.as_ref().map(|l| l.file.as_str()),
        )
    });

    // Byte-level malware pass (raw filesystem bytes off the resolved scan
    // root; not a FileCache analyzer, see
    // `analyzers::malware::scan_malware_pass` docs). Merged in after the
    // devops-noise filter above on purpose, same as `run_scan`: that filter
    // is for benign mentions of shell patterns outside runtime files, not
    // for genuine malware signatures/YARA matches.
    raw_findings.extend(crate::analyzers::malware::scan_malware_pass(&path, excludes));

    // LLM severity gate: keeps HIGH/CRITICAL unconditionally; sub-HIGH findings
    // are dropped when the LLM says !confirmed && confidence >= 0.6.
    let filtered = judge::meta_filter(raw_findings, &ctx.file_cache, llm).await;

    // Score findings (recomputed over the filtered set).
    let score_out = score::score(&filtered, ctx.has_executable_scripts);

    // Emit SARIF.
    let sarif_val = sarif::to_sarif(&filtered, TOOL_VERSION);

    // Serialize SourceType to its lowercase serde name.
    let source_type_str = match source_type {
        resolve::SourceType::Git => "git",
        resolve::SourceType::Url => "url",
        resolve::SourceType::Zip => "zip",
        resolve::SourceType::Dir => "dir",
        resolve::SourceType::File => "file",
    };

    Ok(ScanResult {
        score: score_out.score,
        severity: score_out.severity,
        recommendation: score_out.recommendation,
        findings: filtered,
        sarif: sarif_val,
        source_type: source_type_str.into(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Category, Decision, Severity};

    /// Minimal `Finding` constructor for tests.
    /// All fields required by the real struct are populated.
    fn finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: Severity::Info,
            category: Category::Recon,
            decision: Decision::Allow,
            reason: String::new(),
            owasp: String::new(),
            atlas: String::new(),
            location: None,
            fix: String::new(),
        }
    }

    /// Helper: wrap a vec of findings into an `Analyzer`.
    fn make_analyzer(findings: Vec<Finding>) -> Analyzer {
        Arc::new(move |_cache: &FileCache| findings.clone())
    }

    // -----------------------------------------------------------------------
    // fan_out_concatenates_in_registration_order
    // -----------------------------------------------------------------------

    /// Two mock analyzers [a1,a2] and [b1] → merged ids exactly ["a1","a2","b1"].
    ///
    /// Verifies that fan_out preserves operator.add registration order.
    #[tokio::test]
    async fn fan_out_concatenates_in_registration_order() {
        let a = make_analyzer(vec![finding("a1"), finding("a2")]);
        let b = make_analyzer(vec![finding("b1")]);

        let out = fan_out(FileCache::default(), vec![a, b]).await;

        let ids: Vec<&str> = out.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["a1", "a2", "b1"]);
    }

    // -----------------------------------------------------------------------
    // fan_out_runs_analyzers_concurrently
    // -----------------------------------------------------------------------

    /// Deadlock guard: fan_out must complete within 2 seconds and produce
    /// exactly 2 findings when given two single-finding analyzers.
    #[tokio::test]
    async fn fan_out_runs_analyzers_concurrently() {
        let a = make_analyzer(vec![finding("x1")]);
        let b = make_analyzer(vec![finding("x2")]);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fan_out(FileCache::default(), vec![a, b]),
        )
        .await;

        assert!(result.is_ok(), "fan_out timed out — possible deadlock");
        let out = result.unwrap();
        assert_eq!(out.len(), 2);
    }
}
