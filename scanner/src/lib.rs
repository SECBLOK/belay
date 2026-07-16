pub mod analyzers;
pub mod archive;
pub mod context;
pub mod exclude;
pub mod host_adapter;
pub mod judge;
pub mod llm;
// Shared with `build.rs` via `include!` (see that file and pack_build.rs's own
// doc comment) — compiled here too, but only under `#[cfg(test)]`, so
// `analyzers::malware`'s unit tests can exercise `compile_pack`'s fail-soft
// third-party-skip behavior directly without duplicating the logic. The
// runtime `get_bundled_malware_rules()` path no longer calls this at all; it
// deserializes the blob `build.rs` already compiled.
#[cfg(test)]
mod pack_build;
pub mod pipeline;
pub mod reputation;
pub mod resolve;
pub mod sarif;
pub mod score;
pub mod types;

pub use types::*;

/// The tool version passed to SARIF output.
///
/// "0.1.0" — matches the committed golden SARIF fixtures byte-for-byte (this was
/// the version emitted by the original Python scanner before it was deleted).
///
/// Promoted to `pub(crate)` so `pipeline.rs` can import it instead of
/// duplicating the constant (Phase 11 Task 5 dedup).
pub(crate) const TOOL_VERSION: &str = "0.1.0";

/// Return the real analyzers in fixed registration order: patterns, ast, taint,
/// yara, meta_mcp.
///
/// Used by `pipeline::run_scan` and `pipeline::run_scan_with_llm`.  The yara
/// analyzer receives `None` as its second (custom-rules-path) argument.
///
/// The byte-level malware pass (`analyzers::malware::scan_malware_pass`) is
/// NOT in this list: it walks the scan root directly rather than consuming a
/// `FileCache`, so it cannot be expressed as an `Analyzer` closure. See
/// `run_scan` below (and `pipeline::run_scan`) for where it is invoked.
pub fn default_analyzers() -> Vec<pipeline::Analyzer> {
    use std::sync::Arc;
    vec![
        Arc::new(|c: &pipeline::FileCache| analyzers::patterns::scan_patterns(c)),
        Arc::new(|c: &pipeline::FileCache| analyzers::ast::scan_ast(c)),
        Arc::new(|c: &pipeline::FileCache| analyzers::taint::scan_taint(c)),
        Arc::new(|c: &pipeline::FileCache| analyzers::yara::scan_yara(c, None)),
        Arc::new(|c: &pipeline::FileCache| analyzers::meta_mcp::scan_mcp_metadata(c)),
    ]
}

/// Run a scan on `target` (path/URL/git).
///
/// Pipeline:
///   resolve → build_context → scan_patterns → scan_ast → scan_taint → scan_yara → meta_mcp → scan_malware_pass → score → to_sarif → ScanResult
///
/// Analyzer merge order is fixed as: patterns, ast, taint, yara, meta_mcp, then
/// the byte-level malware pass (see below).
///
/// `excludes`: glob patterns (relative to the resolved scan root, e.g.
/// `"rules/malware/**"`) whose matching paths are dropped from both the
/// `FileCache` (so the patterns/ast/taint/yara/meta_mcp analyzers never see
/// them) and the byte-level malware pass. See `exclude::build_globset` docs
/// for why this is a path-exclude, not an extension skip.
///
/// Delegates to [`run_scan_opts`] with no user-supplied signature DB and the
/// byte-level malware pass always on — identical behaviour to before
/// `run_scan_opts` existed. Kept as a stable, unchanged entry point: parity.rs,
/// golden_sarif.rs, and `run_cli` all call this exact signature.
pub fn run_scan(target: &str, excludes: &[String]) -> ScanResult {
    run_scan_opts(target, excludes, true)
}

/// Like [`run_scan`] but with the `--no-malware` opt-out knob. Bundled-YARA only —
/// this core entry point takes no signature DB.
pub fn run_scan_opts(target: &str, excludes: &[String], run_malware: bool) -> ScanResult {
    run_scan_with_extra(target, excludes, run_malware, |_| Vec::new())
}

/// Run a scan on `target` with two knobs over [`run_scan`]:
///
/// * `run_malware` — whether to run the byte-level malware pass
///   ([`analyzers::malware::scan_malware_pass`]) at all. The pass walks the
///   scan root a second time reading raw bytes, so this is the `--no-malware`
///   opt-out's knob; it defaults to `true` everywhere else in this crate.
/// * `extra_malware` — a closure, given the resolved scan root, returning any
///   additional malware findings to merge into the pass. The public build
///   passes a no-op (`|_| Vec::new()`), so this core carries no dependency on
///   any private signature-DB reader; an opt-in build supplies hash matches.
///
/// `run_scan(target, excludes)` is `run_scan_opts(target, excludes, true)`.
pub(crate) fn run_scan_with_extra(
    target: &str,
    excludes: &[String],
    run_malware: bool,
    extra_malware: impl FnOnce(&std::path::Path) -> Vec<Finding>,
) -> ScanResult {
    // resolve() determines the canonical local path and source type.
    let (path, source_type) = match resolve::resolve(target) {
        Ok(r) => r,
        Err(_) => {
            // Fall back to a safe default if resolution fails (e.g. unresolvable
            // URL) so callers always get a well-formed ScanResult.
            let st = if std::path::Path::new(target).is_dir() {
                "dir"
            } else {
                "file"
            };
            return ScanResult {
                score: 0,
                severity: "LOW".into(),
                recommendation: "SAFE".into(),
                findings: vec![],
                sarif: sarif::to_sarif(&[], TOOL_VERSION),
                source_type: st.into(),
            };
        }
    };

    // build_context walks the resolved directory.
    let mut ctx = context::build_context(&path);

    // Drop excluded paths before any analyzer sees them (see `exclude` module
    // docs). No-op when `excludes` is empty.
    exclude::filter_file_cache(&mut ctx.file_cache, excludes);

    // Fixed merge order: patterns, ast, taint, yara.
    let mut findings: Vec<Finding> = vec![];

    // --- patterns analyzer ---
    findings.extend(analyzers::patterns::scan_patterns(&ctx.file_cache));

    // --- ast analyzer (tree-sitter Python call detection) ---
    findings.extend(analyzers::ast::scan_ast(&ctx.file_cache));

    // --- taint analyzer (source→sink regex analysis) ---
    findings.extend(analyzers::taint::scan_taint(&ctx.file_cache));

    // --- yara analyzer ---
    findings.extend(analyzers::yara::scan_yara(&ctx.file_cache, None));

    // --- MCP tool-poisoning analyzer (hidden instructions in tool/parameter
    //     descriptions — an attack pure pattern/AST scanning misses) ---
    findings.extend(analyzers::meta_mcp::scan_mcp_metadata(&ctx.file_cache));

    // Central false-positive control across ALL analyzers: drop "devops-normal"
    // matches (pip/npm install, env reads, .env paths, DROP TABLE, …) that
    // landed in documentation, CI, build, config, lockfiles or data — they are
    // only meaningful inside an executed script. Behavioural findings
    // (pipe-to-shell, decode-and-exec, exfiltration, …) are kept everywhere.
    // See `analyzers::fileclass`.
    findings.retain(|f| {
        analyzers::fileclass::relevant(&f.rule_id, f.location.as_ref().map(|l| l.file.as_str()))
    });

    // --- byte-level malware pass (raw filesystem bytes, keyed on the
    //     resolved scan root; NOT a FileCache analyzer, see
    //     `analyzers::malware::scan_malware_pass` docs). Merged in after the
    //     devops-noise filter above on purpose: that filter exists to drop
    //     benign *mentions* of dangerous shell patterns outside a real
    //     runtime file, which has no bearing on an actual malware
    //     signature/YARA match, wherever it is found. Gated on `run_malware`
    //     (the `--no-malware` opt-out). `extra_malware` merges any additional
    //     findings the caller computed from the same resolved root. ---
    if run_malware {
        let mut mw = analyzers::malware::scan_malware_pass(&path, excludes);
        // Any additional malware findings the caller supplies (computed from the same
        // resolved root). The public build passes a no-op; the private hash-DB path
        // supplies hash-signature matches. Kept as an opaque closure so this core
        // carries no dependency on the private signature-DB reader.
        mw.extend(extra_malware(&path));
        findings.extend(mw);
    }

    // Score findings.
    let score_out = score::score(&findings, ctx.has_executable_scripts);

    // Emit SARIF.
    let sarif_val = sarif::to_sarif(&findings, TOOL_VERSION);

    // Serialise SourceType to its lowercase serde name.
    let source_type_str = match source_type {
        resolve::SourceType::Git => "git",
        resolve::SourceType::Url => "url",
        resolve::SourceType::Zip => "zip",
        resolve::SourceType::Dir => "dir",
        resolve::SourceType::File => "file",
    };

    ScanResult {
        score: score_out.score,
        severity: score_out.severity,
        recommendation: score_out.recommendation,
        findings,
        sarif: sarif_val,
        source_type: source_type_str.into(),
    }
}

/// Print a `ScanResult` in the requested format and return the appropriate exit code.
///
/// This is the single projection implementation used by both the synchronous
/// `run_cli` path and the async LLM path in the unified `belay scan`
/// subcommand.  Output format:
/// - `"sarif"` (case-insensitive): pretty-printed SARIF JSON on stdout.
/// - anything else (default `"json"`): pretty-printed JSON matching the Python CLI
///   shape exactly: `{ score, severity, recommendation, findings:[{rule_id, severity, reason}] }`.
///
/// Exit code rule: `1` when `score > 50`, otherwise `0`.
pub fn print_result_and_exit(result: &ScanResult, fmt: &str) -> std::process::ExitCode {
    use serde::Serialize;

    /// Minimal projection emitted in JSON mode — matches the Python CLI exactly.
    #[derive(Serialize)]
    struct ScanProjection {
        score: i64,
        severity: String,
        recommendation: String,
        findings: Vec<FindingProjection>,
    }

    #[derive(Serialize)]
    struct FindingProjection {
        rule_id: String,
        severity: String,
        reason: String,
    }

    if fmt.eq_ignore_ascii_case("sarif") {
        println!(
            "{}",
            serde_json::to_string_pretty(&result.sarif).expect("serialisation must not fail")
        );
    } else {
        let projection = ScanProjection {
            score: result.score,
            severity: result.severity.clone(),
            recommendation: result.recommendation.clone(),
            findings: result
                .findings
                .iter()
                .map(|f| FindingProjection {
                    rule_id: f.rule_id.clone(),
                    severity: f.severity.py_name().to_string(),
                    reason: f.reason.clone(),
                })
                .collect(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&projection).expect("serialisation must not fail")
        );
    }

    if result.score > 50 {
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// CLI scan entrypoint, factored out of `bin/scanner.rs` so the unified
/// `belay scan` subcommand (Phase 11 Task 7) can reuse it.
///
/// Runs the scan on `target`, prints the result in the requested format
/// (`"json"` or `"sarif"`; any other value defaults to JSON — clap already
/// restricts user input to those two), and returns an exit code: `1` when the
/// score exceeds 50, otherwise `0`. Behaviour is identical to the original
/// `bin/scanner.rs::main()` except for the addition of `excludes` (see
/// `run_scan`).
///
/// `run_malware`: whether to run the byte-level malware pass at all (the
/// `--no-malware` opt-out; the pass is on by default).
pub fn run_cli(
    target: &str,
    fmt: &str,
    excludes: &[String],
    run_malware: bool,
) -> std::process::ExitCode {
    let result = run_scan_opts(target, excludes, run_malware);
    print_result_and_exit(&result, fmt)
}

#[cfg(test)]
mod tests {
    /// `run_scan_opts` with `run_malware: false` must skip the byte-level
    /// malware pass entirely: an EICAR-planted file yields no finding whose
    /// `rule_id` contains "EICAR". With `run_malware: true` (the `run_scan`
    /// default) the same tree DOES surface the EICAR finding. Locks the
    /// `--no-malware` opt-out toggle threaded from the CLI down to
    /// `run_scan_opts`.
    #[test]
    fn run_scan_opts_with_no_malware_skips_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sample.txt"),
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        let target = dir.path().to_str().unwrap();

        let no_malware = super::run_scan_opts(target, &[], false);
        assert!(
            !no_malware
                .findings
                .iter()
                .any(|f| f.rule_id.contains("EICAR")),
            "expected no EICAR finding with run_malware=false, got: {:?}",
            no_malware.findings
        );

        let with_malware = super::run_scan_opts(target, &[], true);
        assert!(
            with_malware
                .findings
                .iter()
                .any(|f| f.rule_id.contains("EICAR")),
            "expected an EICAR finding with run_malware=true, got: {:?}",
            with_malware.findings
        );
    }
}
