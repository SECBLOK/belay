pub mod analyzers;
pub mod clamav;
pub mod context;
pub mod host_adapter;
pub mod judge;
pub mod llm;
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

/// Return the four real analyzers in fixed registration order: patterns, ast, taint, yara.
///
/// Used by `pipeline::run_scan` and `pipeline::run_scan_with_llm`.  The yara
/// analyzer receives `None` as its second (custom-rules-path) argument.
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
///   resolve → build_context → scan_patterns → scan_ast → scan_taint → scan_yara → score → to_sarif → ScanResult
///
/// Analyzer merge order is fixed as: patterns, ast, taint, yara.
pub fn run_scan(target: &str) -> ScanResult {
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
    let ctx = context::build_context(&path);

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
/// `bin/scanner.rs::main()`.
pub fn run_cli(target: &str, fmt: &str) -> std::process::ExitCode {
    let result = run_scan(target);
    print_result_and_exit(&result, fmt)
}
