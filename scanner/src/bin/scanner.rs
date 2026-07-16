//! scanner CLI — `scanner scan <target> [--format json|sarif]`
//!
//! Mirrors the deleted Python predecessor's `aidefender scan` CLI exactly:
//! - JSON shape: { score, severity, recommendation, findings:[{rule_id, severity, reason}] }
//! - SARIF: result.sarif pretty-printed
//! - Exit 1 when score > 50, else exit 0.
//!
//! The scan/print/exit logic lives in `scanner::run_cli` so the unified
//! `belay scan` subcommand can reuse it; this bin just parses args and
//! delegates.

use clap::{Parser, Subcommand, ValueEnum};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "scanner", about = "Belay static scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target directory, file, git URL, or zip.
    Scan {
        /// Target to scan (path, git URL, zip, …)
        target: String,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// Exclude paths matching this glob (relative to the scan root).
        /// Repeatable. See `scanner::exclude` for matching semantics.
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Skip the on-demand malware pass (it runs by default).
        #[arg(long = "no-malware", default_value_t = false)]
        no_malware: bool,
    },
}

#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Sarif,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            target,
            format,
            exclude,
            no_malware,
        } => {
            let fmt = match format {
                Format::Json => "json",
                Format::Sarif => "sarif",
            };
            scanner::run_cli(&target, fmt, &exclude, !no_malware)
        }
    }
}
