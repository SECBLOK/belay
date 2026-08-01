//! Vendors the false-positive regression corpus into `daemon/tests/data/`,
//! where the regression gate (`daemon/tests/eval_corpus.rs`) runs it as part
//! of `cargo test`.
//!
//! LICENCE SCOPE: only `source == "tldr"` cases are vendored. tldr-pages is
//! CC-BY-4.0, which permits redistribution with attribution (the header this
//! writes). Cases from copyleft-licensed upstreams are excluded outright —
//! see `ALLOWED_SOURCES` — so nothing in this repo carries a licence
//! obligation Belay's own AGPL-3.0 distribution would have to answer for.
//! That makes the vendored subset a FALSE-POSITIVE gate specifically; the
//! false-negative direction is measured from an external corpus that is never
//! committed (see `daemon/tests/eval_corpus.rs`).
//!
//! Selection: **every case from an allowed upstream. No sampling.**
//!
//! Earlier cuts of this tool sampled — one case per binary on an even stride,
//! plus the decision boundary — to keep `cargo test` fast. That was measured
//! and it does not hold up. On 2026-07-27 a regression was deliberately
//! injected that made an ordinary `git status` an Ask, and the sampled subset
//! **passed it twice**: first because one-case-per-binary held 48 `git`
//! commands and no `git status`, then, after adding sibling coverage, because
//! the stride had skipped the `git-status` page entirely so there was no
//! sibling to attach to. Every sampling scheme has holes; the only question is
//! whether you have found them yet.
//!
//! The cost of dropping sampling is small and known: ~4.8 MB in the repo, and
//! ~5 s to evaluate against a suite that already takes ~74 s. That is cheap
//! for a gate that can no longer be blind to a whole binary, and it removes an
//! entire class of "the corpus did not happen to contain that" failure.
//!
//! Commands are normalized on the way in (`/home/<user>` → `/home/agent`):
//! the upstream builder's `--realistic-targets` mode substitutes the *corpus
//! author's own* home directory, which would otherwise ship a real username
//! in the repo and make the fixture machine-specific. The normalization is
//! verified, not assumed — every case is evaluated before and after, and any
//! case whose decision changes aborts the vendoring run.
//!
//! ```text
//! cargo run --release -p belayd --example corpus_vendor -- \
//!     /path/to/cases_realistic.jsonl daemon/tests/data/eval_corpus_frontier.jsonl
//! ```
//!
//! After re-vendoring, re-baseline (see `daemon/tests/eval_corpus.rs`):
//!
//! ```text
//! BELAY_EVAL_REBASELINE=1 cargo test -p belayd --test eval_corpus
//! ```

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use belayd::engine::decide::decide;
use belayd::engine::rules::RuleSet;
use belayd::engine::types::{Decision, SessionState, ToolCall};

/// Upstreams whose cases may be redistributed in this repo. Deliberately an
/// ALLOWLIST, not a denylist: a corpus gaining a new upstream must be an
/// explicit, reviewed decision here rather than silently inheriting whatever
/// licence that upstream carries. tldr-pages is CC-BY-4.0 (redistribution
/// with attribution); the header written below is that attribution.
const ALLOWED_SOURCES: &[&str] = &["tldr"];

#[derive(Clone)]
struct Case {
    id: String,
    source: String,
    origin: String,
    function: String,
    label: String,
    command: String,
    targets: Option<String>,
}

/// Replaces any `/home/<user>` or `/Users/<user>` prefix with a fixed,
/// non-identifying stand-in. Kept deliberately dumb (no regex backtracking,
/// no `~` expansion) so it is obvious by reading what it can and cannot do.
fn normalize_home(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &cmd[i..];
        let prefix = if rest.starts_with("/home/") {
            Some("/home/")
        } else if rest.starts_with("/Users/") {
            Some("/Users/")
        } else {
            None
        };
        match prefix {
            Some(p) => {
                let after = &rest[p.len()..];
                let user_len = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
                    .unwrap_or(after.len());
                if user_len == 0 {
                    out.push_str(p);
                    i += p.len();
                } else {
                    out.push_str(p);
                    out.push_str("agent");
                    i += p.len() + user_len;
                }
            }
            None => {
                let ch = rest.chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

fn parse(path: &str) -> Result<Vec<Case>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut cases = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(t)?;
        cases.push(Case {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            source: v["source"].as_str().unwrap_or_default().to_string(),
            origin: v["origin"].as_str().unwrap_or_default().to_string(),
            function: v["function"].as_str().unwrap_or_default().to_string(),
            label: v["label"].as_str().unwrap_or_default().to_string(),
            command: v["command"].as_str().unwrap_or_default().to_string(),
            targets: v["targets"].as_str().map(|s| s.to_string()),
        });
    }
    Ok(cases)
}

/// One fresh `SessionState` per case — correlation rules are stateful, so a
/// shared session would let earlier cases contaminate later verdicts.
fn verdict_of(rs: &RuleSet, command: &str, id: &str) -> (Decision, Vec<String>) {
    let tc = ToolCall {
        session: format!("vendor-{id}"),
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": command }),
    };
    let mut state = SessionState::new(&tc.session);
    let v = decide(rs, &tc, &mut state);
    (v.decision, v.rules)
}

fn evaluate(rs: &RuleSet, cases: &[Case], use_raw: &[String]) -> Vec<(Decision, Vec<String>)> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let chunk = cases.len().div_ceil(threads).max(1);
    let mut out: Vec<(Decision, Vec<String>)> = Vec::new();
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for (ci, block) in cases.chunks(chunk).enumerate() {
            let base = ci * chunk;
            let raws = &use_raw[base..base + block.len()];
            handles.push(s.spawn(move || {
                block
                    .iter()
                    .zip(raws)
                    .map(|(c, cmd)| verdict_of(rs, cmd, &c.id))
                    .collect::<Vec<_>>()
            }));
        }
        for h in handles {
            out.extend(h.join().expect("evaluation thread panicked"));
        }
    });
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: corpus_vendor <cases.jsonl> <out.jsonl>");
        std::process::exit(2);
    }
    let in_path = args[1].clone();
    let out_path = args[2].clone();

    let raw_cases = parse(&in_path)?;
    eprintln!("read {} cases from {in_path}", raw_cases.len());

    let rs = RuleSet::load().map_err(|e| format!("RuleSet::load failed: {e}"))?;

    // Verify the home-path normalization is verdict-preserving rather than
    // assuming it. A silent decision change here would mean the vendored
    // fixture measures something the published corpus does not.
    let raw_cmds: Vec<String> = raw_cases.iter().map(|c| c.command.clone()).collect();
    let norm_cmds: Vec<String> = raw_cases
        .iter()
        .map(|c| normalize_home(&c.command))
        .collect();
    let before = evaluate(&rs, &raw_cases, &raw_cmds);
    let after = evaluate(&rs, &raw_cases, &norm_cmds);
    let mut drift = Vec::new();
    for (idx, c) in raw_cases.iter().enumerate() {
        if before[idx].0 != after[idx].0 {
            drift.push(format!(
                "  {} {:?} -> {:?}\n    raw:  {}\n    norm: {}",
                c.id, before[idx].0, after[idx].0, raw_cmds[idx], norm_cmds[idx]
            ));
        }
    }
    if !drift.is_empty() {
        eprintln!(
            "ABORT: home-path normalization changed {} decisions:\n{}",
            drift.len(),
            drift.join("\n")
        );
        std::process::exit(1);
    }
    eprintln!(
        "home-path normalization verified verdict-preserving across all {} cases",
        raw_cases.len()
    );

    let cases: Vec<Case> = raw_cases
        .iter()
        .zip(&norm_cmds)
        .map(|(c, cmd)| Case {
            command: cmd.clone(),
            ..c.clone()
        })
        .collect();

    // ---- selection -------------------------------------------------------
    // Licence gate first, so no later selection rule can reach an excluded
    // upstream by any path.
    let mut order: Vec<usize> = (0..cases.len())
        .filter(|&i| ALLOWED_SOURCES.contains(&cases[i].source.as_str()))
        .collect();
    order.sort_by(|a, b| cases[*a].id.cmp(&cases[*b].id));
    eprintln!(
        "licence gate: {} of {} input cases are from an allowed upstream {ALLOWED_SOURCES:?}",
        order.len(),
        cases.len()
    );

    // No sampling: every case that cleared the licence gate is vendored.
    let chosen: Vec<usize> = order.clone();


    // ---- write -----------------------------------------------------------
    let mut f = std::io::BufWriter::new(std::fs::File::create(&out_path)?);
    writeln!(f, "# Belay false-positive regression corpus.")?;
    writeln!(f, "#")?;
    writeln!(
        f,
        "# Ordinary everyday command usage, used to prove that a rule or engine change does"
    )?;
    writeln!(
        f,
        "# not start flagging benign work. Derived from one public corpus we did not write:"
    )?;
    writeln!(f, "#")?;
    writeln!(
        f,
        "#   tldr-pages  https://github.com/tldr-pages/tldr  (CC-BY-4.0)"
    )?;
    writeln!(f, "#")?;
    writeln!(
        f,
        "# Only CC-BY-4.0 material is vendored here; see ALLOWED_SOURCES in"
    )?;
    writeln!(
        f,
        "# daemon/examples/corpus_vendor.rs. Attribution above satisfies the licence."
    )?;
    writeln!(f, "#")?;
    writeln!(
        f,
        "# Selection: every case from an allowed upstream, no sampling - a sampled subset"
    )?;
    writeln!(
        f,
        "# was measurably blind to regressions scoped to a binary it happened to skip."
    )?;
    writeln!(
        f,
        "# Regenerate with daemon/examples/corpus_vendor.rs."
    )?;
    writeln!(f, "#")?;
    writeln!(
        f,
        "# Commands are verbatim upstream except /home/<user> -> /home/agent, which is"
    )?;
    writeln!(f, "# verified verdict-preserving at vendoring time.")?;
    for &idx in &chosen {
        let c = &cases[idx];
        let mut row = serde_json::json!({
            "id": c.id,
            "source": c.source,
            "origin": c.origin,
            "function": c.function,
            "label": c.label,
            "command": c.command,
        });
        if let Some(t) = &c.targets {
            row["targets"] = serde_json::Value::String(t.clone());
        }
        writeln!(f, "{row}")?;
    }
    f.flush()?;

    let mut by_label: BTreeMap<&str, usize> = BTreeMap::new();
    for &idx in &chosen {
        *by_label.entry(cases[idx].label.as_str()).or_insert(0) += 1;
    }
    eprintln!(
        "wrote {} cases to {out_path}",
        chosen.len()
    );
    eprintln!("by label: {by_label:?}");
    Ok(())
}
