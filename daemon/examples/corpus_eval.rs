//! Corpus evaluator: reads cases.jsonl, calls `decide()` directly, emits verdicts
//! plus per-call timing as JSONL.
//!
//! Place this at `daemon/examples/corpus_eval.rs` in the belay tree and run:
//!
//!   cargo run --release --example corpus_eval -- cases.jsonl > verdicts.jsonl
//!
//! Why this calls `decide()` rather than shelling out to `belay hook`: the hook
//! wire only carries allow/deny. `run_hook` maps Ask to "deny" because the hook
//! protocol has two states, so an Ask and a Deny are indistinguishable there. A
//! false-positive measurement has to tell those apart, since one is a prompt and
//! the other is a block. Only the engine returns the real three-way verdict.
//!
//! Timing here measures the decision function alone, with the RuleSet loaded once.
//! That is the floor, not the end-to-end number. See the note at the bottom of this
//! file and the README for measuring the process-level path, which is the figure
//! worth publishing.

use std::io::{BufRead, Write};
use std::time::Instant;

use belayd::engine::decide::decide;
use belayd::engine::rules::RuleSet;
// SessionState lives in engine::types, not a separate engine::state module.
use belayd::engine::types::{Decision, SessionState, ToolCall};

fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
}

/// Sequence identity for a case: multi-step entries share one, single-command
/// entries get a unique one so they can never share a session. Keyed on
/// `origin` + `function` rather than the id, because the id carries a
/// per-step counter that is exactly what must be stripped to group steps.
fn sequence_key(case: &serde_json::Value, id: &str) -> String {
    let len = case["seq_len"].as_u64().unwrap_or(1);
    if len <= 1 {
        return format!("solo:{id}");
    }
    format!(
        "seq:{}/{}/{}",
        case["source"].as_str().unwrap_or(""),
        case["origin"].as_str().unwrap_or(""),
        case["function"].as_str().unwrap_or("")
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut path = String::new();
    let mut sequences = false;
    for a in args.by_ref() {
        match a.as_str() {
            "--sequences" => sequences = true,
            other => path = other.to_string(),
        }
    }
    if path.is_empty() {
        eprintln!("usage: corpus_eval [--sequences] <cases.jsonl>");
        std::process::exit(2);
    }

    // Load once. Every case is then measured against the same compiled ruleset,
    // which is what the daemon does in steady state.
    let load_start = Instant::now();
    let rs = RuleSet::load().map_err(|e| format!("RuleSet::load failed: {e}"))?;
    let load_us = load_start.elapsed().as_micros();
    eprintln!("ruleset loaded in {load_us} us");

    let file = std::fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    // Cases are read in full first so `--sequences` can order each multi-step
    // entry by seq_index. The corpus is already in order, but relying on file
    // order for a correctness-relevant property would be a latent bug.
    let mut cases: Vec<serde_json::Value> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match serde_json::from_str(t) {
            Ok(v) => cases.push(v),
            Err(e) => eprintln!("skipping unparseable case line: {e}"),
        }
    }
    if sequences {
        cases.sort_by(|a, b| {
            let ka = sequence_key(a, a["id"].as_str().unwrap_or(""));
            let kb = sequence_key(b, b["id"].as_str().unwrap_or(""));
            ka.cmp(&kb).then(
                a["seq_index"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&b["seq_index"].as_u64().unwrap_or(0)),
            )
        });
    }

    // In `--sequences` mode the steps of one entry share a SessionState, which
    // is the only way the stateful detectors (correlate, dropper) can see a
    // setup-then-payload chain at all. Sequences never share with each other,
    // so a verdict still depends only on its own entry. Default mode keeps one
    // fresh session per case and measures per-command detection only; the
    // difference between the two runs is the point of the flag.
    let mut n: u64 = 0;
    let mut session: Option<(String, SessionState)> = None;
    let mut verdict_by_id: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for case in &cases {
        let command = case["command"].as_str().unwrap_or("");
        let id = case["id"].as_str().unwrap_or("");
        let key = sequence_key(case, id);

        let tc = ToolCall {
            session: format!("eval-{key}"),
            tool: "Bash".to_string(),
            input: serde_json::json!({ "command": command }),
        };
        let mut fresh;
        let state: &mut SessionState = if sequences {
            if session.as_ref().map(|(k, _)| k != &key).unwrap_or(true) {
                session = Some((key.clone(), SessionState::new(&tc.session)));
            }
            &mut session.as_mut().expect("just set").1
        } else {
            fresh = SessionState::new(&tc.session);
            &mut fresh
        };

        let t0 = Instant::now();
        let verdict = decide(&rs, &tc, state);
        let elapsed_ns = t0.elapsed().as_nanos();

        n += 1;
        verdict_by_id.insert(id.to_string(), decision_str(verdict.decision));
        let row = serde_json::json!({
            "id": id,
            "source": case["source"],
            "origin": case["origin"],
            "function": case["function"],
            "label": case["label"],
            "command": command,
            "seq_index": case["seq_index"],
            "seq_len": case["seq_len"],
            "decision": decision_str(verdict.decision),
            "rules": verdict.rules,
            "severity": verdict.severity.as_wire_str(),
            "reason": verdict.reason,
            "decide_ns": elapsed_ns,
        });
        writeln!(out, "{row}")?;
    }

    out.flush()?;
    eprintln!("evaluated {n} cases");

    if sequences {
        // Per-SEQUENCE detection, which is the operator-facing number and the
        // only fair one for a technique corpus. A multi-step entry is one
        // technique; the operator is prompted once and the chain is broken, so
        // scoring each step independently reports a miss for every step after
        // the one that already stopped it. Both numbers are printed because
        // the gap between them is itself the finding.
        use std::collections::BTreeMap;
        let mut per_seq: BTreeMap<String, (bool, usize)> = BTreeMap::new();
        let mut steps = 0usize;
        let mut steps_missed = 0usize;
        for case in &cases {
            if case["label"].as_str() != Some("malicious") {
                continue;
            }
            let id = case["id"].as_str().unwrap_or("");
            let key = sequence_key(case, id);
            steps += 1;
            let missed = verdict_by_id
                .get(id)
                .map(|d| *d == "allow")
                .unwrap_or(false);
            if missed {
                steps_missed += 1;
            }
            let e = per_seq.entry(key).or_insert((false, 0));
            e.0 |= !missed;
            e.1 += 1;
        }
        let seqs = per_seq.len();
        let seqs_missed = per_seq.values().filter(|(caught, _)| !caught).count();
        let pct = |a: usize, b: usize| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
        eprintln!(
            "malicious STEPS     : {steps} missed {steps_missed} = {:.1}%",
            pct(steps_missed, steps)
        );
        eprintln!(
            "malicious SEQUENCES : {seqs} missed {seqs_missed} = {:.1}%  <- operator-facing",
            pct(seqs_missed, seqs)
        );
    }
    Ok(())
}

// Two things this deliberately does not measure, both of which belong in the
// published number rather than this one:
//
// 1. Process-level latency. The real hook path spawns `belay hook`, reads stdin,
//    and either round-trips a unix socket to the daemon or, on the fallback path,
//    calls RuleSet::load() and recompiles every regex for that single call
//    (app.rs documents that this is intentionally uncached because the process is
//    one-shot). That is the latency a user experiences. Measure it by timing
//    `belay hook pretooluse` with a payload on stdin, from the harness in the
//    README, and report p50/p95/p99 with the hardware stated.
//
// 2. Sequence effects. Multi-line entries are setup-then-payload. Running
//    each line in a fresh session measures per-command detection only. Re-running
//    each multi-line entry as an ordered sequence in ONE session is what exercises
//    the correlation rules, and the difference between the two runs is the
//    interesting result. See --sequences in the README.
