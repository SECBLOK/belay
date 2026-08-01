//! Evaluation-corpus regression gate.
//!
//! # What this is for
//!
//! Belay's detection quality has two directions, and this file gates them
//! differently on purpose.
//!
//! **False positives — gated here, in-repo, on every `cargo test`.** The
//! vendored corpus is ordinary everyday command usage from tldr-pages
//! (CC-BY-4.0, redistributable with the attribution its header carries). A
//! rule change that starts flagging benign work fails right here.
//!
//! **False negatives — measured, but from an EXTERNAL corpus that is never
//! committed.** Adversarial technique corpora are copyleft-licensed, so
//! vendoring one would put a licence obligation on Belay's own distribution.
//! Nothing adversarial lives in this repo; the `#[ignore]`d test below reads a
//! corpus by path and keeps its baseline beside that file, outside the tree.
//! Measuring against a corpus is not redistributing it.
//!
//! Until this file existed that corpus was run by hand, ad hoc, which meant a
//! rule or engine change could move either number and nothing would notice.
//! It happened: `ce43473` closed a self-protection bypass and introduced a
//! false positive that fired live twice within hours, with a fully green
//! 681-test suite the entire time (`bbd9052` fixed it). This test wires the
//! corpus into `cargo test` as a **ratchet**: a change that makes benign
//! commands more restricted, or malicious commands less restricted, fails
//! here with the list of cases that moved.
//!
//! # Two tiers, and why
//!
//! * **Vendored subset** (`daemon/tests/data/eval_corpus_frontier.jsonl`) runs
//!   in the default suite: the entire current decision boundary, a
//!   one-command-per-binary breadth sample, and every benign sibling of a
//!   covered binary. That last part is not padding — see the note on sibling
//!   coverage below.
//! * **External corpus** runs from the same code path behind `#[ignore]` +
//!   `BELAY_EVAL_CORPUS=/path/to/cases.jsonl`, with its baseline kept beside
//!   that file rather than in this repo. It is the ground truth for a release
//!   or a deliberate rule change; the subset is the canary that runs every time.
//!
//! # Why sibling coverage
//!
//! The first cut of the vendored subset sampled benign usage one command per
//! binary. On 2026-07-27 that was tested directly: a regression was injected
//! that made `git status` an Ask, and the subset **passed** — it held 48 `git`
//! commands and no `git status`. Only the external corpus caught it. A gate
//! that cannot be shown to catch a deliberate regression is decoration, and
//! the false-positive direction is exactly where this project has shipped a
//! real regression before (`ce43473`, fixed by `bbd9052`). So the subset now
//! also carries every benign sibling of a binary it already covers, which
//! restores per-subcommand resolution where a rule change actually lands.
//!
//! Measured on this machine (AMD, 16 threads, `cargo test` = debug, opt-level
//! 0): the full corpus is ~45 s single-threaded, ~3.4 s here (16 threads);
//! the subset is well under a second against a suite that already takes ~74 s.
//! Case evaluation is spread over threads because each case is independent —
//! see `evaluate`.
//!
//! # The ratchet
//!
//! The baseline records, per label, the ids of every case that is currently
//! `Ask` or `Deny` (everything else is `Allow`), so a per-case baseline
//! decision is reconstructable exactly while the file stays small and
//! diff-reviewable. Comparison is per case, not per aggregate:
//!
//! * a **benign** case getting stricter (allow→ask, allow→deny, ask→deny) is
//!   a new false positive → **fail**;
//! * a **malicious** case getting looser (deny→ask, deny→allow, ask→allow) is
//!   a new miss → **fail**;
//! * the opposite directions are improvements → pass, with a printed note
//!   suggesting a re-baseline to lock the gain in;
//! * `ambiguous` and `out-of-scope` cases (dangerous commands that are
//!   nonetheless documented as ordinary usage, and technique variants outside
//!   the agent threat model) are reported but never fail, because their
//!   labelling is a judgement call and both directions are defensible.
//!
//! Deliberate, reviewed changes re-baseline with:
//!
//! ```text
//! BELAY_EVAL_REBASELINE=1 cargo test -p belayd --test eval_corpus
//! ```
//!
//! and, for the full corpus, additionally `-- --ignored` with
//! `BELAY_EVAL_CORPUS` set. The re-baseline is a committed diff naming every
//! case that moved, so "we meant to do that" is reviewable rather than
//! asserted.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use belayd::engine::decide::decide;
use belayd::engine::rules::RuleSet;
use belayd::engine::types::{Decision, SessionState, ToolCall};

// ---------------------------------------------------------------------------
// corpus
// ---------------------------------------------------------------------------

struct Case {
    id: String,
    label: String,
    command: String,
}

/// Same normalization the vendoring tool applies (`/home/<user>` →
/// `/home/agent`), repeated here so an *external* corpus file — built by
/// `build_corpus.py --realistic-targets`, which substitutes the builder's own
/// home directory — compares against the same baseline on any machine. It is
/// a no-op on the vendored subset, which is already normalized.
fn normalize_home(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut i = 0;
    while i < cmd.len() {
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
                out.push_str(p);
                if user_len > 0 {
                    out.push_str("agent");
                }
                i += p.len() + user_len;
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

fn parse_cases(text: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        // `#` lines carry the fixture's provenance/licence header.
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(t).unwrap_or_else(|e| panic!("bad corpus line: {e}\n{t}"));
        cases.push(Case {
            id: v["id"].as_str().unwrap_or_default().to_string(),
            label: v["label"].as_str().unwrap_or_default().to_string(),
            command: normalize_home(v["command"].as_str().unwrap_or_default()),
        });
    }
    cases
}

/// Accident-detection fingerprint over the corpus content (id + label +
/// command), not the file bytes — so reformatting or key reordering does not
/// invalidate a baseline, but an edited command does. FNV-1a 64, matching the
/// hash already used for SARIF `partialFingerprints` in this codebase; it is
/// not, and does not need to be, cryptographic.
fn corpus_digest(cases: &[Case]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    let mut ordered: Vec<&Case> = cases.iter().collect();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));
    for c in ordered {
        feed(c.id.as_bytes());
        feed(b"\0");
        feed(c.label.as_bytes());
        feed(b"\0");
        feed(c.command.as_bytes());
        feed(b"\n");
    }
    format!("fnv1a64:{h:016x}")
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------

/// One case → one verdict, in a **fresh** `SessionState`. Correlation rules
/// are stateful; a shared session would let an earlier case contaminate a
/// later verdict and make the result order-dependent.
fn verdict_of(rs: &RuleSet, case: &Case) -> (Decision, Vec<String>) {
    let tc = ToolCall {
        session: format!("eval-{}", case.id),
        tool: "Bash".to_string(),
        input: serde_json::json!({ "command": case.command }),
    };
    let mut state = SessionState::new(&tc.session);
    let v = decide(rs, &tc, &mut state);
    (v.decision, v.rules)
}

/// Evaluates every case, spreading the work over threads. Safe because each
/// case is independent (fresh session above) and `RuleSet` is read-only —
/// which `verdicts_are_deterministic_and_order_independent` pins empirically
/// rather than leaving as a claim.
fn evaluate(rs: &RuleSet, cases: &[Case]) -> Vec<(Decision, Vec<String>)> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let chunk = cases.len().div_ceil(threads).max(1);
    let mut out = Vec::with_capacity(cases.len());
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for block in cases.chunks(chunk) {
            handles.push(s.spawn(move || block.iter().map(|c| verdict_of(rs, c)).collect::<Vec<_>>()));
        }
        for h in handles {
            out.extend(h.join().expect("evaluation thread panicked"));
        }
    });
    out
}

// ---------------------------------------------------------------------------
// baseline
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    // Runtime first so a relocated build tree still resolves (the compile-time
    // value is only the fallback) — same lesson as daemon/build.rs.
    PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").into()),
    )
}

fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
}

/// Baseline decision for one case: the buckets list only `ask` and `deny`
/// ids, so anything absent is `allow`.
fn baseline_decision(buckets: &serde_json::Value, label: &str, id: &str) -> Decision {
    let l = &buckets[label];
    for (name, d) in [("deny", Decision::Deny), ("ask", Decision::Ask)] {
        if let Some(arr) = l[name].as_array() {
            if arr.iter().any(|v| v.as_str() == Some(id)) {
                return d;
            }
        }
    }
    Decision::Allow
}

fn build_baseline(
    corpus_id: &str,
    cases: &[Case],
    verdicts: &[(Decision, Vec<String>)],
) -> serde_json::Value {
    let mut totals: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut buckets: BTreeMap<String, BTreeMap<&str, BTreeSet<String>>> = BTreeMap::new();
    for (c, (d, _)) in cases.iter().zip(verdicts) {
        let t = totals.entry(c.label.clone()).or_default();
        *t.entry("total").or_insert(0) += 1;
        *t.entry(decision_str(*d)).or_insert(0) += 1;
        let b = buckets.entry(c.label.clone()).or_default();
        b.entry("ask").or_default();
        b.entry("deny").or_default();
        if *d != Decision::Allow {
            b.get_mut(decision_str(*d)).unwrap().insert(c.id.clone());
        }
    }
    let pct = |num: usize, den: usize| -> f64 {
        if den == 0 {
            0.0
        } else {
            (num as f64 * 1000.0 / den as f64).round() / 10.0
        }
    };
    let get = |label: &str, k: &str| -> usize { *totals.get(label).and_then(|m| m.get(k)).unwrap_or(&0) };
    let headline = serde_json::json!({
        "miss_rate_pct": pct(get("malicious", "allow"), get("malicious", "total")),
        "hard_fp_rate_pct": pct(get("benign", "deny"), get("benign", "total")),
        "benign_ask_rate_pct": pct(get("benign", "ask"), get("benign", "total")),
    });
    serde_json::json!({
        "schema": 1,
        "corpus_id": corpus_id,
        "case_count": cases.len(),
        "case_digest": corpus_digest(cases),
        "headline": headline,
        "totals": totals,
        "buckets": buckets,
    })
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

struct Drift {
    id: String,
    label: String,
    from: Decision,
    to: Decision,
    rules: Vec<String>,
    command: String,
}

impl Drift {
    fn render(&self) -> String {
        let rules = if self.rules.is_empty() {
            "-".to_string()
        } else {
            self.rules.join(", ")
        };
        let mut cmd = self.command.replace('\n', "\\n");
        if cmd.chars().count() > 140 {
            cmd = cmd.chars().take(137).collect::<String>() + "...";
        }
        format!(
            "    [{}] {} -> {} (now: {})\n        {}",
            self.id,
            decision_str(self.from),
            decision_str(self.to),
            rules,
            cmd
        )
    }
}

fn strictness(d: Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Ask => 1,
        Decision::Deny => 2,
    }
}

/// Runs one corpus against one baseline file. `rebaseline` rewrites the
/// baseline instead of asserting against it.
fn run_gate(corpus_id: &str, corpus_text: &str, baseline_path: PathBuf, rebaseline: bool) {
    let cases = parse_cases(corpus_text);
    assert!(!cases.is_empty(), "corpus '{corpus_id}' parsed to 0 cases");
    let rs = RuleSet::load().expect("RuleSet::load");
    let verdicts = evaluate(&rs, &cases);

    if rebaseline {
        let baseline = build_baseline(corpus_id, &cases, &verdicts);
        std::fs::write(
            &baseline_path,
            format!("{}\n", serde_json::to_string_pretty(&baseline).unwrap()),
        )
        .unwrap_or_else(|e| panic!("writing {}: {e}", baseline_path.display()));
        println!(
            "REBASELINED {corpus_id} ({} cases) -> {}\nheadline: {}",
            cases.len(),
            baseline_path.display(),
            baseline["headline"]
        );
        return;
    }

    let raw = std::fs::read_to_string(&baseline_path).unwrap_or_else(|e| {
        panic!(
            "missing baseline {}: {e}\nGenerate it with: BELAY_EVAL_REBASELINE=1 cargo test -p belayd --test eval_corpus",
            baseline_path.display()
        )
    });
    let baseline: serde_json::Value = serde_json::from_str(&raw).expect("baseline is not JSON");

    let digest = corpus_digest(&cases);
    assert_eq!(
        baseline["case_digest"].as_str().unwrap_or_default(),
        digest,
        "corpus '{corpus_id}' does not match the one this baseline was recorded against \
         (cases now: {}, baseline: {}). Either you are pointing at a different corpus build, \
         or the fixture changed without a re-baseline. Fix the corpus, or re-baseline with \
         BELAY_EVAL_REBASELINE=1 and review the resulting diff.",
        cases.len(),
        baseline["case_count"]
    );

    let buckets = &baseline["buckets"];
    let (mut regressions, mut improvements, mut informational) = (Vec::new(), Vec::new(), Vec::new());
    for (c, (now, rules)) in cases.iter().zip(&verdicts) {
        let was = baseline_decision(buckets, &c.label, &c.id);
        if was == *now {
            continue;
        }
        let d = Drift {
            id: c.id.clone(),
            label: c.label.clone(),
            from: was,
            to: *now,
            rules: rules.clone(),
            command: c.command.clone(),
        };
        let stricter = strictness(*now) > strictness(was);
        match c.label.as_str() {
            "benign" if stricter => regressions.push(d),
            "benign" => improvements.push(d),
            "malicious" if stricter => improvements.push(d),
            "malicious" => regressions.push(d),
            _ => informational.push(d),
        }
    }

    // Cap the printed list: a rule change can move thousands of cases, and a
    // failure message nobody reads is a failure message that teaches nothing.
    const MAX_SHOWN: usize = 25;
    fn note(v: &[&Drift]) -> String {
        let mut s = v
            .iter()
            .take(MAX_SHOWN)
            .map(|d| d.render())
            .collect::<Vec<_>>()
            .join("\n");
        if v.len() > MAX_SHOWN {
            s.push_str(&format!("\n    ... and {} more", v.len() - MAX_SHOWN));
        }
        s
    }

    if !improvements.is_empty() || !informational.is_empty() {
        println!(
            "eval-corpus '{corpus_id}': {} improvement(s), {} informational (ambiguous/out-of-scope) change(s).\n{}\n{}\n\
             Re-baseline to lock the improvement in: BELAY_EVAL_REBASELINE=1 cargo test -p belayd --test eval_corpus",
            improvements.len(),
            informational.len(),
            note(&improvements.iter().collect::<Vec<_>>()),
            note(&informational.iter().collect::<Vec<_>>()),
        );
    }

    if !regressions.is_empty() {
        let fps: Vec<&Drift> = regressions.iter().filter(|d| d.label == "benign").collect();
        let misses: Vec<&Drift> = regressions
            .iter()
            .filter(|d| d.label == "malicious")
            .collect();
        let section = |title: &str, v: &[&Drift]| -> String {
            if v.is_empty() {
                String::new()
            } else {
                format!("\n  {} {}\n{}", v.len(), title, note(v))
            }
        };
        panic!(
            "eval-corpus regression gate FAILED on '{corpus_id}' ({} cases){}{}\n\n\
             Baseline: {}\n\
             If every case above is a deliberate, reviewed change, re-baseline with:\n    \
             BELAY_EVAL_REBASELINE=1 cargo test -p belayd --test eval_corpus\n\
             and name the moved cases (and why) in the commit message.",
            cases.len(),
            section(
                "new FALSE POSITIVE(s) — benign command(s) got stricter:",
                &fps
            ),
            section("new MISS(es) — malicious command(s) got looser:", &misses),
            baseline_path.display(),
        );
    }
}

fn rebaseline_requested() -> bool {
    matches!(
        std::env::var("BELAY_EVAL_REBASELINE").as_deref(),
        Ok("1") | Ok("true")
    )
}

fn frontier_corpus_path() -> PathBuf {
    manifest_dir().join("tests/data/eval_corpus_frontier.jsonl")
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// The gate that runs on every `cargo test`.
#[test]
fn frontier_corpus_has_no_new_false_positives_or_misses() {
    let path = frontier_corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    run_gate(
        "frontier",
        &text,
        manifest_dir().join("tests/data/eval_corpus_frontier.baseline.json"),
        rebaseline_requested(),
    );
}

/// The external corpus — the false-negative direction, and any adversarial
/// material. Deliberately NOT vendored: adversarial technique corpora are
/// copyleft-licensed, and redistributing one would attach that obligation to
/// Belay's own distribution. So it is opt-in by path:
///
/// ```text
/// BELAY_EVAL_CORPUS=/path/to/cases.jsonl \
///   cargo test -p belayd --test eval_corpus -- --ignored
/// ```
///
/// Its baseline is written NEXT TO THE CORPUS, not into this repo, so running
/// this test can never deposit case ids from an external corpus into the tree.
/// Skips loudly rather than failing when the corpus is not available, because
/// a missing external file is not a detection regression.
#[test]
#[ignore = "needs BELAY_EVAL_CORPUS=/path/to/cases.jsonl (external, not vendored)"]
fn external_corpus_has_no_new_false_positives_or_misses() {
    let Ok(corpus) = std::env::var("BELAY_EVAL_CORPUS") else {
        println!(
            "SKIPPED: set BELAY_EVAL_CORPUS to an external corpus in this file's JSONL schema \
             (id, label, command) to run this."
        );
        return;
    };
    let path = PathBuf::from(&corpus);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {corpus}: {e}"));
    // Baseline lives beside the corpus, deliberately outside this repo.
    let baseline = path.with_extension("baseline.json");
    run_gate("external", &text, baseline, rebaseline_requested());
}

/// Determinism, verified rather than asserted: the same case must give the
/// same verdict on a re-run, and must not depend on the order cases are
/// evaluated in (which the threaded `evaluate` above makes non-deterministic
/// in *timing*, so it had better not be observable in *outcome*).
#[test]
fn verdicts_are_deterministic_and_order_independent() {
    let path = frontier_corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let cases = parse_cases(&text);
    let rs = RuleSet::load().expect("RuleSet::load");

    // A slice big enough to cover both halves of the corpus, small enough to
    // stay cheap: the gate above already evaluates all of it once.
    let slice: Vec<Case> = cases
        .iter()
        .step_by(5)
        .map(|c| Case {
            id: c.id.clone(),
            label: c.label.clone(),
            command: c.command.clone(),
        })
        .collect();
    assert!(slice.len() > 100, "slice too small to be meaningful");

    let first = evaluate(&rs, &slice);
    let second = evaluate(&rs, &slice);
    assert_eq!(
        first.iter().map(|(d, _)| *d).collect::<Vec<_>>(),
        second.iter().map(|(d, _)| *d).collect::<Vec<_>>(),
        "re-running the same corpus produced different verdicts"
    );

    // Serial, reversed: catches both order dependence and any difference
    // between the threaded and single-threaded paths.
    let reversed: Vec<Case> = slice
        .iter()
        .rev()
        .map(|c| Case {
            id: c.id.clone(),
            label: c.label.clone(),
            command: c.command.clone(),
        })
        .collect();
    let mut serial: Vec<Decision> = reversed.iter().map(|c| verdict_of(&rs, c).0).collect();
    serial.reverse();
    let mismatches: Vec<String> = slice
        .iter()
        .zip(&first)
        .zip(&serial)
        .filter(|((_, (par, _)), ser)| par != *ser)
        .map(|((c, (par, _)), ser)| {
            format!(
                "  [{}] parallel {} != serial-reversed {}",
                c.id,
                decision_str(*par),
                decision_str(*ser)
            )
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "verdicts depend on evaluation order:\n{}",
        mismatches.join("\n")
    );

    // A machine-specific input would break the ratchet across machines:
    // `self_tamper::mentions_data_dir` compares against the *runner's* real
    // data dir, so no corpus case may mention it.
    let data_dir = belayd::paths::data_dir().to_string_lossy().to_string();
    if !data_dir.is_empty() {
        let leaking: Vec<&str> = cases
            .iter()
            .filter(|c| c.command.contains(data_dir.trim_end_matches('/')))
            .map(|c| c.id.as_str())
            .collect();
        assert!(
            leaking.is_empty(),
            "corpus case(s) mention this machine's Belay data dir ({data_dir}), \
             so their verdict is machine-dependent: {leaking:?}"
        );
    }
}
