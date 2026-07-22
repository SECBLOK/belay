//! Corpus-representative CI regression suite: locks in the false-positive /
//! coverage balance tuned across the `skill.lp.*`/`skill.sc.*`/`skill.rp.*`
//! FP-reduction pass and the `skill.rce.*`/`skill.snoop.*` coverage rules
//! (see `fp_regression.rs` and `src/detect/coverage.rs`), so neither can
//! silently regress.
//!
//! ## Provenance
//!
//! These fixtures are modeled on a real 20-repo / 360-skill benchmark of
//! public Claude Code / Agent skills (`docs/research/2026-07-18-skillscan-fp-corpus-analysis.md`):
//! that corpus is re-runnable manually (`gh search` + `belay scan` per skill)
//! but is NOT checked in here — it is third-party content under mixed
//! licenses, and the scan is network-dependent and non-deterministic (repo
//! contents drift). This suite distills the FP/coverage SHAPES that analysis
//! found into small, synthetic, license-clean, fully-offline fixtures that
//! exercise the exact same detector paths, so every PR gets the regression
//! guard without re-running the real corpus.
//!
//! ## Structure
//!
//! Each fixture is a `tests/corpus/<name>/` directory (`SKILL.md` + optional
//! `scripts/*`), scanned end-to-end via `skillscan::scan_skill`. `EXPECTATIONS`
//! is the single source of truth: `(dir_name, expected_recommendation,
//! required_finding_ids)`. Three buckets:
//!
//! - `benign_*`  — reproduces an FP shape that used to over-flag. Invariant:
//!   MUST be `Safe`. EXCEPTION: `benign_high_accumulation` (see fix #5 below)
//!   is intentionally allowed to land at `Caution` instead -- see the
//!   dedicated carve-out in `aggregate_prefix_convention_holds`.
//! - `malicious_*` — a genuine attack shape. Invariant: MUST be `DoNotInstall`,
//!   via the named Critical signal.
//! - `edge_*` — a nuanced boundary case with no fixed a-priori invariant; the
//!   expected verdict below is the ACTUAL verdict the scanner produces
//!   (verified by running it, not assumed), pinned so a future change to the
//!   scoring/detector logic that shifts this boundary is caught, not silently
//!   absorbed.
//!
//! ## Fix #5 (score.rs `BLOCKING_ELIGIBLE`)
//!
//! `benign_high_accumulation` locks in the structural invariant fix #5 adds:
//! only an executable, high-confidence `BLOCKING_ELIGIBLE` finding may force
//! `DoNotInstall`; a pile of unrelated non-eligible findings (undeclared
//! capabilities, an unpinned pip install, a `shell=True` tool-misuse signal,
//! and a privileged-Kubernetes cache-warmer job) accumulates to an ACTUAL
//! score of 54 -- verified by running it (see
//! `benign_high_accumulation_actually_crosses_the_old_do_not_install_band`
//! below), which genuinely DOES cross the OLD `>=51` DoNotInstall band, but
//! must now cap at `Caution` -- it is genuinely benign (no eligible finding
//! fires) but not scored `Safe`, so it gets its own documented exception
//! below rather than satisfying the blanket `benign_* => Safe` rule.
use skillscan::finding::Recommendation;
use std::path::Path;

const CORPUS_DIR: &str = "tests/corpus";

/// (fixture dir name, expected recommendation, required finding ids).
const EXPECTATIONS: &[(&str, Recommendation, &[&str])] = &[
    // --- BENIGN: must stay Safe (the FP classes the Task 1 pass fixed) ---
    ("benign_undeclared_caps", Recommendation::Safe, &[]),
    ("benign_unpinned_pip", Recommendation::Safe, &[]),
    ("benign_stdlib_import", Recommendation::Safe, &[]),
    ("benign_combined", Recommendation::Safe, &[]),
    ("benign_security_doc_prose", Recommendation::Safe, &[]),
    ("benign_ssh_pubkey", Recommendation::Safe, &[]),
    ("benign_design_skill", Recommendation::Safe, &[]),
    // Fix #5 regression: several non-eligible findings (undeclared caps,
    // unpinned pip install, a `shell=True` tool-misuse signal, a privileged
    // Kubernetes cache-warmer job) accumulate to an ACTUAL score of 54 --
    // genuinely crossing the OLD >=51 DoNotInstall band, not just approaching
    // it -- but with no BLOCKING_ELIGIBLE id present. Must cap at Caution.
    ("benign_high_accumulation", Recommendation::Caution, &[]),
    // --- BLOCKED: must be DoNotInstall via the named genuine Critical signal ---
    ("malicious_remote_exec", Recommendation::DoNotInstall, &["skill.rce.pipe_to_shell"]),
    ("malicious_remote_exec_wrapped", Recommendation::DoNotInstall, &["skill.rce.pipe_to_shell"]),
    ("malicious_credential_exfil", Recommendation::DoNotInstall, &["skill.snoop.credential_exfil"]),
    ("malicious_conversation_exfil", Recommendation::DoNotInstall, &["skill.inject.data_exfil"]),
    ("malicious_cloud_metadata", Recommendation::DoNotInstall, &["skill.ssrf.cloud_metadata"]),
    // --- EDGE: ACTUAL verdict, confirmed by running (see per-fixture comments below) ---
    ("edge_malicious_prose_directive", Recommendation::Caution, &["skill.inject.external_xmit"]),
    ("edge_real_typosquat", Recommendation::Safe, &["skill.sc.typosquat"]),
    ("edge_credential_read_only", Recommendation::Caution, &["skill.snoop.credential_file"]),
];

fn scan(dir: &str) -> skillscan::SkillScanResult {
    skillscan::scan_skill(Path::new(CORPUS_DIR).join(dir).as_path())
}

fn ids(r: &skillscan::SkillScanResult) -> Vec<&str> {
    r.findings.iter().map(|f| f.id.as_str()).collect()
}

#[test]
fn corpus_fixtures_match_expected_recommendation_and_findings() {
    for (dir, expected, required) in EXPECTATIONS {
        let r = scan(dir);
        assert_eq!(&r.recommendation, expected,
            "{dir}: expected {expected:?}, got {:?} (score {}); findings: {:?}",
            r.recommendation, r.score, ids(&r));
        for id in *required {
            assert!(ids(&r).contains(id),
                "{dir}: expected required finding {id:?} to fire; findings: {:?}", ids(&r));
        }
    }
}

/// AGGREGATE sanity guard, independent of what `EXPECTATIONS` happens to
/// declare: re-derives the required verdict from the `benign_`/`malicious_`
/// directory-name PREFIX itself and checks it against the actual scan. This
/// catches a mislabeled EXPECTATIONS entry (e.g. someone adds a
/// `benign_something` fixture and typos its expected value to `Caution`) —
/// the prefix convention itself is the ground truth here, not the table.
#[test]
fn aggregate_prefix_convention_holds() {
    for (dir, _expected, _required) in EXPECTATIONS {
        let r = scan(dir);
        if *dir == "benign_high_accumulation" {
            // Fix #5 exception to the blanket "benign_* must be Safe" rule
            // below: this fixture is genuinely benign (no BLOCKING_ELIGIBLE
            // finding fires) but its accumulated score legitimately lands in
            // the Caution band -- fix #5's invariant is "accumulation alone
            // never reaches DoNotInstall", not "accumulation must be Safe".
            assert_ne!(r.recommendation, Recommendation::DoNotInstall,
                "benign_high_accumulation must never reach DoNotInstall via accumulation alone, got {:?} (score {}); findings: {:?}",
                r.recommendation, r.score, ids(&r));
        } else if dir.starts_with("benign_") {
            assert_eq!(r.recommendation, Recommendation::Safe,
                "{dir}: every benign_* fixture must resolve Safe, got {:?} (score {}); findings: {:?}",
                r.recommendation, r.score, ids(&r));
        } else if dir.starts_with("malicious_") {
            assert_eq!(r.recommendation, Recommendation::DoNotInstall,
                "{dir}: every malicious_* fixture must resolve DoNotInstall, got {:?} (score {}); findings: {:?}",
                r.recommendation, r.score, ids(&r));
        }
        // edge_* fixtures have no fixed prefix invariant; EXPECTATIONS pins
        // their actual verdict in the primary test above.
    }
}

// --- Targeted negative-finding regressions (the exact FP bugs this suite locks in) ---

#[test]
fn benign_stdlib_import_is_never_flagged_typosquat() {
    // Pre-fix, a bare `import urllib` was itself a typosquat candidate
    // (edit-distance 1 from `urllib3`). The typosquat check is install-scoped
    // only (SC6 candidates come from `pip install`/`npm install`/... tokens),
    // so a bare import must never trip it.
    let r = scan("benign_stdlib_import");
    assert!(!ids(&r).contains(&"skill.sc.typosquat"),
        "a bare `import urllib` must never be flagged as a typosquat; findings: {:?}", ids(&r));
}

#[test]
fn benign_ssh_pubkey_is_never_flagged_credential_file() {
    // The PUBLIC half of an SSH keypair (`~/.ssh/id_rsa.pub`) is not a secret.
    // `credential_file_hits` explicitly excludes matches ending in `.pub`.
    let r = scan("benign_ssh_pubkey");
    assert!(!ids(&r).contains(&"skill.snoop.credential_file"),
        "reading the PUBLIC key (.pub) must not be flagged as a credential-file read; findings: {:?}",
        ids(&r));
}

#[test]
fn benign_combined_stays_well_clear_of_do_not_install() {
    // The realistic corpus shape that used to score DoNotInstall before the
    // Task 1 FP-reduction pass: undeclared network+file capabilities stacked
    // with an unpinned pip install, no manifest capabilities declared at all.
    // Locking in the actual score (not just the band) catches any regression
    // that pushes this shape back toward the Caution/DoNotInstall boundary.
    let r = scan("benign_combined");
    assert!(r.score < 21,
        "benign_combined score drifted toward the Caution band (score {}); findings: {:?}",
        r.score, ids(&r));
}

#[test]
fn benign_high_accumulation_actually_crosses_the_old_do_not_install_band() {
    // Fix #2 accuracy check: the fixture's comment previously claimed it
    // "would have crossed the OLD >=51 band" while actually scoring 37 --
    // already Caution under the OLD scoring too, so it never exercised the
    // regression it claimed to guard. The fixture now includes enough
    // distinct non-eligible findings (LP1/LP3 capability hygiene, TM1
    // shell=True, TM2 chaining, TM4 privileged-Kubernetes job, SC1 unpinned
    // install, RP1 unpinned reference) that the score genuinely reaches the
    // OLD DoNotInstall threshold by accumulation alone. Pinning the exact
    // score (not just the >=51 floor) catches any detector change that
    // silently pulls this fixture back under the band it exists to probe.
    let r = scan("benign_high_accumulation");
    assert_eq!(r.score, 54,
        "benign_high_accumulation score drifted (findings: {:?})", ids(&r));
    assert!(r.score >= 51,
        "benign_high_accumulation must genuinely cross the OLD >=51 DoNotInstall \
         band by accumulation alone (score {}); findings: {:?}", r.score, ids(&r));
    assert_eq!(r.recommendation, Recommendation::Caution,
        "must cap at Caution -- no BLOCKING_ELIGIBLE finding fires (score {}); findings: {:?}",
        r.score, ids(&r));
    assert!(!ids(&r).iter().any(|id| ["skill.rce.pipe_to_shell", "skill.snoop.credential_exfil",
        "skill.ssrf.cloud_metadata", "skill.inject.data_exfil"].contains(id)),
        "fixture must stay genuinely benign -- no eligible dropper/exfil/cloud-metadata finding; findings: {:?}",
        ids(&r));
}

#[test]
fn malicious_remote_exec_wrapped_fires_the_same_critical_signal_as_unwrapped() {
    // A `sudo`/`env` wrapper right after the pipe must not evade COV1 — both
    // the bare and wrapped dropper must produce the identical Critical
    // finding and hard-block via the same code path.
    let unwrapped = scan("malicious_remote_exec");
    let wrapped = scan("malicious_remote_exec_wrapped");
    assert!(ids(&unwrapped).contains(&"skill.rce.pipe_to_shell"));
    assert!(ids(&wrapped).contains(&"skill.rce.pipe_to_shell"));
    assert_eq!(unwrapped.recommendation, Recommendation::DoNotInstall);
    assert_eq!(wrapped.recommendation, Recommendation::DoNotInstall);
}

#[test]
fn edge_credential_read_only_does_not_escalate_to_the_exfil_correlation() {
    // Reading a credential file WITHOUT any external-transmission signal in
    // the same script must stay at the standalone High `credential_file`
    // finding — it must never correlate into the Critical `credential_exfil`
    // finding (that requires both signals in the same file; see COV3).
    let r = scan("edge_credential_read_only");
    assert!(!ids(&r).contains(&"skill.snoop.credential_exfil"),
        "a credential read with no transmission signal must not escalate to credential_exfil; findings: {:?}",
        ids(&r));
    assert_ne!(r.recommendation, Recommendation::DoNotInstall,
        "a lone credential-file read (no exfil) must not hard-block; findings: {:?}", ids(&r));
}

#[test]
fn edge_real_typosquat_detection_is_retained_even_though_it_does_not_block_alone() {
    // `reqests` is edit-distance-1 from `requests` (POPULAR). SC6 is Low
    // severity by design (a suspicion worth a second look, not proof of
    // malice), so this fixture alone must stay well under DoNotInstall — but
    // the finding itself must still fire, proving the FP-reduction pass
    // didn't remove detection entirely.
    let r = scan("edge_real_typosquat");
    assert!(ids(&r).contains(&"skill.sc.typosquat"));
    assert_ne!(r.recommendation, Recommendation::DoNotInstall);
}
