//! Dedicated temp-file tests for referenced-script-file resolution
//! (`engine::extract::resolve_script_files`) — see
//! `docs/superpowers/specs/2026-07-17-command-gate-script-file-resolution-design.md`,
//! "Testing".
//!
//! File-resolution can't be expressed as a pure-string `bypass_corpus::Case`:
//! a `Case`'s `input` is a plain `fn() -> serde_json::Value` with no captured
//! state, and the corpus driver builds no files on disk. These tests instead
//! create a real temp script and drive `decide()` end to end, exactly as the
//! design's own Testing section prescribes. Shape-level (file-absent)
//! regression pins for the detection forms themselves — provable without a
//! real backing file — live in `bypass_corpus::script_file` instead; pure
//! detection-logic unit tests (no filesystem I/O at all) live alongside
//! `detect_script_exec_file` in `engine::extract`'s own test module.

use crate::engine::decide::decide;
use crate::engine::rules::RuleSet;
use crate::engine::types::{Decision, SessionState, ToolCall};

/// One flag-separation payload (`rm -r -f /`) reused across every
/// bypass-closed case below — the same content, same bypass class, every
/// exec form: what varies is how the file gets *run*, not what's in it.
const DANGEROUS_CONTENT: &str = "rm -r -f /\n";

fn tc(command: &str, cwd: Option<&str>) -> ToolCall {
    let mut input = serde_json::json!({ "command": command });
    if let Some(cwd) = cwd {
        input["cwd"] = serde_json::json!(cwd);
    }
    ToolCall {
        session: "script-file-tests".into(),
        tool: "Bash".into(),
        input,
    }
}

fn decide_for(command: &str, cwd: Option<&str>) -> Decision {
    let rs = RuleSet::load().expect("catalog loads");
    let mut st = SessionState::new("script-file-tests");
    decide(&rs, &tc(command, cwd), &mut st).decision
}

fn write_script(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write temp script");
    path
}

// ============================================================================
// Bypass closed — every recognized exec form resolves and denies.
// ============================================================================

#[test]
fn bash_absolute_path_flag_separation_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Deny,
        "bash <absolute path to a flag-separated rm -r -f /> must resolve and deny"
    );
}

#[test]
fn dot_source_form_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cmd = format!(". {}", script.display());
    assert_eq!(decide_for(&cmd, None), Decision::Deny, "`. <path>` (dot-source) must resolve and deny");
}

#[test]
fn source_keyword_form_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cmd = format!("source {}", script.display());
    assert_eq!(decide_for(&cmd, None), Decision::Deny, "`source <path>` must resolve and deny");
}

#[test]
fn direct_dot_slash_form_via_cwd_denies() {
    let tmp = tempfile::tempdir().unwrap();
    write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cwd = tmp.path().to_str().unwrap();
    assert_eq!(
        decide_for("./x.sh", Some(cwd)),
        Decision::Deny,
        "direct `./x.sh` execution, resolved against cwd, must deny"
    );
}

#[test]
fn python_interpreter_form_denies() {
    let tmp = tempfile::tempdir().unwrap();
    // The design does not parse the target language's grammar — it scans
    // the file's bytes through the same catalog patterns regardless of what
    // interpreter runs them, same scope as the sibling inline-body feature.
    let script = write_script(tmp.path(), "deploy.py", DANGEROUS_CONTENT);
    let cmd = format!("python {}", script.display());
    assert_eq!(decide_for(&cmd, None), Decision::Deny, "`python <file>` with a shell-shaped payload must resolve and deny");
}

// ---- value-taking interpreter flags don't defeat resolution (Task 2 fix 2)

#[test]
fn python_dash_w_flag_value_does_not_defeat_resolution_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "evil.py", DANGEROUS_CONTENT);
    let cmd = format!("python -W ignore {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Deny,
        "`python -W ignore evil.py` must skip -W's value (`ignore`) and still resolve+deny on evil.py, not latch onto the flag's value"
    );
}

#[test]
fn ruby_dash_capital_i_flag_value_does_not_defeat_resolution_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "evil.rb", DANGEROUS_CONTENT);
    let cmd = format!("ruby -I lib {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Deny,
        "`ruby -I lib evil.rb` must skip -I's value (`lib`) and still resolve+deny on evil.rb"
    );
}

#[test]
fn node_dash_r_flag_value_does_not_defeat_resolution_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "evil.js", DANGEROUS_CONTENT);
    let cmd = format!("node -r ./pre {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Deny,
        "`node -r ./pre evil.js` must skip -r's value (`./pre`) and still resolve+deny on evil.js"
    );
}

#[test]
fn unrecognized_value_taking_flag_defeats_resolution_known_miss() {
    // SHOULD BE: Deny. Mirror of
    // `extract::script_file_shape_tests::unrecognized_value_taking_flag_still_defeats_resolution_known_miss`
    // at the full `decide()` level: an unrecognized value-taking flag (`-Z`,
    // not in the small per-interpreter allowlist) still gets its value
    // token mistaken for "the file" — the real `evil.py`, with genuinely
    // dangerous content, is never resolved or scanned. Documented residual
    // gap (design brief), pinned so it stays visible rather than a silent
    // miss.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let script = write_script(tmp.path(), "evil.py", DANGEROUS_CONTENT);
    let cmd = format!("python -Z something {}", script.display());
    assert_eq!(
        decide_for(&cmd, Some(cwd)),
        Decision::Allow,
        "KNOWN MISS: an unrecognized value-taking interpreter flag before the script still defeats resolution"
    );
}

// ---- relative-via-cwd (Bash form specifically, distinct from the direct
// `./x.sh` form above) --------------------------------------------------

#[test]
fn bash_relative_path_via_cwd_denies() {
    let tmp = tempfile::tempdir().unwrap();
    write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cwd = tmp.path().to_str().unwrap();
    assert_eq!(
        decide_for("bash x.sh", Some(cwd)),
        Decision::Deny,
        "`bash x.sh` with a relative filename must resolve against cwd and deny"
    );
}

// ============================================================================
// Fail-open — resolution failure never blocks, never panics.
// ============================================================================

#[test]
fn bash_nonexistent_absolute_path_allows_no_panic() {
    assert_eq!(
        decide_for("bash /no/such/file-belay-does-not-exist.sh", None),
        Decision::Allow,
        "a nonexistent absolute script path must fail open (Allow), never panic"
    );
}

#[test]
fn oversized_script_file_is_dropped_and_allows() {
    let tmp = tempfile::tempdir().unwrap();
    // Comfortably over the 256 KiB per-file cap; content itself is otherwise
    // dangerous, proving the cap — not the content — is what drops it.
    let big = format!("rm -r -f /\n{}", "a".repeat(300 * 1024));
    let script = write_script(tmp.path(), "big.sh", &big);
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Allow,
        "an oversized script file must be dropped (not truncated, not scanned) and fail open"
    );
}

#[test]
fn directory_target_allows_fast_no_hang() {
    // Regression pin for the read_bounded_script availability-DoS fix
    // (Task 2 fix 1): before the fix, `resolve_script_files` read the whole
    // referenced file via `std::fs::read` before ever checking its size or
    // type, which blocks indefinitely on a FIFO or a character device like
    // `/dev/zero` (`bash /dev/zero` never returns) — an availability DoS on
    // the security-critical `decide()` gate path. A directory is the
    // portable proxy for "non-regular file" this suite can construct
    // without shelling out or a POSIX-specific dependency (see
    // `extract::script_file_shape_tests`' own doc for why): `is_file()` is
    // false for it exactly like a FIFO/char device, so it exercises the
    // very same rejection branch. `bash <dir>` isn't dangerous content on
    // its own — what this pins is that `decide()` returns promptly and
    // Allow (fail-open), never hangs, never panics.
    let tmp = tempfile::tempdir().unwrap();
    let cmd = format!("bash {}", tmp.path().display());
    let start = std::time::Instant::now();
    let decision = decide_for(&cmd, None);
    let elapsed = start.elapsed();
    assert_eq!(decision, Decision::Allow, "resolving a directory as a script-exec target must fail open");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "decide() must return quickly even when the referenced script-exec path is a non-regular file (took {elapsed:?})"
    );
}

#[test]
fn absent_cwd_relative_path_allows() {
    // No cwd on the ToolCall at all — the relative path is skipped before
    // any filesystem access is attempted (see `resolve_path`), regardless of
    // whether a file named x.sh happens to exist anywhere.
    assert_eq!(
        decide_for("bash x.sh", None),
        Decision::Allow,
        "a relative script path with no cwd on the tool call must fail open (Allow)"
    );
}

// ============================================================================
// False-positive guards — only EXECUTED files are ever read.
// ============================================================================

#[test]
fn cat_reads_not_executes_allows() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cmd = format!("cat {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Allow,
        "`cat x.sh` reads the file but never executes it — must never be resolved/scanned"
    );
}

#[test]
fn benign_script_allows() {
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "hello.sh", "echo hello world\n");
    let cmd = format!("bash {}", script.display());
    assert_eq!(decide_for(&cmd, None), Decision::Allow, "a benign script's content must not spuriously deny");
}

#[test]
fn masked_echo_mention_allows() {
    // The `bash x.sh` text sits inside echo's own (masked) data argument —
    // never a real invocation. Set a real cwd with a REAL dangerous x.sh
    // present, so a false positive here would be a genuine masking failure,
    // not an accidental fail-open.
    let tmp = tempfile::tempdir().unwrap();
    write_script(tmp.path(), "x.sh", DANGEROUS_CONTENT);
    let cwd = tmp.path().to_str().unwrap();
    assert_eq!(
        decide_for(r#"echo "run bash x.sh""#, Some(cwd)),
        Decision::Allow,
        "`bash x.sh` merely mentioned inside an echo argument must never be resolved"
    );
}

#[test]
fn script_with_only_scoped_rm_allows() {
    let tmp = tempfile::tempdir().unwrap();
    // `rm -rf ./build` is an already-safe, project-scoped delete — the
    // existing destructive.rm_rf pattern only fires on dangerous roots
    // (/, ~, $HOME, ., *), so resolving and scanning this content must not
    // manufacture a new false positive.
    let script = write_script(tmp.path(), "clean.sh", "rm -rf ./build\n");
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Allow,
        "a script containing only a scoped, already-safe `rm -rf ./build` must not deny"
    );
}

#[test]
fn script_with_only_echoed_warning_allows() {
    // The script never RUNS `rm -rf /` — it only echoes a warning string
    // that happens to contain that text. Before the body-normalization fix,
    // extracted/resolved bodies were collapsed+canonicalized WITHOUT the
    // `data_region::mask_data_regions` pass the outer command gets, so the
    // echo argument's content (which mask_data_regions exists precisely to
    // blank out) was scanned literally and falsely denied. Real deploy/
    // install scripts routinely carry lines exactly like this one.
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "warn.sh", "echo \"danger: rm -rf / will wipe you\"\n");
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Allow,
        "a script that only echoes a warning mentioning `rm -rf /` must not be denied"
    );
}

#[test]
fn script_with_only_a_comment_mentioning_danger_allows() {
    // Same false-positive class as above, via a `#`-comment instead of an
    // echo argument — both are masked by `data_region::mask_data_regions`
    // for the outer command, and must be masked identically for a resolved
    // script-file body.
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(tmp.path(), "doc.sh", "# do NOT run rm -rf / ever\necho done\n");
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Allow,
        "a script whose only mention of `rm -rf /` is inside a comment must not be denied"
    );
}

#[test]
fn script_with_a_real_rm_rf_still_denies_despite_masking() {
    // Proves the masking fix above didn't overreach: `mask_data_regions`
    // only ever blanks data-consuming command *arguments* (echo/printf/git
    // commit -m/git log --grep) and comments — never a bare command
    // invocation. A script that actually RUNS `rm -r -f /` (not echoed, not
    // commented out) alongside an unrelated echoed warning must still deny.
    let tmp = tempfile::tempdir().unwrap();
    let script = write_script(
        tmp.path(),
        "real.sh",
        "echo \"about to clean up\"\nrm -r -f /\n",
    );
    let cmd = format!("bash {}", script.display());
    assert_eq!(
        decide_for(&cmd, None),
        Decision::Deny,
        "a script that actually executes `rm -r -f /` must still deny even with an unrelated echoed line present"
    );
}

// ============================================================================
// Additivity — a resolution failure never changes the outer decision either
// way: it can't manufacture a new Deny (fail-open, tested above), and it
// can't erase a Deny the outer raw command already earns on its own.
// ============================================================================

#[test]
fn unreadable_referenced_file_never_suppresses_an_outer_deny() {
    // The outer command is already dangerous on its own raw text
    // (`rm -rf /`), chained with a Bash call to a script file that does not
    // exist. Resolution of the second segment fails (fail-open, no body) —
    // it must never suppress the Deny the first segment already earns.
    assert_eq!(
        decide_for("rm -rf / && bash /no/such/file-belay-does-not-exist.sh", None),
        Decision::Deny,
        "an unresolvable referenced script must never suppress an outer command's own Deny"
    );
}

#[test]
fn unreadable_referenced_file_never_changes_an_outer_allow() {
    // Mirror of the above in the safe direction: a harmless outer command
    // plus an unresolvable script reference must stay Allow (already
    // exercised individually by the fail-open tests above; this pins the
    // additivity property — "contributes nothing" — explicitly by name).
    assert_eq!(
        decide_for("echo hi && bash /no/such/file-belay-does-not-exist.sh", None),
        Decision::Allow,
        "an unresolvable referenced script must never turn a harmless outer command into a Deny"
    );
}
