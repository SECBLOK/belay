//! Named-bypass regression corpus for Belay's command gate (`decide()`).
//!
//! One file per evasion-technique bucket — `ls` this directory to see the
//! taxonomy of evasions defended against, without opening any file:
//!
//! - `wrapper_prefix`         — sudo / `\cmd` / `env FOO=bar` / bare `FOO=bar` / `command` / `env -C`
//! - `path_normalization`     — absolute paths, versioned interpreters, Windows path forms
//! - `compound_command`       — `&&`/`||`/`;`/pipes, reversed order, redirection
//! - `line_continuation`      — backslash-newline flag splitting
//! - `long_flag_and_multi_arg` — `--force` vs `-f`, `-r -f` vs `-rf`, `--recursive --force`
//! - `quoting`                — quoted-token-split, quoted targets
//! - `inline_interpreter`     — `python -u -c`, versioned interpreters
//! - `heredoc`                — `<<EOF | bash`
//! - `script_file`            — referenced-script-file exec shapes (write-then-run); fail-open pins only, see that module's own doc for why
//! - `false_positive_guards`  — echo/comment/commit-message/grep — must NOT deny
//! - `fetch_chmod_exec`       — download → chmod +x → exec dropper (single-command forms; cross-call forms live in `engine::dropper` tests)
//! - `data_region_masking`    — classifier must-deny verification (sh -c, the carve-out, depth-0) — must NOT over-mask
//! - `execution_context`      — forward-looking: needs branch/session state, not text
//! - `powershell_alias`       — PowerShell built-in cmdlet aliases for Remove-Item (rm/del/erase/rd/rmdir), force-optional bare-drive-root
//! - `ransomware_hallmarks`   — vssadmin/wmic shadowcopy/bcdedit/cipher anti-recovery commands
//! - `system_abuse`           — fork bombs (POSIX self-pipe, Windows batch `%0|%0`) + raw-disk-device writes (`dd`/redirect to `/dev/sd*` etc.)
//!
//! Every `Active` case is a permanent regression pin, asserted by
//! `active_cases_match_expected_decision` below — a failure there is a real
//! regression of a previously-working detection or false-positive guard.
//!
//! Every `KnownMiss` case is an *inverted canary*: its `expected` holds the
//! CURRENT (documented-wrong) decision, so the canary passes today and fails
//! loudly the moment the behavior changes — that failure is the signal to
//! graduate the case to `Active` with the corrected `expected`. Each
//! `KnownMiss` case carries a `// SHOULD BE: ...` comment recording the
//! target decision and which follow-on feature is expected to fix it.
//!
//! See `docs/superpowers/specs/2026-07-17-command-gate-bypass-corpus-design.md`
//! for the full design and the empirical audit behind every case below. Note:
//! two false-positive-guard cases in this corpus (`fp_guard_git_force_in_commit_message`,
//! `fp_guard_git_force_in_log_grep`) are filed as `Active`, not `KnownMiss`, even
//! though that design doc's audit narrative describes them as a "confirmed
//! active bug" — re-verified empirically against the real `decide()` entry
//! point (not just `RuleSet::matches`) while writing this corpus, both are
//! already correctly `Allow` today because the dev-toolchain allowlist
//! (`allow.git`, matching the `git commit`/`git log` prefix with no
//! shell-chaining metacharacter present) downgrades the underlying
//! `destructive.git_force` Ask to Allow before `decide()` returns. The design
//! doc's throwaway audit harness evidently exercised `RuleSet::matches`
//! directly and did not go through the allowlist stage of `decide()`.

use crate::engine::decide::decide;
use crate::engine::rules::RuleSet;
use crate::engine::types::{Decision, SessionState, ToolCall};

mod compound_command;
mod data_region_masking;
mod execution_context;
mod false_positive_guards;
mod fetch_chmod_exec;
mod heredoc;
mod inline_interpreter;
mod line_continuation;
mod long_flag_and_multi_arg;
mod path_normalization;
mod powershell_alias;
mod quoting;
mod ransomware_hallmarks;
mod script_file;
mod system_abuse;
mod wrapper_prefix;

/// A single named regression case: one command-string-or-tool-call, one
/// expected `decide()` outcome, one human-readable reason it must be that way.
#[derive(Clone, Copy)]
pub(crate) struct Case {
    /// Permanent, grep-able identifier. This is what gets checked before
    /// adding a new case for a "rediscovered" bypass — if the name already
    /// exists, the bug is a regression of THIS case, not a new one.
    pub name: &'static str,
    /// "Bash" | "Read" | "Write" | ...
    pub tool: &'static str,
    /// `ToolCall.input` shape, e.g. `|| json!({"command": "..."})`. A `fn`
    /// pointer (not a bare `Value`) because `serde_json::Value` is not
    /// const-constructible.
    pub input: fn() -> serde_json::Value,
    pub expected: Decision,
    pub status: CaseStatus,
    /// Taxonomy bucket — matches the file this case lives in (redundant with
    /// file location, kept explicit so a failure message is self-contained).
    pub technique: &'static str,
    /// One line: why this must (or must not) be denied. Printed verbatim in
    /// the failure message, so treat it as user-facing documentation, not a
    /// code comment.
    pub rationale: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) enum CaseStatus {
    /// Must pass today. A failure here is a real regression — the whole
    /// point of this corpus.
    Active,
    /// Confirmed miss/false-positive at design time; not yet fixable by the
    /// current text-pattern engine. Runs as an inverted canary — see the
    /// module doc above. `tracking` names the follow-on feature (or work
    /// item) expected to fix/graduate it.
    KnownMiss { tracking: &'static str },
}

const ALL_BUCKETS: &[&[Case]] = &[
    wrapper_prefix::CASES,
    path_normalization::CASES,
    compound_command::CASES,
    line_continuation::CASES,
    long_flag_and_multi_arg::CASES,
    quoting::CASES,
    inline_interpreter::CASES,
    heredoc::CASES,
    script_file::CASES,
    false_positive_guards::CASES,
    fetch_chmod_exec::CASES,
    data_region_masking::CASES,
    execution_context::CASES,
    powershell_alias::CASES,
    ransomware_hallmarks::CASES,
    system_abuse::CASES,
];

fn all_active_cases() -> Vec<&'static Case> {
    ALL_BUCKETS
        .iter()
        .flat_map(|bucket| bucket.iter())
        .filter(|c| matches!(c.status, CaseStatus::Active))
        .collect()
}

fn all_known_miss_cases() -> Vec<&'static Case> {
    ALL_BUCKETS
        .iter()
        .flat_map(|bucket| bucket.iter())
        .filter(|c| matches!(c.status, CaseStatus::KnownMiss { .. }))
        .collect()
}

#[test]
fn active_cases_match_expected_decision() {
    let rs = RuleSet::load().unwrap();
    let mut failures = Vec::new();
    for c in all_active_cases() {
        let mut st = SessionState::new("bypass-corpus");
        let tc = ToolCall {
            session: "bypass-corpus".into(),
            tool: c.tool.into(),
            input: (c.input)(),
        };
        let v = decide(&rs, &tc, &mut st);
        if v.decision != c.expected {
            failures.push(format!(
                "[{}] ({}) expected {:?}, got {:?} — {}",
                c.name, c.technique, c.expected, v.decision, c.rationale
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "bypass-corpus regressions:\n{}",
        failures.join("\n")
    );
}

#[test]
fn known_miss_canaries_still_reproduce() {
    // Each KnownMiss asserts the CURRENT (documented-wrong) decision. A failure
    // here means the behavior changed — go graduate the case to Active.
    let rs = RuleSet::load().unwrap();
    let mut surprises = Vec::new();
    for c in all_known_miss_cases() {
        let mut st = SessionState::new("bypass-corpus");
        let tc = ToolCall {
            session: "bypass-corpus".into(),
            tool: c.tool.into(),
            input: (c.input)(),
        };
        let v = decide(&rs, &tc, &mut st);
        if v.decision != c.expected {
            let tracking = match c.status {
                CaseStatus::KnownMiss { tracking } => tracking,
                CaseStatus::Active => "",
            };
            surprises.push(format!(
                "[{}] KnownMiss (tracking: {}) now yields {:?} (was {:?}) — GRADUATE IT",
                c.name, tracking, v.decision, c.expected
            ));
        }
    }
    assert!(
        surprises.is_empty(),
        "KnownMiss canaries changed:\n{}",
        surprises.join("\n")
    );
}
