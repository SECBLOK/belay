//! Bucket: the data-region classifier's own must-deny verification set
//! (`engine::data_region::mask_data_regions`, wired into `rules::norm_cmd`).
//!
//! These are the "must NOT stop being caught" and "new cases this design
//! must hand-verify" commands from
//! `docs/superpowers/specs/2026-07-17-command-gate-exec-context-classifier-design.md`
//! ("Verification"), empirically re-checked against the real `decide()`
//! entry point while writing this bucket (the design doc's own table was
//! hand-traced only — "no implementation exists to run yet" — so two gaps
//! surfaced here that a straight read of that table would have missed; see
//! `data_region_sh_c_dangerous_root_quote_adjacency` and the note on
//! `data_region_sh_c_not_data_consuming` below).
//!
//! Unlike `false_positive_guards.rs` (inert text that must NOT deny), every
//! case here proves the classifier's narrow data-consuming table does NOT
//! over-mask — real danger sitting next to (but outside) a data region must
//! still be caught.
//!
//! FIX-2 rework (this bucket's own cases): the classifier no longer tries to
//! find where a `$(...)`/backtick substitution *closes* — it only detects
//! that one is *present*, and disqualifies the whole data-consuming argument
//! from content-masking the instant one is seen outside single quotes. This
//! eliminates the false-negative class the old close-parsing scanner kept
//! reopening (any bash construct producing a bare `)` with no matching
//! `(` — a subshell group, a `case pat)` arm, an extglob, ...) by
//! construction, not by enumeration. `data_region_case_statement_bare_paren`
//! below is the case that motivated the rework: a `case x)` arm's bare `)`
//! has no matching `(` at all, so even the prior fix's bare-paren-depth
//! counter (added for the subshell-group shape) still mistook it for the
//! substitution's own close.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "data_region_sh_c_not_data_consuming",
        tool: "Bash",
        // A trailing space before the closing quote keeps the target
        // adjacent to whitespace (see the KnownMiss case below for why the
        // brief's literal `sh -c "rm -rf /"` does not deny). This case's
        // job is narrower and unambiguous: prove `sh -c`'s quoted argument
        // is never masked (haystack == input, verified byte-for-byte while
        // writing this case), so whatever the underlying pattern can catch
        // there, it still does.
        input: || serde_json::json!({"command": "sh -c \"rm -rf / \""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "`sh`/`bash -c` are never on the data-consuming table — the quoted `-c` argument stays executed/visible, exactly like `powershell -c \"...\"` and `python -c \"...\"` already do",
    },
    Case {
        name: "data_region_sh_c_dangerous_root_quote_adjacency",
        tool: "Bash",
        input: || serde_json::json!({"command": "sh -c \"rm -rf /\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "graduated by inline-script/heredoc body extraction (Task 4), not by wrapper/prefix normalization as originally tracked: the design doc's own hand-trace (written before any implementation existed) predicted this would graduate once normalization shipped, since it's the same class as `quoting.rs`'s `quoting_target_root` (`rm -rf \"/\"`) — but normalization's transform 5 only unwraps a quoted TARGET argument, and here the whole `rm -rf /` sits inside `sh -c`'s OWN `-c` argument, one token-depth deeper than normalization's position-scoping can reach (its first-token slot is `sh`, not `rm`). Extraction pulls `rm -rf /` out as its own haystack — critically without the enclosing quote character adjacent to `/` — so destructive.rm_rf's `(\\s|$)` requirement right after the target is satisfied by end-of-string where it previously wasn't (the classifier itself still makes zero change here; haystack == input, confirmed, exactly as originally documented)",
    },
    Case {
        name: "data_region_echo_command_substitution_carve_out",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"$(rm -rf /)\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "the mere presence of `$(` disqualifies echo's whole argument from content-masking, so `rm -rf /` stays visible even though it sits inside echo's data argument. The `$(`/`)` delimiter punctuation itself IS still masked unconditionally (it carries no content) so it cannot land a stray `)` immediately after the disqualified target and break destructive.rm_rf's own adjacency check the way leaving it fully untouched would",
    },
    Case {
        name: "data_region_git_commit_message_command_substitution_carve_out",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m \"backup: $(rm -rf /old_data)\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "presence-only disqualification correctly keeps `rm -rf /old_data` visible in the haystack (confirmed: `git commit -m rm -rf /old_data`) — the *decision* is Allow only because destructive.rm_rf's pattern is itself scoped to dangerous roots (/, ~, $HOME, ., *) and a scoped path like /old_data was never in that pattern's coverage, on or off this classifier; that scope limitation is pre-existing and out of scope here (see the design doc's 'Where this design draws its own line')",
    },
    Case {
        name: "data_region_eval_depth_zero_only",
        tool: "Bash",
        input: || serde_json::json!({"command": "eval \"$(echo 'rm -rf /')\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "`eval` is not on the data-consuming table at all, so its argument is never scanned as a data region — the classifier leaves this command byte-for-byte unchanged (confirmed), full stop, regardless of what data-consuming commands (here, `echo`) happen to sit inside it. It denies via rce.decode_exec, not destructive.rm_rf, but the point under test — the text stays visible — holds either way. (This case's name predates the FIX-2 rework, which removed the depth-0-only restriction entirely along with the recursive substitution-close scanning it protected against; kept for continuity as a permanent regression pin)",
    },
    Case {
        name: "data_region_single_quoted_dollar_paren_stays_inert",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo 'literal $(rm -rf /) text'"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "single quotes suppress the shell's own substitution — the single-quote exemption means `$(` here does not disqualify the argument from content-masking",
    },
    Case {
        name: "data_region_nested_single_quote_inside_double_quoted_echo_argument",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "echo \"never run 'r'm -rf / on prod\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "a single quote has no special meaning inside a double-quoted span in real bash — it's literal content, not a nested quote delimiter — so this whole double-quoted argument has zero execution-capable constructs (the `'r'm` split never forms a `(` or `$(` either way) and content-masks as one span, same as prior behavior; must not newly break",
    },
    Case {
        name: "data_region_bare_paren_subshell_inside_dollar_paren",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"$( (true); rm -rf / )\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "Critical false-negative fix: a real shell balances the bare `(true)` subshell group before the enclosing `$(...)` closes, so `rm -rf /` genuinely runs. A prior fix (the bare-paren-depth counter) patched exactly this shape, but was itself superseded by the FIX-2 rework below: the classifier no longer looks for where `$(...)` closes at all — the mere presence of the inner `(` (or the outer `$(`) disqualifies the whole echo argument from content-masking, so `rm -rf /` stays visible regardless of how the parens nest",
    },
    Case {
        name: "data_region_case_statement_bare_paren",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "echo \"$( case x in x) rm -rf / ;; esac )\""})
        },
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "The case that motivated the FIX-2 presence-detection rework: a `case x)` arm's bare `)` has no matching `(` at all — even the bare-paren-DEPTH counter (which only balances a `(...)` group that has a real opener) still mistook this `)` for the substitution's own close, wrongly ending it right after `x)` and reprocessing `rm -rf / ;; esac )` as ordinary masked echo data. Presence-only detection has no such blind spot: any bare `(` or `$(` anywhere in the argument (here, the outer `$(`) disqualifies content-masking outright, so this — and every other bare-`)`-producing shape (extglob, `select`, array subscripts, ...) — denies by construction",
    },
    Case {
        name: "data_region_escaped_quote_does_not_swallow_next_command",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo hi \\\" ; rm -rf / \\\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "Critical false-negative fix: `\\\"` in unquoted context is a backslash-escaped, literal quote character — it does not open a real quoted span. The scanner used to toggle quote state on it anyway, so the real `;` separator and the entire `rm -rf /` command that follows were wrongly absorbed into echo's masked data region — this command wrongly resolved Allow before the escape-awareness fix. `rm -rf /` is a real, separate, executed command here",
    },
    Case {
        name: "data_region_disqualified_argument_denies_on_separately_dangerous_literal_text",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"$(date) rm -rf /\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "The deliberately accepted safe false-positive of the FIX-2 presence-detection rework: `$(date)` disqualifies the whole echo argument from content-masking, so the separately dangerous literal text `rm -rf /` — merely echoed here, never actually run — is left visible too, and now denies. This is the safe direction (fail toward blocking, not toward hiding) traded for eliminating the close-parsing false-negative class; never traded back",
    },
    // ---- FIX-3: bare `$` disqualifies too (bash 5.3 `${ ...; }` funsub) --
    //
    // FIX-2 enumerated only `$(`, backtick, and bare `(` as disqualifying,
    // which missed bash 5.3's `${ command; }` funsub (opens with `${`, not
    // `$(`) — `echo "${ rm -rf / ; }"` was wrongly bulk-masked and denied
    // decide() an Allow it should never have gotten. FIX-3 broadens the
    // disqualifying set to ANY `$`, which is provably complete: every
    // command-execution-from-argument form needs `$`, a backtick, or `(`.
    Case {
        name: "data_region_funsub_inside_echo_denies",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"${ rm -rf / ; }\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "the funsub case that motivated FIX-3: a bare `$` (not followed by `(`) now disqualifies echo's whole argument from content-masking, same as `$(`/backtick/bare `(` already did, so `rm -rf /` stays visible and denies",
    },
    Case {
        name: "data_region_funsub_inside_printf_denies",
        tool: "Bash",
        input: || serde_json::json!({"command": "printf \"%s\" \"${ rm -rf / ; }\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "same funsub gap as data_region_funsub_inside_echo_denies, via printf's argument list",
    },
    Case {
        name: "data_region_funsub_inside_git_commit_message_denies",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m \"backup: ${ rm -rf / ; }\""})
        },
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "same funsub gap as data_region_funsub_inside_echo_denies, via git commit -m's value",
    },
    Case {
        name: "data_region_funsub_inside_git_log_grep_denies",
        tool: "Bash",
        input: || serde_json::json!({"command": "git log --grep \"${ rm -rf / ; }\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "data_region_masking",
        rationale: "same funsub gap as data_region_funsub_inside_echo_denies, via git log --grep's value",
    },
];
