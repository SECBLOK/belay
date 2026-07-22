//! Bucket: inline-interpreter flags (`python -c`, and variants) and quoted
//! bodies (`bash -c`, `eval`).
//!
//! The unversioned baseline (`python -c ... exec(`) is already caught
//! (`Active`). An extra flag before `-c` (e.g. `-u`, unbuffered) was a
//! confirmed silent miss, graduated to `Active` by wrapper/flag
//! normalization's benign-preflag collapse (transform 6.4).
//!
//! The four cases below were graduated by inline-script/heredoc body
//! extraction (`engine::extract`, Task 4 of
//! `docs/superpowers/specs/2026-07-17-command-gate-inline-script-extraction-design.md`).
//! Extraction's job is narrow: it pulls the literal text inside a quoted
//! `-c`/`eval` argument out as its own haystack, so it becomes genuinely
//! first-token-of-segment for `canonicalize()`'s position-scoped transforms
//! (which the *outer* command's segment splitter can never make it, since
//! `rm` sits one token-depth inside `bash`'s/`eval`'s own argument) — every
//! actual detection here still comes from `canonicalize()`'s existing
//! transforms (flag-cluster-merge, target-quote-unwrap), not a new pattern.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "inline_interpreter_decode_exec_baseline",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "python -c \"import os; exec(open('x').read())\""})
        },
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "baseline: unversioned `python -c` + `exec(` is already caught",
    },
    Case {
        name: "inline_interpreter_extra_flag_before_dash_c",
        tool: "Bash",
        input: || serde_json::json!({"command": "python -u -c \"exec(x)\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "an extra flag (`-u`, unbuffered) before `-c` breaks the required `python\\d?\\s+-c` adjacency; graduated by wrapper/flag normalization dropping recognized benign CPython preflags between the interpreter and `-c`",
    },
    Case {
        name: "inline_interpreter_bash_c_multi_arg_flags",
        tool: "Bash",
        input: || serde_json::json!({"command": "bash -c \"rm -r -f /\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "flag-separation bypass hidden inside a `bash -c` body; unreachable by `canonicalize()`'s position-scoping alone since `rm` isn't first-token-of-segment at the outer level (`bash` is) — extraction pulls the body out as its own haystack, making `rm` genuinely first-token there, so canonicalize's existing flag-cluster-merge transform folds `-r -f` to `-rf` and destructive.rm_rf fires",
    },
    Case {
        name: "inline_interpreter_eval_quoted_multi_arg_flags",
        tool: "Bash",
        input: || serde_json::json!({"command": "eval \"rm -r -f /\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "was a TOTAL miss before extraction — verified against every catalog pattern, not just destructive.rm_rf: the pre-existing `rce.decode_exec` pattern (`eval\\s+\"?\\$\\(`) only covers the `eval \"$(...)\"` form, not a plain literal string argument. Extraction's `eval`-specific detector (distinct from the interpreter+`-c` detectors, since `eval` is a shell builtin taking its quoted argument directly) closes this",
    },
    Case {
        name: "inline_interpreter_sh_c_quoted_target",
        tool: "Bash",
        input: || serde_json::json!({"command": "sh -c \"rm -rf \\\"/\\\"\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "compound case: needed extraction *and* transform 5's target-argument quote-unwrap to compose. Critically, extraction must first reverse the outer shell's own double-quote backslash-escape removal (`\\\"` -> `\"`) to recover the actual argument value `rm -rf \"/\"` (real quote characters) — without that unescape step the target token would start with a literal `\\`, not a real quote character, and `canonicalize::unwrap_target_token_quotes` would never recognize it as a quoted target at all (see `extract::unescape_double_quoted`'s own doc). With real quotes recovered, the body's own first-token context lets that existing transform fire, unwrapping `\"/\"` to `/` so destructive.rm_rf's target pattern matches",
    },
    Case {
        name: "inline_interpreter_bare_env_prefix_bash_c",
        tool: "Bash",
        input: || serde_json::json!({"command": "FOO=bar bash -c \"rm -r -f /\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "Task 2 fix 3's extraction-side twin of `wrapper_prefix::wrapper_bare_env_assignment_prefix`: before the fix, `segment_command_word` (which reuses `canonicalize::strip_wrapper_prefixes`) resolved this segment's command word to the bare `FOO=bar` token itself, not `bash` — so `bash -c \"...\"` was never recognized as the segment's actual interpreter shape, extraction found zero bodies, and the whole command was `Allow`",
    },
    Case {
        name: "inline_interpreter_double_wrapped_not_extracted",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "bash -c \"bash -c \\\"rm -r -f /\\\"\""})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "inline_interpreter",
        rationale: "documents the intentional no-recursion limitation (Owner Decision 2A): extraction runs exactly once per outer command and never re-scans an already-extracted body's own text, so a second, inner `bash -c` wrapping stays a permanent, honest miss — pinned the same way `compound_pipe_target_via_xargs` pins the `xargs` dataflow gap, so it can never be mistaken for an accidental regression. (The extracted OUTER body is `bash -c \\\"rm -r -f /\\\"` — its own first token is `bash`, not `rm`, so canonicalize's flag-merge never fires on it either, consistent with zero recursion happening anywhere in this path.)",
    },
];
