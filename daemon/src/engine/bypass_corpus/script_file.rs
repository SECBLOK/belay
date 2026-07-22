//! Bucket: referenced-script-file resolution shapes (`engine::extract::
//! resolve_script_files`, `shape: "script_file"`) — closes the write-then-run
//! bypass (a `Write`'d script's bytes were never scanned; running it via a
//! syntactically-clean `bash x.sh` defeated the whole catalog).
//!
//! File-resolution genuinely needs a real file on disk to prove a *Deny* (the
//! resolved content is what gets scanned) — that can't be expressed as a pure
//! `Case` (`input` is a plain `fn() -> Value` with no captured state, and the
//! corpus driver builds no files). Those content-dependent assertions live in
//! `engine::script_file_tests` (dedicated temp-file tests) instead.
//!
//! What *is* expressible here, pure-string, is that each recognized
//! script-exec **shape** is reached and exercised by `resolve_script_files`
//! without regressing to a panic or an unexpected Deny: every case below
//! references a file that does not exist (or, for `direct_dot_slash_shape`, a
//! relative path with no `cwd` on the tool call at all), so resolution always
//! fails open — `expected: Decision::Allow` pins "the code path runs and
//! degrades safely," not "this content is dangerous." Regression value: if a
//! future change to `detect_script_exec_file`/`resolve_path` ever started
//! treating one of these shapes as *not* script-exec at all (silently
//! skipping detection), these would keep passing by coincidence — so they are
//! deliberately paired with the pure-logic `detect_script_exec_file` unit
//! tests in `engine::extract`'s own test module, which assert the shape is
//! actually recognized (`Some(...)`), not just that `decide()` stays Allow.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "script_file_direct_dot_slash_shape_fail_open",
        tool: "Bash",
        input: || serde_json::json!({"command": "./x.sh"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "script_file",
        rationale: "direct `./x.sh` execution is a recognized script-exec shape (form 3), but with no `cwd` on the tool call the relative path is never resolved (fail-open, no filesystem access) — the content-dependent Deny (same shape, real file, cwd set) is pinned in engine::script_file_tests::direct_dot_slash_form_via_cwd_denies",
    },
    Case {
        name: "script_file_bash_absolute_nonexistent_shape_fail_open",
        tool: "Bash",
        input: || serde_json::json!({"command": "bash /no/such/file-belay-corpus-pin.sh"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "script_file",
        rationale: "`bash <absolute path>` is a recognized script-exec shape (form 1), but the referenced file does not exist — resolution fails open (no panic, no body, no change to the outer Allow) — the content-dependent Deny is pinned in engine::script_file_tests::bash_absolute_path_flag_separation_denies",
    },
    Case {
        name: "script_file_source_keyword_shape_fail_open",
        tool: "Bash",
        input: || serde_json::json!({"command": "source /no/such/file-belay-corpus-pin.sh"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "script_file",
        rationale: "`source <path>` is a recognized script-exec shape (form 2), same fail-open proof as the sibling cases above — the content-dependent Deny is pinned in engine::script_file_tests::source_keyword_form_denies",
    },
];
