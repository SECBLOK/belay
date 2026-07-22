//! Bucket: quoted-argument edge cases.
//!
//! Adjacent-quote token splitting and quoted destructive targets were
//! confirmed silent misses, graduated to `Active` by wrapper/flag
//! normalization's quote-unwrap transform (position-scoped to the
//! command-name slot and the token immediately following `rm`'s flag
//! cluster — see `canonicalize::unwrap_quoted_tokens`/
//! `unwrap_target_token_quotes`, and `false_positive_guards`'s
//! `fp_guard_quote_spliced_warning_in_echo` for the regression proof that
//! this scoping holds). A scoped project subfolder (`./build`) must not be
//! treated as a dangerous root — already correctly handled (`Active`).

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "quoting_split_command_token",
        tool: "Bash",
        input: || serde_json::json!({"command": "'r'm -rf /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "quoting",
        rationale: "adjacent-quote concatenation is valid shell syntax; the literal characters `r`,`m` are never contiguous in the raw command text, but the command-name-slot quote-unwrap makes `'r'm` -> `rm` in the canonical form",
    },
    Case {
        name: "quoting_target_root",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -rf \"/\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "quoting",
        rationale: "quoted target — a quote character breaks the required target-class adjacency, but the target-argument quote-unwrap (scoped to the token right after `rm`'s flag cluster) makes `\"/\"` -> `/` in the canonical form",
    },
    Case {
        name: "quoting_target_dollar_home",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -rf \"$HOME\""}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "quoting",
        rationale: "same gap, `$HOME` target, graduated the same way",
    },
    Case {
        name: "quoting_scoped_subfolder_not_denied",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -rf ./build"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "quoting",
        rationale: "FP guard: a scoped project subfolder must not be treated as a dangerous root — already correctly handled (the `.` target-class match requires `(\\s|$)` immediately after, which a following `/build` breaks)",
    },
];
