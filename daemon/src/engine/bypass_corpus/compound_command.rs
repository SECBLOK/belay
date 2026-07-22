//! Bucket: `&&`/`||`/`;`/pipes, reversed order, redirection, statement separators.
//!
//! Shell-chaining metacharacters and trailing/leading no-op commands don't hide
//! the literal destructive substring from the unanchored match (all `Active`).
//! `$IFS`-substitution (same shape as the line-continuation gap) was graduated
//! by wrapper/flag normalization. A dataflow-only case (`xargs`) remains — no
//! text-pattern fix can ever close it.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "compound_semicolon_suffix",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -rf / ; echo done"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "compound_command",
        rationale: "trailing chained command doesn't hide the substring",
    },
    Case {
        name: "compound_reversed_order",
        tool: "Bash",
        input: || serde_json::json!({"command": ": ; rm -rf /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "compound_command",
        rationale: "leading no-op + separator doesn't hide the substring; order-independence is a property of unanchored substring search",
    },
    Case {
        name: "compound_redirection_stderr_discard",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -rf / > /dev/null 2>&1"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "compound_command",
        rationale: "trailing redirection doesn't hide the target",
    },
    Case {
        name: "compound_allowlist_prefix_chain",
        tool: "Bash",
        input: || serde_json::json!({"command": "git checkout main && rm -rf /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "compound_command",
        rationale: "already proven by decide.rs::chained_allowlist_prefix_is_denied; dev-allowlist prefix + shell-chaining metacharacter must never downgrade a real Deny (defense-in-depth)",
    },
    Case {
        name: "compound_pipe_target_via_xargs",
        tool: "Bash",
        // SHOULD BE: Deny — but no owning feature: this needs dataflow/taint
        // tracking (the destructive target is never textual), not a
        // tokenizer/normalizer. Filed here so it stays visible, not silently
        // missing.
        input: || serde_json::json!({"command": "find / -type f | xargs rm -rf"}),
        expected: Decision::Allow,
        status: CaseStatus::KnownMiss {
            tracking: "none — documented limitation: needs dataflow/taint tracking, no current owner",
        },
        technique: "compound_command",
        rationale: "the destructive target is supplied dynamically by xargs, never appearing as a literal string in the command; no text-pattern fix is possible here",
    },
    Case {
        name: "compound_ifs_whitespace_substitution",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm${IFS}-rf${IFS}/"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "compound_command",
        rationale: "`$IFS` expands to whitespace at shell-runtime but is literal non-whitespace text in the command string; a very common real-world flag-splitting evasion, same shape as line continuation — graduated by wrapper/flag normalization's `$IFS` fold, position-scoped to the tokens wrapper-stripping itself inspects so it never touches e.g. an echoed `$IFS`",
    },
];
