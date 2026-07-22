//! Bucket: long-flag variants, multi-arg/interspersed short-flag forms.
//!
//! `git push --force`/`-f` with an explicit branch is already caught
//! (`Active`). Splitting `rm`'s short flags into separate tokens (`-r -f`) or
//! using GNU long options (`--recursive --force`) is a confirmed silent miss,
//! owned by the wrapper/prefix normalization follow-on feature.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "long_flag_git_push_force_explicit_branch",
        tool: "Bash",
        input: || serde_json::json!({"command": "git push --force origin main"}),
        expected: Decision::Ask,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "`--force` is directly in the pattern's alternation, and the branch is explicit",
    },
    Case {
        name: "long_flag_git_push_short_explicit_branch",
        tool: "Bash",
        input: || serde_json::json!({"command": "git push -f origin master"}),
        expected: Decision::Ask,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "`-f` short form, explicit branch — sibling of the above",
    },
    Case {
        name: "long_flag_git_push_force_with_lease",
        tool: "Bash",
        input: || serde_json::json!({"command": "git push --force-with-lease origin main"}),
        expected: Decision::Ask,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "`\\b` after `--force` is satisfied by the following `-`; intentionally over-cautious (Ask, not Deny) rather than a bypass",
    },
    Case {
        name: "multi_arg_rm_separate_short_flags_rf",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -r -f /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "functionally identical to `rm -rf /` in every POSIX shell; graduated by wrapper/flag normalization's short-flag-cluster merge (transform 6.2), which canonicalizes `-r -f` -> `-rf`",
    },
    Case {
        name: "multi_arg_rm_separate_short_flags_fr",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm -f -r /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "same gap, reversed flag order; canonicalizes to `-fr` (encountered order preserved, matching the catalog pattern's own `-rf`/`-fr` alternation)",
    },
    Case {
        name: "long_flag_rm_gnu_long_options",
        tool: "Bash",
        input: || serde_json::json!({"command": "rm --recursive --force /"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "long_flag_and_multi_arg",
        rationale: "GNU long options; graduated by wrapper/flag normalization's long->short mapping (transform 6.1) composed with the cluster merge (6.2), canonicalizing to `rm -rf /`",
    },
];
