//! Bucket: forward-looking cases that need information `decide()` doesn't
//! have from the command text alone (current branch, upstream tracking, cwd
//! contents) — seeds the execution-context classifier follow-on feature.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[Case {
    name: "execution_context_git_push_force_implicit_branch",
    tool: "Bash",
    // SHOULD BE: Ask — graduates when the execution-context classifier
    // (repository current/tracking-branch resolution) ships.
    input: || serde_json::json!({"command": "git push --force"}),
    expected: Decision::Allow,
    status: CaseStatus::KnownMiss {
        tracking: "execution-context classifier",
    },
    technique: "execution_context",
    rationale: "force-pushes whatever branch is currently checked out/tracked — often main — but is textually silent about which branch; requires resolving the repository's actual current/tracking branch, not a text-normalization fix",
}];
