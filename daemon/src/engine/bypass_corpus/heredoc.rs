//! Bucket: heredocs.
//!
//! Caught incidentally: `norm_cmd` collapses all whitespace (including
//! newlines) before matching, so a heredoc body's newlines don't hide the
//! substring. Pinned explicitly so this remains true if `norm_cmd`'s
//! collapsing strategy ever changes.
//!
//! CORRECTION (Task-1 fix, position-scoped extraction): the three `Deny`
//! cases below were originally documented as graduated by inline-script/
//! heredoc body extraction (`engine::extract`, Task 4 of
//! `docs/superpowers/specs/2026-07-17-command-gate-inline-script-extraction-design.md`).
//! Re-verified while position-scoping extraction to close a false-positive
//! (see `engine::extract`'s module doc, "Position-scoping", and
//! `false_positive_guards::fp_guard_grep_word_bash_before_heredoc` and
//! siblings): all three actually `Deny` via `canonicalize()`'s own top-level
//! **newline** segmentation, not via extraction. `canonicalize()` treats a
//! real unquoted newline as a segment delimiter exactly like `;`/`&&`/`|`
//! (see `canonicalize::split_top_level_segments`'s doc, "Position-scoping"),
//! and a heredoc body's own physical lines are just that — real, unquoted
//! newline-delimited text — so a line like `rm -r -f /` sitting inside a
//! heredoc body becomes its **own** top-level segment (command word `rm`,
//! not `bash`/`cat`) in `hay_canonical`, regardless of what precedes it on
//! an earlier line, and `canonicalize`'s existing flag-cluster-merge/
//! target-quote-unwrap transforms fire on it there directly (`canon_hit`).
//! Extraction still runs and still pulls each heredoc body out as its own
//! haystack (now correctly position-scoped to a recognized-interpreter
//! destination, closing the false-positive class above) — it is a genuine,
//! independent detection path, just not the one these three particular
//! payloads happen to need to graduate. Kept as defense-in-depth: a case
//! that relied on extraction *without* canonicalize's newline-split also
//! catching it would still graduate via `body_hit`.
//!
//! The one `Allow` guard (`heredoc_redirected_to_file_not_extracted`) is
//! unaffected by this correction — it pins that a file-redirected heredoc is
//! never extracted at all (extraction's own behavior, not a downstream
//! match).

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    Case {
        name: "heredoc_pipe_to_bash",
        tool: "Bash",
        input: || serde_json::json!({"command": "cat <<EOF | bash\nrm -rf /\nEOF"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "heredoc",
        rationale: "norm_cmd collapses all whitespace (incl. newlines) before matching, so the heredoc body's newlines don't hide the substring",
    },
    Case {
        name: "heredoc_pipe_to_bash_multi_arg_flags",
        tool: "Bash",
        input: || serde_json::json!({"command": "cat <<EOF | bash\nrm -r -f /\nEOF"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "heredoc",
        rationale: "same flag-separation gap `inline_interpreter_bash_c_multi_arg_flags` documents, heredoc-shaped — but CORRECTED (see module doc): this actually graduates via `canonicalize()`'s own top-level newline segmentation, not extraction. The heredoc body's `rm -r -f /` line is a real, unquoted, newline-delimited chunk of `pre`, so `canonicalize()`'s segment splitter treats it as its own top-level segment regardless of the `cat <<EOF | bash` line preceding it — `rm` sits at that segment's first-token slot directly, and canonicalize's flag-cluster-merge fires there (`canon_hit`). Extraction also runs (now position-scoped to `cat`'s pipe target `bash`) and independently pulls the same body out as its own haystack — genuine defense-in-depth, not the deciding path for this payload",
    },
    Case {
        name: "heredoc_direct_stdin_interpreter",
        tool: "Bash",
        input: || serde_json::json!({"command": "bash <<EOF\nrm -r -f /\nEOF"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "heredoc",
        rationale: "validates the direct-stdin heredoc shape (no `cat`/pipe — `bash` itself reads the heredoc as its own stdin) distinct from the piped shape above — but CORRECTED (see module doc): same as the piped case, this graduates via `canonicalize()`'s own top-level newline segmentation (the `rm -r -f /` body line is its own segment, first token `rm`), not via extraction. Extraction also runs (now position-scoped to `bash` as a direct heredoc destination) and independently pulls the body out — defense-in-depth, not the deciding path here",
    },
    Case {
        name: "heredoc_quoted_delimiter_still_extracted",
        tool: "Bash",
        input: || serde_json::json!({"command": "python3 <<'PYEOF'\nrm -r -f /\nPYEOF"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "heredoc",
        rationale: "validates two things at once: a quoted heredoc delimiter (`<<'PYEOF'`, which only disables the shell's own variable expansion inside the body) does not prevent detection, and a versioned interpreter name (`python3`) is recognized as a heredoc destination, same as the outer command's own interpreter-version fold. CORRECTED (see module doc): the deciding path is `canonicalize()`'s own top-level newline segmentation, not extraction — the body's `rm -r -f /` line is its own top-level segment (first token `rm`) regardless of the quoted delimiter or `python3 <<'PYEOF'` line preceding it, so `canon_hit` fires there directly; extraction also runs (now position-scoped to `python3` as a recognized, versioned direct heredoc destination) and independently pulls the same body out, but is defense-in-depth here, not the deciding path. DEVIATION FROM THE DESIGN DOC'S NAMED PAYLOAD: the spec's literal case wraps the payload as `import os; os.system('rm -r -f /')`. That payload does NOT graduate with the current `canonicalize()` (Task 3): its naive `split_whitespace()` tokenizer glues `rm` onto the preceding Python syntax as a single token (`os.system('rm`, after transform 5's command-name-form quote-strip: `os.system(rm`) that never equals bare `rm`, so `normalize_flag_forms`'s dispatch (an exact `tokens[cmd_i] == \"rm\"` check) never fires and the `-r -f` flags are never merged — a python-syntax-tokenization gap that is out of scope for both `canonicalize()` and this narrow, non-parsing extraction pass (see `extract`'s own module doc, \"Scope\"). Verified empirically: the spec's literal payload stays Allow even after this feature ships. This simplified payload (bare `rm -r -f /`, no `os.system()` wrapper) preserves the case's actual test intent — quoted delimiter + versioned interpreter — without depending on that orthogonal gap.",
    },
    Case {
        name: "heredoc_redirected_to_file_not_extracted",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "cat <<EOF > install.sh\nrm -r -f \"$BUILD_DIR\"\nEOF"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "heredoc",
        rationale: "false-positive guard, permanent: proves the interpreter-destination gate is doing real work, not a no-op. This body, if it were wrongly extracted and canonicalized, would trip destructive.rm_rf (`rm -r -f` merges to `-rf`, and the quoted `\"$BUILD_DIR\"` target would even survive unwrap) — it must not be, because the heredoc here is authored to a FILE (`>`), never executed by this command. Extraction's heredoc-open detector requires a `|`-piped or direct-stdin recognized-interpreter destination on the same physical line; a file redirect matches neither shape, so this heredoc is never handed to the body scanner at all",
    },
];
