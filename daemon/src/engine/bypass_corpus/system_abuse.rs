//! Bucket: System-Abuse (fork bombs, raw-disk-device writes) — Task 2 of the
//! command-gate expansion. `rules/catalog.yaml` does not carry a
//! `sysabuse.fork_bomb` / `sysabuse.disk_device_write` rule yet — this whole
//! bucket is `KnownMiss` inverted canaries (today's real gap) plus the
//! `Active` false-positive guards those two proposed rules must never trip.
//! See `docs/superpowers/plans/2026-07-18-system-abuse-catalog-patch.md` for
//! the validated catalog YAML (hand-traced against `RuleSet::haystack()`'s
//! real preprocessing — masking, backslash fold, canonicalization — not just
//! the pretty-printed source) and the exact status-flip follow-up that
//! graduates every `KnownMiss` below to `Active`/`Deny` once a human applies
//! it (this file cannot edit `rules/catalog.yaml` — see that doc's header
//! for why).
//!
//! Two must-Deny IOCs, kept deliberately narrow (near-zero FP, per the
//! design brief's explicit "DO NOT ship" list — generic `dd of=<file>`,
//! `while true` loops, interpreted `fork()`, and memory-exhaustion loops all
//! need semantic/quantity awareness a text-pattern gate can't add without
//! false positives, so none of them are rules here):
//!
//! - **`sysabuse.fork_bomb`**: the classic POSIX self-referential function
//!   piped to itself and backgrounded (`:(){ :|:& };:` and named variants),
//!   plus the Windows batch form (`%0|%0`). The validated pattern uses a
//!   `fancy_regex` lookahead + backreference (`\1`) to verify the piped
//!   target is the *same* name as the declared function — the brief's
//!   naive non-lookahead backreference form (`(\1|:)` with no `(?=`)
//!   actually fails to COMPILE at all: `RuleSet`'s `needs_fancy()` only
//!   routes a pattern to `fancy_regex` when it contains a lookaround marker
//!   (`(?=`/`(?!`/`(?<=`/`(?<!`), so a bare `\1` with no lookaround falls to
//!   plain `regex::Regex`, which rejects backreferences outright
//!   (`regex parse error: backreferences are not supported`). Wrapping the
//!   backreference inside a real `(?=...)` lookahead is not cosmetic — it is
//!   the only way to keep the self-reference check AND have the pattern
//!   compile at all. Dropping the backreference instead (accepting *any*
//!   two-name self-pipe) was measured and rejected: `build() { compile |
//!   tee log.txt & }` — an ordinary backgrounded build-log pipe — matches
//!   the backreference-free form, a real false positive the tight pattern
//!   must not have.
//! - **`sysabuse.disk_device_write`**: `dd ... of=/dev/(sd|nvme|hd|vd|disk|
//!   mmcblk|loop)...` and a bare shell redirect (`cat ... > /dev/sda`) to
//!   the same device families. Deliberately asymmetric: `dd if=/dev/sda
//!   of=backup.img` (reading a raw device INTO a regular file — ordinary
//!   disk imaging) is untouched, only `of=` (or `>`) TARGETING a raw device
//!   is flagged.
//!
//! All must-Deny/FP-guard commands and their `decide()` outcomes here were
//! hand-verified against a synthetic `RuleSet::from_yaml` carrying only the
//! two candidate rules (the exact same public API `RuleSet::load()` uses),
//! run through the real `decide()` pipeline — not eyeballed against the
//! pretty-printed regex source. See the patch doc for the full validation
//! transcript and the additional adversarial cases (tabs/newlines/no-space
//! obfuscation, `sudo`-wrapped `dd`, `/dev/disk/by-id/...` aliases,
//! reversed `dd` flag order) that were also confirmed to work correctly
//! before the pattern was finalized.

use super::{Case, CaseStatus};
use crate::engine::types::Decision;

pub(crate) const CASES: &[Case] = &[
    // ---- must-Deny (KnownMiss today — graduates when the catalog patch lands) ----
    Case {
        name: "sysabuse_fork_bomb_classic_posix",
        tool: "Bash",
        input: || serde_json::json!({"command": ":(){ :|:& };:"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "the canonical POSIX fork bomb — a `:` function that pipes to itself and backgrounds — has zero legitimate use and no rule currently catches it",
    },
    Case {
        name: "sysabuse_fork_bomb_named_self_pipe_bg",
        tool: "Bash",
        input: || serde_json::json!({"command": "bomb() { bomb | bomb & }; bomb"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "a NAMED self-referential function (not just the anonymous `:` form) piped to itself and backgrounded is the same fork-bomb structure with a human-readable name",
    },
    Case {
        name: "sysabuse_fork_bomb_windows_batch",
        tool: "Bash",
        input: || serde_json::json!({"command": "%0|%0"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "the Windows batch-file fork bomb: `%0` (the running script's own path) piped/escaped into itself, spawning copies indefinitely",
    },
    Case {
        name: "sysabuse_fork_bomb_whitespace_obfuscated",
        tool: "Bash",
        input: || serde_json::json!({"command": ": ( ) { : | : & } ; :"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "spaced-out reformatting of the classic fork bomb (space inside the empty parens) — a trivial obfuscation of the exact same IOC, not a different technique",
    },
    Case {
        name: "sysabuse_disk_write_dd_to_mmcblk",
        tool: "Bash",
        input: || serde_json::json!({"command": "dd if=/dev/zero of=/dev/mmcblk0"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`dd` writing zeros directly to a raw eMMC/SD-card block device destroys the partition table and every file on the device, with no confirmation prompt and no undo — `mmcblk` is outside the pre-existing `destructive.disk_wipe` rule's device-family list (sd/nvme/vd only), a real gap `sysabuse.disk_device_write`'s wider family list closes",
    },
    Case {
        name: "sysabuse_disk_write_dd_to_sda_already_caught_by_disk_wipe",
        tool: "Bash",
        input: || serde_json::json!({"command": "dd if=/dev/zero of=/dev/sda"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "documents that the brief's literal must-Deny example is ALREADY caught today by the pre-existing `destructive.disk_wipe` rule (`\\bdd\\b.*of=/dev/(sd|nvme|vd)`) — not a sysabuse.disk_device_write gap at all; kept as a permanent Active regression pin (not a KnownMiss) precisely because it must stay Deny with or without the new rule",
    },
    Case {
        name: "sysabuse_disk_write_urandom_redirect_nvme",
        tool: "Bash",
        input: || serde_json::json!({"command": "cat /dev/urandom > /dev/nvme0n1"}),
        expected: Decision::Deny,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "a bare shell redirect (no `dd` involved at all) is an equally destructive way to overwrite a raw NVMe device — the `dd`-specific pattern alone would miss this",
    },
    // ---- permanent KnownMiss (deliberately NOT covered even after the patch) ----
    Case {
        name: "sysabuse_fork_bomb_self_reinvoke_via_dollar_zero",
        tool: "Bash",
        input: || serde_json::json!({"command": "bash -c '$0|$0' &"}),
        expected: Decision::Allow,
        status: CaseStatus::KnownMiss {
            tracking: "permanent — different fork-bomb technique (self-reinvocation via `$0`, not a self-piping function), not covered by sysabuse.fork_bomb's function-shape pattern; closing it needs a `$0`-recursion-aware detector, which is a much wider net (any script referencing its own `$0` is extremely common and legitimate) and was explicitly out of scope for a near-zero-FP text pattern",
        },
        technique: "system_abuse",
        rationale: "`$0` self-reinvocation is a real, different fork-bomb construction technique from the function-self-pipe IOC the shipped pattern targets — pinned honestly as a gap rather than widening the pattern into `$0`-recursion territory and risking false positives on ordinary self-referencing scripts",
    },
    // ---- FP guards (Active — must stay Allow today AND after the patch lands) ----
    Case {
        name: "fp_guard_dd_to_regular_file",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "dd if=/dev/zero of=disk.img bs=1M count=100"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`dd` writing to an ordinary regular file (disk-image creation, a common and legitimate workflow) must never be confused with writing to a raw block device — the DO-NOT-ship list explicitly excludes generic `dd of=<file>`",
    },
    Case {
        name: "fp_guard_dd_read_raw_disk_write_regular_file",
        tool: "Bash",
        input: || serde_json::json!({"command": "dd if=/dev/sda of=backup.img"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "ordinary disk-imaging direction (READ from a raw device, write to a regular file) is the opposite of the destructive direction the rule targets — only `of=` (or `>`) TARGETING a device is flagged, never `if=` sourcing one",
    },
    Case {
        name: "fp_guard_dd_write_to_devnull",
        tool: "Bash",
        input: || serde_json::json!({"command": "dd if=/dev/zero of=/dev/null"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`/dev/null` is not in the raw-block-device family list (sd/nvme/hd/vd/disk/mmcblk/loop) — discarding output to the null device is an extremely common, totally benign idiom",
    },
    Case {
        name: "fp_guard_benign_shell_function",
        tool: "Bash",
        input: || serde_json::json!({"command": "deploy() { make build; }"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "an ordinary shell function definition with no pipe and no backgrounding must never trip the fork-bomb pattern — shell functions are ubiquitous in scripts",
    },
    Case {
        name: "fp_guard_while_true_sleep_loop",
        tool: "Bash",
        input: || serde_json::json!({"command": "while true; do sleep 1; done"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`while true; do ... done` polling loops are ubiquitous in scripts and CI wait-conditions — the DO-NOT-ship list explicitly excludes these (needs quantity/semantic awareness a regex can't add safely)",
    },
    Case {
        name: "fp_guard_similarly_named_functions_piped_not_self",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "build() { compile | tee log.txt & }"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "an ordinary backgrounded build-log pipe (function pipes to a DIFFERENT command, `tee`, not to itself) — this is exactly the false positive the pattern's backreference (`\\1`, not a bare `\\w+`) exists to avoid; without it, any `name() { other | other & }` shape would be wrongly denied",
    },
    Case {
        name: "fp_guard_prefix_similar_function_name_not_exact_match",
        tool: "Bash",
        input: || serde_json::json!({"command": "bomb() { bomb2 | bomb2 & }"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`bomb2` merely starts with `bomb` — the pattern's negative lookahead (`\\1(?!\\w)`) requires an exact word-bounded name match, not a prefix match, so a function piping to a differently-named-but-similar-looking function stays Allow",
    },
    Case {
        name: "fp_guard_self_pipe_without_backgrounding",
        tool: "Bash",
        input: || serde_json::json!({"command": "bomb() { bomb | bomb; }"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "a function piping to itself WITHOUT backgrounding (`&`) cannot fork-bomb — it blocks on the pipe rather than spawning unbounded parallel copies — the pattern requires the trailing `&` for exactly this reason",
    },
    Case {
        name: "fp_guard_echoed_fork_bomb_double_quoted",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo \":(){ :|:& };:\""}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "an echoed fork-bomb string is merely printed, never executed. The `(` inside the double-quoted argument disqualifies the rest of the argument from bulk masking (per the data-region classifier's presence-only rule), so the surrounding literal text (`:`, `{`, `:|:&`, `}`, `:`) stays visible — BUT the `(`/`)` characters themselves are still always masked individually as bare structural punctuation regardless of disqualification, which removes the literal `()` the fork-bomb pattern requires adjacent to the function name, so this correctly stays Allow",
    },
    Case {
        name: "fp_guard_echoed_fork_bomb_single_quoted",
        tool: "Bash",
        input: || serde_json::json!({"command": "echo ':(){ :|:& };:'"}),
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "same as the double-quoted echo guard but single-quoted — the single-quote exemption means the data-region classifier's disqualification-by-`(` never even triggers here (single-quoted content is inert to the shell and bulk-masked instead), so this stays Allow through a different path in the same classifier",
    },
    Case {
        name: "fp_guard_comment_mentioning_fork_bomb",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "# never run :(){ :|:& };: on prod"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "a shell comment is never executed — the data-region classifier always masks `#`-at-token-start to end of line, regardless of content, so a comment merely mentioning a fork bomb can never be denied",
    },
    Case {
        name: "fp_guard_git_commit_message_mentioning_fork_bomb",
        tool: "Bash",
        input: || {
            serde_json::json!({"command": "git commit -m 'note: never run :(){ :|:& }; in prod'"})
        },
        expected: Decision::Allow,
        status: CaseStatus::Active,
        technique: "system_abuse",
        rationale: "`git commit -m`'s message value is a data-consuming argument the classifier masks (single-quoted, no `$`/backtick/unescaped-`(` outside the quotes to disqualify it), so a commit message merely documenting a fork bomb stays Allow",
    },
];
