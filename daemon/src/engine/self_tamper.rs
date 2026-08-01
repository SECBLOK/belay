//! Compiled-in self-protection backstop.
//!
//! `tamper.agent_config_write` (in `rules/catalog.yaml`) denies *direct* writes
//! to Belay's own artifacts by matching the protected path string in the
//! tool call. Three gaps remain that a catalog rule cannot reliably close:
//!
//!  1. **Indirection** — `git apply <patch>` / `git am` / `patch` modify a
//!     protected file WITHOUT naming it, so no path string is present to match.
//!  2. **Self-disable** — anything expressed only in the YAML can itself be
//!     weakened by editing the YAML.
//!  3. **Anchoring** — the catalog's own Bash coverage for named targets uses
//!     `path_glob_regex` patterns anchored with `$` (correct for a real
//!     Write/Edit `file_path` field, where `$` means "end of the path"), but
//!     those patterns are merged unmodified into the Bash *command* haystack,
//!     where `$` instead means "end of the entire command". Anything trailing
//!     the path mention — a heredoc body, `&& true`, a comment — silently
//!     defeats the match. Found live: `cat > rules/catalog.yaml <<EOF` was
//!     allowed outright, and a script that ran `python3 a_patch_script.py`
//!     (which itself wrote the catalog with an ordinary `pathlib` path join,
//!     no obfuscation) wrote to it with nothing blocking. See
//!     `docs/research/2026-07-26-self-tamper-bash-gap.md`.
//!
//! This module is the un-disableable backstop: it is compiled into the binary
//! and consulted by [`crate::engine::decide::decide`] regardless of the catalog
//! contents. It returns synthetic [`RuleHit`]s that the dev-toolchain allowlist
//! is forbidden to downgrade.

use crate::engine::rules::RuleHit;
use crate::engine::types::{Decision, Severity, ToolCall};
use crate::service::is_self_tamper;
use std::sync::OnceLock;

/// Regex fragment matching a position where a new command word can begin:
/// the start of the string, or immediately after something the shell treats
/// as a command boundary.
///
/// The boundary set is deliberately wider than the obvious `;`/`&`/`|`. A
/// NEWLINE separates commands exactly as `;` does, and it is the most natural
/// way to write a two-line command, so anchoring on punctuation alone left a
/// trivial bypass: `echo hi\ngit apply x.patch` matched nothing. Verified
/// against the shipped rule on 2026-07-27 before this change — it is why the
/// probe cases in `opaque_write_commands_are_ask` and
/// `belay_self_disabling_subcommands_are_denied` exist. Command substitution
/// `$(...)`, backticks, and group/subshell braces are boundaries for the same
/// reason: `echo $(belay unprotect claude-code)` runs the command.
///
/// Quoted text is NOT excluded here — that is handled by requiring a real
/// command word to follow, plus the negative tests that pin mere mentions
/// (`grep -r "belay unprotect" docs/`) as unflagged, since a quote character
/// is not in this set and so cannot open a match.
const CMD_BOUNDARY: &str = r"(?:^|[;&|(){}`\n\r]\s*)";

/// Matches a Bash command that applies opaque external content - at a command
/// boundary (see [`CMD_BOUNDARY`]), with optional `sudo`: `git apply`,
/// `git am`, or `patch`. These can write arbitrary (including protected) files
/// without naming them, so they are surfaced for human review.
fn opaque_write_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(&format!(
            r"{CMD_BOUNDARY}(?:sudo\s+)?(?:git\s+(?:apply|am)|patch)\b"
        ))
        .expect("opaque-write regex is valid")
    })
}

/// Matches `rules/catalog.yaml` or `audit.ndjson` mentioned anywhere in a Bash
/// command, on either path separator. Unlike the catalog's own
/// `path_glob_regex` patterns (`$`-anchored — see the module doc's gap 3),
/// this is deliberately unanchored: the mention can be followed by anything,
/// including a heredoc body.
fn protected_relative_path_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"rules[/\\]catalog\.yaml|audit\.ndjson")
            .expect("protected-relative-path regex is valid")
    })
}

/// Matches a Belay binary name (`belay`, `belayd`, or the `.exe` forms) ONLY
/// when it is referenced as a path — preceded by `/` or `\`, as an overwrite
/// target normally is (`/usr/local/bin/belay`, `.\belayd.exe`) — never as a
/// bare word.
///
/// This exclusion is load-bearing, not incidental: `belayd` is this
/// project's own Cargo package name, and `cargo test -p belayd`,
/// `cargo build -p belayd`, `--bin belay`, and similar are constant,
/// completely ordinary commands in THIS repository's own development
/// workflow (used dozens of times over the course of this investigation). A
/// bare-word match on `belay`/`belayd` would turn nearly every build or test
/// invocation in this repo into a false positive. Requiring a preceding path
/// separator excludes all of those (the name follows a space or a flag
/// there, never a slash) while still catching the actual overwrite shape.
///
/// Known residual gap, stated rather than hidden: `cp fake belay` with no
/// separator, relying on an already-correct working directory, is not
/// caught. Closing that generally requires resolving relative paths against
/// a real cwd, which this text-level check does not attempt — see the
/// module doc's gap 3 discussion and `docs/research/2026-07-26-self-tamper-
/// bash-gap.md`.
fn protected_binary_path_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"[/\\](belayd?|belayd?\.exe)(?:[\s'"]|$)"#)
            .expect("protected-binary-path regex is valid")
    })
}

/// Matches an invocation of Belay's OWN CLI with a subcommand that would
/// disable its supervision, destroy its evidence, or self-grant trust.
///
/// This closes a gap the path-based checks structurally cannot see: nothing
/// about `belay unprotect claude-code` names a protected FILE, so
/// [`protected_relative_path_re`], [`protected_binary_path_re`] and
/// [`mentions_data_dir`] all correctly decline, `looks_like_a_write` finds no
/// write verb, and the catalog's `tamper.agent_config_write` has no path to
/// match either. Confirmed live on 2026-07-27: the gate returned
/// `permissionDecision: "allow"`, reason "no findings". One ordinary-looking
/// command strips Belay's hook out of the agent's settings and ends its own
/// supervision — strictly cheaper for an attacker than the runtime
/// path-computation gap that motivated `tamper.direct_write`, since it needs
/// no indirection at all.
///
/// Unlike an arbitrary file path, the consequential-subcommand vocabulary is
/// small, fixed, and known at compile time, so text matching genuinely CAN
/// close this one:
///   - `unprotect` — removes the hook; ends gating for that agent
///   - `uninstall` — removes Belay entirely; `--purge` also deletes the audit
///     log, i.e. destroys the evidence of having done so
///   - `skill-approve` — grants durable trust to a skill (a decision the
///     approval path deliberately reserves for the operator)
///   - `skill-watch off` — stops skill monitoring (`on` is safe, so only the
///     disabling direction matches)
///
/// **Deny, not Ask, and it costs the operator nothing**: Belay's hook only
/// gates AGENT tool calls. A human typing any of these in their own terminal
/// is not gated at all and is entirely unaffected. So there is no legitimate
/// flow this blocks — only the agent-initiated one, which has no valid use
/// case. (An operator who wants the agent to do it can still run it
/// themselves; that is a deliberate human action, not a silent self-disable.)
///
/// Anchored to COMMAND POSITION — a command boundary (see [`CMD_BOUNDARY`]),
/// optionally after `sudo`, with an optional path prefix — so merely
/// MENTIONING the phrase (`grep -r "belay unprotect" docs/`, or writing this
/// very doc comment) is not a match.
fn self_disable_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(&format!(
            r"{CMD_BOUNDARY}(?:sudo\s+)?(?:[\w./\\-]*[/\\])?belayd?(?:\.exe)?\s+(?:unprotect|uninstall|skill-approve|skill-watch\s+off)\b",
        ))
        .expect("self-disable regex is valid")
    })
}

/// True if `cmd` contains something that looks like it modifies a file,
/// rather than merely reading or naming one. Deliberately a co-occurrence
/// check (does the command contain a write-shaped verb/operator ANYWHERE),
/// not a positional parse of what a redirect or verb's target actually is —
/// consistent with this being a defense-in-depth backstop layered on top of
/// the catalog's own rules, not the only line of defense.
///
/// Gating on this is what keeps this check from Asking on every ordinary
/// read of a protected file (`git diff rules/catalog.yaml`, `cat
/// audit.ndjson`) — before this gate existed, this investigation's own
/// read-only `git status`/`git diff --stat` commands were denied by the
/// catalog's $-anchored pattern purely for ending with the path.
fn write_verb_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `\b` on the left handles both "verb is the first token" (start of
        // command, nothing before it to require a space against) and "verb
        // follows a chain operator" — a naive space-padded substring check
        // (`" tee "`) misses the first case entirely, which is how `tee
        // rules/catalog.yaml < /tmp/fake` first slipped past this check.
        regex::Regex::new(
            r"\b(sed\s+(-i|--in-place)|tee|cp|mv|install|dd\s+of=|truncate|rm|unlink|shred)\b",
        )
        .expect("write-verb regex is valid")
    })
}

/// True if the `>` at byte `i` is the operator of a file-descriptor
/// DUPLICATION (`2>&1`, `>&2`) rather than a file redirection.
///
/// Shape: an optional leading fd digit, `>`, `&`, one or more digits, then an
/// optional `-` (the `2>&-` close form), and then a character that cannot
/// continue a filename. That last condition is what keeps `>&file` — a real
/// redirect-to-file — out of this exclusion: `file` is not digits.
fn is_fd_dup(bytes: &[u8], i: usize) -> bool {
    if bytes.get(i + 1) != Some(&b'&') {
        return false;
    }
    let mut j = i + 2;
    let start = j;
    while matches!(bytes.get(j), Some(d) if d.is_ascii_digit()) {
        j += 1;
    }
    let had_digits = j > start;
    let had_close_dash = bytes.get(j) == Some(&b'-');
    if had_close_dash {
        j += 1;
    }
    // `>&file` has neither a target fd nor the `-` close marker, and really
    // does open a file.
    if !had_digits && !had_close_dash {
        return false;
    }
    match bytes.get(j) {
        None => true,
        Some(c) => c.is_ascii_whitespace() || matches!(c, b';' | b'|' | b'&' | b')' | b'`'),
    }
}

/// Every target of a real (unquoted, non-fd-duplicating) output redirection in
/// `cmd`, with surrounding quotes stripped.
///
/// This exists because "there is a `>` somewhere" and "a protected path is
/// named somewhere" are independent facts, and treating their co-occurrence as
/// a write flagged a long tail of ordinary commands: writing a commit message
/// to a scratch file whose text discusses the rules file, or a heredoc'd
/// program containing `d >= cutoff`, where `>=` is a comparison and not a
/// redirection at all. Both blocked real work on 2026-07-27.
///
/// Quote-aware: a `>` inside `'...'`/`"..."` is literal text and starts no
/// redirection. That distinction is not cosmetic — it replaced a naive
/// `cmd.contains('>')` after two live false positives on 2026-07-26, where
/// read-only diagnostic scripts were flagged because a `>` appeared inside a
/// Python string (`struct.pack(">I", …)`, an `'->'` separator).
/// Returns the targets, plus `true` if the scan hit an UNTERMINATED quote and
/// therefore cannot be trusted to have seen every redirection. The caller must
/// fail safe on that flag: an unterminated quote is exactly the shape an
/// attacker would use to hide a redirection from a quote-aware scanner, and
/// the previous implementation's fail-safe behaviour here is load-bearing.
fn redirect_targets(cmd: &str) -> (Vec<String>, bool) {
    let bytes = cmd.as_bytes();
    let mut out = Vec::new();
    let mut chars = cmd.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '>' if is_fd_dup(bytes, i) => {}
            '>' => {
                // Skip the operator itself (`>`, `>>`, `>&`, and the `&>` form
                // whose `&` precedes the `>` and so is already behind us).
                let mut j = i + 1;
                while matches!(bytes.get(j), Some(b'>') | Some(b'&')) {
                    j += 1;
                }
                while matches!(bytes.get(j), Some(c) if c.is_ascii_whitespace()) {
                    j += 1;
                }
                // Read one token, honouring a quoted target.
                let quote = match bytes.get(j) {
                    Some(&q @ (b'\'' | b'"')) => {
                        j += 1;
                        Some(q)
                    }
                    _ => None,
                };
                let start = j;
                while let Some(&b) = bytes.get(j) {
                    let done = match quote {
                        Some(q) => b == q,
                        None => {
                            b.is_ascii_whitespace()
                                || matches!(b, b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')')
                        }
                    };
                    if done {
                        break;
                    }
                    j += 1;
                }
                if j > start {
                    out.push(cmd[start..j].to_string());
                }
                // Resume the outer walk after the token so a quoted target
                // cannot be mistaken for the start of a quoted span.
                while let Some((k, _)) = chars.clone().next() {
                    if k >= j {
                        break;
                    }
                    chars.next();
                }
            }
            '\\' => {
                chars.next();
            }
            '\'' => {
                if !chars.any(|(_, q)| q == '\'') {
                    return (out, true); // unterminated -> caller fails safe
                }
            }
            '"' => {
                let mut closed = false;
                while let Some((_, q)) = chars.next() {
                    match q {
                        '\\' => {
                            chars.next();
                        }
                        '"' => {
                            closed = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if !closed {
                    return (out, true); // unterminated -> caller fails safe
                }
            }
            _ => {}
        }
    }
    (out, false)
}

/// True if a single token names one of Belay's own protected artifacts.
fn token_is_protected(tok: &str) -> bool {
    protected_relative_path_re().is_match(tok)
        || protected_binary_path_re().is_match(tok)
        || mentions_data_dir(tok)
}

/// True if `cmd` mentions the daemon's own data directory (`~/.belay` or its
/// resolved absolute form) at all. Any write under that directory is in
/// scope — it holds the audit log, channel credentials, the AI key, the
/// self-approval-guard enable flag, and other state an agent must not be
/// able to touch, per `service::is_self_tamper`'s directory-wide coverage.
fn mentions_data_dir(cmd: &str) -> bool {
    if cmd.contains("~/.belay") || cmd.contains("~\\.belay") {
        return true;
    }
    let data = crate::paths::data_dir().to_string_lossy().replace('\\', "/");
    if data.is_empty() {
        return false;
    }
    cmd.replace('\\', "/").contains(data.trim_end_matches('/'))
}

fn hit(id: &str, decision: Decision, severity: Severity, reason: &str) -> RuleHit {
    RuleHit {
        id: id.to_string(),
        category: "tamper".to_string(),
        severity,
        decision,
        reason: reason.to_string(),
        sink: false,
        arms: None,
        ingest: false,
        owasp: None,
        atlas: None,
        explain: None,
    }
}

/// Synthetic self-protection hits for a tool call (empty when none apply):
///  - a direct `Write`/`Edit` to a Belay-protected artifact → **Deny**;
///  - a `Bash` command applying opaque external content, without naming a
///    target → **Ask** (`tamper.indirect_write`);
///  - a `Bash` command that both names a protected artifact AND looks like a
///    write → **Ask** (`tamper.direct_write`) — closes the anchoring gap
///    described in the module doc's point 3, without Asking on an ordinary
///    read of the same file.
pub fn self_tamper_hits(tc: &ToolCall) -> Vec<RuleHit> {
    match tc.tool.as_str() {
        "Write" | "Edit" => {
            let path = tc
                .input
                .get("file_path")
                .or_else(|| tc.input.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_self_tamper(path) {
                return vec![hit(
                    "tamper.self_protect",
                    Decision::Deny,
                    Severity::Critical,
                    "direct write to a Belay-protected file",
                )];
            }
        }
        "Bash" => {
            let cmd = tc
                .input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Checked FIRST: disabling the gate outright is strictly more
            // severe than any single write it would otherwise catch, and
            // unlike the path checks below it needs no file to be named.
            if self_disable_re().is_match(cmd) {
                return vec![hit(
                    "tamper.self_disable",
                    Decision::Deny,
                    Severity::Critical,
                    "disables Belay's own protection, monitoring, or evidence",
                )];
            }
            if opaque_write_re().is_match(cmd) {
                return vec![hit(
                    "tamper.indirect_write",
                    Decision::Ask,
                    Severity::High,
                    "applies opaque external content (could modify a protected file without naming it)",
                )];
            }
            // Inert DATA regions are masked out first — the value of `git
            // commit -m`, an `echo`/`printf` argument list, and so on. Without
            // this the check is a pure co-occurrence scan over the raw string,
            // so a commit message or an `echo` that merely *describes* a write
            // ("cp the backup over rules/catalog.yaml") satisfies both halves
            // and is flagged. That fired live on 2026-07-27 and burned a
            // 60-second approval window that expired to auto-deny; five of the
            // eight auto-denies that hour were this rule.
            //
            // `mask_data_regions` is the right tool rather than a new quote
            // stripper: it already distinguishes inert data from executed code,
            // so `sh -c 'cp /tmp/f rules/catalog.yaml'` keeps matching (a
            // quoted argument to an interpreter is code, not data), and it
            // fails toward MORE matching whenever it cannot classify safely —
            // the correct direction for a self-protection backstop.
            let scanned = crate::engine::data_region::mask_data_regions(cmd);
            let names_protected_target = protected_relative_path_re().is_match(&scanned)
                || protected_binary_path_re().is_match(&scanned)
                || mentions_data_dir(&scanned);
            // A redirection counts only when ITS OWN TARGET is protected.
            // Asking merely "is there a redirect somewhere" made every command
            // that redirected anywhere and mentioned a protected path a hit.
            // Write VERBS keep the co-occurrence test: they take the path as a
            // positional operand, and tying verb to operand needs real argument
            // parsing, so the conservative reading is kept there deliberately.
            let (targets, ambiguous) = redirect_targets(&scanned);
            // `ambiguous` means an unterminated quote stopped the scan, so a
            // redirection may exist that was never seen. Fall back to the old
            // co-occurrence reading there: it over-flags, which is the right
            // direction when the input is deliberately malformed.
            let redirect_hits_protected = targets.iter().any(|t| token_is_protected(t))
                || (ambiguous && names_protected_target);
            let verb_write = write_verb_re().is_match(&scanned);
            if redirect_hits_protected || (verb_write && names_protected_target) {
                return vec![hit(
                    "tamper.direct_write",
                    Decision::Ask,
                    Severity::High,
                    "names a Belay-protected file in what looks like a write",
                )];
            }
        }
        _ => {}
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tc(tool: &str, input: serde_json::Value) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: tool.into(),
            input,
        }
    }

    /// Live false positive, 2026-07-27: committing a doc that *describes* the
    /// protected file was blocked. The message names the path and separately
    /// contains write verbs (`dd of=`, `tee`), and the check was a pure
    /// co-occurrence scan over the whole command, so prose about a write
    /// looked exactly like a write.
    ///
    /// It cost a real 60-second approval window that expired to auto-deny.
    /// Five of the eight auto-denies that hour were this rule.
    #[test]
    fn prose_about_a_protected_file_is_not_a_write() {
        for cmd in [
            // The verbatim shape that was blocked.
            r#"git commit -q -m "docs: fix the rules/catalog.yaml read false positive; writes are enumerated, and dd of= / tee < forms are strengthened""#,
            r#"git commit -m "note: rm and cp of rules/catalog.yaml stay denied""#,
            // Same thing via the long flag.
            r#"git commit --message "audit.ndjson is truncated by tee, see rules/catalog.yaml""#,
            // Describing it with echo, rather than committing it.
            r#"echo "to restore, cp the backup over rules/catalog.yaml""#,
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                !hits.iter().any(|h| h.id == "tamper.direct_write"),
                "prose is not a write: {cmd} -> {hits:?}"
            );
        }
    }

    /// A redirect to an UNRELATED file that merely shares a command with a
    /// protected-path mention is not a write to the protected file. The old
    /// check asked "is there a redirect anywhere" and "is a protected path
    /// named anywhere" independently, so any command doing both was flagged.
    ///
    /// Every case here blocked me for real on 2026-07-27, twice after the
    /// earlier fixes had already shipped: writing a commit message to a
    /// scratch file whose body discussed the rules file, and a Python heredoc
    /// containing `d >= cutoff`, where `>=` was read as a redirection.
    #[test]
    fn a_redirect_to_an_unrelated_file_is_not_a_write_to_a_protected_one() {
        for cmd in [
            // Real redirect, unrelated target, protected path only in the body.
            "cat > /tmp/notes.txt <<'EOF'\nsee rules/catalog.yaml for the rule\nEOF",
            "echo done > /tmp/log.txt; grep -c x rules/catalog.yaml",
            // A comparison operator inside embedded code, not a redirection.
            "python3 - <<'PY'\nif d >= cutoff: print(open('audit.ndjson'))\nPY",
            "awk '$1 >= 5 {print}' audit.ndjson",
            // Redirect of an unrelated command's output while naming the binary.
            "/usr/local/bin/belay status > /tmp/status.txt",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                !hits.iter().any(|h| h.id == "tamper.direct_write"),
                "unrelated redirect target: {cmd} -> {hits:?}"
            );
        }
    }

    /// `2>&1` duplicates a file descriptor; it opens no file. Counting it as a
    /// write made this rule fire on anything that merely NAMED a protected
    /// path in the same command. Found live on 2026-07-27 while trying to run
    /// `ls -la target/release/belay 2>&1` — a plain listing, blocked as a
    /// write to the Belay binary.
    #[test]
    fn fd_duplication_is_not_a_file_write() {
        for cmd in [
            "ls -la target/release/belay 2>&1",
            "target/release/belay channels 2>&1 | head -4",
            "/usr/local/bin/belay status 2>&1",
            "cargo build --bin belay 2>&1 | tail -5",
            "wc -l audit.ndjson 2>&1",
            "grep -c x rules/catalog.yaml 2>&1",
            // close-fd form, and the bare `>&N` spelling
            "target/release/belay status 2>&-",
            "target/release/belay status >&2",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                !hits.iter().any(|h| h.id == "tamper.direct_write"),
                "fd duplication is not a write: {cmd} -> {hits:?}"
            );
        }
    }

    /// The exclusion is only for fd duplication. `>&file` and `&>file` open a
    /// file for real, and must keep counting.
    #[test]
    fn redirect_to_a_file_still_counts_even_with_ampersand() {
        for cmd in [
            "echo x >& rules/catalog.yaml",
            "echo x &> rules/catalog.yaml",
            "echo x >&rules/catalog.yaml",
            "echo x > rules/catalog.yaml 2>&1",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                hits.iter().any(|h| h.id == "tamper.direct_write"),
                "a real redirect-to-file must still flag: {cmd} -> {hits:?}"
            );
        }
    }

    /// The other half of the same fix: masking data regions must not let a
    /// real write hide inside one. `sh -c '...'` is executed code, not data,
    /// and a redirect target stays a target whether or not it is quoted.
    #[test]
    fn masking_data_regions_does_not_hide_a_real_write() {
        for cmd in [
            "cp /tmp/f rules/catalog.yaml",
            "sh -c 'cp /tmp/f rules/catalog.yaml'",
            "bash -c \"tee rules/catalog.yaml < /tmp/f\"",
            "echo x > rules/catalog.yaml",
            r#"echo x > "rules/catalog.yaml""#,
            "rm /home/agent/.belay/audit.ndjson",
            "git commit -m msg && cp /tmp/f rules/catalog.yaml",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                !hits.is_empty(),
                "a real write must still be flagged: {cmd}"
            );
        }
    }

    #[test]
    fn direct_write_to_protected_file_is_deny() {
        for path in [
            "/home/u/project/rules/catalog.yaml",
            "/home/u/.belay/audit.ndjson",
            "/usr/local/bin/belayd",
        ] {
            let hits = self_tamper_hits(&tc("Write", json!({ "file_path": path })));
            assert_eq!(hits.len(), 1, "{path}");
            assert_eq!(hits[0].id, "tamper.self_protect");
            assert_eq!(hits[0].decision, Decision::Deny);
        }
        // Edit is gated identically.
        let hits = self_tamper_hits(&tc("Edit", json!({"file_path": "/p/rules/catalog.yaml"})));
        assert_eq!(hits[0].decision, Decision::Deny);
    }

    #[test]
    fn ordinary_write_is_not_self_tamper() {
        let hits = self_tamper_hits(&tc("Write", json!({"file_path": "/p/src/main.rs"})));
        assert!(hits.is_empty());
    }

    #[test]
    fn opaque_write_commands_are_ask() {
        // The exact indirection that bypassed the path-string deny, plus siblings.
        for cmd in [
            "git apply /tmp/x.patch",
            "git am < series.mbox",
            "patch -p1 < change.diff",
            "echo hi && git apply x.patch",
            "sudo patch -p0 -i z.diff",
            // A newline separates commands exactly as `;` does. Until
            // 2026-07-27 this shipped rule anchored on `[;&|]` only, so this
            // two-line form matched nothing at all.
            "echo hi\ngit apply x.patch",
            "echo $(git apply x.patch)",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "{cmd}");
            assert_eq!(hits[0].id, "tamper.indirect_write", "{cmd}");
            assert_eq!(hits[0].decision, Decision::Ask, "{cmd}");
        }
    }

    #[test]
    fn benign_git_and_lookalikes_are_not_flagged() {
        for cmd in [
            "git status",
            "git commit -m x",
            "git checkout main",
            "npm run patch-release", // 'patch' only as a substring, not the command
            "echo 'git apply' is a phrase",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(hits.is_empty(), "must not flag: {cmd} -> {hits:?}");
        }
    }

    /// THE INCIDENT: a heredoc body trailing the path mention defeated the
    /// catalog's $-anchored `path_glob_regex`, so `cat > rules/catalog.yaml
    /// <<EOF ... EOF` was allowed outright. This is the case
    /// `tamper.direct_write` exists to close.
    #[test]
    fn heredoc_write_to_catalog_is_flagged() {
        let hits = self_tamper_hits(&tc(
            "Bash",
            json!({ "command": "cat > rules/catalog.yaml <<EOF\nmalicious\nEOF" }),
        ));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "tamper.direct_write");
        assert_eq!(hits[0].decision, Decision::Ask);
    }

    #[test]
    fn direct_writes_to_protected_paths_are_flagged() {
        for cmd in [
            "echo 'malicious: content' > rules/catalog.yaml",
            "sed -i 's/deny/allow/' rules/catalog.yaml",
            "cat > audit.ndjson <<EOF\nx\nEOF",
            "tee rules/catalog.yaml < /tmp/fake",
            "cp /tmp/fake rules/catalog.yaml",
            "mv /tmp/fake rules/catalog.yaml",
            "dd of=rules/catalog.yaml if=/tmp/fake",
            "rm rules/catalog.yaml",
            "truncate -s 0 rules/catalog.yaml",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must flag: {cmd}");
            assert_eq!(hits[0].id, "tamper.direct_write", "{cmd}");
            assert_eq!(hits[0].decision, Decision::Ask, "{cmd}");
        }
    }

    /// The regression this whole fix exists to close: with any trailing
    /// content — a chained command, a comment, a redirect target list — the
    /// OLD $-anchored catalog pattern missed it. Confirm none of these do.
    #[test]
    fn trailing_content_after_the_path_no_longer_defeats_detection() {
        for cmd in [
            "echo x > rules/catalog.yaml && true",
            "echo x > rules/catalog.yaml # done",
            "echo x > rules/catalog.yaml; echo ok",
            "sed -i 's/a/b/' rules/catalog.yaml 2>/tmp/err",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must flag despite trailing content: {cmd}");
            assert_eq!(hits[0].id, "tamper.direct_write", "{cmd}");
        }
    }

    /// The false-positive direction of the SAME bug: a read-only mention of
    /// the protected path must not be flagged. Before this fix, the old
    /// $-anchored catalog pattern denied `git status`/`git diff --stat`
    /// commands during this investigation purely for ending with the path —
    /// an over-block in the opposite direction from the under-block above.
    #[test]
    fn read_only_mentions_of_protected_paths_are_not_flagged() {
        for cmd in [
            "cat rules/catalog.yaml",
            "git diff rules/catalog.yaml",
            "git diff --stat rules/catalog.yaml",
            "git status rules/catalog.yaml",
            "wc -l rules/catalog.yaml",
            "grep deny rules/catalog.yaml",
            "less audit.ndjson",
            "git log -- rules/catalog.yaml",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(hits.is_empty(), "must not flag a read: {cmd} -> {hits:?}");
        }
    }

    /// The zero-indirection self-disable, found 2026-07-27. `belay unprotect
    /// claude-code` removes Belay's own hook and ends supervision, yet named
    /// no protected file, so every path-based check correctly declined and the
    /// live gate answered "allow — no findings". Verified against the real
    /// daemon before the fix.
    #[test]
    fn belay_self_disabling_subcommands_are_denied() {
        for cmd in [
            "belay unprotect claude-code",
            "belayd unprotect codex",
            "sudo belay unprotect claude-code",
            "/usr/local/bin/belay unprotect claude-code",
            "./target/release/belay unprotect claude-code",
            "belay.exe unprotect claude-code",
            "belay uninstall --purge --yes",
            "sudo belay uninstall",
            "belay skill-approve some-skill",
            "belay skill-watch off",
            // After a chain operator, which is how a self-disable would most
            // plausibly be smuggled in behind something innocuous.
            "echo starting; belay unprotect claude-code",
            "true && belay unprotect claude-code",
            "cat /etc/hostname | belay uninstall",
            // Boundaries other than `;`/`&`/`|`: a newline (the natural way to
            // write a two-line command, and the form that evaded the first cut
            // of this rule), command substitution, group, subshell.
            "echo starting\nbelay unprotect claude-code",
            "echo $(belay unprotect claude-code)",
            "{ belay unprotect claude-code; }",
            "(belay unprotect claude-code)",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must flag: {cmd}");
            assert_eq!(hits[0].id, "tamper.self_disable", "{cmd}");
            assert_eq!(hits[0].decision, Decision::Deny, "{cmd}");
            assert_eq!(hits[0].severity, Severity::Critical, "{cmd}");
        }
    }

    /// The self-disable check must not fire on ordinary Belay use, on this
    /// repo's own build commands, or on merely NAMING the phrase — including
    /// in the very doc comment that documents it, or a grep for it.
    #[test]
    fn ordinary_belay_use_and_mere_mentions_are_not_self_disable() {
        for cmd in [
            // Enabling/mundane subcommands.
            "belay protect claude-code",
            "belay status",
            "belay scan .",
            "belay skill-watch on",
            "belay posture",
            // This repo's own constant build/test invocations.
            "cargo test -p belayd --lib",
            "cargo build --release --bin belay",
            "cargo clippy -p belayd --lib -- -D warnings",
            // Mentions, not invocations — the phrase appears mid-argument.
            r#"grep -r "belay unprotect" docs/"#,
            r#"echo "run belay unprotect to disable""#,
            "rg 'belay uninstall' --files-with-matches",
            // A different tool that merely starts with the same letters.
            "belayground --help",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                !hits.iter().any(|h| h.id == "tamper.self_disable"),
                "must not flag as self-disable: {cmd} -> {hits:?}"
            );
        }
    }

    /// A `>` inside a QUOTED span is not a redirect — the shell only treats
    /// `>` as a redirection operator when it is unquoted. Both cases below are
    /// verbatim reproductions of live false positives from 2026-07-26: two
    /// read-only diagnostic scripts, inspecting the approvals log, were Asked
    /// on purely because a `>` appeared inside a Python string literal
    /// (`struct.pack(">I", ...)` — a big-endian format spec — and a `'->'`
    /// separator in a print). Neither command writes anything.
    #[test]
    fn a_quoted_angle_bracket_is_not_a_redirect() {
        for cmd in [
            // The exact shape of the first live FP: reading approvals.ndjson,
            // with `>` only ever inside a double-quoted Python string.
            r#"python3 -c 'import struct; print(struct.pack(">I", 5))' ~/.belay/approvals.ndjson"#,
            // The second live FP: `->` inside a single-quoted print argument.
            r#"python3 -c "print('->', open('/home/agent/.belay/approvals.ndjson').read())""#,
            // Minimal forms of the same rule, both quote styles.
            r#"grep ">" rules/catalog.yaml"#,
            r#"grep '>' rules/catalog.yaml"#,
            r#"awk '{print $1 "->" $2}' audit.ndjson"#,
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(
                hits.is_empty(),
                "a quoted `>` is not a redirect, must not flag a read: {cmd} -> {hits:?}"
            );
        }
    }

    /// The other half of the same rule: an UNQUOTED `>` still counts, including
    /// when the command also contains quoted spans elsewhere. Guards against
    /// "fixing" the false positive by ignoring `>` too broadly.
    #[test]
    fn an_unquoted_redirect_still_counts_even_alongside_quoted_text() {
        for cmd in [
            // Quoted content present, but the redirect itself is unquoted.
            r#"echo "some > text" > rules/catalog.yaml"#,
            r#"printf '%s' 'a > b' > audit.ndjson"#,
            // Append redirect, unquoted.
            "echo x >> rules/catalog.yaml",
            // Unbalanced quote (fail-safe: must still flag, never fall open).
            r#"echo "unterminated > rules/catalog.yaml"#,
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must still flag a real redirect: {cmd}");
            assert_eq!(hits[0].id, "tamper.direct_write", "{cmd}");
        }
    }

    /// The binary-path check must require a path separator before the name,
    /// specifically so it does NOT fire on this repo's own, constantly-used
    /// build/test commands, where `belayd`/`belay` are bare Cargo
    /// package/binary identifiers, never a path.
    #[test]
    fn cargo_package_name_is_not_mistaken_for_the_binary_path() {
        for cmd in [
            "cargo test -p belayd --lib",
            "cargo build -p belayd",
            "cargo build --release --bin belay",
            "cargo run --bin belayd",
            "cargo clippy -p belayd --lib -- -D warnings",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert!(hits.is_empty(), "must not flag: {cmd} -> {hits:?}");
        }
    }

    /// The binary-path check DOES fire on an actual overwrite-shaped target.
    #[test]
    fn binary_overwrite_via_path_is_flagged() {
        for cmd in [
            "cp /tmp/fake /usr/local/bin/belay",
            "sudo install -m 0755 /tmp/fake /usr/local/bin/belay",
            "mv /tmp/fake ./belayd",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must flag: {cmd}");
            assert_eq!(hits[0].id, "tamper.direct_write", "{cmd}");
        }
    }

    /// Data-directory coverage: the audit log, channel credentials, the AI
    /// key, and — most importantly — the flag controlling whether the
    /// self-approval guard even enforces, all live under `~/.belay`.
    #[test]
    fn writes_under_the_data_dir_are_flagged() {
        for cmd in [
            "echo '{}' > ~/.belay/gateguard_enforce.json",
            "echo '{}' > ~/.belay/channels.json",
            "rm ~/.belay/audit.ndjson",
        ] {
            let hits = self_tamper_hits(&tc("Bash", json!({ "command": cmd })));
            assert_eq!(hits.len(), 1, "must flag: {cmd}");
            assert_eq!(hits[0].id, "tamper.direct_write", "{cmd}");
        }
    }

    /// KNOWN, DOCUMENTED RESIDUAL GAP — not a regression, a stated limit.
    /// A script that computes the protected path from parts at runtime
    /// (ordinary `pathlib`/`os.path.join`, no obfuscation) never has the
    /// literal path string anywhere in the invoking command OR in its own
    /// static source text, so no text-matching check — this one included —
    /// can see it. This is exactly the incident that motivated this fix,
    /// and it remains open by design; see
    /// docs/research/2026-07-26-self-tamper-bash-gap.md gap 2/"Gap B".
    #[test]
    fn indirect_write_via_a_path_joining_script_is_a_known_uncaught_gap() {
        let hits = self_tamper_hits(&tc(
            "Bash",
            json!({ "command": "python3 scripts/apply-fp-patch-2026-07-26-round2.py" }),
        ));
        assert!(
            hits.is_empty(),
            "documented gap: a script that computes the path at runtime is invisible \
             to a text matcher, must not be silently 'fixed' by accident — if this \
             starts failing, update the doc rather than just the assertion"
        );
    }
}
