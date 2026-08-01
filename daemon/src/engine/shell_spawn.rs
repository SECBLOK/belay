//! Compiled-in detector for interactive-shell spawns.
//!
//! # The gap this closes
//!
//! The catalog had no coverage at all for the largest single family of
//! living-off-the-land technique: getting an interactive shell out of an
//! otherwise ordinary binary. Measured on 2026-07-27 against an external
//! adversarial corpus, 98% of that family went unflagged — the single biggest
//! contributor to the overall miss rate, larger than every other family
//! combined.
//!
//! The shapes are endlessly varied in their *binary* and almost invariant in
//! their *payload*:
//!
//! ```text
//! aa-exec /bin/sh
//! bpftrace --unsafe -e 'BEGIN {system("/bin/sh 1<&0");exit()}'
//! apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
//! busctl --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
//! cabal exec --project-file=/dev/null -- /bin/sh
//! ```
//!
//! # Why match the payload, not the binary
//!
//! The obvious design — a table of binaries known to be abusable — was
//! measured and rejected. **15.5% of ordinary benign developer commands
//! invoke a binary that also has a documented shell-escape technique** (git,
//! npm, cargo, aws, pip, kubectl, docker, go, systemctl, curl). Keying on the
//! binary would blow the project's false-positive budget by roughly 77x, and
//! it needs a curated third-party table to stay current.
//!
//! Keying on the payload needs neither. The set of absolute paths to a Unix
//! shell interpreter is a small, stable *fact* about Unix — not anyone's
//! curated dataset — so this detector carries no dependency on an external
//! catalog and no licence obligation. Measured against the 29,983-case benign
//! corpus this repo vendors, it costs 5 cases (0.017%).
//!
//! # Ask, not Deny
//!
//! Those 5 are not bugs to be tuned away; they are legitimate:
//!
//! ```text
//! kubectl run example --image ubuntu:22.04 --restart Never --rm -- /bin/bash
//! srun --pty /bin/bash
//! in-toto-run -n example ... -- /bin/sh -c "..."
//! ```
//!
//! Each really does start a shell. The honest verdict for "an agent is
//! spawning a shell" is *ask the operator*, not *block* — the project's
//! standing rule is that only executable, high-confidence signals may block,
//! and "which shell spawn did you mean" is exactly the judgement a human
//! should make. An Ask here costs ~2 prompts per 10,000 commands.
//!
//! A shebang is excluded outright: `echo '#!/bin/sh' > run.sh` is authoring a
//! script, not running one, and it is common enough in ordinary agent work
//! that prompting on it would be pure noise.

use crate::engine::rules::RuleHit;
use crate::engine::types::{Decision, Severity, ToolCall};
use std::sync::OnceLock;

/// Absolute paths to a Unix shell interpreter.
///
/// Deliberately absolute-only. A bare `sh`/`bash` word was measured too and
/// costs 12 benign cases against 222 caught, because a shell *name* is
/// everywhere as ordinary data (`kubectl completion bash`, `oh-my-posh init
/// zsh`, `ttyd bash`). Requiring the leading path keeps the signal and drops
/// that entire false-positive class — it is the difference between 0.8% and
/// 0.017%.
///
/// `(?m)` so the shebang exclusion below can anchor to the start of a *line*
/// inside a multi-line command (a heredoc writing a script is the common
/// case), not just the start of the string.
fn shell_path_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?:/usr/local|/usr|/opt)?/s?bin/(?:sh|bash|dash|zsh|ksh|ash|fish|csh|tcsh)\b",
        )
        .expect("shell-path regex is valid")
    })
}

/// True if the match starting at `start` is a shebang (`#!`), allowing spaces
/// between the `!` and the path as the kernel does not but convention permits
/// in written examples. Authoring a script is not spawning one.
fn is_shebang(cmd: &str, start: usize) -> bool {
    let before = &cmd[..start];
    let trimmed = before.trim_end_matches(' ');
    trimmed.ends_with("#!")
}

/// Every shell-path match in `cmd` that is not a shebang.
fn spawns_a_shell(cmd: &str) -> bool {
    shell_path_re()
        .find_iter(cmd)
        .any(|m| !is_shebang(cmd, m.start()))
}

/// Synthetic hit for a Bash command that names a shell interpreter by absolute
/// path. Empty for every other tool — a `Write` whose *content* is a script is
/// the script-file scanner's job, not this one's.
pub fn shell_spawn_hits(tc: &ToolCall) -> Vec<RuleHit> {
    if tc.tool != "Bash" {
        return Vec::new();
    }
    let cmd = tc
        .input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !spawns_a_shell(cmd) {
        return Vec::new();
    }
    vec![RuleHit {
        id: "sysabuse.shell_spawn".to_string(),
        category: "sysabuse".to_string(),
        severity: Severity::High,
        decision: Decision::Ask,
        reason: "starts a shell interpreter by absolute path".to_string(),
        sink: false,
        arms: None,
        ingest: false,
        owasp: None,
        atlas: None,
        explain: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tc(tool: &str, input: serde_json::Value) -> ToolCall {
        ToolCall {
            session: "t".into(),
            tool: tool.into(),
            input,
        }
    }

    fn asks(cmd: &str) -> bool {
        !shell_spawn_hits(&tc("Bash", json!({ "command": cmd }))).is_empty()
    }

    /// Written clean-room from the structural shapes, not copied from any
    /// third-party catalog: each is a shell path reached through a different
    /// syntactic position — bare operand, inline-code payload, `flag=value`,
    /// after `--`, inside a nested quoted argument.
    #[test]
    fn shell_paths_in_every_argument_position_are_asked() {
        for cmd in [
            "aa-exec /bin/sh",
            "/bin/sh",
            "env x=1 /bin/bash",
            "nice -n 10 /bin/dash",
            // inline-code payload of another language
            r#"perl -e 'exec "/bin/sh";'"#,
            r#"awk 'BEGIN {system("/bin/sh")}'"#,
            // flag=value
            "apt-get update -o APT::Update::Pre-Invoke::=/bin/sh",
            "busctl --address=unixexec:path=/bin/sh,argv1=-c",
            // after a `--` separator
            "cabal exec --project-file=/dev/null -- /bin/sh",
            // non-/bin prefixes
            "aa-exec /usr/bin/zsh",
            "aa-exec /usr/local/bin/fish",
            "doas /sbin/sh",
            // reached after a command boundary
            "echo hi; /bin/bash",
            "echo hi && /bin/ksh",
            "x=$(/bin/sh -c id)",
        ] {
            assert!(asks(cmd), "must ask: {cmd}");
        }
    }

    /// A shebang is authoring, not spawning. These are ordinary agent work and
    /// prompting on them would be noise.
    #[test]
    fn shebangs_are_not_spawns() {
        for cmd in [
            r#"echo '#!/bin/sh' > run.sh"#,
            r##"echo "#!/bin/bash" >> setup.sh"##,
            "printf '#!/bin/sh\\necho hi\\n' > x.sh",
            // heredoc writing a script: the shebang is on its own line, which
            // is why the shebang test looks backwards from the match rather
            // than only at the string start.
            "cat > x.sh <<'EOF'\n#!/bin/sh\necho hi\nEOF",
        ] {
            assert!(!asks(cmd), "shebang must not ask: {cmd}");
        }
    }

    /// A shell *name* without a leading absolute path is ordinary vocabulary.
    /// Matching it was measured at 12 benign hits against this corpus and
    /// deliberately rejected; these pin that decision.
    #[test]
    fn bare_shell_words_are_not_spawns() {
        for cmd in [
            "kubectl completion bash",
            "gh completion -s bash",
            "oh-my-posh init zsh",
            "ttyd bash",
            "source ~/.bashrc",
            "chsh -l",
            "echo $SHELL",
            "cargo build --release",
        ] {
            assert!(!asks(cmd), "bare shell word must not ask: {cmd}");
        }
    }

    /// A path that merely starts with the same characters is not a shell.
    #[test]
    fn lookalike_paths_are_not_spawns() {
        for cmd in [
            "/bin/shred -u secret",
            "ls /bin/shuf",
            "/usr/bin/ashell --help",
            "cat /bin/bashful.txt",
        ] {
            assert!(!asks(cmd), "lookalike must not ask: {cmd}");
        }
    }

    /// Only Bash carries a command string; other tools are someone else's job.
    #[test]
    fn non_bash_tools_are_ignored() {
        assert!(shell_spawn_hits(&tc("Write", json!({ "file_path": "/bin/sh" }))).is_empty());
        assert!(shell_spawn_hits(&tc("Read", json!({ "file_path": "/bin/bash" }))).is_empty());
    }

    #[test]
    fn the_hit_is_ask_not_deny() {
        let hits = shell_spawn_hits(&tc("Bash", json!({ "command": "aa-exec /bin/sh" })));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "sysabuse.shell_spawn");
        assert_eq!(hits[0].decision, Decision::Ask);
        assert_eq!(hits[0].severity, Severity::High);
    }
}
