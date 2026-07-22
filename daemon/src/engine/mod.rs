pub mod allowlist;
pub mod canonicalize;
pub mod correlate;
pub(crate) mod data_region;
pub mod decide;
pub mod dropper;
pub(crate) mod extract;
pub mod integrity;
pub mod rule_i18n;
pub mod rules;
pub mod self_tamper;
pub mod trust;
pub mod types;

use crate::egress::{classify_connect, EgressAllowlist};
use crate::engine::types::{Decision, SessionState, Severity, Verdict};
use crate::observe::secrets::scan_secret_bytes;
use crate::observe::{EventKind, ObservedEvent};

/// Evaluate an action observed in the kernel that bypassed the PreToolUse hook.
///
/// Connect events are classified against the egress allowlist when `egress` is
/// provided; destinations absent from the allowlist produce a `Deny`.  If no
/// allowlist is supplied the existing "new destination → Deny" behaviour is
/// preserved unchanged.
pub fn evaluate_event(ev: &ObservedEvent, state: &mut SessionState) -> Verdict {
    evaluate_event_with_egress(ev, state, None, "")
}

/// Like [`evaluate_event`] but with an optional egress allowlist.
///
/// `proc_path` is the resolved `/proc/{pid}/exe` symlink for the process that
/// triggered the Connect event.  Pass an empty string when unknown — the
/// classification will then always deny (safe default).
pub fn evaluate_event_with_egress(
    ev: &ObservedEvent,
    state: &mut SessionState,
    egress: Option<&EgressAllowlist>,
    proc_path: &str,
) -> Verdict {
    match ev.kind {
        EventKind::Open => {
            if is_proc_secret_path(&ev.detail) {
                return Verdict {
                    decision: Decision::Deny,
                    reason: format!("hook bypass: read of {}", ev.detail),
                    rules: vec!["bypass.proc_environ".into()],
                    severity: Severity::Critical,
                    primary_rule: None,
                    category: None,
                    owasp: None,
                    atlas: None,
                    explain: None,
                };
            }
            if is_sensitive_read_path(&ev.detail) {
                return Verdict {
                    decision: Decision::Ask,
                    reason: format!("reads a sensitive credential file: {}", ev.detail),
                    rules: vec!["secrets.sensitive_path".into()],
                    severity: Severity::High,
                    primary_rule: None,
                    category: Some("secrets".into()),
                    owasp: None,
                    atlas: None,
                    explain: None,
                };
            }
            allow()
        }
        EventKind::Connect => {
            let dest = ev.detail.trim();
            if dest.is_empty() || state.egress_destinations.iter().any(|d| d == dest) {
                return allow();
            }
            state.egress_destinations.push(dest.to_string());

            // If an egress allowlist was provided, consult it.
            if let Some(allowlist) = egress {
                match classify_connect(ev.pid, dest, allowlist, proc_path) {
                    Decision::Allow => return allow(),
                    Decision::Ask | Decision::Deny => {}
                }
            }

            Verdict {
                decision: Decision::Deny,
                reason: format!("hook bypass: raw connect to new destination {dest}"),
                rules: vec!["bypass.new_destination".into()],
                severity: Severity::High,
                primary_rule: None,
                category: None,
                owasp: None,
                atlas: None,
                explain: None,
            }
        }
        EventKind::TlsWrite => {
            let hits = scan_secret_bytes(ev.detail.as_bytes());
            if hits.is_empty() {
                return allow();
            }
            // High-confidence credential exfil (cloud keys, private keys, VCS tokens) ->
            // Critical (reflex auto-kills). A generic token/secret KV match (secrets.bearer_or_kv)
            // fires on ordinary authenticated HTTPS, so it is High (deny+alert) but NOT Critical,
            // so reflex does not SIGKILL legitimate processes on normal API traffic.
            const HIGH_CONFIDENCE: &[&str] = &[
                "secrets.aws_access_key",
                "secrets.aws_secret_key",
                "secrets.private_key",
                "secrets.github_token",
            ];
            let high = hits.iter().any(|h| HIGH_CONFIDENCE.contains(h));
            let mut rules = vec!["bypass.secret_egress".to_string()];
            rules.extend(hits.iter().map(|h| h.to_string()));
            Verdict {
                decision: Decision::Deny,
                reason: "hook bypass: secret-shaped bytes leaving over TLS".into(),
                rules,
                severity: if high {
                    Severity::Critical
                } else {
                    Severity::High
                },
                primary_rule: None,
                category: None,
                owasp: None,
                atlas: None,
                explain: None,
            }
        }
        EventKind::Exec => allow(),
        EventKind::OpenWrite => {
            if crate::service::is_self_tamper(&ev.detail) {
                return Verdict {
                    decision: Decision::Deny,
                    reason: format!(
                        "hook bypass: write to Belay-protected file {}",
                        ev.detail
                    ),
                    rules: vec!["bypass.self_tamper_write".into()],
                    severity: Severity::Critical,
                    primary_rule: None,
                    category: None,
                    owasp: None,
                    atlas: None,
                    explain: None,
                };
            }
            allow()
        }
    }
}

fn is_proc_secret_path(p: &str) -> bool {
    // /proc/<pid>/environ or /proc/<pid>/mem
    // pid segment may be numeric, "self", or "thread-self"
    if let Some(rest) = p.strip_prefix("/proc/") {
        let mut parts = rest.splitn(2, '/');
        let pid = parts.next().unwrap_or("");
        let tail = parts.next().unwrap_or("");
        let pid_ok = pid == "self"
            || pid == "thread-self"
            || (!pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()));
        return pid_ok && (tail == "environ" || tail == "mem");
    }
    false
}

/// Does `path` name a well-known on-disk credential/secret file — the same set
/// the `secrets.sensitive_path` catalog rule matches for the cooperative-hook
/// path? Wired into the `Open` arm so a kernel/eBPF/kfilter-observed read of
/// `.env`, `~/.aws/credentials`, an SSH private key, etc. is gated even though
/// it never reached the hook. Backslashes are folded to `/` first so native
/// Windows paths (`C:\Users\x\.env`) match the same POSIX-shaped patterns.
/// Match-only — never used for I/O.
fn is_sensitive_read_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    let base = p.rsplit('/').next().unwrap_or(&p);

    // `.env`, `.env.local`, `.env.production`, … — but NOT `.environment`.
    if base == ".env" || base.starts_with(".env.") {
        return true;
    }
    // `serviceAccount*.json` (GCP service-account keys).
    if base.starts_with("serviceAccount") && base.ends_with(".json") {
        return true;
    }
    // Canonical credential file/dir paths (POSIX-shaped after folding), mirroring
    // the `secrets.sensitive_path` catalog rule (incl. the Aegis-derived stores).
    const NEEDLES: &[&str] = &[
        "/.aws/credentials",
        "/.ssh/id_rsa",
        "/.ssh/id_ed25519",
        "/.ssh/id_ecdsa",
        "/.ssh/id_dsa",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        "/.git-credentials",
        "/.kube/config",
        "/.docker/config.json",
        "/.config/gcloud/",
        "/.gcloud/",
        "/.config/gh/hosts.yml",
        "/.azure/",
        "/.gnupg/",
        "/.oci/",
        "/.terraform.d/credentials",
    ];
    NEEDLES.iter().any(|n| p.contains(n))
}

fn allow() -> Verdict {
    Verdict {
        decision: Decision::Allow,
        reason: String::new(),
        rules: vec![],
        severity: Severity::Info,
        primary_rule: None,
        category: None,
        owasp: None,
        atlas: None,
        explain: None,
    }
}

#[path = "event_eval.rs"]
#[cfg(test)]
mod event_eval;

#[path = "bypass_corpus/mod.rs"]
#[cfg(test)]
mod bypass_corpus;

#[path = "script_file_tests.rs"]
#[cfg(test)]
mod script_file_tests;
