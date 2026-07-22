//! Secret-shaped-byte scanner. Reused by the TLS-write path and the honeypot
//! egress check. Pattern set mirrors the Phase 6 `secrets` rule family.
use regex::bytes::Regex;
use std::sync::OnceLock;

struct Pat {
    id: &'static str,
    re: Regex,
}

fn patterns() -> &'static [Pat] {
    static PATS: OnceLock<Vec<Pat>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Pat { id: "secrets.aws_access_key", re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap() },
            Pat {
                id: "secrets.aws_secret_key",
                re: Regex::new(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}").unwrap(),
            },
            Pat {
                id: "secrets.private_key",
                re: Regex::new(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----").unwrap(),
            },
            Pat { id: "secrets.github_token", re: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap() },
            Pat {
                id: "secrets.bearer_or_kv",
                re: Regex::new(r"(?i)(?:bearer\s+[A-Za-z0-9._\-]{20,}|(?:api[_-]?key|secret|token)\s*[=:]\s*\S{12,})").unwrap(),
            },
        ]
    })
}

/// Return the deduped, stable-ordered rule ids whose pattern matches `buf`.
pub fn scan_secret_bytes(buf: &[u8]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for p in patterns() {
        if p.re.is_match(buf) && !out.contains(&p.id) {
            out.push(p.id);
        }
    }
    out
}

/// The HIGH-CONFIDENCE subset of [`patterns`] used by
/// [`redact_high_confidence_secrets`]. Deliberately excludes
/// `secrets.bearer_or_kv` — that pattern matches config-shaped text like
/// `token = <12 chars>` and would over-redact ordinary tool output that
/// merely mentions a `token`/`api_key`/`secret` field. Adds a Slack-token
/// pattern (`xox[baprs]-...`), which is as low-FP as the AWS/GitHub/PEM
/// patterns above.
fn high_confidence_patterns() -> &'static [Pat] {
    static PATS: OnceLock<Vec<Pat>> = OnceLock::new();
    PATS.get_or_init(|| {
        vec![
            Pat { id: "secrets.aws_access_key", re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap() },
            Pat {
                id: "secrets.aws_secret_key",
                re: Regex::new(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}").unwrap(),
            },
            Pat {
                id: "secrets.private_key",
                re: Regex::new(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----").unwrap(),
            },
            Pat { id: "secrets.github_token", re: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap() },
            Pat {
                id: "secrets.slack_token",
                re: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
            },
        ]
    })
}

/// Fixed replacement spliced in for every redacted secret span. Deliberately
/// static/attacker-uncontrolled — redaction only ever REMOVES bytes, it never
/// echoes anything derived from the matched text.
const REDACTION_MARKER: &[u8] = b"[REDACTED:belay]";

/// Scan `buf` for HIGH-CONFIDENCE secrets only (see [`high_confidence_patterns`])
/// and, if any match, return the byte-spliced redacted copy plus the deduped,
/// pattern-declaration-ordered list of matched rule ids. Returns `None` when no
/// high-confidence pattern matches, in which case the caller MUST forward the
/// original bytes unchanged (this function never signals "redact nothing but
/// still swap the buffer").
///
/// Match spans across all patterns are collected, sorted by start offset, and
/// merged when overlapping OR touching (`start <= previous_end`) before
/// splicing, so two secrets sitting back-to-back collapse into one marker
/// instead of two glued-together ones. Operates on raw bytes throughout (no
/// UTF-8 boundary requirement), so it's always safe to slice at a match
/// boundary even inside non-UTF-8 or binary-ish input.
pub fn redact_high_confidence_secrets(buf: &[u8]) -> Option<(Vec<u8>, Vec<&'static str>)> {
    let mut ids: Vec<&'static str> = Vec::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for p in high_confidence_patterns() {
        let mut matched = false;
        for m in p.re.find_iter(buf) {
            ranges.push((m.start(), m.end()));
            matched = true;
        }
        if matched {
            ids.push(p.id);
        }
    }
    if ranges.is_empty() {
        return None;
    }

    ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }

    let mut out = Vec::with_capacity(buf.len());
    let mut cursor = 0usize;
    for (start, end) in merged {
        out.extend_from_slice(&buf[cursor..start]);
        out.extend_from_slice(REDACTION_MARKER);
        cursor = end;
    }
    out.extend_from_slice(&buf[cursor..]);

    Some((out, ids))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_aws_access_key() {
        let hits = scan_secret_bytes(b"data=AKIAIOSFODNN7EXAMPLE&more=1");
        assert!(hits.contains(&"secrets.aws_access_key"));
    }

    #[test]
    fn flags_private_key_header() {
        let hits = scan_secret_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nMII...");
        assert!(hits.contains(&"secrets.private_key"));
    }

    #[test]
    fn flags_github_token() {
        let hits =
            scan_secret_bytes(b"Authorization: token ghp_0123456789abcdefABCDEF0123456789abcd");
        assert!(hits.contains(&"secrets.github_token"));
    }

    #[test]
    fn benign_bytes_have_no_hits() {
        assert!(scan_secret_bytes(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n").is_empty());
    }

    #[test]
    fn hits_are_deduped() {
        let hits = scan_secret_bytes(b"AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            hits.iter()
                .filter(|h| **h == "secrets.aws_access_key")
                .count(),
            1
        );
    }

    // ── redact_high_confidence_secrets ──────────────────────────────────────

    #[test]
    fn redacts_aws_access_key_and_preserves_surrounding_text() {
        let input = b"prefix AKIAIOSFODNN7EXAMPLE suffix";
        let (redacted, ids) =
            redact_high_confidence_secrets(input).expect("AWS key must be flagged+redacted");
        let out = String::from_utf8_lossy(&redacted);
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret bytes must be gone: {out}"
        );
        assert!(
            out.contains("[REDACTED:belay]"),
            "marker must be present: {out}"
        );
        assert!(
            out.contains("prefix") && out.contains("suffix"),
            "non-secret surrounding text must survive: {out}"
        );
        assert_eq!(ids, vec!["secrets.aws_access_key"]);
    }

    #[test]
    fn redacts_private_key_header() {
        let input = b"before\n-----BEGIN OPENSSH PRIVATE KEY-----\nMII...\nafter";
        let (redacted, ids) =
            redact_high_confidence_secrets(input).expect("PEM header must be flagged+redacted");
        let out = String::from_utf8_lossy(&redacted);
        assert!(!out.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(out.contains("[REDACTED:belay]"));
        assert!(out.contains("before") && out.contains("after"));
        assert_eq!(ids, vec!["secrets.private_key"]);
    }

    #[test]
    fn redacts_github_token() {
        let input = b"Authorization: token ghp_0123456789abcdefABCDEF0123456789abcd\n";
        let (redacted, ids) =
            redact_high_confidence_secrets(input).expect("GitHub token must be flagged+redacted");
        let out = String::from_utf8_lossy(&redacted);
        assert!(!out.contains("ghp_0123456789abcdefABCDEF0123456789abcd"));
        assert!(out.contains("[REDACTED:belay]"));
        assert_eq!(ids, vec!["secrets.github_token"]);
    }

    #[test]
    fn benign_bytes_return_none() {
        assert_eq!(
            redact_high_confidence_secrets(b"Build succeeded. 12 tests passed."),
            None
        );
    }

    #[test]
    fn bearer_or_kv_style_secret_is_not_redacted() {
        // Medium-confidence-only input: `secrets.bearer_or_kv` (NOT in the
        // high-confidence set) would match `token = <12+ chars>`, but none of
        // the four high-confidence patterns do — so this must return None.
        let input = b"config: token = aVeryLongValue123\n";
        assert_eq!(
            redact_high_confidence_secrets(input),
            None,
            "bearer_or_kv-shaped text must NOT be redacted by the high-confidence path"
        );
    }

    #[test]
    fn redacts_multiple_distinct_secrets_and_dedupes_ids_in_pattern_order() {
        let input = b"AKIAIOSFODNN7EXAMPLE and ghp_0123456789abcdefABCDEF0123456789abcd";
        let (redacted, ids) =
            redact_high_confidence_secrets(input).expect("both secrets must be flagged");
        let out = String::from_utf8_lossy(&redacted);
        assert_eq!(
            out.matches("[REDACTED:belay]").count(),
            2,
            "two distinct, non-adjacent secrets must produce two markers: {out}"
        );
        assert_eq!(ids, vec!["secrets.aws_access_key", "secrets.github_token"]);
    }

    #[test]
    fn preserves_trailing_newline_framing() {
        // The s2c pump splices this over a whole NDJSON line including its
        // trailing `\n`; the newline must survive redaction untouched.
        let input = b"prefix AKIAIOSFODNN7EXAMPLE suffix\n";
        let (redacted, _ids) =
            redact_high_confidence_secrets(input).expect("AWS key must be flagged+redacted");
        assert!(
            redacted.ends_with(b"\n"),
            "trailing newline framing must survive redaction: {:?}",
            String::from_utf8_lossy(&redacted)
        );
    }
}
