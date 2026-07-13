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
}
