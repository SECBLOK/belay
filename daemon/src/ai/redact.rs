//! Redactor: strips secrets and host paths from a flagged action's `input`
//! before it is ever sent to any AI provider (a privacy invariant).
//!
//! Applies a fixed set of conservative, well-anchored regexes to every
//! string value reachable in the JSON tree (objects, arrays, and scalar
//! strings). Regexes are compiled exactly once behind a [`OnceLock`] so
//! repeated calls never pay recompilation cost. Pure and deterministic: no
//! clock, no rng, no I/O — same input always yields the same output.

use regex::{Captures, Regex};
use serde_json::Value;
use std::sync::OnceLock;

/// Placeholder that replaces any masked secret-shaped token.
const REDACTED_TOKEN: &str = "<redacted-token>";

/// Substrings (checked case-insensitively against the KEY of a `KEY=VALUE`
/// fragment) that mark the KEY as secret-shaped.
const SECRET_KEY_MARKERS: &[&str] = &["SECRET", "TOKEN", "KEY", "PASSWORD", "PWD"];

/// The fixed set of compiled regexes used by [`redact_str`], built once.
struct Patterns {
    /// `Bearer <token>` — masks just the token, keeps the `Bearer` keyword.
    bearer: Regex,
    /// OpenAI-style secret keys: `sk-<...>` or the hyphenated `sk-proj-<...>` form.
    sk: Regex,
    /// GitHub tokens: `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + `<...>`.
    ghp: Regex,
    /// AWS access key IDs: `AKIA` (long-term) or `ASIA` (STS temp) + 16 uppercase alphanumerics.
    akia: Regex,
    /// PEM-encoded key blocks: `-----BEGIN ... KEY-----` through the matching
    /// `-----END ... KEY-----` if present, otherwise through the end of the
    /// string (so a truncated blob with no END marker is still masked).
    pem: Regex,
    /// Absolute Linux home paths: `/home/<user>`.
    home: Regex,
    /// Absolute macOS home paths: `/Users/<user>`.
    users: Regex,
    /// `KEY=VALUE` fragments (e.g. shell env assignments). VALUE is either a
    /// double- or single-quoted span (masked whole, quotes included) or an
    /// unquoted run of non-whitespace.
    kv: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        bearer: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-_.+/]+").unwrap(),
        sk: Regex::new(r"\bsk-[A-Za-z0-9-]{10,}\b").unwrap(),
        ghp: Regex::new(r"\bgh[opusr]_[A-Za-z0-9]{10,}\b").unwrap(),
        akia: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        pem: Regex::new(r"(?s)-----BEGIN [A-Z ]+-----.*?(?:-----END [A-Z ]+-----|$)").unwrap(),
        home: Regex::new(r"/home/[^/\s]+").unwrap(),
        users: Regex::new(r"/Users/[^/\s]+").unwrap(),
        kv: Regex::new(r#"\b([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S+)"#).unwrap(),
    })
}

/// Redact one string: mask secret-shaped tokens, rewrite absolute home
/// paths to `~`, and mask `KEY=VALUE` fragments whose KEY looks secret.
/// Benign strings (no matches for any pattern) pass through byte-for-byte.
fn redact_str(input: &str) -> String {
    let p = patterns();
    let mut s = input.to_string();

    // Token shapes first, most specific/contextual (Bearer) before bare
    // prefixes, so e.g. "Bearer sk-..." collapses to "Bearer <redacted-token>"
    // in one pass rather than leaving a stray "sk-" fragment behind.
    s = p
        .bearer
        .replace_all(&s, |_: &Captures| format!("Bearer {REDACTED_TOKEN}"))
        .into_owned();
    s = p.sk.replace_all(&s, REDACTED_TOKEN).into_owned();
    s = p.ghp.replace_all(&s, REDACTED_TOKEN).into_owned();
    s = p.akia.replace_all(&s, REDACTED_TOKEN).into_owned();
    s = p.pem.replace_all(&s, REDACTED_TOKEN).into_owned();

    // Host paths.
    s = p.home.replace_all(&s, "~").into_owned();
    s = p.users.replace_all(&s, "~").into_owned();

    // KEY=VALUE fragments where KEY is secret-shaped.
    s = p
        .kv
        .replace_all(&s, |caps: &Captures| {
            let key = &caps[1];
            let value = &caps[2];
            let key_upper = key.to_uppercase();
            if SECRET_KEY_MARKERS.iter().any(|m| key_upper.contains(m)) {
                format!("{key}={REDACTED_TOKEN}")
            } else {
                format!("{key}={value}")
            }
        })
        .into_owned();

    s
}

/// Recursively redact every string value in a `serde_json::Value` tree.
/// Non-string scalars (numbers, bools, null) pass through unchanged.
fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_str(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), redact_value(v));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Redact a flagged action's `input` before it is ever sent to any AI
/// provider. Returns a deep copy of `input` with secret-shaped tokens
/// masked and absolute home paths rewritten to `~`.
///
/// `tool` is accepted for future tool-specific behavior; today a generic
/// recursive string walk covers every tool shape (`Bash`'s `command`,
/// `Edit`/`Write`'s `file_path`/content, etc.) without needing per-tool
/// parsing.
pub fn redact_action(tool: &str, input: &Value) -> Value {
    let _ = tool;
    redact_value(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bearer_token_is_masked_rest_of_command_remains() {
        let input = json!({"command": "curl -H 'Authorization: Bearer sk-abc123XYZ...' https://x"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("sk-abc123XYZ"), "token leaked: {command}");
        assert!(command.contains("curl -H"), "command structure lost: {command}");
        assert!(command.contains("https://x"), "command structure lost: {command}");
        assert!(command.contains("<redacted-token>"), "no placeholder: {command}");
    }

    #[test]
    fn home_path_is_rewritten_to_tilde() {
        let input = json!({"file_path": "/home/alice/.ssh/id_rsa"});
        let out = redact_action("Read", &input);
        assert_eq!(out["file_path"], "~/.ssh/id_rsa");
    }

    #[test]
    fn macos_users_path_is_rewritten_to_tilde() {
        let input = json!({"file_path": "/Users/alice/.aws/creds"});
        let out = redact_action("Read", &input);
        assert_eq!(out["file_path"], "~/.aws/creds");
    }

    #[test]
    fn secret_shaped_env_value_is_masked() {
        let input = json!({"command": "FOO_SECRET=hunter2 ./run.sh"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("hunter2"));
        assert!(command.contains("FOO_SECRET=<redacted-token>"));
    }

    #[test]
    fn token_env_value_is_masked() {
        let input = json!({"command": "API_TOKEN=abcdef123456 ./run.sh"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("abcdef123456"));
        assert!(command.contains("API_TOKEN=<redacted-token>"));
    }

    #[test]
    fn non_secret_env_value_is_left_unchanged() {
        let input = json!({"command": "PATH=/usr/bin ls"});
        let out = redact_action("Bash", &input);
        assert_eq!(out["command"], "PATH=/usr/bin ls");
    }

    #[test]
    fn benign_command_is_unchanged() {
        let input = json!({"command": "ls -la /tmp"});
        let out = redact_action("Bash", &input);
        assert_eq!(out, input);
    }

    #[test]
    fn secret_inside_nested_array_is_masked() {
        let input = json!({
            "command": "aws configure",
            "args": ["--key", "AKIAIOSFODNN7EXAMPLE", "--region", "us-east-1"]
        });
        let out = redact_action("Bash", &input);
        let args = out["args"].as_array().unwrap();
        assert!(!args.iter().any(|v| v.as_str().unwrap_or("").contains("AKIAIOSFODNN7EXAMPLE")));
        assert!(args.iter().any(|v| v.as_str().unwrap_or("").contains("<redacted-token>")));
        // sibling values untouched
        assert_eq!(args[2], "--region");
        assert_eq!(args[3], "us-east-1");
    }

    #[test]
    fn secret_inside_nested_object_is_masked() {
        let input = json!({
            "file_path": "/tmp/env",
            "env": {
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "REGION": "us-east-1"
            }
        });
        let out = redact_action("Write", &input);
        let key_val = out["env"]["AWS_ACCESS_KEY_ID"].as_str().unwrap();
        assert!(!key_val.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(key_val.contains("<redacted-token>"));
        assert_eq!(out["env"]["REGION"], "us-east-1");
    }

    #[test]
    fn github_token_shape_is_masked() {
        let input = json!({"command": "git remote set-url origin https://ghp_1234567890abcdefghijABCDEFGHIJ@github.com/x/y"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("ghp_1234567890abcdefghijABCDEFGHIJ"));
        assert!(command.contains("<redacted-token>"));
    }

    #[test]
    fn pem_private_key_block_is_masked() {
        let input = json!({
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        });
        let out = redact_action("Write", &input);
        let content = out["content"].as_str().unwrap();
        assert!(!content.contains("MIIEpAIBAAKCAQEA"));
        assert!(content.contains("<redacted-token>"));
    }

    // --- Finding 1: quoted KEY=VALUE must mask the whole quoted span ---

    #[test]
    fn quoted_password_with_spaces_is_fully_masked() {
        let input = json!({"command": "PASSWORD=\"hunter two words\" ./run.sh"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("hunter"), "value leaked: {command}");
        assert!(!command.contains("two words"), "value leaked: {command}");
        assert!(
            command.contains("PASSWORD=<redacted-token>"),
            "not fully masked: {command}"
        );
    }

    #[test]
    fn single_quoted_token_with_spaces_is_fully_masked() {
        let input = json!({"command": "API_TOKEN='a b c' ./run.sh"});
        let out = redact_action("Bash", &input);
        let command = out["command"].as_str().unwrap();
        assert!(!command.contains("a b c"), "value leaked: {command}");
        assert!(!command.contains("b c"), "value remainder leaked: {command}");
        assert_eq!(
            command, "API_TOKEN=<redacted-token> ./run.sh",
            "not fully masked: {command}"
        );
    }

    // --- Finding 2: sk-proj-... (hyphenated OpenAI key form) must be masked ---

    #[test]
    fn openai_project_key_shape_is_masked() {
        let input = json!({"api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"});
        let out = redact_action("Bash", &input);
        let api_key = out["api_key"].as_str().unwrap();
        assert!(
            !api_key.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
            "token leaked: {api_key}"
        );
        assert!(api_key.contains("<redacted-token>"), "not masked: {api_key}");
    }

    // --- Finding 3: ASIA-prefixed AWS STS temp creds must be masked ---

    #[test]
    fn aws_sts_temp_credential_asia_is_masked() {
        let input = json!({"credential": "ASIAIOSFODNN7EXAMPLE"});
        let out = redact_action("Bash", &input);
        let credential = out["credential"].as_str().unwrap();
        assert!(!credential.contains("ASIAIOSFODNN7EXAMPLE"), "key leaked: {credential}");
        assert!(credential.contains("<redacted-token>"), "not masked: {credential}");
    }

    // --- Finding 4: truncated PEM (BEGIN, no END) must still be masked ---

    #[test]
    fn truncated_pem_without_end_marker_is_masked() {
        let input = json!({
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...(truncated, no END line)"
        });
        let out = redact_action("Write", &input);
        let content = out["content"].as_str().unwrap();
        assert!(!content.contains("MIIEow"), "key body leaked: {content}");
        assert!(content.contains("<redacted-token>"), "not masked: {content}");
    }

    // --- Cheap win: gho_/ghu_/ghs_/ghr_ GitHub token prefixes must be masked ---

    #[test]
    fn github_oauth_token_gho_prefix_is_masked() {
        let input = json!({"token": "gho_ABCDEFghijkl0123456789"});
        let out = redact_action("Bash", &input);
        let token = out["token"].as_str().unwrap();
        assert!(!token.contains("gho_ABCDEFghijkl0123456789"), "token leaked: {token}");
        assert!(token.contains("<redacted-token>"), "not masked: {token}");
    }
}
