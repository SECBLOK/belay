//! Host/VPS security posture checks — Rust port of the deleted Python
//! predecessor's `runtime/posture.py`.
//!
//! `check_posture(home) -> Vec<Finding>` runs 4 checks in the same order as
//! the Python oracle:
//!   1. SSH world-readable keys
//!   2. `.env` in home directory
//!   3. Risky agent flags (calls the detect stub; Task 2 fills it in)
//!   4. MCP server configs bound to 0.0.0.0

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;

use regex::Regex;
use scanner::types::{Category, Decision, Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry-point
// ─────────────────────────────────────────────────────────────────────────────

/// Run all host posture checks and return the collected findings.
///
/// Mirrors `check_posture(home)` in `runtime/posture.py` exactly:
/// same 4 checks, same order, same Finding field values, same duplicate
/// behaviour for overlapping SSH glob patterns.
///
/// `home` is `None` for the real `$HOME`, or `Some(path)` to override (used
/// in tests and the `--home` CLI option).
pub fn check_posture(home: Option<&Path>) -> Vec<Finding> {
    let home_dir: std::path::PathBuf = match home {
        Some(p) => p.to_path_buf(),
        None => {
            let h = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            std::path::PathBuf::from(h)
        }
    };

    let mut findings: Vec<Finding> = Vec::new();

    // Check 1: world-readable SSH private keys
    check_ssh_keys(&home_dir, &mut findings);

    // Check 2: .env file in home directory
    check_env_file(&home_dir, &mut findings);

    // Check 3: risky agent flags (real detection registry from Task 2)
    check_agent_flags(&home_dir, &mut findings);

    // Check 4: MCP servers bound to 0.0.0.0
    check_mcp_configs(&home_dir, &mut findings);

    findings
}

/// Print findings in the `posture_cmd` format and return the appropriate exit
/// code (1 if any finding is Critical, 0 otherwise).
///
/// Mirrors `posture_cmd` in the deleted Python predecessor's `cli/main.py`.
pub fn run(home: Option<&Path>) -> ExitCode {
    let findings = check_posture(home);

    if findings.is_empty() {
        println!("Posture OK: no issues found.");
        return ExitCode::SUCCESS;
    }

    let mut has_critical = false;
    for f in &findings {
        let icon = if f.severity >= Severity::Critical {
            "CRITICAL"
        } else if f.severity >= Severity::High {
            "HIGH"
        } else {
            "MEDIUM"
        };
        println!("[{}] {}: {}", icon, f.rule_id, f.reason);
        if f.severity >= Severity::Critical {
            has_critical = true;
        }
    }

    if has_critical {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check 1: SSH world-readable keys
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_check_ssh_keys` in posture.py.
///
/// Iterates the patterns `["id_rsa","id_dsa","id_ecdsa","id_ed25519","id_*"]`
/// in order.  For each regular file whose mode has the world-read bit set
/// (S_IROTH, octal 0o004), a finding is appended.  Overlapping patterns are
/// intentional — `id_rsa` will emit findings for both the `"id_rsa"` pattern
/// and the `"id_*"` wildcard, just as Python's `pathlib.Path.glob` does.
// `findings` is only written inside the `#[cfg(unix)]` mode-based check below;
// on non-Unix (NTFS ACL model) this produces no finding, so the param is unused there.
#[cfg_attr(not(unix), allow(unused_variables))]
fn check_ssh_keys(home_dir: &Path, findings: &mut Vec<Finding>) {
    let ssh_dir = home_dir.join(".ssh");
    if !ssh_dir.is_dir() {
        return;
    }

    let patterns = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_*"];

    for pattern in &patterns {
        // Use glob-style matching: the only wildcard Python uses here is `id_*`
        // which means "starts with id_".
        let matched_files = glob_ssh_pattern(&ssh_dir, pattern);
        for key_file in matched_files {
            if !key_file.is_file() {
                continue;
            }
            // ignore stat errors; mode-based check is Unix-only (NTFS uses ACLs)
            #[cfg(unix)]
            if let Ok(meta) = std::fs::metadata(&key_file) {
                let mode = meta.permissions().mode();
                // World-readable: others-read bit (0o004)
                if mode & 0o004 != 0 {
                    findings.push(Finding {
                        rule_id: "posture.ssh_world_readable".into(),
                        severity: Severity::Critical,
                        category: Category::Secrets,
                        decision: Decision::Deny,
                        reason: format!(
                            "SSH private key is world-readable: {}",
                            key_file.display()
                        ),
                        owasp: "A02".into(),
                        atlas: "AML.CredentialExposure".into(),
                        location: None,
                        fix: "chmod 600 ~/.ssh/id_*".into(),
                    });
                }
            }
        }
    }
}

/// Return files in `ssh_dir` that match the given glob pattern.
///
/// Only two pattern forms appear in posture.py:
/// - Exact names like `"id_rsa"` — checked with a direct path test.
/// - Wildcard `"id_*"` — all entries starting with `"id_"`.
///
/// This matches Python's `Path.glob()` semantics for these specific patterns.
fn glob_ssh_pattern(ssh_dir: &Path, pattern: &str) -> Vec<std::path::PathBuf> {
    if pattern.contains('*') {
        // Wildcard: match all entries with the given prefix.
        let prefix = pattern.trim_end_matches('*');
        let mut results = Vec::new();
        if let Ok(rd) = std::fs::read_dir(ssh_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with(prefix) {
                    results.push(entry.path());
                }
            }
            // Sort for deterministic order (Python glob order is OS-dependent
            // but the test only checks count, not order).
            results.sort();
        }
        results
    } else {
        // Exact match: just test if the file exists.
        let p = ssh_dir.join(pattern);
        if p.exists() {
            vec![p]
        } else {
            vec![]
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check 2: .env in home directory
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_check_env_file` in posture.py.
fn check_env_file(home_dir: &Path, findings: &mut Vec<Finding>) {
    let env_file = home_dir.join(".env");
    if env_file.is_file() {
        findings.push(Finding {
            rule_id: "posture.env_in_home".into(),
            severity: Severity::High,
            category: Category::Secrets,
            decision: Decision::Ask,
            reason: format!(".env file found in home directory: {}", env_file.display()),
            owasp: "A02".into(),
            atlas: "AML.CredentialExposure".into(),
            location: None,
            fix: "Move .env to a project directory with restricted permissions".into(),
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check 3: Risky agent flags
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_check_agent_flags` in posture.py.
///
/// Calls `crate::detect::find_agents` (real registry, Task 2).  Errors from
/// detection are swallowed (same as the Python `except Exception: pass`).
fn check_agent_flags(home_dir: &Path, findings: &mut Vec<Finding>) {
    // Catch any panic from the detection layer (mirrors Python's bare `except`).
    let home_str = home_dir.to_str().map(|s| s.to_owned());
    let result = std::panic::catch_unwind(move || crate::detect::find_agents(home_str.as_deref()));

    let agents = match result {
        Ok(a) => a,
        Err(_) => return, // detection failure must not block posture
    };

    for agent in agents {
        if !agent.risky_flags.is_empty() {
            // Format the flag list exactly as Python's list repr: ['a', 'b']
            let flags_repr = crate::detect::py_list_repr(&agent.risky_flags);
            findings.push(Finding {
                rule_id: "posture.agent_risky_flags".into(),
                severity: Severity::High,
                category: Category::Tamper,
                decision: Decision::Ask,
                reason: format!("Agent '{}' has risky flags: {}", agent.name, flags_repr),
                owasp: "ASI03".into(),
                atlas: "AML.Persistence".into(),
                location: None,
                fix: "Review and disable risky agent flags".into(),
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Check 4: MCP bound to 0.0.0.0
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors `_check_mcp_configs` in posture.py.
///
/// Scans three glob patterns:
///   - `~/.claude/*.json`
///   - `~/.config/mcp/*.json`
///   - `~/.mcp/*.json`
///
/// For each JSON file, reads content as UTF-8 (replacing invalid bytes) and
/// checks for the regex `"host"\s*:\s*"0\.0\.0\.0"`.
fn check_mcp_configs(home_dir: &Path, findings: &mut Vec<Finding>) {
    let zero_re = Regex::new(r#""host"\s*:\s*"0\.0\.0\.0""#).expect("static regex must compile");

    let config_dirs_and_globs: &[(&str, &str)] = &[
        (".claude", "*.json"),
        (".config/mcp", "*.json"),
        (".mcp", "*.json"),
    ];

    for (rel_dir, glob_pattern) in config_dirs_and_globs {
        let dir = home_dir.join(rel_dir);
        if !dir.is_dir() {
            continue;
        }
        let files = glob_json_files(&dir, glob_pattern);
        for config_file in files {
            if !config_file.is_file() {
                continue;
            }
            // Read as UTF-8 with lossy replacement (matches Python errors="replace")
            let content = match std::fs::read(&config_file) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => continue,
            };
            if zero_re.is_match(&content) {
                findings.push(Finding {
                    rule_id: "posture.mcp_bound_all_interfaces".into(),
                    severity: Severity::Critical,
                    category: Category::Egress,
                    decision: Decision::Deny,
                    reason: format!(
                        "MCP server config binds to 0.0.0.0: {}",
                        config_file.display()
                    ),
                    owasp: "A05".into(),
                    atlas: "AML.LateralMovement".into(),
                    location: None,
                    fix: "Change host to 127.0.0.1 in MCP server config".into(),
                });
            }
        }
    }
}

/// Return all `*.json` files in `dir`.  Only the `*.json` pattern is used here.
fn glob_json_files(dir: &Path, _pattern: &str) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                results.push(path);
            }
        }
        results.sort();
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::detect::py_list_repr;

    #[test]
    fn python_list_repr_empty() {
        assert_eq!(py_list_repr(&[]), "[]");
    }

    #[test]
    fn python_list_repr_single() {
        assert_eq!(
            py_list_repr(&["--dangerously-skip-permissions".to_string()]),
            "['--dangerously-skip-permissions']"
        );
    }

    #[test]
    fn python_list_repr_multi() {
        assert_eq!(
            py_list_repr(&["--no-verify".to_string(), "--force".to_string()]),
            "['--no-verify', '--force']"
        );
    }
}
