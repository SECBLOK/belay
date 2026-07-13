//! Pure-Rust hardening posture checks (sshd config, listening ports, file modes).
//!
//! `check_sshd` is a pure parser — fully testable without filesystem access.
//! `audit_host` wraps filesystem reads; it is best-effort and never panics if
//! files are absent.

use crate::engine::types::{Decision, Severity};
use crate::finding::{HostCategory, HostFinding};

/// Parse a raw `sshd_config` string and return any hardening findings.
///
/// Risky directives detected:
/// - `PermitRootLogin yes`
/// - `PasswordAuthentication yes`
/// - `X11Forwarding yes`
/// - `PermitEmptyPasswords yes`
pub fn check_sshd(config: &str) -> Vec<HostFinding> {
    let mut findings = Vec::new();

    for line in config.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };

        // Skip comment lines (key starts with '#').
        if key.starts_with('#') {
            continue;
        }

        match (key.to_lowercase().as_str(), val.to_lowercase().as_str()) {
            ("permitrootlogin", "yes") => {
                findings.push(HostFinding {
                    rule_id: "harden.ssh.root_login".into(),
                    severity: Severity::High,
                    category: HostCategory::Tamper,
                    decision: Decision::Ask,
                    reason: "sshd allows direct root login".into(),
                    owasp: "A05:2021 – Security Misconfiguration".into(),
                    atlas: "AML.T0051".into(),
                    fix: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config".into(),
                });
            }
            ("passwordauthentication", "yes") => {
                findings.push(HostFinding {
                    rule_id: "harden.ssh.password_auth".into(),
                    severity: Severity::High,
                    category: HostCategory::Tamper,
                    decision: Decision::Ask,
                    reason: "sshd allows password-based authentication".into(),
                    owasp: "A05:2021 – Security Misconfiguration".into(),
                    atlas: "AML.T0051".into(),
                    fix: "Set 'PasswordAuthentication no' and use key-based auth instead".into(),
                });
            }
            ("x11forwarding", "yes") => {
                findings.push(HostFinding {
                    rule_id: "harden.ssh.x11forwarding".into(),
                    severity: Severity::High,
                    category: HostCategory::Tamper,
                    decision: Decision::Ask,
                    reason: "sshd enables X11 forwarding, increasing attack surface".into(),
                    owasp: "A05:2021 – Security Misconfiguration".into(),
                    atlas: "AML.T0051".into(),
                    fix: "Set 'X11Forwarding no' in /etc/ssh/sshd_config".into(),
                });
            }
            ("permitemptypasswords", "yes") => {
                findings.push(HostFinding {
                    rule_id: "harden.ssh.empty_passwords".into(),
                    severity: Severity::High,
                    category: HostCategory::Tamper,
                    decision: Decision::Ask,
                    reason: "sshd permits accounts with empty passwords".into(),
                    owasp: "A05:2021 – Security Misconfiguration".into(),
                    atlas: "AML.T0051".into(),
                    fix: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config".into(),
                });
            }
            _ => {}
        }
    }

    findings
}

/// Read host configuration files (best-effort) and return hardening findings.
///
/// Checks performed:
/// 1. `/etc/ssh/sshd_config` — parsed by `check_sshd`.
/// 2. `/proc/net/tcp` — flag non-loopback listeners on privileged ports.
/// 3. Critical file modes — warn if `/etc/passwd` or `/etc/shadow` are
///    world-writable.
///
/// Never panics on missing or unreadable files; absent files simply contribute
/// no findings.
pub fn audit_host() -> Vec<HostFinding> {
    let mut findings = Vec::new();

    // 1. sshd_config
    if let Ok(contents) = std::fs::read_to_string("/etc/ssh/sshd_config") {
        findings.extend(check_sshd(&contents));
    }

    // 2. /proc/net/tcp — detect non-loopback listeners (state 0A = LISTEN).
    findings.extend(check_listening_ports());

    // 3. Critical file modes
    findings.extend(check_file_modes());

    findings
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse `/proc/net/tcp` for unexpected non-loopback listeners.
fn check_listening_ports() -> Vec<HostFinding> {
    let mut findings = Vec::new();

    let Ok(contents) = std::fs::read_to_string("/proc/net/tcp") else {
        return findings;
    };

    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // state is column 3; "0A" means LISTEN
        if cols[3] != "0A" {
            continue;
        }
        let local_addr = cols[1];
        // local_addr is "XXXXXXXX:PPPP" in hex; last 8 chars before colon are IP
        let Some(colon_pos) = local_addr.find(':') else {
            continue;
        };
        let ip_hex = &local_addr[..colon_pos];
        let port_hex = &local_addr[colon_pos + 1..];

        // Skip loopback only (127.0.0.1 == 0100007F little-endian). A 0.0.0.0
        // (00000000) bind-to-all listener IS externally reachable, so it must
        // NOT be skipped — that is exactly the exposure this check surfaces.
        if ip_hex.eq_ignore_ascii_case("0100007F") {
            continue;
        }

        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };

        // Only flag privileged ports (< 1024) on non-loopback addresses.
        if port < 1024 {
            findings.push(HostFinding {
                rule_id: format!("harden.ports.privileged_{port}"),
                severity: Severity::High,
                category: HostCategory::Tamper,
                decision: Decision::Ask,
                reason: format!("Non-loopback listener on privileged port {port}"),
                owasp: "A05:2021 – Security Misconfiguration".into(),
                atlas: "AML.T0051".into(),
                fix: format!(
                    "Confirm port {port} is intentional; bind to loopback if not needed externally"
                ),
            });
        }
    }

    findings
}

/// Check world-writability of critical system files.
#[cfg(unix)]
fn check_file_modes() -> Vec<HostFinding> {
    use std::os::unix::fs::PermissionsExt;

    let mut findings = Vec::new();
    let critical_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"];

    for path in &critical_files {
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        let mode = meta.permissions().mode();
        // world-writable bit: 0o002
        if mode & 0o002 != 0 {
            findings.push(HostFinding {
                rule_id: format!("harden.filemode.world_writable_{}", path.replace('/', "_")),
                severity: Severity::High,
                category: HostCategory::Tamper,
                decision: Decision::Ask,
                reason: format!("{path} is world-writable"),
                owasp: "A05:2021 – Security Misconfiguration".into(),
                atlas: "AML.T0051".into(),
                fix: format!("Run: chmod o-w {path}"),
            });
        }
    }

    findings
}

/// Stub: no POSIX file modes on Windows (ACL check planned for a later task).
#[cfg(not(unix))]
fn check_file_modes() -> Vec<HostFinding> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_root_login_and_password_auth() {
        let cfg = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n";
        let findings = check_sshd(cfg);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "harden.ssh.root_login"));
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "harden.ssh.password_auth"));
    }

    #[test]
    fn clean_sshd_config_has_no_findings() {
        let cfg = "PermitRootLogin no\nPasswordAuthentication no\n";
        assert!(check_sshd(cfg).is_empty());
    }
}
