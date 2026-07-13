//! DTOs that serialise to the TypeScript `hostTypes.ts` shapes.
//! All field names and enum string values must match the TS contract exactly.

use serde::Serialize;

use crate::engine::types::Severity;
use crate::finding::HostFinding;

// ── HardeningPosture ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HardeningCheckDto {
    pub id: String,
    pub label: String,
    /// "pass" | "fail" | "warn" | "skip"
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardeningPostureDto {
    pub score: u8,
    pub checks: Vec<HardeningCheckDto>,
    /// False when host hardening auditing is not available on this platform
    /// (Windows). The checks (sshd_config, listening ports, key-file modes) are
    /// Linux/macOS-specific; on Windows an empty `checks` would misleadingly
    /// render as a perfectly hardened `score: 100`, so the UI shows a neutral
    /// "not available on this OS" card instead. Mirrors `VulnPostureDto`.
    pub supported: bool,
    /// Human-readable reason when `supported == false`.
    pub reason: Option<String>,
}

// ── VulnPosture ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CveFindingDto {
    pub cve_id: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    /// "critical" | "high" | "medium" | "low"
    pub severity: String,
    pub description: String,
    pub published_at: String,
    pub kev: bool,
    /// EPSS probability of exploitation in the next 30 days `[0,1]`, or `null` when
    /// the advisory carries no EPSS score (bundled/open DB). TS: `epss: number | null`.
    pub epss: Option<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnPostureDto {
    pub scanned_at: Option<String>,
    pub job_id: Option<String>,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub findings: Vec<CveFindingDto>,
    /// False when this OS/bundle is not covered (rpm distros, rolling distros,
    /// or a bundle for a different ecosystem). The UI shows a neutral
    /// "not available on this OS" card instead of a misleading score.
    pub supported: bool,
    /// Human-readable reason when `supported == false`.
    pub reason: Option<String>,
}

// ── ProposedRuleset ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct EgressRuleDto {
    pub id: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// "tcp" | "udp" | "any"
    pub proto: &'static str,
    /// "allow" | "deny"
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProposedRulesetDto {
    pub description: String,
    pub rules: Vec<EgressRuleDto>,
    pub generated_at: String,
}

// ── Ban (SSH brute-force guard) ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct BanDto {
    pub id: String,
    pub target: String,
    /// "ip" | "user"
    pub kind: &'static str,
    pub banned_at: String,
    /// RFC3339 expiry, or `null` for a permanent ban (serialises as JSON null,
    /// never omitted — the TS contract is `string | null`, not optional).
    pub expires_at: Option<String>,
    pub reason: String,
}

// ── FirewallStatus ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct FirewallStatusDto {
    pub active: bool,
    /// "off" | "monitor" | "enforce"
    pub mode: &'static str,
    pub handle: Option<String>,
    pub revert_deadline: Option<u64>,
    pub rule_count: usize,
}

// ── Conversion helpers ────────────────────────────────────────────────────────

fn sev_weight(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 25,
        Severity::High => 15,
        Severity::Medium => 8,
        Severity::Low => 3,
        Severity::Info => 0,
    }
}

fn humanize_rule_id(rule_id: &str) -> String {
    // "harden.ssh.root_login" → "Ssh Root Login"
    // "harden.ports.privileged_80" → "Privileged 80"
    let last = rule_id.rsplit('.').next().unwrap_or(rule_id);
    last.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sev_status(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "fail",
        Severity::Medium | Severity::Low => "warn",
        Severity::Info => "skip",
    }
}

fn sev_str(s: &Severity) -> String {
    match s {
        Severity::Critical => "critical".to_string(),
        Severity::High => "high".to_string(),
        Severity::Medium => "medium".to_string(),
        Severity::Low => "low".to_string(),
        Severity::Info => "low".to_string(), // clamp info→low for CveFinding
    }
}

/// Build a `HardeningPostureDto` from the daemon's `audit_host()` output.
///
/// On Windows the underlying checks are inapplicable (they probe sshd_config,
/// `/proc/net/tcp`, and POSIX key-file modes), so instead of returning an empty
/// `checks` that scores 100 — falsely reading as a perfectly hardened host — we
/// return an explicit `supported: false` marker with a reason.
pub fn build_hardening_posture() -> HardeningPostureDto {
    #[cfg(windows)]
    {
        HardeningPostureDto {
            score: 0,
            checks: Vec::new(),
            supported: false,
            reason: Some("Host hardening audit is not supported on Windows.".to_string()),
        }
    }
    #[cfg(not(windows))]
    {
        let findings = crate::hardening::audit_host();
        posture_from_findings(&findings)
    }
}

/// Testable core — separated so unit tests can pass synthetic findings.
pub fn posture_from_findings(findings: &[HostFinding]) -> HardeningPostureDto {
    let total_weight: u32 = findings
        .iter()
        .map(|f| u32::from(sev_weight(&f.severity)))
        .sum();
    let score = 100u32.saturating_sub(total_weight).min(100) as u8;

    let checks = findings
        .iter()
        .map(|f| HardeningCheckDto {
            id: f.rule_id.clone(),
            label: humanize_rule_id(&f.rule_id),
            status: sev_status(&f.severity),
            detail: Some(format!("{} — Fix: {}", f.reason, f.fix)),
        })
        .collect();

    HardeningPostureDto { score, checks, supported: true, reason: None }
}

/// Build a `VulnPostureDto` from dpkg status + advisory cache.
pub fn build_vuln_posture() -> VulnPostureDto {
    let host_eco = crate::vuln::host_ecosystem();
    let advisories = crate::vuln::load_advisories();
    vuln_posture_for(host_eco.as_deref(), &advisories)
}

/// Pure core: gate first, then (if supported) match installed packages.
pub fn vuln_posture_for(
    host_ecosystem: Option<&str>,
    advisories: &[crate::vuln::Advisory],
) -> VulnPostureDto {
    use crate::vuln::{bundle_ecosystems, match_advisories_enriched, parse_dpkg_status};

    let unsupported = |reason: String| VulnPostureDto {
        scanned_at: None,
        job_id: None,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        findings: Vec::new(),
        supported: false,
        reason: Some(reason),
    };

    let Some(host_eco) = host_ecosystem else {
        return unsupported(
            "Vulnerability posture currently supports Debian and Ubuntu; this OS is not covered."
                .into(),
        );
    };
    let covered = bundle_ecosystems(advisories)
        .iter()
        .any(|e| e == host_eco || (e == "Debian:*" && host_eco.starts_with("Debian:")));
    if !covered {
        return unsupported(format!(
            "No bundled advisory data for {host_eco}; this build covers a different distribution."
        ));
    }

    let dpkg_text = std::fs::read_to_string("/var/lib/dpkg/status").unwrap_or_default();
    let installed = parse_dpkg_status(&dpkg_text);
    let raw_findings = match_advisories_enriched(&installed, advisories);

    // Map each raw (HostFinding, enrichment) pair to one CveFindingDto, parsing the
    // finding's structured `reason` string ("<pkg> <ver> is affected by <CVEs>
    // (fixed in <ver>)") for the core fields and taking KEV/EPSS from the paired
    // advisory enrichment.
    let findings: Vec<CveFindingDto> = raw_findings
        .iter()
        .enumerate()
        .map(|(idx, (f, enr))| {
            let pkg = f
                .reason
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            let installed_ver = f.reason.split_whitespace().nth(1).unwrap_or("").to_string();
            let fixed_ver = f
                .reason
                .split("fixed in ")
                .nth(1)
                .map(|s| s.trim_end_matches(')').to_string());
            let cve_id = f
                .reason
                .split_whitespace()
                .find(|w| w.starts_with("CVE-"))
                .map(|s| s.trim_end_matches(',').to_string())
                .unwrap_or_else(|| format!("UNKNOWN-{idx}"));
            CveFindingDto {
                cve_id,
                package: pkg,
                installed_version: installed_ver,
                fixed_version: fixed_ver,
                severity: sev_str(&f.severity),
                description: f.reason.clone(),
                published_at: String::new(),
                kev: enr.kev,
                epss: enr.epss,
            }
        })
        .collect();

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();
    let total = findings.len();

    // Rolling Debian derivatives (Kali, Debian testing/sid) are matched against
    // the Debian unstable (sid) bundle — close, but not an exact per-release
    // map — so the posture carries an explicit "approximate" caveat even though
    // it is `supported`.
    let reason = (host_eco == crate::vuln::ROLLING_DEBIAN_ECOSYSTEM).then(|| {
        "Rolling release (Kali / Debian testing): matched against Debian unstable \
         (sid) — results are approximate."
            .to_string()
    });

    VulnPostureDto {
        scanned_at: None,
        job_id: None,
        total,
        critical,
        high,
        medium,
        low,
        findings,
        supported: true,
        reason,
    }
}

/// Build a read-only `FirewallStatusDto` (piece 1: no applied state yet).
pub fn build_firewall_status() -> FirewallStatusDto {
    FirewallStatusDto {
        active: false,
        mode: "off",
        handle: None,
        revert_deadline: None,
        rule_count: 0,
    }
}

/// Build a `ProposedRulesetDto` for the MANUAL flow.
/// With fw: observe live listening ports and propose a ruleset.
/// Without it: return an empty ruleset with an explanatory description.
pub fn build_proposed_ruleset() -> ProposedRulesetDto {
    #[cfg(fw)]
    {
        use crate::firewall::assistant::{observe_listen_ports, propose_ruleset};
        let managed = propose_ruleset(&observe_listen_ports(), None);
        let allow_count = managed.allow_ports.len() + managed.ssh_source.is_some() as usize;
        managed_to_dto(
            &managed,
            format!("Least-privilege proposal: {allow_count} allow rule(s) + default drop"),
        )
    }
    #[cfg(not(fw))]
    {
        firewall_unavailable_dto()
    }
}

/// Build a `ProposedRulesetDto` for the one-click AUTO setup: auto-detect the
/// system (OS, listening TCP+UDP services, SSH source) and propose a
/// least-privilege ruleset pre-filled for a single confirm click. Applying it
/// reuses the same manual `firewall_apply` path (dead-man's-switch + SSH pin).
pub fn build_auto_proposed_ruleset() -> ProposedRulesetDto {
    #[cfg(fw)]
    {
        use crate::firewall::assistant::propose_auto_ruleset;
        use crate::firewall::detect::detect_system;
        let profile = detect_system();
        let managed = propose_auto_ruleset(&profile);
        let allow_count = managed.allow_ports.len() + managed.ssh_source.is_some() as usize;
        let os = if profile.os.is_empty() {
            "this host".to_string()
        } else {
            profile.os.clone()
        };
        let ssh_note = match managed.ssh_source {
            Some(ip) => format!(", SSH pinned to {ip}"),
            None => String::new(),
        };
        managed_to_dto(
            &managed,
            format!("Auto-detected on {os}: {allow_count} allow rule(s) + default drop{ssh_note}"),
        )
    }
    #[cfg(not(fw))]
    {
        firewall_unavailable_dto()
    }
}

/// Convert a `ManagedRuleset` to the GUI DTO (allow rules + optional SSH pin +
/// optional default-drop), stamped with a valid RFC3339 `generated_at`. Shared
/// by the manual and auto proposal builders so they never diverge.
#[cfg(fw)]
fn managed_to_dto(
    managed: &crate::firewall::ManagedRuleset,
    description: String,
) -> ProposedRulesetDto {
    let generated_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format_rfc3339_utc(secs)
    };

    let mut rules: Vec<EgressRuleDto> = managed
        .allow_ports
        .iter()
        .enumerate()
        .map(|(i, &port)| EgressRuleDto {
            id: format!("auto-{i}"),
            host: "0.0.0.0".to_string(),
            port: Some(port),
            proto: "tcp",
            action: "allow",
            comment: None,
        })
        .collect();

    if let Some(ssh_ip) = managed.ssh_source {
        rules.push(EgressRuleDto {
            id: "ssh-pinned".to_string(),
            host: ssh_ip.to_string(),
            port: Some(22),
            proto: "tcp",
            action: "allow",
            comment: Some("SSH origin — pinned (anti-lockout)".to_string()),
        });
    }

    if managed.default_drop {
        rules.push(EgressRuleDto {
            id: "default-drop".to_string(),
            host: "0.0.0.0/0".to_string(),
            port: None,
            proto: "any",
            action: "deny",
            comment: Some("default drop".to_string()),
        });
    }

    ProposedRulesetDto {
        description,
        rules,
        generated_at,
    }
}

/// Shared empty DTO when the firewall feature is not compiled in.
#[cfg(not(fw))]
fn firewall_unavailable_dto() -> ProposedRulesetDto {
    ProposedRulesetDto {
        description: "Firewall support is not compiled in (build with --features firewall)"
            .to_string(),
        rules: vec![],
        generated_at: String::new(),
    }
}

/// Format a Unix timestamp as RFC3339 UTC string "YYYY-MM-DDTHH:MM:SSZ".
/// No chrono dependency; pure integer Gregorian-calendar math.
#[cfg(fw)]
fn format_rfc3339_utc(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };

    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::{Decision, Severity};
    use crate::finding::{HostCategory, HostFinding};

    fn make_finding(rule_id: &str, severity: Severity) -> HostFinding {
        HostFinding {
            rule_id: rule_id.to_string(),
            severity,
            category: HostCategory::Tamper,
            decision: Decision::Ask,
            reason: "test reason".to_string(),
            owasp: String::new(),
            atlas: String::new(),
            fix: "test fix".to_string(),
        }
    }

    #[test]
    fn hardening_posture_score_field_and_checks_key() {
        let findings = vec![make_finding("harden.ssh.root_login", Severity::High)];
        let dto = posture_from_findings(&findings);
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("score").is_some(), "must have 'score' key");
        assert!(v.get("checks").is_some(), "must have 'checks' key");
        assert_eq!(v["score"].as_u64().unwrap(), 85); // 100 - 15 (High)
    }

    #[test]
    fn hardening_posture_from_findings_is_supported() {
        // The normal (Unix) build path marks the posture supported.
        let dto = posture_from_findings(&[]);
        assert!(dto.supported);
        assert!(dto.reason.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn hardening_unsupported_on_windows() {
        // On Windows the checks are inapplicable — the DTO must say so explicitly
        // rather than returning an empty checks list that scores as fully hardened.
        let dto = build_hardening_posture();
        assert!(!dto.supported);
        assert!(dto.reason.is_some());
        assert!(dto.checks.is_empty());
    }

    #[test]
    fn hardening_check_status_is_fail_for_high_severity() {
        let findings = vec![make_finding("harden.ssh.root_login", Severity::High)];
        let dto = posture_from_findings(&findings);
        let v = serde_json::to_value(&dto).unwrap();
        let status = v["checks"][0]["status"].as_str().unwrap();
        assert_eq!(status, "fail");
    }

    #[test]
    fn hardening_check_status_is_warn_for_medium_severity() {
        let findings = vec![make_finding("harden.ports.privileged_80", Severity::Medium)];
        let dto = posture_from_findings(&findings);
        let v = serde_json::to_value(&dto).unwrap();
        let status = v["checks"][0]["status"].as_str().unwrap();
        assert_eq!(status, "warn");
    }

    #[test]
    fn hardening_check_has_id_and_label_fields() {
        let findings = vec![make_finding("harden.ssh.root_login", Severity::High)];
        let dto = posture_from_findings(&findings);
        let v = serde_json::to_value(&dto).unwrap();
        let check = &v["checks"][0];
        assert_eq!(check["id"].as_str().unwrap(), "harden.ssh.root_login");
        assert!(check.get("label").is_some(), "must have 'label' key");
    }

    #[test]
    fn vuln_posture_has_required_fields() {
        let dto = VulnPostureDto {
            scanned_at: None,
            job_id: None,
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            findings: vec![CveFindingDto {
                cve_id: "CVE-2024-6387".to_string(),
                package: "openssh-server".to_string(),
                installed_version: "1:8.9p1-3".to_string(),
                fixed_version: Some("1:8.9p1-3ubuntu0.1".to_string()),
                severity: "high".to_string(),
                description: "openssh-server is vulnerable".to_string(),
                published_at: String::new(),
                kev: false,
                epss: None,
            }],
            supported: true,
            reason: None,
        };
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("scanned_at").is_some());
        assert!(v.get("job_id").is_some());
        assert!(v.get("total").is_some());
        assert!(v.get("findings").is_some());
        let finding = &v["findings"][0];
        assert_eq!(finding["cve_id"].as_str().unwrap(), "CVE-2024-6387");
        assert_eq!(finding["severity"].as_str().unwrap(), "high");
        assert!(!finding["kev"].as_bool().unwrap());
        assert!(finding["epss"].is_null(), "epss serialises as number|null");
    }

    #[test]
    fn posture_gates_unsupported_distro() {
        let dto = vuln_posture_for(None, &[]); // host ecosystem unknown/unsupported
        assert!(!dto.supported);
        assert!(dto.reason.is_some());
        assert_eq!(dto.total, 0);
        assert!(dto.findings.is_empty());
    }

    #[test]
    fn posture_gates_bundle_host_mismatch() {
        use crate::vuln::Advisory;
        let bundle = vec![Advisory {
            id: "x".into(),
            package: "p".into(),
            fixed_version: "1".into(),
            severity: "low".into(),
            cve: vec![],
            release: "bookworm".into(),
            ecosystem: String::new(),
            source: String::new(),
            epss: None,
            kev: None,
            exploit: None,
            cvss: None,
            references: vec![],
            updated_at: String::new(),
        }];
        let dto = vuln_posture_for(Some("Ubuntu:24.04"), &bundle);
        assert!(!dto.supported, "Debian bundle must not score an Ubuntu host");
    }

    #[test]
    fn posture_carries_approximate_caveat_for_rolling_host() {
        use crate::vuln::{Advisory, ROLLING_DEBIAN_ECOSYSTEM};
        // A sid-tagged bundle covering a rolling (Kali/Debian-sid) host: the
        // posture is supported but must carry the "approximate" caveat.
        let bundle = vec![Advisory {
            id: "CVE-1".into(),
            package: "openssl".into(),
            fixed_version: "3.0.1".into(),
            severity: "high".into(),
            cve: vec!["CVE-1".into()],
            release: String::new(),
            ecosystem: ROLLING_DEBIAN_ECOSYSTEM.into(),
            source: "debian-tracker".into(),
            epss: None,
            kev: None,
            exploit: None,
            cvss: None,
            references: vec![],
            updated_at: String::new(),
        }];
        let dto = vuln_posture_for(Some(ROLLING_DEBIAN_ECOSYSTEM), &bundle);
        assert!(dto.supported, "a sid bundle covers a sid host");
        let reason = dto.reason.expect("rolling host must carry a caveat");
        assert!(reason.contains("approximate"), "caveat text: {reason}");
    }

    #[test]
    fn vuln_posture_parses_reason_into_cve_finding() {
        // Synthetic installed pkg + advisory → one CveFinding with right fields.
        use crate::vuln::{match_advisories_enriched, Advisory, Epss, InstalledPackage, Kev};
        let installed = vec![InstalledPackage {
            name: "openssh-server".to_string(),
            version: "1:8.9p1-3".to_string(),
        }];
        let advisories = vec![Advisory {
            id: "USN-0001-1".to_string(),
            package: "openssh-server".to_string(),
            fixed_version: "1:8.9p1-3ubuntu0.1".to_string(),
            severity: "high".to_string(),
            cve: vec!["CVE-2024-6387".to_string()],
            release: String::new(),
            ecosystem: String::new(),
            source: String::new(),
            epss: Some(Epss { score: 0.87, percentile: 0.98, as_of: "2026-07-01".into() }),
            kev: Some(Kev {
                known_exploited: true,
                date_added: "2024-07-01".into(),
                ransomware: false,
            }),
            exploit: None,
            cvss: None,
            references: vec![],
            updated_at: String::new(),
        }];
        let raw = match_advisories_enriched(&installed, &advisories);
        assert_eq!(raw.len(), 1);
        // Drive the same parse + enrichment path build_vuln_posture uses.
        let (f, enr) = &raw[0];
        // KEV/EPSS surface exactly as vuln_posture_for wires them into the DTO.
        assert!(enr.kev);
        assert_eq!(enr.epss, Some(0.87));
        let pkg = f.reason.split_whitespace().next().unwrap();
        let cve_id = f
            .reason
            .split_whitespace()
            .find(|w| w.starts_with("CVE-"))
            .map(|s| s.trim_end_matches(','))
            .unwrap();
        let fixed = f
            .reason
            .split("fixed in ")
            .nth(1)
            .map(|s| s.trim_end_matches(')'));
        assert_eq!(pkg, "openssh-server");
        assert_eq!(cve_id, "CVE-2024-6387");
        assert_eq!(fixed, Some("1:8.9p1-3ubuntu0.1"));
        assert_eq!(sev_str(&f.severity), "high");
    }

    #[test]
    fn firewall_status_dto_serialises_to_ts_contract() {
        let dto = build_firewall_status();
        let v = serde_json::to_value(&dto).unwrap();
        assert!(!v["active"].as_bool().unwrap());
        assert_eq!(v["mode"].as_str().unwrap(), "off");
        assert!(v["handle"].is_null());
        assert!(v["revert_deadline"].is_null());
        assert_eq!(v["rule_count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn proposed_ruleset_has_required_fields() {
        let dto = build_proposed_ruleset();
        let v = serde_json::to_value(&dto).unwrap();
        assert!(v.get("description").is_some());
        assert!(v.get("rules").is_some());
        assert!(v.get("generated_at").is_some());
    }

    #[test]
    fn score_clamps_to_zero_on_overflow() {
        let findings = vec![
            make_finding("a", Severity::Critical), // 25
            make_finding("b", Severity::Critical), // 25
            make_finding("c", Severity::Critical), // 25
            make_finding("d", Severity::Critical), // 25
            make_finding("e", Severity::High),     // 15 → total 115
        ];
        let dto = posture_from_findings(&findings);
        assert_eq!(dto.score, 0);
    }

    #[cfg(fw)]
    #[test]
    fn format_rfc3339_utc_produces_iso_format() {
        let s = format_rfc3339_utc(0);
        assert_eq!(s, "1970-01-01T00:00:00Z");
        let s2 = format_rfc3339_utc(1_705_320_000);
        assert_eq!(s2, "2024-01-15T12:00:00Z");
    }
}
