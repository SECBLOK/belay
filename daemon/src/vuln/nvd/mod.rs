//! NVD CVE engine: CPE range evaluation, alias resolution, HTTP sync, and lookup.
//!
//! This module is only compiled when the `vulndb` Cargo feature is enabled.

mod nvd_parse;
mod nvd_store;

pub use nvd_parse::{extract_cpe_matches, parse_cve, StoredCve};
pub use nvd_store::{load_product, upsert_cve, NvdStore};

use crate::engine::types::{Decision, Severity};
use crate::finding::{HostCategory, HostFinding};

// ---------------------------------------------------------------------------
// Product alias table
// ---------------------------------------------------------------------------

/// Maps a dpkg/rpm package name to `(vendor, canonical_nvd_product)`.
///
/// Populated from the Python `PRODUCT_ALIASES` dict. The scanner key is the
/// lowercase package name as it appears in `dpkg --list` / `rpm -qa`.
pub const PRODUCT_ALIASES: &[(&str, (&str, &str))] = &[
    ("apache2", ("apache", "http_server")),
    ("httpd", ("apache", "http_server")),
    ("apache", ("apache", "http_server")),
    ("nginx", ("nginx", "nginx")),
    ("openssl", ("openssl", "openssl")),
    ("libssl", ("openssl", "openssl")),
    ("libssl-dev", ("openssl", "openssl")),
    ("libssl3", ("openssl", "openssl")),
    ("openssh-server", ("openbsd", "openssh")),
    ("openssh-client", ("openbsd", "openssh")),
    ("openssh", ("openbsd", "openssh")),
    ("ssh", ("openbsd", "openssh")),
    ("sshd", ("openbsd", "openssh")),
    ("curl", ("haxx", "curl")),
    ("libcurl", ("haxx", "curl")),
    ("libcurl4", ("haxx", "curl")),
    ("libcurl3", ("haxx", "curl")),
    ("wget", ("gnu", "wget")),
    ("bash", ("gnu", "bash")),
    ("python3", ("python", "python")),
    ("python", ("python", "python")),
    ("python3-minimal", ("python", "python")),
    ("nodejs", ("nodejs", "node.js")),
    ("node", ("nodejs", "node.js")),
    ("php", ("php", "php")),
    ("php8.2", ("php", "php")),
    ("php8.1", ("php", "php")),
    ("php8.0", ("php", "php")),
    ("php7.4", ("php", "php")),
    ("php-fpm", ("php", "php")),
    ("mysql-server", ("oracle", "mysql")),
    ("mysql-client", ("oracle", "mysql")),
    ("mariadb-server", ("mariadb", "mariadb")),
    ("mariadb-client", ("mariadb", "mariadb")),
    ("postgresql", ("postgresql", "postgresql")),
    ("redis-server", ("redis", "redis")),
    ("redis", ("redis", "redis")),
    ("mongodb", ("mongodb", "mongodb")),
    ("docker", ("docker", "docker")),
    ("docker-ce", ("docker", "docker")),
    ("containerd", ("docker", "containerd")),
    ("kubernetes", ("kubernetes", "kubernetes")),
    ("kubectl", ("kubernetes", "kubernetes")),
    ("linux-image", ("linux", "linux_kernel")),
    ("linux-kernel", ("linux", "linux_kernel")),
    ("glibc", ("gnu", "glibc")),
    ("libc6", ("gnu", "glibc")),
    ("sudo", ("sudo_project", "sudo")),
    ("git", ("git-scm", "git")),
    ("vim", ("vim", "vim")),
    ("wordpress", ("wordpress", "wordpress")),
    ("drupal", ("drupal", "drupal")),
    ("joomla", ("joomla", "joomla")),
    ("exim4", ("exim", "exim")),
    ("postfix", ("wietse_venema", "postfix")),
    ("sendmail", ("sendmail", "sendmail")),
    ("samba", ("samba", "samba")),
    ("bind9", ("isc", "bind")),
    ("named", ("isc", "bind")),
    ("dnsmasq", ("thekelleys", "dnsmasq")),
    ("ntp", ("ntp", "ntp")),
    ("ntpd", ("ntp", "ntp")),
    ("vsftpd", ("beasts", "vsftpd")),
    ("proftpd", ("proftpd_project", "proftpd")),
    ("squid", ("squid-cache", "squid")),
    ("haproxy", ("haproxy", "haproxy")),
    ("varnish", ("varnish-cache", "varnish")),
    ("rsync", ("rsync_project", "rsync")),
    ("tar", ("gnu", "tar")),
    ("gzip", ("gnu", "gzip")),
    ("zlib1g", ("zlib", "zlib")),
    ("libz", ("zlib", "zlib")),
    ("libpng", ("libpng", "libpng")),
    ("libjpeg", ("libjpeg-turbo", "libjpeg-turbo")),
    ("libxml2", ("xmlsoft", "libxml2")),
    ("libxslt", ("xmlsoft", "libxslt")),
    ("libxslt1.1", ("xmlsoft", "libxslt")),
    ("imagemagick", ("imagemagick", "imagemagick")),
    ("ghostscript", ("artifex", "ghostscript")),
    ("ffmpeg", ("ffmpeg", "ffmpeg")),
    ("vlc", ("videolan", "vlc_media_player")),
    ("openjdk-17-jdk", ("oracle", "jdk")),
    ("openjdk-11-jdk", ("oracle", "jdk")),
    ("default-jdk", ("oracle", "jdk")),
    ("java", ("oracle", "jdk")),
    ("perl", ("perl", "perl")),
    ("ruby", ("ruby-lang", "ruby")),
    ("ruby-full", ("ruby-lang", "ruby")),
    ("golang", ("google", "go")),
    ("golang-go", ("google", "go")),
    ("go", ("google", "go")),
    ("rustc", ("rust-lang", "rust")),
    ("rust", ("rust-lang", "rust")),
    ("pip", ("python", "pip")),
    ("python3-pip", ("python", "pip")),
    ("npm", ("npmjs", "npm")),
    ("yarn", ("yarnpkg", "yarn")),
    ("ansible", ("redhat", "ansible")),
    ("terraform", ("hashicorp", "terraform")),
    ("vault", ("hashicorp", "vault")),
    ("consul", ("hashicorp", "consul")),
    ("grafana", ("grafana", "grafana")),
    ("prometheus", ("prometheus", "prometheus")),
    ("elasticsearch", ("elastic", "elasticsearch")),
    ("logstash", ("elastic", "logstash")),
    ("kibana", ("elastic", "kibana")),
    ("jenkins", ("jenkins", "jenkins")),
    ("gitlab", ("gitlab", "gitlab")),
    ("chromium", ("google", "chrome")),
    ("chromium-browser", ("google", "chrome")),
    ("firefox", ("mozilla", "firefox")),
    ("firefox-esr", ("mozilla", "firefox")),
    ("wireshark", ("wireshark", "wireshark")),
    ("tcpdump", ("tcpdump", "tcpdump")),
    ("nmap", ("nmap", "nmap")),
    ("snort", ("snort", "snort")),
    ("suricata", ("oisf", "suricata")),
    ("libssl1.1", ("openssl", "openssl")),
    // --- Python PRODUCT_ALIASES additions ---
    ("mysql", ("oracle", "mysql")),
    ("postgres", ("postgresql", "postgresql")),
    ("tomcat", ("apache", "tomcat")),
    ("iis", ("microsoft", "internet_information_services")),
    ("smb", ("samba", "samba")),
    ("phpmyadmin", ("phpmyadmin", "phpmyadmin")),
    ("webmin", ("webmin", "webmin")),
    ("django", ("djangoproject", "django")),
    ("flask", ("palletsprojects", "flask")),
    ("pyyaml", ("pyyaml", "pyyaml")),
    ("pillow", ("python", "pillow")),
    ("jinja2", ("palletsprojects", "jinja2")),
    ("tornado", ("tornadoweb", "tornado")),
    ("twisted", ("twisted", "twisted")),
    ("requests", ("python-requests", "requests")),
    ("numpy", ("numpy", "numpy")),
    ("pandas", ("pandas", "pandas")),
    ("airflow", ("apache", "airflow")),
    ("aiohttp", ("aiohttp", "aiohttp")),
    ("celery", ("celeryproject", "celery")),
    ("sqlalchemy", ("sqlalchemy", "sqlalchemy")),
    ("fastapi", ("tiangolo", "fastapi")),
    ("salt", ("saltstack", "salt")),
    ("scrapy", ("scrapinghub", "scrapy")),
    ("urllib3", ("python", "urllib3")),
    ("cpython", ("python", "python")),
];

// ---------------------------------------------------------------------------
// CPE match struct
// ---------------------------------------------------------------------------

/// One CPE match entry from an NVD configuration node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CpeMatch {
    pub product: String,
    pub exact_version: Option<String>,
    pub version_start: Option<String>,
    pub version_start_including: bool,
    pub version_end: Option<String>,
    pub version_end_including: bool,
}

// ---------------------------------------------------------------------------
// CVE record (returned from lookup)
// ---------------------------------------------------------------------------

/// A resolved CVE record returned by [`lookup`].
#[derive(Debug, Clone)]
pub struct CveRecord {
    pub cve_id: String,
    pub cvss3_score: f32,
    pub cvss3_severity: String,
    pub cwe_id: String,
    pub is_kev: bool,
    pub description: String,
}

// ---------------------------------------------------------------------------
// 15.1 — in_vulnerable_range
// ---------------------------------------------------------------------------

/// Return `true` if `installed` falls within the vulnerable version window
/// described by `m`.
///
/// Rules (mirrors NVD CPE match semantics):
/// - If `exact_version` is set, only that exact version matches.
/// - Otherwise the version must satisfy every bound that is present:
///   - `version_start` (including or excluding)
///   - `version_end` (including or excluding)
/// - If no bounds are set at all (bare wildcard), every version matches.
pub fn in_vulnerable_range(installed: &str, m: &CpeMatch) -> bool {
    use version_compare::{compare_to, Cmp};

    if let Some(ref exact) = m.exact_version {
        return installed == exact.as_str();
    }

    // Check lower bound
    if let Some(ref start) = m.version_start {
        if m.version_start_including {
            // installed >= start
            if !compare_to(installed, start, Cmp::Ge).unwrap_or(false) {
                return false;
            }
        } else {
            // installed > start
            if !compare_to(installed, start, Cmp::Gt).unwrap_or(false) {
                return false;
            }
        }
    }

    // Check upper bound
    if let Some(ref end) = m.version_end {
        if m.version_end_including {
            // installed <= end
            if !compare_to(installed, end, Cmp::Le).unwrap_or(false) {
                return false;
            }
        } else {
            // installed < end
            if !compare_to(installed, end, Cmp::Lt).unwrap_or(false) {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 15.1 — resolve_alias
// ---------------------------------------------------------------------------

/// Resolve a package/product name through `PRODUCT_ALIASES`.
///
/// Returns `(vendor_option, canonical_product_name)`.  If no alias is found
/// the original name is returned as the product with no vendor.
pub fn resolve_alias(name: &str) -> (Option<&'static str>, String) {
    let key = name.to_lowercase().replace(' ', "_");
    for (alias, (vendor, product)) in PRODUCT_ALIASES {
        if *alias == key.as_str() {
            return (Some(vendor), product.to_string());
        }
    }
    (None, key)
}

// ---------------------------------------------------------------------------
// 15.4 — keyword_for
// ---------------------------------------------------------------------------

/// Build an NVD keyword search string from a vendor + product pair.
///
/// Mirrors the Python:
/// ```python
/// keyword = cpe_string.replace("cpe:2.3:a:", "").replace(":", " ").replace("_", " ")
/// keyword = " ".join(dict.fromkeys(keyword.split()))
/// ```
pub fn keyword_for(vendor: &str, product: &str) -> String {
    let raw = format!("{}:{}", vendor, product)
        .replace(':', " ")
        .replace('_', " ");
    let mut seen = Vec::new();
    let mut seen_set = std::collections::HashSet::new();
    for word in raw.split_whitespace() {
        if seen_set.insert(word.to_string()) {
            seen.push(word.to_string());
        }
    }
    seen.join(" ")
}

// ---------------------------------------------------------------------------
// 15.5 — parse_kev_ids
// ---------------------------------------------------------------------------

/// Extract CVE IDs from a CISA KEV JSON payload.
///
/// The payload has the shape `{ "vulnerabilities": [{ "cveID": "CVE-…" }, …] }`.
pub fn parse_kev_ids(json: &serde_json::Value) -> Vec<String> {
    json.get("vulnerabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.get("cveID")?.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 15.4 — sync_product (network, ignore in CI)
// ---------------------------------------------------------------------------

/// Sync NVD CVE data for a vendor+product pair into the local store with full pagination.
///
/// Returns `(inserted, updated)` counts.
///
/// Reads the NVD API key from the `BELAY_NVD_API_KEY` environment variable.
/// Implements rate-limiting (700 ms between pages) and up to 3 retries with
/// exponential backoff for 429/503 responses.
///
/// Integration tests using this function should be marked `#[ignore]`.
#[allow(dead_code)]
pub async fn sync_product(
    store: &NvdStore,
    vendor: &str,
    product: &str,
) -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::time::{sleep, Duration};

    let api_key = std::env::var("BELAY_NVD_API_KEY").ok();
    let keyword = keyword_for(vendor, product);
    let encoded_keyword = urlencoding::encode(&keyword).into_owned();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut start_index: usize = 0;
    let results_per_page: usize = 500;
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut first_page = true;
    let mut total_results: usize = 0;

    loop {
        if !first_page && start_index >= total_results {
            break;
        }

        // Rate-limit: 700ms between pages (after the first)
        if !first_page {
            sleep(Duration::from_millis(700)).await;
        }
        first_page = false;

        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&startIndex={}&resultsPerPage={}",
            encoded_keyword, start_index, results_per_page
        );

        // Retry loop: up to 3 attempts with exponential backoff (5s, 10s, 20s)
        let body: serde_json::Value = {
            let mut attempt = 0u32;
            let mut backoff_secs = 5u64;
            loop {
                attempt += 1;
                let mut req = client.get(&url);
                if let Some(ref key) = api_key {
                    req = req.header("apiKey", key.as_str());
                }
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        {
                            if attempt >= 3 {
                                return Err(
                                    format!("NVD API returned {} after 3 retries", status).into()
                                );
                            }
                            sleep(Duration::from_secs(backoff_secs)).await;
                            backoff_secs *= 2;
                            continue;
                        }
                        if !status.is_success() {
                            return Err(format!("NVD API HTTP {}", status).into());
                        }
                        match resp.json::<serde_json::Value>().await {
                            Ok(v) => break v,
                            Err(e) => {
                                if attempt >= 3 {
                                    return Err(e.into());
                                }
                                sleep(Duration::from_secs(backoff_secs)).await;
                                backoff_secs *= 2;
                            }
                        }
                    }
                    Err(e) => {
                        if attempt >= 3 {
                            return Err(e.into());
                        }
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs *= 2;
                    }
                }
            }
        };

        // Read totalResults on first page
        if total_results == 0 {
            total_results = body
                .get("totalResults")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
        }

        let vulnerabilities = body
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if vulnerabilities.is_empty() {
            break;
        }

        for vuln_wrapper in &vulnerabilities {
            let cve_val = match vuln_wrapper.get("cve") {
                Some(v) => v,
                None => continue,
            };
            let stored = match parse_cve(cve_val) {
                Some(s) => s,
                None => continue,
            };

            let prod_key = stored
                .cpe_matches
                .first()
                .map(|m| m.product.clone())
                .unwrap_or_else(|| product.to_string());

            let existing = load_product(store, &prod_key).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;
            let already_exists = existing.iter().any(|c| c.cve_id == stored.cve_id);

            upsert_cve(store, &prod_key, stored).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;

            if already_exists {
                updated += 1;
            } else {
                inserted += 1;
            }
        }

        start_index += results_per_page;
    }

    Ok((inserted, updated))
}

// ---------------------------------------------------------------------------
// 15.5 — sync_kev (network, ignore in CI)
// ---------------------------------------------------------------------------

/// Download the CISA KEV catalog, fetch each CVE from NVD, and upsert into the store
/// with `is_kev = true`.
///
/// Returns the number of CVEs upserted.
///
/// Reads the NVD API key from the `BELAY_NVD_API_KEY` environment variable.
/// The `_api_key` parameter is kept for backward compatibility but ignored.
///
/// Integration tests using this function should be marked `#[ignore]`.
#[allow(dead_code)]
pub async fn sync_kev(
    store: &NvdStore,
    _api_key: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::time::{sleep, Duration};

    let api_key = std::env::var("BELAY_NVD_API_KEY").ok();

    let kev_url =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client.get(kev_url).send().await?;
    let body: serde_json::Value = resp.json().await?;
    let ids = parse_kev_ids(&body);

    let mut updated = 0usize;

    for cve_id in &ids {
        // Look up this CVE in NVD by ID
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
            cve_id
        );

        // Retry with exponential backoff
        let mut attempt = 0u32;
        let mut backoff_secs = 5u64;
        let nvd_body: serde_json::Value = loop {
            attempt += 1;
            let mut req = client.get(&url);
            if let Some(ref key) = api_key {
                req = req.header("apiKey", key.as_str());
            }
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    {
                        if attempt >= 3 {
                            break serde_json::Value::Null;
                        }
                        sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs *= 2;
                        continue;
                    }
                    if status == reqwest::StatusCode::NOT_FOUND {
                        break serde_json::Value::Null;
                    }
                    if !status.is_success() {
                        break serde_json::Value::Null;
                    }
                    match resp.json::<serde_json::Value>().await {
                        Ok(v) => break v,
                        Err(_) => {
                            if attempt >= 3 {
                                break serde_json::Value::Null;
                            }
                            sleep(Duration::from_secs(backoff_secs)).await;
                            backoff_secs *= 2;
                        }
                    }
                }
                Err(_) => {
                    if attempt >= 3 {
                        break serde_json::Value::Null;
                    }
                    sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs *= 2;
                }
            }
        };

        if nvd_body.is_null() {
            continue;
        }

        let vulns = match nvd_body.get("vulnerabilities").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr.clone(),
            _ => continue,
        };

        for vuln_wrapper in &vulns {
            let cve_val = match vuln_wrapper.get("cve") {
                Some(v) => v.clone(),
                None => continue,
            };

            let mut stored = match parse_cve(&cve_val) {
                Some(s) => s,
                None => continue,
            };

            // Force is_kev = true (KEV catalog is the authority)
            stored.is_kev = true;

            let prod_key = stored
                .cpe_matches
                .first()
                .map(|m| m.product.clone())
                .unwrap_or_else(|| cve_id.to_lowercase().replace('-', "_"));

            upsert_cve(store, &prod_key, stored).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },
            )?;
            updated += 1;
        }

        // Rate-limit between CVE lookups
        sleep(Duration::from_millis(700)).await;
    }

    Ok(updated)
}

// ---------------------------------------------------------------------------
// 15.6 — lookup
// ---------------------------------------------------------------------------

/// Look up all CVEs that apply to `name` at version `version`.
///
/// Resolution steps:
/// 1. Alias-resolve `name` to get the canonical NVD product name.
/// 2. Load all stored CVEs for that product.
/// 3. If `version` is non-empty, keep only CVEs where at least one `CpeMatch`
///    covers `version` via [`in_vulnerable_range`].
/// 4. Sort: KEV-first, then descending CVSS3 score.
pub fn lookup(
    store: &NvdStore,
    name: &str,
    version: &str,
) -> Result<Vec<CveRecord>, Box<dyn std::error::Error>> {
    let (_vendor, product) = resolve_alias(name);
    let stored = load_product(store, &product)?;

    let mut records: Vec<CveRecord> = stored
        .into_iter()
        .filter(|cve| {
            if version.is_empty() {
                return true;
            }
            cve.cpe_matches
                .iter()
                .any(|m| in_vulnerable_range(version, m))
        })
        .map(|cve| CveRecord {
            cve_id: cve.cve_id,
            cvss3_score: cve.cvss3_score.unwrap_or(0.0),
            cvss3_severity: cve.cvss3_severity,
            cwe_id: cve.cwe_id,
            is_kev: cve.is_kev,
            description: cve.description,
        })
        .collect();

    // Sort: KEV first, then CVSS score descending
    records.sort_by(|a, b| {
        b.is_kev.cmp(&a.is_kev).then(
            b.cvss3_score
                .partial_cmp(&a.cvss3_score)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    Ok(records)
}

// ---------------------------------------------------------------------------
// 15.6 — to_findings
// ---------------------------------------------------------------------------

/// Convert a slice of [`CveRecord`]s to [`HostFinding`]s for unified reporting.
///
/// Severity mapping:
/// - KEV → `Critical` (regardless of CVSS score)
/// - Otherwise: "CRITICAL"→Critical, "HIGH"→High, "MEDIUM"→Medium, "LOW"→Low, else Info
pub fn to_findings(hits: &[CveRecord], where_: &str) -> Vec<HostFinding> {
    hits.iter()
        .map(|cve| {
            let severity = if cve.is_kev {
                Severity::Critical
            } else {
                match cve.cvss3_severity.to_ascii_uppercase().as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Info,
                }
            };

            let kev_tag = if cve.is_kev { " [CISA-KEV]" } else { "" };
            HostFinding {
                rule_id: "vuln.nvd_cve".to_string(),
                severity,
                category: HostCategory::Recon,
                decision: Decision::Ask,
                reason: format!(
                    "{}{} — {} ({})",
                    cve.cve_id, kev_tag, cve.description, where_
                ),
                owasp: String::new(),
                atlas: String::new(),
                fix: format!(
                    "Patch or mitigate {} ({} CVSS {})",
                    cve.cve_id, cve.cvss3_severity, cve.cvss3_score
                ),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests for 15.1
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn m(exact: Option<&str>, vs: Option<(&str, bool)>, ve: Option<(&str, bool)>) -> CpeMatch {
        CpeMatch {
            product: "http_server".into(),
            exact_version: exact.map(String::from),
            version_start: vs.map(|(v, _)| v.to_string()),
            version_start_including: vs.map(|(_, inc)| inc).unwrap_or(false),
            version_end: ve.map(|(v, _)| v.to_string()),
            version_end_including: ve.map(|(_, inc)| inc).unwrap_or(false),
        }
    }

    #[test]
    fn exact_version_matches_only_itself() {
        let cpe = m(Some("2.4.41"), None, None);
        assert!(in_vulnerable_range("2.4.41", &cpe));
        assert!(!in_vulnerable_range("2.4.42", &cpe));
    }

    #[test]
    fn end_excluding_means_vulnerable_below_the_fix() {
        let cpe = m(None, None, Some(("2.4.49", false)));
        assert!(in_vulnerable_range("2.4.41", &cpe));
        assert!(!in_vulnerable_range("2.4.49", &cpe));
        assert!(!in_vulnerable_range("2.4.50", &cpe));
    }

    #[test]
    fn start_including_and_end_excluding_window() {
        let cpe = m(None, Some(("2.4.0", true)), Some(("2.4.49", false)));
        assert!(!in_vulnerable_range("2.3.9", &cpe));
        assert!(in_vulnerable_range("2.4.10", &cpe));
        assert!(!in_vulnerable_range("2.4.49", &cpe));
    }

    #[test]
    fn bare_wildcard_applies_to_all_versions() {
        let cpe = m(None, None, None);
        assert!(in_vulnerable_range("anything", &cpe));
    }

    // 15.4 tests
    #[test]
    fn keyword_from_cpe_strips_prefix_and_dedups() {
        assert_eq!(keyword_for("apache", "http_server"), "apache http server");
        assert_eq!(keyword_for("wordpress", "wordpress"), "wordpress");
    }

    // 15.5 tests
    #[test]
    fn parse_kev_ids_reads_cve_id_field() {
        let j: serde_json::Value = serde_json::from_str(
            r#"{"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2014-0160"},{"x":1}]}"#,
        )
        .unwrap();
        assert_eq!(parse_kev_ids(&j), vec!["CVE-2021-44228", "CVE-2014-0160"]);
    }

    // 15.6 tests
    #[test]
    fn lookup_ranks_kev_before_non_kev() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let store = NvdStore::open(&dir.path().join("test.redb")).unwrap();
        let kev_cve = StoredCve {
            cve_id: "CVE-2021-41773".to_string(),
            description: "KEV".to_string(),
            cvss3_score: Some(6.0),
            cvss3_severity: "MEDIUM".to_string(),
            cwe_id: "CWE-22".to_string(),
            is_kev: true,
            cpe_matches: vec![CpeMatch {
                product: "http_server".into(),
                exact_version: Some("2.4.49".into()),
                version_start: None,
                version_start_including: false,
                version_end: None,
                version_end_including: false,
            }],
        };
        let high_cve = StoredCve {
            cve_id: "CVE-2021-99999".to_string(),
            description: "non-KEV HIGH".to_string(),
            cvss3_score: Some(8.0),
            cvss3_severity: "HIGH".to_string(),
            cwe_id: "CWE-79".to_string(),
            is_kev: false,
            cpe_matches: vec![CpeMatch {
                product: "http_server".into(),
                exact_version: Some("2.4.49".into()),
                version_start: None,
                version_start_including: false,
                version_end: None,
                version_end_including: false,
            }],
        };
        upsert_cve(&store, "http_server", kev_cve).unwrap();
        upsert_cve(&store, "http_server", high_cve).unwrap();
        let results = lookup(&store, "apache", "2.4.49").unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_kev, "KEV should rank first");
        assert_eq!(results[0].cve_id, "CVE-2021-41773");
    }

    #[test]
    fn lookup_filters_out_non_matching_versions() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let store = NvdStore::open(&dir.path().join("test2.redb")).unwrap();
        let cve = StoredCve {
            cve_id: "CVE-2021-41773".to_string(),
            description: "path traversal".to_string(),
            cvss3_score: Some(7.5),
            cvss3_severity: "HIGH".to_string(),
            cwe_id: "CWE-22".to_string(),
            is_kev: false,
            cpe_matches: vec![CpeMatch {
                product: "http_server".into(),
                exact_version: Some("2.4.49".into()),
                version_start: None,
                version_start_including: false,
                version_end: None,
                version_end_including: false,
            }],
        };
        upsert_cve(&store, "http_server", cve).unwrap();
        assert!(lookup(&store, "apache", "2.4.50").unwrap().is_empty());
        assert_eq!(lookup(&store, "apache", "2.4.49").unwrap().len(), 1);
    }

    #[test]
    fn lookup_resolve_alias_ssh_finds_openssh_cves() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let store = NvdStore::open(&dir.path().join("test3.redb")).unwrap();
        let cve = StoredCve {
            cve_id: "CVE-2023-38408".to_string(),
            description: "openssh vuln".to_string(),
            cvss3_score: Some(9.8),
            cvss3_severity: "CRITICAL".to_string(),
            cwe_id: "CWE-94".to_string(),
            is_kev: true,
            cpe_matches: vec![CpeMatch {
                product: "openssh".into(),
                exact_version: None,
                version_start: None,
                version_start_including: false,
                version_end: Some("9.3p2".into()),
                version_end_including: false,
            }],
        };
        upsert_cve(&store, "openssh", cve).unwrap();
        let results = lookup(&store, "ssh", "9.3p1").unwrap();
        assert_eq!(results.len(), 1, "ssh alias should find openssh CVEs");
    }
}
