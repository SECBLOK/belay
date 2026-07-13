//! OSV.dev batch CVE lookup. Never raises; offline returns [].
//! Faithful port of the deleted Python predecessor's scan/analyzers/osv.py

use crate::types::{Category, Decision, Finding, Severity};

#[derive(serde::Deserialize)]
struct OsvResponse {
    #[serde(default)]
    results: Vec<OsvResult>,
}

#[derive(serde::Deserialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(serde::Deserialize)]
struct OsvVuln {
    #[serde(default)]
    id: String,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type", default)]
    typ: String,
    #[serde(default)]
    score: String,
}

fn extract_severity(vuln: &OsvVuln) -> Severity {
    for entry in &vuln.severity {
        // _cvss_to_severity always returns MEDIUM for CVSS vector strings (those
        // containing '/'). For non-slash scores Python's parser ignores the float
        // and falls through to database_specific, so only vector strings match here.
        if entry.typ.to_uppercase().contains("CVSS")
            && !entry.score.is_empty()
            && entry.score.contains('/')
        {
            return Severity::Medium;
        }
    }
    // Fall back to database_specific.severity
    let sev_str = vuln
        .database_specific
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();
    match sev_str.as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Batch-query OSV.dev for known CVEs.
///
/// - `packages`: list of (name, version_or_None) tuples.
/// - `ecosystem`: e.g. "npm", "PyPI", "Go".
/// - `base_url`: override for the POST endpoint (used in tests with httpmock).
///
/// Returns Vec<Finding>, never panics. Returns [] when offline or on error.
pub fn osv_lookup(
    packages: &[(String, Option<String>)],
    ecosystem: &str,
    base_url: Option<&str>,
) -> Vec<Finding> {
    if packages.is_empty() {
        return vec![];
    }
    if std::env::var("BELAY_OSV_OFFLINE").is_ok() {
        return vec![];
    }

    let url = base_url.unwrap_or("https://api.osv.dev/v1/querybatch");

    let client = match reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let queries: Vec<serde_json::Value> = packages
        .iter()
        .map(|(name, version)| {
            let mut q = serde_json::json!({
                "package": {
                    "name": name,
                    "ecosystem": ecosystem,
                }
            });
            if let Some(v) = version {
                q["version"] = serde_json::Value::String(v.clone());
            }
            q
        })
        .collect();

    let payload = serde_json::json!({ "queries": queries });

    let response = match client.post(url).json(&payload).send() {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let data: OsvResponse = match response.json() {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();
    for (i, result) in data.results.iter().enumerate() {
        for vuln in &result.vulns {
            let vuln_id = if vuln.id.is_empty() {
                "UNKNOWN".to_string()
            } else {
                vuln.id.clone()
            };
            let severity = extract_severity(vuln);
            let pkg_name = packages
                .get(i)
                .map(|(n, _)| n.as_str())
                .unwrap_or("unknown");
            let rule_id = format!("osv.{}", vuln_id.to_lowercase().replace('-', "_"));
            let decision = if severity >= Severity::High {
                Decision::Deny
            } else {
                Decision::Ask
            };
            findings.push(Finding {
                rule_id,
                severity,
                category: Category::Rce,
                decision,
                reason: format!("CVE {} in package '{}' ({})", vuln_id, pkg_name, ecosystem),
                owasp: "A06".to_string(),
                atlas: "AML.SupplyChain".to_string(),
                location: None,
                fix: String::new(),
            });
        }
    }
    findings
}
