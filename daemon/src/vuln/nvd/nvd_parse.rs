//! NVD JSON → [`StoredCve`] parser.

use super::CpeMatch;

// ---------------------------------------------------------------------------
// StoredCve
// ---------------------------------------------------------------------------

/// A CVE record serialised into the local redb store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCve {
    pub cve_id: String,
    pub description: String,
    pub cvss3_score: Option<f32>,
    pub cvss3_severity: String,
    pub cwe_id: String,
    pub is_kev: bool,
    pub cpe_matches: Vec<CpeMatch>,
}

// ---------------------------------------------------------------------------
// 15.2 — parse_cve
// ---------------------------------------------------------------------------

/// Parse one CVE entry from the NVD REST API v2 JSON format.
///
/// Returns `None` if the entry lacks a CVE ID (considered malformed).
pub fn parse_cve(v: &serde_json::Value) -> Option<StoredCve> {
    let cve_id = v.get("id")?.as_str()?.to_string();

    // English description
    let description = v
        .get("descriptions")
        .and_then(|d| d.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .and_then(|e| e.get("value")?.as_str().map(|s| s.to_string()))
        })
        .unwrap_or_default();

    // CVSS v3.1 (preferred) or v3.0
    let (cvss3_score, cvss3_severity) = extract_cvss3(v);

    // CWE — iterate all weaknesses[*].description[*], take first "CWE-xxx"
    // (skips NVD-CWE-noinfo, NVD-CWE-Other, and any non-CWE values)
    let cwe_id = v
        .get("weaknesses")
        .and_then(|w| w.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|weakness| {
                weakness
                    .get("description")?
                    .as_array()?
                    .iter()
                    .find_map(|d| {
                        d.get("value")?.as_str().and_then(|val| {
                            if val.starts_with("CWE-") {
                                Some(val.to_string())
                            } else {
                                None
                            }
                        })
                    })
            })
        })
        .unwrap_or_default();

    // KEV: presence of `cisaExploitAdd` field
    let is_kev = v.get("cisaExploitAdd").is_some();

    // CPE matches
    let cpe_matches = extract_cpe_matches(v);

    Some(StoredCve {
        cve_id,
        description,
        cvss3_score,
        cvss3_severity,
        cwe_id,
        is_kev,
        cpe_matches,
    })
}

/// Extract CVSS v3 score and severity from the metrics field.
fn extract_cvss3(v: &serde_json::Value) -> (Option<f32>, String) {
    let metrics = match v.get("metrics") {
        Some(m) => m,
        None => return (None, String::new()),
    };

    // Try cvssMetricV31 first, then cvssMetricV30, finally cvssMetricV40
    for key in &["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"] {
        if let Some(arr) = metrics.get(key).and_then(|a| a.as_array()) {
            if let Some(entry) = arr.first() {
                if let Some(data) = entry.get("cvssData") {
                    let score = data
                        .get("baseScore")
                        .and_then(|s| s.as_f64())
                        .map(|f| f as f32);
                    let severity = data
                        .get("baseSeverity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    return (score, severity);
                }
            }
        }
    }

    (None, String::new())
}

// ---------------------------------------------------------------------------
// 15.2 — extract_cpe_matches
// ---------------------------------------------------------------------------

/// Recursively extract all CPE match entries from NVD configuration nodes.
///
/// NVD v2 shape:
/// ```json
/// { "configurations": [ { "nodes": [ { "cpeMatch": [...], "children": [...] } ] } ] }
/// ```
pub fn extract_cpe_matches(v: &serde_json::Value) -> Vec<CpeMatch> {
    let mut out = Vec::new();

    let configs = match v.get("configurations").and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return out,
    };

    for config in configs {
        let nodes = match config.get("nodes").and_then(|n| n.as_array()) {
            Some(n) => n,
            None => continue,
        };
        for node in nodes {
            walk_node(node, &mut out);
        }
    }

    out
}

/// Walk one configuration node (and its children) collecting [`CpeMatch`]es.
fn walk_node(node: &serde_json::Value, out: &mut Vec<CpeMatch>) {
    // Direct cpeMatch entries
    if let Some(matches) = node.get("cpeMatch").and_then(|m| m.as_array()) {
        for cpe in matches {
            if let Some(m) = parse_cpe_match(cpe) {
                out.push(m);
            }
        }
    }

    // Recurse into children
    if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
        for child in children {
            walk_node(child, out);
        }
    }
}

/// Parse one `cpeMatch` object.
///
/// The `criteria` field has the shape `cpe:2.3:a:<vendor>:<product>:<version>:*:…`.
/// Parts (0-indexed): 0=cpe, 1=2.3, 2=a, 3=vendor, 4=product, 5=version, 6..=*
fn parse_cpe_match(cpe: &serde_json::Value) -> Option<CpeMatch> {
    let criteria = cpe.get("criteria")?.as_str()?;
    let parts: Vec<&str> = criteria.split(':').collect();
    // cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*  (idx 0..11)
    let product = parts.get(4).copied().unwrap_or("*").to_string();

    // exact version: component at index 5 when not a wildcard/dash/empty
    let raw_version = parts.get(5).copied().unwrap_or("*");
    let exact_version = if raw_version != "*"
        && raw_version != "-"
        && !raw_version.is_empty()
        && cpe.get("versionStartIncluding").is_none()
        && cpe.get("versionStartExcluding").is_none()
        && cpe.get("versionEndIncluding").is_none()
        && cpe.get("versionEndExcluding").is_none()
    {
        Some(raw_version.to_string())
    } else {
        None
    };

    let version_start_including = cpe
        .get("versionStartIncluding")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version_start_excluding = cpe
        .get("versionStartExcluding")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version_end_including = cpe
        .get("versionEndIncluding")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version_end_excluding = cpe
        .get("versionEndExcluding")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let (version_start, version_start_inc) = if let Some(v) = version_start_including {
        (Some(v), true)
    } else if let Some(v) = version_start_excluding {
        (Some(v), false)
    } else {
        (None, false)
    };

    let (version_end, version_end_inc) = if let Some(v) = version_end_including {
        (Some(v), true)
    } else if let Some(v) = version_end_excluding {
        (Some(v), false)
    } else {
        (None, false)
    };

    Some(CpeMatch {
        product,
        exact_version,
        version_start,
        version_start_including: version_start_inc,
        version_end,
        version_end_including: version_end_inc,
    })
}

// ---------------------------------------------------------------------------
// Tests for 15.2
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpe_with_exact_version_yields_some() {
        // C-1 / C-2 regression: splitn(6) left parts[5]="2.4.49:*:…"
        let j: serde_json::Value = serde_json::from_str(
            r#"{
          "id":"CVE-2021-41773","cisaExploitAdd":"2021-11-03",
          "descriptions":[{"lang":"en","value":"path traversal"}],
          "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"AV:N"}}]},
          "weaknesses":[{"description":[{"value":"CWE-22"}]}],
          "configurations":[{"nodes":[{"cpeMatch":[
            {"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*","vulnerable":true}
          ]}]}]
        }"#,
        )
        .unwrap();
        let c = parse_cve(&j).expect("parsed");
        let m = &c.cpe_matches[0];
        assert_eq!(m.product, "http_server");
        assert_eq!(
            m.exact_version.as_deref(),
            Some("2.4.49"),
            "exact_version must be Some(\"2.4.49\"), not None or a multi-field string"
        );
    }

    #[test]
    fn cpe_bare_wildcard_yields_none_exact_version() {
        // C-1 / C-2 regression: wildcard CPE must yield exact_version = None
        let j: serde_json::Value = serde_json::from_str(
            r#"{
          "id":"CVE-2021-99999",
          "descriptions":[{"lang":"en","value":"test"}],
          "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"AV:N"}}]},
          "weaknesses":[{"description":[{"value":"CWE-79"}]}],
          "configurations":[{"nodes":[{"cpeMatch":[
            {"criteria":"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*","vulnerable":true}
          ]}]}]
        }"#,
        )
        .unwrap();
        let c = parse_cve(&j).expect("parsed");
        let m = &c.cpe_matches[0];
        assert_eq!(
            m.exact_version, None,
            "wildcard CPE must yield exact_version = None"
        );
    }

    #[test]
    fn cvss_v40_only_yields_score_and_severity() {
        // H-1 regression: cvssMetricV40 must be picked up when v31/v30 absent
        let j: serde_json::Value = serde_json::from_str(
            r#"{
          "id":"CVE-2024-99999",
          "descriptions":[{"lang":"en","value":"v4 only cve"}],
          "metrics":{"cvssMetricV40":[{"cvssData":{"baseScore":8.7,"baseSeverity":"HIGH","vectorString":"CVSS:4.0/AV:N"}}]},
          "weaknesses":[{"description":[{"value":"CWE-200"}]}],
          "configurations":[]
        }"#,
        )
        .unwrap();
        let c = parse_cve(&j).expect("parsed");
        assert_eq!(c.cvss3_score, Some(8.7));
        assert_eq!(c.cvss3_severity, "HIGH");
    }

    #[test]
    fn cwe_extraction_skips_nvd_noinfo() {
        // M-3 regression: NVD-CWE-noinfo must be skipped; real CWE-xxx found
        let j: serde_json::Value = serde_json::from_str(
            r#"{
          "id":"CVE-2023-11111",
          "descriptions":[{"lang":"en","value":"test"}],
          "metrics":{},
          "weaknesses":[
            {"description":[{"value":"NVD-CWE-noinfo"}]},
            {"description":[{"value":"NVD-CWE-Other"}]},
            {"description":[{"value":"CWE-89"}]}
          ],
          "configurations":[]
        }"#,
        )
        .unwrap();
        let c = parse_cve(&j).expect("parsed");
        assert_eq!(c.cwe_id, "CWE-89");
    }

    #[test]
    fn parses_cvss31_kev_and_end_excluding_range() {
        let j: serde_json::Value = serde_json::from_str(
            r#"{
          "id":"CVE-2021-41773","cisaExploitAdd":"2021-11-03",
          "descriptions":[{"lang":"en","value":"path traversal"}],
          "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"AV:N"}}]},
          "weaknesses":[{"description":[{"value":"CWE-22"}]}],
          "configurations":[{"nodes":[{"cpeMatch":[
            {"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.50"}
          ]}]}]
        }"#,
        )
        .unwrap();
        let c = parse_cve(&j).expect("parsed");
        assert_eq!(c.cve_id, "CVE-2021-41773");
        assert!(c.is_kev);
        assert_eq!(c.cwe_id, "CWE-22");
        assert_eq!(c.cvss3_severity, "HIGH");
        assert_eq!(c.cpe_matches.len(), 1);
        let m = &c.cpe_matches[0];
        assert_eq!(m.product, "http_server");
        assert_eq!(m.exact_version, None);
        assert_eq!(m.version_end.as_deref(), Some("2.4.50"));
        assert!(!m.version_end_including);
    }
}
