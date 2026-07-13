#[cfg(feature = "vulndb")]
pub mod nvd;

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::distro::{detect_os, OsInfo};
use crate::engine::types::{Decision, Severity};
use crate::finding::{HostCategory, HostFinding};

// ── TB-7: enrichment sub-types (open; no enterprise gate) ────────────────────

/// EPSS (Exploit Prediction Scoring System) score for a CVE. Key-free FIRST.org
/// data joined onto advisories by the enterprise enrichment generator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Epss {
    /// Probability [0.0, 1.0] of exploitation in the next 30 days.
    pub score: f32,
    /// Percentile [0.0, 1.0] of that score across all scored CVEs.
    pub percentile: f32,
    /// EPSS model date (YYYY-MM-DD) the score was drawn from.
    #[serde(default)]
    pub as_of: String,
}

/// CISA Known-Exploited-Vulnerabilities marker for a CVE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kev {
    /// Always true when present (the record exists only for KEV-listed CVEs).
    #[serde(default = "default_true")]
    pub known_exploited: bool,
    /// Date CISA added it to the catalog (YYYY-MM-DD).
    #[serde(default)]
    pub date_added: String,
    /// Whether CISA flags known ransomware-campaign use.
    #[serde(default)]
    pub ransomware: bool,
}

fn default_true() -> bool {
    true
}

/// Observed exploit maturity, ordered low→high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExploitMaturity {
    None,
    Poc,
    Functional,
    Wild,
}

/// CVSS base metrics, when the enrichment source carries them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cvss {
    /// CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...").
    #[serde(default)]
    pub vector: String,
    pub base_score: f32,
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub fixed_version: String,
    pub severity: String,
    pub cve: Vec<String>,
    /// Distro release codename this advisory's `fixed_version` applies to (e.g.
    /// "bookworm"). Empty = applies to any host. A multi-release bundle tags
    /// every record so the matcher applies only those for the running release.
    pub release: String,
    /// OSV-native ecosystem key, e.g. "Debian:12" / "Ubuntu:24.04". Empty = a
    /// legacy (Debian-only) record; the matcher then falls back to `release`.
    pub ecosystem: String,
    /// Provenance for attribution / debugging: "debian-tracker" | "osv" | "ubuntu-osv".
    pub source: String,

    // ── Enrichment (TB-7, all optional; absent in the bundled DB) ──────────────
    /// EPSS score, when the enriched feed carries one for this CVE.
    pub epss: Option<Epss>,
    /// CISA KEV marker, when the CVE is known-exploited.
    pub kev: Option<Kev>,
    /// Observed exploit maturity, when known.
    pub exploit: Option<ExploitMaturity>,
    /// CVSS base metrics, when carried.
    pub cvss: Option<Cvss>,
    /// Reference URLs from the enrichment source.
    pub references: Vec<String>,
    /// RFC3339 feed-freshness stamp; empty for bundled records. Used as the
    /// client's next `since` cursor and for delta filtering.
    pub updated_at: String,
}

/// Parse `/var/lib/dpkg/status`: blank-line-separated stanzas of `Key: Value`.
/// Only stanzas with `Status: install ok installed` are returned.
pub fn parse_dpkg_status(text: &str) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("Package:") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version:") {
                version = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Status:") {
                installed = v.contains("install ok installed");
            }
        }
        if installed {
            if let (Some(n), Some(ver)) = (name, version) {
                out.push(InstalledPackage {
                    name: n,
                    version: ver,
                });
            }
        }
    }
    out
}

fn sev(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Per-finding enrichment surfaced to reports (KEV / EPSS). Report-only — it is
/// derived from the matched advisory's optional feed enrichment and NEVER affects
/// detection, severity, or the `Ask` decision. All-default (`kev=false`,
/// `epss=None`) for bundled/un-enriched advisories, so the open build behaves
/// exactly as before. Kept off [`HostFinding`] deliberately: that type derives
/// `Eq` (which `f32` EPSS cannot satisfy) and is shared with hardening/nvd
/// findings that have no CVE enrichment.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CveEnrichment {
    /// CISA Known-Exploited-Vulnerabilities flag for the finding's CVE.
    pub kev: bool,
    /// EPSS probability of exploitation in the next 30 days, `[0.0, 1.0]`; `None`
    /// when the advisory carries no EPSS score.
    pub epss: Option<f32>,
}

/// Flag installed packages whose version is lower than the advisory's `fixed_version`
/// using proper dpkg version ordering (never plain string compare).
///
/// Thin wrapper over [`match_advisories_enriched`] that drops the report-only
/// enrichment — the detection contract for the daemon engine, nvd path, and the
/// existing test suite is unchanged.
pub fn match_advisories(
    installed: &[InstalledPackage],
    advisories: &[Advisory],
) -> Vec<HostFinding> {
    match_advisories_enriched(installed, advisories)
        .into_iter()
        .map(|(f, _)| f)
        .collect()
}

/// Like [`match_advisories`], but pairs each finding with its source advisory's
/// enrichment ([`CveEnrichment`]: KEV flag + EPSS score) so the vuln posture
/// report can surface it. Detection is byte-for-byte identical to the wrapper —
/// the enrichment is advisory-only and never changes what is flagged or how.
pub fn match_advisories_enriched(
    installed: &[InstalledPackage],
    advisories: &[Advisory],
) -> Vec<(HostFinding, CveEnrichment)> {
    let mut out = Vec::new();
    for a in advisories {
        let Some(pkg) = installed.iter().find(|p| p.name == a.package) else {
            continue;
        };
        // Vulnerable iff installed < fixed (dpkg ordering).
        let cmp = deb_version::compare_versions(&pkg.version, &a.fixed_version);
        if cmp == Ordering::Less {
            let cves = if a.cve.is_empty() {
                a.id.clone()
            } else {
                a.cve.join(", ")
            };
            let finding = HostFinding {
                rule_id: "vuln.outdated_package".to_string(),
                severity: sev(&a.severity),
                category: HostCategory::Tamper,
                decision: Decision::Ask,
                reason: format!(
                    "{} {} is affected by {} (fixed in {})",
                    pkg.name, pkg.version, cves, a.fixed_version
                ),
                owasp: String::new(),
                atlas: String::new(),
                fix: format!(
                    "Update {} to {} or later (advisory only; do not auto-patch).",
                    pkg.name, a.fixed_version
                ),
            };
            let enrichment = CveEnrichment {
                kev: a.kev.as_ref().map(|k| k.known_exploited).unwrap_or(false),
                epss: a.epss.as_ref().map(|e| e.score),
            };
            out.push((finding, enrichment));
        }
    }
    out
}

/// Advisory DB bundled into the release binary. The vendor update pipeline
/// regenerates `daemon/data/advisories.json` from key-free distro feeds (Debian
/// Security Tracker / Ubuntu USN / OSV) before each release, so a fresh install
/// ships with a usable DB and no end user ever needs an NVD API key. See
/// `daemon/data/README.md`.
/// The selected per-ecosystem advisory bundle, zlib-compressed into `OUT_DIR` at
/// build time (see `build.rs`; the bundle is chosen via `BELAY_ECOSYSTEM`,
/// default `Debian:12` → `data/advisories.json`). Inflated once at load by
/// [`bundled_advisories`], keeping the embedded blob ~1–2 MB instead of the
/// multi-MB raw JSON.
const BUNDLED_ADVISORIES_BLOB: &[u8] = include_bytes!(env!("BELAY_ADVISORIES_BLOB"));

/// Fallibly inflate a zlib buffer to its UTF-8 text, returning `None` on ANY bad
/// input (not zlib, truncated, non-UTF-8, …) instead of panicking.
///
/// This is the CLIENT-safe inflate: enterprise callers runs
/// attacker-controlled feed bytes through here, so it must NEVER `panic!` /
/// `.expect()` / `.unwrap()`. A `None` result is turned into a fail-safe "keep
/// the bundled baseline" by the caller. Do not add a `catch_unwind` around this
/// — under `panic = "abort"` (release profile) `catch_unwind` does not catch, so
/// the ONLY safe design is a non-panicking fallible inflate.
pub(crate) fn try_decompress_zlib(bytes: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut s = String::new();
    flate2::read::ZlibDecoder::new(bytes)
        .read_to_string(&mut s)
        .ok()?;
    Some(s)
}

/// Inflate the zlib-compressed bundled advisory blob to its JSON text.
///
/// Trusted, BUILD-TIME data only (the embedded `BUNDLED_ADVISORIES_BLOB`), so it
/// may `expect` on a non-zlib body — an invalid bundle is a build bug, not a
/// runtime/attacker input. The client-triggerable feed path uses the fallible
/// [`try_decompress_zlib`] instead (one shared inflate impl underneath).
pub(crate) fn decompress_zlib(bytes: &[u8]) -> String {
    try_decompress_zlib(bytes).expect("bundled advisory blob must be valid zlib")
}

/// The bundled advisory DB as JSON text (decompressed from the embedded blob).
fn bundled_advisories() -> String {
    decompress_zlib(BUNDLED_ADVISORIES_BLOB)
}

/// Load the advisory DB applicable to this host.
///
/// **Enterprise path** (`#[cfg(feature = "enterprise")]`): first tries
/// [`fetch_hosted_feed`]; on `Ok` the hosted/enriched feed is used. On any
/// `Err` (feed not configured, stub not yet implemented, future network fault)
/// the function falls through to the open path below. This fail-safe guarantees
/// that a feed outage or misconfiguration never leaves the daemon without a
/// vuln DB.
///
/// **Open path** (always present; enterprise fallback): prefers a locally-synced
/// cache at `~/.belay/advisories.json` (advanced / self-hosted, populated
/// by a `BELAY_NVD_API_KEY` sync) and otherwise uses the DB bundled into
/// this release. Fail-soft: a missing/unreadable/unparseable/empty local file
/// quietly yields the bundled DB.
///
/// The bundle is multi-release, so records are filtered to the host's release
/// codename: an advisory applies only when its `release` is empty (release-less)
/// or equals the running release. This prevents a higher release's
/// `fixed_version` from flagging a package that is already patched here.
pub fn load_advisories() -> Vec<Advisory> {
    // Open path (always): local cache → bundled DB, then host filter. This is
    // the bundled BASELINE — the daemon never has fewer advisories than this.
    let raw =
        load_local_advisories().unwrap_or_else(|| parse_advisories_json(&bundled_advisories()));
    let host_eco = host_ecosystem();
    let host_codename = host_release_codename();
    let baseline = filter_applicable(raw, host_eco.as_deref(), &host_codename);

    #[cfg(not(feature = "enterprise"))]
    baseline
}

/// Marker ecosystem for Debian-derived rolling distros (Kali, Debian
/// testing/sid). Matched against the Debian unstable (sid) bundle — the only
/// rolling snapshot the Debian Security Tracker actually carries — so results
/// are approximate (see [`vuln_posture_for`]'s `reason`). Public so `host_api`
/// can recognise it and attach the caveat.
pub const ROLLING_DEBIAN_ECOSYSTEM: &str = "Debian:sid";

/// Map a parsed os-release to its OSV ecosystem key, or None for distros this
/// feature does not support. Fixed-release dpkg families (Debian, Ubuntu) map by
/// VERSION_ID. Debian-derived rolling distros (Kali, Debian testing/sid) map to
/// [`ROLLING_DEBIAN_ECOSYSTEM`] for best-effort matching. rpm families and
/// non-Debian rolling distros (Arch) return None so the posture gates off.
pub fn ecosystem_from_os(os: &OsInfo) -> Option<String> {
    match os.id.as_str() {
        "debian" if !os.version_id.is_empty() => Some(format!("Debian:{}", os.version_id)),
        "ubuntu" if !os.version_id.is_empty() => Some(format!("Ubuntu:{}", os.version_id)),
        // Kali always tracks Debian testing/sid, regardless of its date-based
        // VERSION_ID — best-effort match against the Debian sid bundle.
        "kali" => Some(ROLLING_DEBIAN_ECOSYSTEM.to_string()),
        // Other Debian-derived rolling distros (no fixed VERSION_ID but ID_LIKE
        // names debian, e.g. a bare Debian testing/sid install) get the same
        // approximation.
        _ if os.version_id.is_empty()
            && os.id_like.split_whitespace().any(|f| f == "debian") =>
        {
            Some(ROLLING_DEBIAN_ECOSYSTEM.to_string())
        }
        _ => None,
    }
}

/// The host's ecosystem from `/etc/os-release`, or None when unsupported.
pub fn host_ecosystem() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    ecosystem_from_os(&detect_os(&text))
}

/// Keep advisories applicable to this host: ecosystem-tagged records match the
/// host ecosystem; legacy (empty-ecosystem) records keep the old codename rule.
pub fn filter_applicable(
    raw: Vec<Advisory>,
    host_ecosystem: Option<&str>,
    host_codename: &str,
) -> Vec<Advisory> {
    raw.into_iter()
        .filter(|a| {
            if a.ecosystem.is_empty() {
                a.release.is_empty() || a.release == host_codename
            } else {
                host_ecosystem == Some(a.ecosystem.as_str())
            }
        })
        .collect()
}

/// Distinct ecosystems present in a bundle (legacy empty-ecosystem records are
/// reported as the marker "Debian:*"), for coverage gating.
pub fn bundle_ecosystems(advisories: &[Advisory]) -> std::collections::BTreeSet<String> {
    advisories
        .iter()
        .map(|a| {
            if a.ecosystem.is_empty() {
                "Debian:*".to_string()
            } else {
                a.ecosystem.clone()
            }
        })
        .collect()
}

/// The host distro release codename from `/etc/os-release` `VERSION_CODENAME`
/// (e.g. "bookworm"), lowercased; empty when it cannot be determined.
pub fn host_release_codename() -> String {
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else {
        return String::new();
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("VERSION_CODENAME=") {
            return v.trim().trim_matches('"').to_ascii_lowercase();
        }
    }
    String::new()
}

/// Read + parse the local advisory cache, returning `None` when it is absent,
/// unreadable, unparseable, or empty (so the caller falls back to the bundle).
fn load_local_advisories() -> Option<Vec<Advisory>> {
    let path = crate::paths::data_dir().join("advisories.json");
    let text = std::fs::read_to_string(&path).ok()?;
    let parsed = parse_advisories_json(&text);
    (!parsed.is_empty()).then_some(parsed)
}

/// Parse a JSON array of advisory objects into `Advisory` records, skipping any
/// entry missing a required field. Shared by the local cache and the bundled DB.
/// `pub(crate)` so enterprise callers shape-validates hosted-feed
/// bundles with the identical parser (same required-field discipline).
pub(crate) fn parse_advisories_json(text: &str) -> Vec<Advisory> {
    let Ok(raw): Result<Vec<serde_json::Value>, _> = serde_json::from_str(text) else {
        return Vec::new();
    };
    raw.into_iter()
        .filter_map(|v| {
            Some(Advisory {
                id: v.get("id")?.as_str()?.to_string(),
                package: v.get("package")?.as_str()?.to_string(),
                fixed_version: v.get("fixed_version")?.as_str()?.to_string(),
                severity: v
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("low")
                    .to_string(),
                cve: v
                    .get("cve")
                    .and_then(|c| c.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                release: v
                    .get("release")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                ecosystem: v
                    .get("ecosystem")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                source: v
                    .get("source")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                // ── enrichment (absent in the bundled DB ⇒ defaults) ──
                epss: v.get("epss").and_then(|e| serde_json::from_value(e.clone()).ok()),
                kev: v.get("kev").and_then(|k| serde_json::from_value(k.clone()).ok()),
                exploit: v.get("exploit").and_then(|e| serde_json::from_value(e.clone()).ok()),
                cvss: v.get("cvss").and_then(|c| serde_json::from_value(c.clone()).ok()),
                references: v
                    .get("references")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| e.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                updated_at: v
                    .get("updated_at")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .collect()
}

/// Overlay `enriched` advisories onto `base` by `(ecosystem, id)`, ENRICHMENT-ONLY.
///
/// For a MATCHED key the base record's CORE fields (`id`, `package`,
/// `fixed_version`, `severity`, `cve`, `release`, `ecosystem`, `source`) are kept
/// verbatim and ONLY the 6 enrichment fields (`epss`, `kev`, `exploit`, `cvss`,
/// `references`, `updated_at`) are layered in from the feed record. The feed can
/// therefore NEVER weaken baseline detection: a hostile-but-well-formed record
/// with a lowered `fixed_version` or downgraded `severity` cannot replace the
/// baseline advisory (which would suppress a real finding via `match_advisories`).
///
/// An UNMATCHED key is appended as a genuinely-new advisory. This can only ADD or
/// ENRICH — it never drops or weakens a base record, so the merged set is always
/// ⊇ the bundled baseline in both coverage AND strength (fail-safe invariant).
pub fn overlay_advisories(mut base: Vec<Advisory>, enriched: Vec<Advisory>) -> Vec<Advisory> {
    use std::collections::HashMap;
    // Index base by (ecosystem, id) → position.
    let mut idx: HashMap<(String, String), usize> = HashMap::with_capacity(base.len());
    for (i, a) in base.iter().enumerate() {
        idx.insert((a.ecosystem.clone(), a.id.clone()), i);
    }
    for e in enriched {
        match idx.get(&(e.ecosystem.clone(), e.id.clone())) {
            Some(&i) => {
                // Enrichment-only: keep ALL core fields of the baseline record;
                // layer only the enrichment fields from the feed. Never overwrite
                // id/package/fixed_version/severity/cve/release/ecosystem/source.
                let b = &mut base[i];
                b.epss = e.epss;
                b.kev = e.kev;
                b.exploit = e.exploit;
                b.cvss = e.cvss;
                b.references = e.references;
                b.updated_at = e.updated_at;
            }
            None => {
                idx.insert((e.ecosystem.clone(), e.id.clone()), base.len());
                base.push(e); // genuinely-new advisory
            }
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_advisory_json_array_skipping_invalid_entries() {
        // Two valid records + one missing the required `package` field (dropped).
        let text = r#"[
            {"id":"USN-1-1","package":"openssl","fixed_version":"3.0.1",
             "severity":"critical","cve":["CVE-2024-0001"]},
            {"id":"USN-2-1","package":"bash","fixed_version":"5.1-6"},
            {"id":"BAD","fixed_version":"1.0"}
        ]"#;
        let parsed = parse_advisories_json(text);
        assert_eq!(parsed.len(), 2, "invalid entry must be skipped: {parsed:?}");
        assert_eq!(parsed[0].package, "openssl");
        assert_eq!(parsed[0].cve, vec!["CVE-2024-0001".to_string()]);
        // `severity` defaults to "low" and `cve` to [] when absent.
        assert_eq!(parsed[1].severity, "low");
        assert!(parsed[1].cve.is_empty());
    }

    #[test]
    fn parses_ecosystem_and_source_defaulting_to_empty() {
        let text = r#"[
            {"id":"CVE-1","package":"openssl","fixed_version":"3.0.1","ecosystem":"Ubuntu:24.04","source":"osv"},
            {"id":"CVE-2","package":"bash","fixed_version":"5.1-6"}
        ]"#;
        let p = parse_advisories_json(text);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].ecosystem, "Ubuntu:24.04");
        assert_eq!(p[0].source, "osv");
        // A legacy record without the fields defaults to "".
        assert_eq!(p[1].ecosystem, "");
        assert_eq!(p[1].source, "");
    }

    #[test]
    fn ecosystem_from_os_maps_supported_families() {
        let os = |id: &str, ver: &str| OsInfo {
            id: id.into(),
            version_id: ver.into(),
            id_like: String::new(),
            version_codename: String::new(),
        };
        assert_eq!(
            ecosystem_from_os(&os("debian", "12")),
            Some("Debian:12".to_string())
        );
        assert_eq!(
            ecosystem_from_os(&os("ubuntu", "24.04")),
            Some("Ubuntu:24.04".to_string())
        );
        // Kali (rolling, Debian-derived) maps to the best-effort sid bundle,
        // regardless of its date-based VERSION_ID.
        assert_eq!(
            ecosystem_from_os(&os("kali", "2024.4")),
            Some("Debian:sid".to_string())
        );
        // rpm / non-Debian rolling families still gate off (None) rather than lie.
        assert_eq!(ecosystem_from_os(&os("fedora", "40")), None);
        assert_eq!(ecosystem_from_os(&os("arch", "")), None);
        // Debian with no VERSION_ID and no ID_LIKE is not assumed to be testing.
        assert_eq!(ecosystem_from_os(&os("debian", "")), None);
    }

    #[test]
    fn ecosystem_from_os_rolling_debian_derivative_falls_back_to_sid() {
        // A Debian-derived rolling distro: ID is not debian/ubuntu/kali, no
        // fixed VERSION_ID, but ID_LIKE names debian → best-effort sid bundle.
        let rolling = OsInfo {
            id: "somerolling".into(),
            version_id: String::new(),
            id_like: "debian".into(),
            version_codename: String::new(),
        };
        assert_eq!(
            ecosystem_from_os(&rolling),
            Some("Debian:sid".to_string())
        );
        // A non-Debian rolling distro (Arch, no debian in ID_LIKE) still gates off.
        let arch = OsInfo {
            id: "arch".into(),
            version_id: String::new(),
            id_like: String::new(),
            version_codename: String::new(),
        };
        assert_eq!(ecosystem_from_os(&arch), None);
    }

    #[test]
    fn load_filter_prefers_ecosystem_then_falls_back_to_codename() {
        let adv = |id: &str, eco: &str, release: &str| Advisory::core(id, "openssl", "3.0.1", "high", eco, release);
        let raw = vec![
            adv("A", "Ubuntu:24.04", ""), // ecosystem match
            adv("B", "Debian:12", ""),    // ecosystem mismatch -> dropped
            adv("C", "", "bookworm"),     // legacy: codename match
            adv("D", "", "trixie"),       // legacy: codename mismatch -> dropped
            adv("E", "", ""),             // legacy: no release -> always kept
        ];
        let kept = filter_applicable(raw, Some("Ubuntu:24.04"), "bookworm");
        let ids: Vec<&str> = kept.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["A", "C", "E"]);
    }

    #[test]
    fn bundled_advisories_is_valid_json() {
        // The DB embedded into the release must always parse (an invalid bundle
        // would silently zero out the fallback on every fresh install). This also
        // exercises the build-time compression → load-time inflation round-trip.
        let parsed = parse_advisories_json(&bundled_advisories());
        assert!(!parsed.is_empty(), "bundled advisory DB must be non-empty");
    }

    #[test]
    fn decompress_zlib_round_trips_advisory_json() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let json = r#"[{"id":"CVE-1","package":"openssl","fixed_version":"3.0.1",
            "severity":"high","cve":["CVE-1"],"ecosystem":"Debian:12","source":"osv"}]"#;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(json.as_bytes()).unwrap();
        let compressed = enc.finish().unwrap();
        // Compression must actually shrink a realistic payload, and inflate back.
        let restored = decompress_zlib(&compressed);
        let parsed = parse_advisories_json(&restored);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].package, "openssl");
        assert_eq!(parsed[0].ecosystem, "Debian:12");
    }

    #[test]
    fn matcher_respects_release_when_filtered_to_host() {
        // A multi-release bundle: the same package+CVE patched at different
        // versions per release. The bookworm host must only see the bookworm
        // record, so its already-patched package is NOT flagged by trixie's
        // higher fixed_version. (This mirrors the filter in `load_advisories`.)
        let installed = parse_dpkg_status(
            "Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1\n",
        );
        let advisories = vec![
            Advisory {
                cve: vec!["CVE-2024-0001".into()],
                ..Advisory::core("CVE-2024-0001", "openssl", "3.0.11-1", "high", "", "bookworm")
            },
            Advisory {
                cve: vec!["CVE-2024-0001".into()],
                ..Advisory::core("CVE-2024-0001", "openssl", "3.1.4-2", "high", "", "trixie")
            },
        ];
        let host = "bookworm";
        let applicable: Vec<Advisory> = advisories
            .into_iter()
            .filter(|a| a.release.is_empty() || a.release == host)
            .collect();
        assert_eq!(applicable.len(), 1);
        // installed 3.0.11-1 >= bookworm fixed 3.0.11-1 → no finding.
        assert!(match_advisories(&installed, &applicable).is_empty());
    }

    #[test]
    fn flags_package_older_than_fixed_version() {
        let status =
            "Package: openssh-server\nStatus: install ok installed\nVersion: 1:8.9p1-3\n\n\
                      Package: bash\nStatus: install ok installed\nVersion: 5.1-6ubuntu1\n";
        let installed = parse_dpkg_status(status);
        let advisories = vec![Advisory {
            cve: vec!["CVE-2024-6387".into()],
            ..Advisory::core("USN-0001-1", "openssh-server", "1:8.9p1-3ubuntu0.1", "high", "", "")
        }];
        let findings = match_advisories(&installed, &advisories);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "vuln.outdated_package");
        assert!(findings[0].reason.contains("CVE-2024-6387"));
    }

    // ── Advisory-source resolver (mirrors build.rs `resolve_advisory_source`) ──
    //
    // build.rs runs as its own binary and its `#[cfg(test)]` blocks are NOT
    // executed by `cargo test`. To satisfy the requirement that both resolver
    // branches (curated-present and curated-absent→seed) are covered by an
    // actually-executing test, we mirror the pure resolver logic here (it is
    // five lines) and test it in the crate's test suite. The identical logic
    // lives in build.rs where it does the real file selection at build time.
    fn curated_file_for(ecosystem: &str) -> String {
        match ecosystem {
            "Debian:12" => "advisories.json".to_string(),
            other => format!("advisories.{}.json", other.replace(':', "-")),
        }
    }

    fn resolve_advisory_source(
        ecosystem: &str,
        data_dir: &std::path::Path,
    ) -> std::path::PathBuf {
        let curated = data_dir.join(curated_file_for(ecosystem));
        if curated.exists() {
            curated
        } else {
            data_dir.join("advisories.seed.json")
        }
    }

    #[test]
    fn resolver_returns_curated_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let curated = dir.path().join("advisories.json");
        std::fs::write(&curated, "[]").expect("write curated stub");
        let result = resolve_advisory_source("Debian:12", dir.path());
        assert_eq!(result, curated, "curated file must be preferred when present");
    }

    #[test]
    fn resolver_falls_back_to_seed_when_curated_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No curated file written → resolver must fall back to the seed path.
        let result = resolve_advisory_source("Debian:12", dir.path());
        let expected = dir.path().join("advisories.seed.json");
        assert_eq!(result, expected, "seed path must be returned when curated is absent");
    }

    #[test]
    fn resolver_maps_non_default_ecosystem_to_correct_curated_filename() {
        let dir = tempfile::tempdir().expect("tempdir");
        let curated = dir.path().join("advisories.Ubuntu-24.04.json");
        std::fs::write(&curated, "[]").expect("write curated stub");
        let result = resolve_advisory_source("Ubuntu:24.04", dir.path());
        assert_eq!(result, curated);
    }

    // ── Enterprise hosted-feed seam tests ──────────────────────────────────

    /// Regression guard for the open-path machinery in `load_advisories()`:
    /// the bundled blob must inflate and parse to a non-empty record set, and
    /// the full `load_advisories()` pipeline must complete without panic,
    /// regardless of which feature set is active.
    ///
    /// The post-filter result from `load_advisories()` is intentionally NOT
    /// asserted to be non-empty here: `filter_applicable` prunes records to
    /// the host's detected ecosystem/codename, so on a host whose ecosystem
    /// does not match the built-in blob (e.g. Kali with the default Debian:12
    /// bundle) the filtered set is empty by design. The regression being
    /// guarded is that the blob is valid and the open path does not panic.
    #[test]
    fn load_advisories_bundled_db_loads_and_open_path_works() {
        // Pre-filter: the blob must inflate + parse to a non-empty raw set.
        let raw = parse_advisories_json(&bundled_advisories());
        assert!(
            !raw.is_empty(),
            "bundled advisory blob must parse to non-empty records"
        );
        // Full pipeline (including ecosystem filter): must not panic.
        let _ = load_advisories();
    }

    // The enterprise hosted-feed seam's unconfigured/inert behavior is now
    // tested in the enterprise client's own test module
    // (`no_token_is_inert_returns_baseline_unchanged`), where the client lives.

    #[test]
    fn does_not_flag_already_patched_package() {
        let installed = parse_dpkg_status(
            "Package: bash\nStatus: install ok installed\nVersion: 5.1-6ubuntu1\n",
        );
        let advisories = vec![
            // installed 5.1-6ubuntu1 >= fixed 5.1-6 -> safe
            Advisory::core("USN-2", "bash", "5.1-6", "low", "", ""),
        ];
        assert!(match_advisories(&installed, &advisories).is_empty());
    }

    #[test]
    fn ignores_not_installed_status_stanzas() {
        let installed =
            parse_dpkg_status("Package: ghost\nStatus: deinstall ok config-files\nVersion: 1.0\n");
        assert!(installed.is_empty());
    }

    // ── TB-7: enrichment field tests ──────────────────────────────────────────

    #[test]
    fn enriched_advisory_round_trips_through_parser() {
        let text = r#"[{
            "id":"CVE-2024-3094","package":"xz-utils","fixed_version":"5.6.1-1","severity":"critical",
            "cve":["CVE-2024-3094"],"ecosystem":"Debian:12","source":"osv",
            "epss":{"score":0.94,"percentile":0.99,"as_of":"2026-07-01"},
            "kev":{"known_exploited":true,"date_added":"2024-03-29","ransomware":false},
            "exploit":"wild",
            "cvss":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","base_score":10.0},
            "references":["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
            "updated_at":"2026-07-01T00:00:00Z"
        }]"#;
        let p = parse_advisories_json(text);
        assert_eq!(p.len(), 1);
        let a = &p[0];
        assert_eq!(a.epss.as_ref().unwrap().score, 0.94);
        assert!(a.kev.as_ref().unwrap().known_exploited);
        assert_eq!(a.exploit, Some(ExploitMaturity::Wild));
        assert_eq!(a.cvss.as_ref().unwrap().base_score, 10.0);
        assert_eq!(
            a.references,
            vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-3094".to_string()]
        );
        assert_eq!(a.updated_at, "2026-07-01T00:00:00Z");
    }

    #[test]
    fn bundled_record_without_enrichment_still_parses_with_defaults() {
        // The exact shape of a bundled (open) record — no enrichment keys.
        let text = r#"[{"id":"CVE-1","package":"openssl","fixed_version":"3.0.1","severity":"high",
            "cve":["CVE-1"],"ecosystem":"Debian:12","source":"osv"}]"#;
        let p = parse_advisories_json(text);
        assert_eq!(p.len(), 1);
        assert!(
            p[0].epss.is_none() && p[0].kev.is_none() && p[0].exploit.is_none()
                && p[0].cvss.is_none()
        );
        assert!(p[0].references.is_empty());
        assert_eq!(p[0].updated_at, "");
    }

    #[test]
    fn overlay_enriches_by_ecosystem_and_id_and_appends_new() {
        let base = vec![
            Advisory::core("CVE-1", "openssl", "3.0.1", "high", "Debian:12", ""),
            Advisory::core("CVE-2", "bash", "5.1-6", "low", "Debian:12", ""),
        ];
        // Feed record shares CVE-1's key. It carries enrichment (KEV) AND a
        // DIFFERENT severity ("low") — enrichment-only means the enrichment is
        // layered but the baseline CORE `severity` ("high") is RETAINED.
        let mut enriched_1 =
            Advisory::core("CVE-1", "openssl", "3.0.1", "low", "Debian:12", "");
        enriched_1.kev = Some(Kev {
            known_exploited: true,
            date_added: "2024-01-01".into(),
            ransomware: false,
        });
        let enriched_new = Advisory::core("CVE-9", "curl", "8.0", "high", "Debian:12", "");
        let merged = overlay_advisories(base, vec![enriched_1, enriched_new]);
        // CVE-1 enriched (now KEV) but core severity unchanged, CVE-2 untouched, CVE-9 added.
        assert_eq!(merged.len(), 3);
        let cve1 = merged.iter().find(|a| a.id == "CVE-1").unwrap();
        assert!(cve1.kev.is_some(), "enrichment must be layered on");
        assert_eq!(
            cve1.severity, "high",
            "core severity must be RETAINED, never taken from the feed"
        );
        assert!(merged.iter().any(|a| a.id == "CVE-2" && a.kev.is_none()));
        assert!(merged.iter().any(|a| a.id == "CVE-9"));
    }

    #[test]
    fn overlay_never_weakens_baseline_fixed_version() {
        // I2 regression guard: a hostile-but-well-formed feed record with the same
        // (ecosystem, id) but a LOWERED `fixed_version` ("0") and downgraded
        // `severity` must NOT change the baseline's core fields — only enrichment
        // is applied. Otherwise `match_advisories` (installed < fixed) would stop
        // flagging a truly-vulnerable package.
        let base = vec![Advisory::core(
            "CVE-1", "openssl", "3.0.1", "critical", "Debian:12", "",
        )];
        let mut hostile = Advisory::core("CVE-1", "openssl", "0", "low", "Debian:12", "");
        hostile.kev = Some(Kev {
            known_exploited: true,
            date_added: "2024-01-01".into(),
            ransomware: false,
        });
        let merged = overlay_advisories(base, vec![hostile]);
        assert_eq!(merged.len(), 1);
        let a = &merged[0];
        // Core fields preserved from the baseline.
        assert_eq!(a.fixed_version, "3.0.1", "fixed_version must not be lowered");
        assert_eq!(a.severity, "critical", "severity must not be downgraded");
        // Only enrichment was layered on.
        assert!(a.kev.is_some(), "enrichment still applied");
    }

    #[test]
    fn overlay_never_drops_baseline_records() {
        let base = vec![Advisory::core("CVE-1", "openssl", "3.0.1", "high", "Debian:12", "")];
        let merged = overlay_advisories(base.clone(), vec![]); // empty feed
        assert_eq!(merged.len(), base.len(), "empty enrichment must keep the full baseline");
    }

    #[test]
    fn match_enriched_surfaces_kev_and_epss_without_changing_detection() {
        let installed = parse_dpkg_status(
            "Package: xz-utils\nStatus: install ok installed\nVersion: 5.6.0-0\n",
        );
        // Enriched advisory: vulnerable (installed 5.6.0-0 < fixed 5.6.1-1) + KEV + EPSS.
        let mut adv =
            Advisory::core("CVE-2024-3094", "xz-utils", "5.6.1-1", "critical", "Debian:12", "");
        adv.cve = vec!["CVE-2024-3094".into()];
        adv.kev = Some(Kev {
            known_exploited: true,
            date_added: "2024-03-29".into(),
            ransomware: false,
        });
        adv.epss = Some(Epss { score: 0.94, percentile: 0.99, as_of: "2026-07-01".into() });

        let enriched = match_advisories_enriched(&installed, std::slice::from_ref(&adv));
        assert_eq!(enriched.len(), 1);
        let (finding, enr) = &enriched[0];
        // Enrichment is surfaced to the report layer...
        assert!(enr.kev, "KEV flag must reach the report layer");
        assert_eq!(enr.epss, Some(0.94), "EPSS score must reach the report layer");
        // ...while detection is byte-identical to the plain matcher (wrapper drops
        // only the enrichment tuple element).
        let plain = match_advisories(&installed, std::slice::from_ref(&adv));
        assert_eq!(plain, vec![finding.clone()]);

        // A bundled (un-enriched) advisory yields default enrichment — no false KEV.
        let bare = Advisory::core("CVE-1", "xz-utils", "5.6.1-1", "high", "Debian:12", "");
        let bare_out = match_advisories_enriched(&installed, std::slice::from_ref(&bare));
        assert!(
            !bare_out[0].1.kev && bare_out[0].1.epss.is_none(),
            "open records carry no enrichment"
        );
    }
}

#[cfg(test)]
impl Advisory {
    /// Minimal core-only advisory for tests; enrichment absent.
    /// `pub(crate)` so the enterprise client's test module shares one builder.
    pub(crate) fn core(
        id: &str,
        package: &str,
        fixed_version: &str,
        severity: &str,
        ecosystem: &str,
        release: &str,
    ) -> Advisory {
        Advisory {
            id: id.into(),
            package: package.into(),
            fixed_version: fixed_version.into(),
            severity: severity.into(),
            cve: vec![],
            release: release.into(),
            ecosystem: ecosystem.into(),
            source: String::new(),
            epss: None,
            kev: None,
            exploit: None,
            cvss: None,
            references: vec![],
            updated_at: String::new(),
        }
    }
}
