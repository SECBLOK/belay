//! advisory-gen — vendor build-time tool that regenerates the bundled advisory
//! DB (`daemon/data/advisories.json`) from key-free distribution feeds.
//!
//! Source: the Debian Security Tracker JSON
//! (`https://security-tracker.debian.org/tracker/data/json`), which maps each
//! source package's CVEs to a per-release fix status + fixed version — no NVD
//! CPE matching and no API key. Run before a release and commit the output:
//!
//!     cargo run -p advisory-gen -- --release bookworm --out daemon/data/advisories.json
//!
//! OSV (`Debian:<n>` / `Ubuntu:<n>` ecosystems) and Ubuntu USN are the next
//! key-free sources to add behind a `--source` selector; the output shape and
//! merge/sort below are source-agnostic so they slot in without changes here.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};


// Enrichment output shapes (serde). Mirror the runtime Epss/Kev in belayd::vuln.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "enrich", derive(Deserialize))]
pub struct EpssOut {
    pub score: f32,
    pub percentile: f32,
    pub as_of: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "enrich", derive(Deserialize))]
pub struct KevOut {
    pub known_exploited: bool,
    pub date_added: String,
    pub ransomware: bool,
}

const DEBIAN_TRACKER_URL: &str = "https://security-tracker.debian.org/tracker/data/json";
const DEFAULT_RELEASE: &str = "bookworm";
const DEFAULT_OUT: &str = "daemon/data/advisories.json";

/// One record in the bundled advisory DB. The field names/shape MUST match the
/// `Advisory` struct consumed by `belayd::vuln` (see `daemon/data/README.md`):
/// `{id, package, fixed_version, severity, cve[], release}`. `release` lets the
/// matcher apply only the records for the host's running release, so multiple
/// releases can be bundled together without cross-release false positives.
///
/// Enrichment fields (TB-7) are all `skip_serializing_if` so the non-enriched
/// bundled JSON is byte-identical to the pre-TB-7 output.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[cfg_attr(feature = "enrich", derive(Deserialize))]
struct AdvisoryOut {
    id: String,
    package: String,
    fixed_version: String,
    severity: String,
    cve: Vec<String>,
    release: String,
    /// OSV-native ecosystem key (e.g. "Debian:12"). Lets the runtime matcher key
    /// records by ecosystem, not just codename. See `belayd::vuln::Advisory`.
    ecosystem: String,
    /// Provenance: "debian-tracker" | "osv" | "ubuntu-osv".
    source: String,
    // ── Enrichment fields (TB-7; absent in the non-enriched bundle) ──────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epss: Option<EpssOut>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kev: Option<KevOut>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exploit: Option<String>,         // "poc" | "functional" | "wild"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    references: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    updated_at: String,
}

// ── Debian Security Tracker schema (only the fields we consume) ───────────────

#[derive(Debug, Deserialize)]
struct CveEntry {
    #[serde(default)]
    releases: BTreeMap<String, ReleaseInfo>,
}

#[derive(Debug, Deserialize)]
struct ReleaseInfo {
    #[serde(default)]
    status: String,
    #[serde(default)]
    fixed_version: String,
    #[serde(default)]
    urgency: String,
}

/// Map Debian urgency to our severity bucket. Urgency may carry trailing `*`
/// markers (e.g. "high**" = high but unimportant-filtered) which we ignore.
fn severity_from_urgency(urgency: &str) -> &'static str {
    let u = urgency.trim_end_matches('*').trim();
    if u.starts_with("high") {
        "high"
    } else if u.starts_with("medium") {
        "medium"
    } else {
        // "low", "unimportant", "not yet assigned", "end-of-life", unknown → low.
        "low"
    }
}

/// Map a Debian release codename to its numeric major (the OSV `Debian:<n>`
/// ecosystem key). Unknown codenames (e.g. "testing"/"sid") yield the codename
/// itself so the ecosystem stays self-describing.
fn debian_release_number(codename: &str) -> &str {
    match codename {
        "bullseye" => "11",
        "bookworm" => "12",
        "trixie" => "13",
        other => other,
    }
}

/// Parse the Debian Security Tracker JSON into advisories for one release,
/// tagging each record with that release. Emits a record only for CVEs marked
/// `resolved` in the release with a concrete fixed version; skips
/// `open`/undetermined entries and the `0` sentinel ("never vulnerable here").
fn parse_debian_tracker(
    by_package: &BTreeMap<String, BTreeMap<String, CveEntry>>,
    release: &str,
) -> Vec<AdvisoryOut> {
    let mut out: Vec<AdvisoryOut> = Vec::new();
    for (package, cves) in by_package {
        for (id, entry) in cves {
            // Keep only CVE-keyed entries (the tracker also keys TEMP-/DSA- ids)
            // so every advisory carries a stable, citable id.
            if !id.starts_with("CVE-") {
                continue;
            }
            let Some(rel) = entry.releases.get(release) else {
                continue;
            };
            if rel.status != "resolved" {
                continue;
            }
            let fixed = rel.fixed_version.trim();
            if fixed.is_empty() || fixed == "0" {
                continue;
            }
            out.push(AdvisoryOut {
                id: id.clone(),
                package: package.clone(),
                fixed_version: fixed.to_string(),
                severity: severity_from_urgency(&rel.urgency).to_string(),
                cve: vec![id.clone()],
                release: release.to_string(),
                ecosystem: format!("Debian:{}", debian_release_number(release)),
                source: "debian-tracker".to_string(),
                ..Default::default()
            });
        }
    }
    out
}

// ── OSV schema (only the fields we consume) ───────────────────────────────────
// One OSV record per vulnerability; see https://ossf.github.io/osv-schema/.
// Used for the Ubuntu slice (Canonical's OSV feed) and any OSV ecosystem dump.

#[derive(Debug, Deserialize)]
struct OsvRecord {
    /// Standard-OSV cross-refs; for generic feeds the CVE lives here.
    #[serde(default)]
    aliases: Vec<String>,
    /// Canonical's Ubuntu feed puts the originating CVE here (no `aliases`).
    #[serde(default)]
    upstream: Vec<String>,
    /// Top-level severity array. Canonical overloads it with
    /// `{type:"Ubuntu", score:"low"}`; generic OSV uses CVSS entries.
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: OsvDbSpecific,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Default, Deserialize)]
struct OsvDbSpecific {
    #[serde(default)]
    severity: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Default, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

/// Map an OSV severity word to our bucket.
fn severity_from_osv(label: &str) -> &'static str {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        _ => "low",
    }
}

/// True when an OSV record's `affected` ecosystem belongs to the target base
/// distro. Accepts an optional trailing `:LTS` (`Ubuntu:24.04:LTS` ⇒
/// `Ubuntu:24.04`) but rejects ESM-only variants (`Ubuntu:Pro:…`,
/// `Ubuntu:Pro:FIPS…`) which would over-report on an unsubscribed host.
fn osv_ecosystem_matches(record_ecosystem: &str, target: &str) -> bool {
    let base = record_ecosystem
        .strip_suffix(":LTS")
        .unwrap_or(record_ecosystem);
    base == target
}

/// The record's CVE id from `aliases` first, then Canonical's `upstream`.
fn osv_cve(rec: &OsvRecord) -> Option<String> {
    rec.aliases
        .iter()
        .chain(rec.upstream.iter())
        .find(|a| a.starts_with("CVE-"))
        .cloned()
}

/// Severity: prefer the Ubuntu word-score entry, then `database_specific`.
fn osv_severity(rec: &OsvRecord) -> &'static str {
    if let Some(s) = rec
        .severity
        .iter()
        .find(|s| s.kind.eq_ignore_ascii_case("ubuntu"))
    {
        return severity_from_osv(&s.score);
    }
    severity_from_osv(&rec.database_specific.severity)
}

/// Parse one OSV JSON record into an `AdvisoryOut` for `ecosystem`, or `None`
/// when it carries no CVE (not citable) or no `fixed` event (nothing
/// actionable) for that ecosystem. Takes the first matching `affected` entry
/// and the first `fixed` event. The emitted `ecosystem` is the normalized
/// target (e.g. `Ubuntu:24.04`) so it matches host detection.
fn parse_osv_record(json: &str, ecosystem: &str) -> Option<AdvisoryOut> {
    let rec: OsvRecord = serde_json::from_str(json).ok()?;
    let cve = osv_cve(&rec)?;
    let affected = rec
        .affected
        .iter()
        .find(|a| osv_ecosystem_matches(&a.package.ecosystem, ecosystem))?;
    let fixed = affected
        .ranges
        .iter()
        .flat_map(|r| &r.events)
        .find_map(|e| e.fixed.clone())?;
    Some(AdvisoryOut {
        id: cve.clone(),
        package: affected.package.name.clone(),
        fixed_version: fixed,
        severity: osv_severity(&rec).to_string(),
        cve: vec![cve],
        release: String::new(),
        ecosystem: ecosystem.to_string(),
        source: "osv".to_string(),
        ..Default::default()
    })
}

/// Build the merged advisory set across all requested releases from one fetched
/// tracker document, sorted deterministically so committed diffs stay minimal.
fn build(json: &str, releases: &[String]) -> Result<Vec<AdvisoryOut>> {
    let by_package: BTreeMap<String, BTreeMap<String, CveEntry>> =
        serde_json::from_str(json).context("parsing Debian tracker JSON")?;
    let mut out: Vec<AdvisoryOut> = Vec::new();
    for release in releases {
        out.extend(parse_debian_tracker(&by_package, release));
    }
    sort_dedup(&mut out);
    Ok(out)
}

/// Build the merged advisory set from an in-memory collection of OSV JSON
/// records, keeping only those that apply to `ecosystem`. The production path
/// (`fetch_osv`) streams instead, to bound memory on the ~560 MB Ubuntu feed;
/// this in-memory form exists to unit-test the filter+sort composition.
#[cfg(test)]
fn build_osv<I: IntoIterator<Item = String>>(records: I, ecosystem: &str) -> Vec<AdvisoryOut> {
    let mut out: Vec<AdvisoryOut> = records
        .into_iter()
        .filter_map(|j| parse_osv_record(&j, ecosystem))
        .collect();
    sort_dedup(&mut out);
    out
}

/// Deterministic ordering shared by every source so the committed JSON is stable.
fn sort_dedup(out: &mut Vec<AdvisoryOut>) {
    out.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.release.cmp(&b.release))
    });
    out.dedup();
}

/// The OSV bulk-feed URL for an ecosystem. OSV organises its storage bucket by
/// the ecosystem name *before* the version colon (e.g. "Ubuntu:24.04" → the
/// `Ubuntu` bucket), shipping every record for that ecosystem in one `all.zip`.
fn osv_zip_url(ecosystem: &str) -> String {
    let bucket = ecosystem.split(':').next().unwrap_or(ecosystem);
    format!("https://osv-vulnerabilities.storage.googleapis.com/{bucket}/all.zip")
}

/// Download an OSV `all.zip` and build the advisories for `ecosystem`. The zip
/// holds one `<id>.json` per record (the Ubuntu feed is ~560 MB / ~hundreds of
/// thousands of entries), so each entry is parsed and filtered as it is read —
/// only the small set of matching `AdvisoryOut`s is retained in memory.
fn fetch_osv(url: &str, ecosystem: &str) -> Result<Vec<AdvisoryOut>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("belay-advisory-gen")
        .timeout(std::time::Duration::from_secs(600))
        .build()?;
    let bytes = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .bytes()?;
    let reader = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(reader).context("opening OSV all.zip")?;
    let mut out: Vec<AdvisoryOut> = Vec::new();
    let mut buf = String::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if !entry.name().ends_with(".json") {
            continue;
        }
        buf.clear();
        std::io::Read::read_to_string(&mut entry, &mut buf)?;
        if let Some(adv) = parse_osv_record(&buf, ecosystem) {
            out.push(adv);
        }
    }
    sort_dedup(&mut out);
    Ok(out)
}

fn fetch(url: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("belay-advisory-gen")
        .timeout(std::time::Duration::from_secs(180))
        .build()?;
    let body = client
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .text()?;
    Ok(body)
}

/// Which key-free feed to regenerate from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Debian Security Tracker JSON (keyed by release codename).
    DebianTracker,
    /// OSV bulk feed (keyed by ecosystem, e.g. `Ubuntu:24.04`).
    Osv,
}

struct Args {
    source: Source,
    releases: Vec<String>,
    ecosystem: Option<String>,
    out: String,
    /// Path to the base (already-generated) advisory JSON for enrichment.
    #[cfg(feature = "enrich")]
    enrich_in: String,
    /// RFC3339 freshness stamp written into enriched records (`updated_at`).
    #[cfg(feature = "enrich")]
    updated_at: String,
}

fn parse_args() -> Args {
    let mut source = Source::DebianTracker;
    let mut releases: Vec<String> = Vec::new();
    let mut ecosystem: Option<String> = None;
    let mut out = DEFAULT_OUT.to_string();
    #[cfg(feature = "enrich")]
    let mut enrich_in = String::new();
    #[cfg(feature = "enrich")]
    let mut updated_at = String::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--source" => match it.next().as_deref() {
                Some("debian-tracker") => source = Source::DebianTracker,
                Some("osv") => source = Source::Osv,
                other => {
                    eprintln!("error: --source must be debian-tracker|osv (got {other:?})");
                    std::process::exit(2);
                }
            },
            // Repeatable, and comma-separated values are also accepted:
            //   --release bookworm --release trixie   ==   --release bookworm,trixie
            "--release" => {
                if let Some(v) = it.next() {
                    releases.extend(
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
            }
            "--ecosystem" => {
                if let Some(v) = it.next() {
                    ecosystem = Some(v);
                }
            }
            "--out" => {
                if let Some(v) = it.next() {
                    out = v;
                }
            }
            #[cfg(feature = "enrich")]
            "--enrich-in" => {
                if let Some(v) = it.next() {
                    enrich_in = v;
                }
            }
            #[cfg(feature = "enrich")]
            "--updated-at" => {
                if let Some(v) = it.next() {
                    updated_at = v;
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: advisory-gen [--source debian-tracker|osv] \
                     [--release <codename>]... [--ecosystem <Ecosystem:ver>] [--out <path>]"
                );
                std::process::exit(0);
            }
            other => eprintln!("warning: ignoring unknown arg {other:?}"),
        }
    }
    if releases.is_empty() {
        releases.push(DEFAULT_RELEASE.to_string());
    }
    Args {
        source,
        releases,
        ecosystem,
        out,
        #[cfg(feature = "enrich")]
        enrich_in,
        #[cfg(feature = "enrich")]
        updated_at,
    }
}

fn main() -> Result<()> {
    let args = parse_args();

    let advisories = match args.source {
        Source::DebianTracker => {
            eprintln!(
                "advisory-gen: fetching Debian Security Tracker for releases {:?}…",
                args.releases
            );
            let json = fetch(DEBIAN_TRACKER_URL).context("fetching Debian tracker")?;
            build(&json, &args.releases)?
        }
        Source::Osv => {
            let ecosystem = args.ecosystem.as_deref().context(
                "--source osv requires --ecosystem <Ecosystem:ver> (e.g. Ubuntu:24.04)",
            )?;
            let url = osv_zip_url(ecosystem);
            eprintln!("advisory-gen: fetching OSV feed {url} for {ecosystem}…");
            fetch_osv(&url, ecosystem).context("fetching OSV feed")?
        }
    };
    eprintln!("advisory-gen: {} advisories", advisories.len());

    let mut text = serde_json::to_string_pretty(&advisories)?;
    text.push('\n');
    std::fs::write(&args.out, text).with_context(|| format!("writing {}", args.out))?;
    eprintln!("advisory-gen: wrote {}", args.out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_urgency_to_severity() {
        assert_eq!(severity_from_urgency("high"), "high");
        assert_eq!(severity_from_urgency("high**"), "high");
        assert_eq!(severity_from_urgency("medium*"), "medium");
        assert_eq!(severity_from_urgency("low"), "low");
        assert_eq!(severity_from_urgency("unimportant"), "low");
        assert_eq!(severity_from_urgency("not yet assigned"), "low");
        assert_eq!(severity_from_urgency(""), "low");
    }

    const SAMPLE: &str = r#"{
        "openssl": {
            "CVE-2024-0001": {"releases": {
                "bookworm": {"status":"resolved","fixed_version":"3.0.11-1","urgency":"high"},
                "trixie": {"status":"resolved","fixed_version":"3.1.4-2","urgency":"high"}
            }},
            "CVE-2024-0002": {"releases": {"bookworm": {"status":"open","urgency":"medium"}}},
            "CVE-2023-9999": {"releases": {"bookworm": {"status":"resolved","fixed_version":"0","urgency":"low"}}}
        },
        "bash": {
            "CVE-2024-0003": {"releases": {"bullseye": {"status":"resolved","fixed_version":"5.1-2","urgency":"low"}}},
            "TEMP-0000000-ABCDEF": {"releases": {"bookworm": {"status":"resolved","fixed_version":"1.0","urgency":"low"}}}
        },
        "zlib": {
            "CVE-2024-0005": {"releases": {"bookworm": {"status":"resolved","fixed_version":"1:1.2.13.dfsg-1","urgency":"medium**"}}}
        }
    }"#;

    #[test]
    fn parses_resolved_cves_for_target_release_only() {
        let got = build(SAMPLE, &["bookworm".to_string()]).unwrap();
        // openssl CVE-0002 (open), CVE-2023-9999 (fixed "0"), bash CVE-0003
        // (wrong release) and the TEMP- entry (non-CVE) are all skipped.
        let expected = vec![
            AdvisoryOut {
                id: "CVE-2024-0001".into(),
                package: "openssl".into(),
                fixed_version: "3.0.11-1".into(),
                severity: "high".into(),
                cve: vec!["CVE-2024-0001".into()],
                release: "bookworm".into(),
                ecosystem: "Debian:12".into(),
                source: "debian-tracker".into(),
                ..Default::default()
            },
            AdvisoryOut {
                id: "CVE-2024-0005".into(),
                package: "zlib".into(),
                fixed_version: "1:1.2.13.dfsg-1".into(),
                severity: "medium".into(),
                cve: vec!["CVE-2024-0005".into()],
                release: "bookworm".into(),
                ecosystem: "Debian:12".into(),
                source: "debian-tracker".into(),
                ..Default::default()
            },
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn multi_release_tags_each_record_and_sorts() {
        let got = build(SAMPLE, &["bookworm".to_string(), "trixie".to_string()]).unwrap();
        // openssl CVE-0001 appears once per release; zlib only in bookworm.
        let openssl: Vec<_> = got.iter().filter(|a| a.package == "openssl").collect();
        assert_eq!(openssl.len(), 2, "{got:?}");
        assert_eq!(openssl[0].release, "bookworm");
        assert_eq!(openssl[0].fixed_version, "3.0.11-1");
        assert_eq!(openssl[1].release, "trixie");
        assert_eq!(openssl[1].fixed_version, "3.1.4-2");
        // Sorted by (package, id, release): openssl before zlib.
        assert_eq!(got.first().unwrap().package, "openssl");
        assert_eq!(got.last().unwrap().package, "zlib");
    }

    #[test]
    fn parses_osv_record_to_advisory() {
        let osv = r#"{"id":"UBUNTU-CVE-2024-1","aliases":["CVE-2024-1"],
          "database_specific":{"severity":"High"},
          "affected":[{"package":{"ecosystem":"Ubuntu:24.04","name":"openssl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.1"}]}]}]}"#;
        let out = parse_osv_record(osv, "Ubuntu:24.04").unwrap();
        assert_eq!(out.package, "openssl");
        assert_eq!(out.fixed_version, "3.0.13-0ubuntu3.1");
        assert_eq!(out.cve, vec!["CVE-2024-1".to_string()]);
        assert_eq!(out.ecosystem, "Ubuntu:24.04");
        assert_eq!(out.source, "osv");
        assert_eq!(out.severity, "high");
    }

    #[test]
    fn build_osv_filters_by_ecosystem_sorts_and_skips_bad_records() {
        let rec = |name: &str, eco: &str, cve: &str, fixed: &str| {
            format!(
                r#"{{"id":"X-{cve}","aliases":["{cve}"],"database_specific":{{"severity":"Low"}},
                  "affected":[{{"package":{{"ecosystem":"{eco}","name":"{name}"}},
                    "ranges":[{{"events":[{{"fixed":"{fixed}"}}]}}]}}]}}"#
            )
        };
        let records = vec![
            rec("zlib", "Ubuntu:24.04", "CVE-2024-2", "1:1.3"),
            rec("openssl", "Ubuntu:24.04", "CVE-2024-1", "3.0.13"),
            rec("other", "Debian:12", "CVE-2024-9", "9"), // wrong ecosystem → dropped
        ];
        let out = build_osv(records, "Ubuntu:24.04");
        let pkgs: Vec<&str> = out.iter().map(|a| a.package.as_str()).collect();
        assert_eq!(pkgs, vec!["openssl", "zlib"], "sorted, Debian record dropped");
    }

    #[test]
    fn osv_zip_url_uses_bucket_before_colon() {
        assert_eq!(
            osv_zip_url("Ubuntu:24.04"),
            "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
        );
    }

    #[test]
    fn parses_real_canonical_ubuntu_shape() {
        // Mirrors the live Canonical OSV feed: CVE in `upstream` (no aliases),
        // severity as a top-level {type:"Ubuntu",score} entry, ":LTS" ecosystem.
        let osv = r#"{"id":"UBUNTU-CVE-2010-5298","upstream":["CVE-2010-5298"],
          "severity":[{"type":"Ubuntu","score":"low"}],
          "affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.1f-1ubuntu2.1"}]}]}]}"#;
        let out = parse_osv_record(osv, "Ubuntu:24.04").unwrap();
        assert_eq!(out.package, "openssl");
        assert_eq!(out.fixed_version, "1.0.1f-1ubuntu2.1");
        assert_eq!(out.cve, vec!["CVE-2010-5298".to_string()]);
        assert_eq!(out.ecosystem, "Ubuntu:24.04"); // normalized, matches host
        assert_eq!(out.severity, "low");
    }

    #[test]
    fn osv_excludes_ubuntu_pro_and_fips_variants() {
        // Pro/FIPS ESM ecosystems must NOT match a base-distro target — they'd
        // over-report on a host without an ESM subscription.
        for eco in ["Ubuntu:Pro:24.04:LTS", "Ubuntu:Pro:FIPS:24.04:LTS"] {
            assert!(!osv_ecosystem_matches(eco, "Ubuntu:24.04"), "{eco} must be excluded");
        }
        assert!(osv_ecosystem_matches("Ubuntu:24.04:LTS", "Ubuntu:24.04"));
        assert!(osv_ecosystem_matches("Ubuntu:24.10", "Ubuntu:24.10"));
    }

    #[test]
    fn osv_record_without_cve_alias_or_fixed_event_is_skipped() {
        // No CVE alias → not citable → skipped.
        let no_cve = r#"{"id":"UBUNTU-X","aliases":["GHSA-zzzz"],
          "affected":[{"package":{"ecosystem":"Ubuntu:24.04","name":"p"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1"}]}]}]}"#;
        assert!(parse_osv_record(no_cve, "Ubuntu:24.04").is_none());
        // No `fixed` event (still vulnerable, no patch) → nothing actionable → skipped.
        let no_fix = r#"{"id":"UBUNTU-Y","aliases":["CVE-2024-2"],
          "affected":[{"package":{"ecosystem":"Ubuntu:24.04","name":"p"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#;
        assert!(parse_osv_record(no_fix, "Ubuntu:24.04").is_none());
    }

    #[test]
    fn output_matches_bundled_db_shape() {
        // Serialized records must use the exact keys belayd::vuln consumes.
        let rec = AdvisoryOut {
            id: "CVE-2024-0001".into(),
            package: "openssl".into(),
            fixed_version: "3.0.11-1".into(),
            severity: "high".into(),
            cve: vec!["CVE-2024-0001".into()],
            release: "bookworm".into(),
            ecosystem: "Debian:12".into(),
            source: "debian-tracker".into(),
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::to_value(&rec).unwrap();
        assert!(v.get("id").is_some());
        assert!(v.get("package").is_some());
        assert!(v.get("fixed_version").is_some());
        assert!(v.get("severity").is_some());
        assert!(v.get("cve").unwrap().is_array());
        assert_eq!(v.get("release").unwrap().as_str(), Some("bookworm"));
        assert_eq!(v.get("ecosystem").unwrap().as_str(), Some("Debian:12"));
        assert_eq!(v.get("source").unwrap().as_str(), Some("debian-tracker"));
    }

    #[test]
    fn non_enriched_advisory_has_no_enrichment_keys_in_json() {
        // Regression: adding enrichment fields must NOT change the serialized bytes
        // for a plain (non-enriched) advisory — all enrichment keys must be absent.
        let rec = AdvisoryOut {
            id: "CVE-2024-0001".into(),
            package: "openssl".into(),
            fixed_version: "3.0.11-1".into(),
            severity: "high".into(),
            cve: vec!["CVE-2024-0001".into()],
            release: "bookworm".into(),
            ecosystem: "Debian:12".into(),
            source: "debian-tracker".into(),
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::to_value(&rec).unwrap();
        // These keys must NOT appear in non-enriched output.
        assert!(v.get("epss").is_none(), "epss must be absent in non-enriched output");
        assert!(v.get("kev").is_none(), "kev must be absent in non-enriched output");
        assert!(v.get("exploit").is_none(), "exploit must be absent in non-enriched output");
        assert!(v.get("references").is_none(), "references must be absent in non-enriched output");
        assert!(v.get("updated_at").is_none(), "updated_at must be absent in non-enriched output");
    }
}
