//! Host/EDR configuration persisted as small JSON files under `~/.belay`,
//! plus quarantine-directory listing.
//!
//! This is the single source of truth shared by every surface that exposes the
//! ssh-guard config, the scan schedule and the quarantine list — the daemon, the
//! server's HTTP routes and the Tauri desktop commands all call these functions,
//! so the on-disk shapes and the DEFAULTS can never drift between web and
//! desktop. The module is feature-independent (no `firewall`/`vulndb` deps).
//!
//! TS contract: `web/src/lib/hostTypes.ts` (`SshGuardConfig`, `ScanSchedule`,
//! `QuarantineEntry`).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Belay data directory (platform-specific; delegates to `paths::data_dir()`).
/// Not created here; writers create it on demand.
pub fn belay_dir() -> PathBuf {
    crate::paths::data_dir()
}

/// Format epoch seconds as RFC3339 UTC ("YYYY-MM-DDTHH:MM:SSZ").
/// Pure integer Gregorian-calendar math; no chrono dependency.
pub fn rfc3339_utc(secs: u64) -> String {
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

/// Read a JSON config file under `~/.belay`, or `default` if it is absent
/// or unparseable (fail-soft).
pub fn read_json(name: &str, default: Value) -> Value {
    read_json_at(&belay_dir(), name, default)
}

/// Write a JSON config file under `~/.belay` (creating the dir).
pub fn write_json(name: &str, value: &Value) -> Result<(), String> {
    write_json_at(&belay_dir(), name, value)
}

/// Test/injectable seam behind [`read_json`]: reads from an explicit
/// directory instead of always resolving [`belay_dir`]. Kept private —
/// production callers always go through [`read_json`]; this only exists so
/// unit tests (e.g. the `net_enrich` round-trip test) can exercise real
/// read/write behavior against a temp directory instead of a real `$HOME`.
fn read_json_at(dir: &Path, name: &str, default: Value) -> Value {
    match std::fs::read(dir.join(name)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or(default),
        Err(_) => default,
    }
}

/// Test/injectable seam behind [`write_json`]. See [`read_json_at`].
fn write_json_at(dir: &Path, name: &str, value: &Value) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(name), bytes).map_err(|e| e.to_string())
}

// ── SSH guard config ──────────────────────────────────────────────────────────

const SSH_GUARD_FILE: &str = "ssh_guard.json";

/// Default `SshGuardConfig`. Sensible hardening defaults applied when unset.
pub fn default_ssh_guard() -> Value {
    json!({
        "enabled": true,
        "max_auth_tries": 3,
        "ban_threshold": 5,
        "ban_duration_secs": 3600,
        "permit_root_login": false,
    })
}

/// The current SSH-guard config (persisted, or defaults when unset).
pub fn ssh_guard() -> Value {
    read_json(SSH_GUARD_FILE, default_ssh_guard())
}

/// Persist an SSH-guard config patch, merged over the current/default config.
pub fn set_ssh_guard(patch: &Value) -> Result<(), String> {
    let mut current = ssh_guard();
    if let (Some(cur), Some(p)) = (current.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            cur.insert(k.clone(), v.clone());
        }
    }
    write_json(SSH_GUARD_FILE, &current)
}

// ── Network-destination enrichment toggle ───────────────────────────────────
//
// Backs the optional `netenrich` daemon feature (reverse-DNS + ASN/owner/
// country lookups; see `crate::netenrich`, gated behind `#[cfg(feature =
// "netenrich")]`). This config helper is feature-independent by design —
// like the rest of this module — so the toggle can be read/written (and
// defaults to enabled) even in builds where the `netenrich` feature itself
// is compiled out; in that case the toggle is simply inert.

const NET_ENRICH_FILE: &str = "net_enrich.json";

/// Default net-enrich config: `{"enabled": true}` — on by default when the
/// `netenrich` feature is compiled in (display-only; the runtime toggle
/// exists so an operator can turn lookups off without a rebuild).
pub fn default_net_enrich() -> Value {
    json!({ "enabled": true })
}

/// The current net-enrich config (persisted, or defaults when unset).
pub fn net_enrich() -> Value {
    net_enrich_at(&belay_dir())
}

/// Persist the net-enrich toggle (full replace — it is a single bool field).
pub fn set_net_enrich(enabled: bool) -> Result<(), String> {
    set_net_enrich_at(&belay_dir(), enabled)
}

/// Test/injectable seam behind [`net_enrich`]. See [`read_json_at`].
fn net_enrich_at(dir: &Path) -> Value {
    read_json_at(dir, NET_ENRICH_FILE, default_net_enrich())
}

/// Test/injectable seam behind [`set_net_enrich`]. See [`read_json_at`].
fn set_net_enrich_at(dir: &Path, enabled: bool) -> Result<(), String> {
    write_json_at(dir, NET_ENRICH_FILE, &json!({ "enabled": enabled }))
}

// ── Scan schedule ─────────────────────────────────────────────────────────────

const SCHEDULE_FILE: &str = "scan_schedule.json";

/// Default `ScanSchedule` (disabled; daily-at-03:00 quick scan when enabled).
pub fn default_schedule() -> Value {
    json!({ "enabled": false, "cron": "0 3 * * *", "scope": "quick" })
}

/// The current scan schedule (persisted, or defaults when unset).
pub fn scan_schedule() -> Value {
    read_json(SCHEDULE_FILE, default_schedule())
}

/// Persist the scan schedule (full replace — `ScanSchedule` is not partial).
pub fn set_scan_schedule(value: &Value) -> Result<(), String> {
    write_json(SCHEDULE_FILE, value)
}

// ── Quarantine ────────────────────────────────────────────────────────────────

/// `~/.belay/quarantine`.
pub fn quarantine_dir() -> PathBuf {
    belay_dir().join("quarantine")
}

/// List files under the quarantine directory as `QuarantineEntry`-shaped JSON.
///
/// The quarantine *store* (original-path / rule / severity metadata) is not yet
/// implemented, so those fields are best-effort placeholders for any files that
/// are present; a fresh install has none and returns `[]`.
pub fn list_quarantine() -> Vec<Value> {
    let dir = quarantine_dir();
    let mut entries = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let meta = match e.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let quarantined_at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| rfc3339_utc(d.as_secs()))
                .unwrap_or_default();
            entries.push(json!({
                "id": e.file_name().to_string_lossy(),
                "original_path": "",
                "quarantined_at": quarantined_at,
                "rule_id": "",
                "severity": "low",
            }));
        }
    }
    entries
}

/// Permanently delete a quarantined file by id (its bare filename).
pub fn delete_quarantine(id: &str) -> Result<(), String> {
    // Reject anything but a bare filename (path-traversal guard).
    if id.is_empty() || id.contains('/') || id.contains("..") {
        return Err("invalid quarantine id".to_string());
    }
    std::fs::remove_file(quarantine_dir().join(id)).map_err(|e| e.to_string())
}

/// Restore a quarantined file. The metadata store needed to recover each file's
/// original path is not implemented, so restore is unavailable (honest error).
pub fn restore_quarantine(id: &str) -> Result<(), String> {
    let _ = id;
    Err("restore is unavailable — the quarantine store is not yet implemented".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_timestamps() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_705_320_000), "2024-01-15T12:00:00Z");
    }

    #[test]
    fn ssh_guard_default_shape() {
        let d = default_ssh_guard();
        assert_eq!(d["enabled"], json!(true));
        assert_eq!(d["max_auth_tries"], json!(3));
        assert_eq!(d["ban_threshold"], json!(5));
        assert_eq!(d["ban_duration_secs"], json!(3600));
        assert_eq!(d["permit_root_login"], json!(false));
    }

    // NOTE: test fn names deliberately spell "netenrich" (no underscore) so
    // they're picked up by the `cargo test --features netenrich netenrich`
    // substring filter used as this feature's gate, alongside
    // `netenrich::tests::*` — the public API itself stays `net_enrich`
    // (matches the interface spec / the `ai`/`ssh_guard` naming convention).

    #[test]
    fn netenrich_default_shape() {
        let d = default_net_enrich();
        assert_eq!(d["enabled"], json!(true));
    }

    /// Hermetic round-trip: exercises the real `net_enrich_at`/
    /// `set_net_enrich_at` read/write behavior — the same code paths
    /// `net_enrich()`/`set_net_enrich()` delegate to — against a unique temp
    /// directory, never the real `$HOME`/`.belay`. Mirrors the temp-dir
    /// pattern already used by `ai::secret::tests::TempKeyFile`.
    #[test]
    fn netenrich_set_and_read_roundtrip_hermetic() {
        let dir = std::env::temp_dir().join(format!(
            "belayd-net-enrich-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));

        // Default (nothing persisted yet in this fresh temp dir): enabled.
        assert_eq!(net_enrich_at(&dir)["enabled"], json!(true));

        set_net_enrich_at(&dir, false).expect("write must succeed");
        assert_eq!(net_enrich_at(&dir)["enabled"], json!(false));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn schedule_default_shape() {
        let d = default_schedule();
        assert_eq!(d["enabled"], json!(false));
        assert_eq!(d["cron"], json!("0 3 * * *"));
        assert_eq!(d["scope"], json!("quick"));
    }

    #[test]
    fn delete_quarantine_rejects_traversal() {
        assert!(delete_quarantine("../etc/passwd").is_err());
        assert!(delete_quarantine("a/b").is_err());
        assert!(delete_quarantine("").is_err());
    }

    #[test]
    fn restore_quarantine_is_unavailable() {
        assert!(restore_quarantine("anything").is_err());
    }
}
