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

// ── UI locale ───────────────────────────────────────────────────────────────
//
// One source of truth for the language every Belay surface renders in: the
// desktop GUI, the CLI, the setup wizard and the rule-catalog explanations.
// Chosen in the setup wizard and changeable from the GUI.

const LOCALE_FILE: &str = "locale.json";

/// Locales this build actually ships.
///
/// A persisted value outside this list is NEVER trusted. The locale selects a
/// compiled-in catalogue, so echoing back an arbitrary string would let a
/// hand-edited config name something that was never built - and if it ever
/// reached a path join, a traversal.
pub const SUPPORTED_LOCALES: &[&str] = &["en", "zh-Hans"];

/// The UI locale (persisted, or `en` when unset or unrecognised).
pub fn locale() -> String {
    locale_at(&belay_dir())
}

/// Persist the UI locale. Rejects anything outside [`SUPPORTED_LOCALES`] rather
/// than writing a value that would silently fall back to English on read.
pub fn set_locale(locale: &str) -> Result<(), String> {
    set_locale_at(&belay_dir(), locale)
}

/// Test/injectable seam behind [`locale`]. See [`read_json_at`].
fn locale_at(dir: &Path) -> String {
    let raw = read_json_at(dir, LOCALE_FILE, json!({ "locale": "en" }))["locale"]
        .as_str()
        .unwrap_or("en")
        .to_string();
    if SUPPORTED_LOCALES.contains(&raw.as_str()) {
        raw
    } else {
        "en".to_string()
    }
}

/// Test/injectable seam behind [`set_locale`]. See [`read_json_at`].
fn set_locale_at(dir: &Path, locale: &str) -> Result<(), String> {
    if !SUPPORTED_LOCALES.contains(&locale) {
        return Err(format!("unsupported locale: {locale}"));
    }
    write_json_at(dir, LOCALE_FILE, &json!({ "locale": locale }))
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

/// On-disk quarantine metadata store: `<quarantine_dir>/index.json`, mapping
/// quarantine id -> `{"original_path", "quarantined_at", "kind"}`. This is what
/// makes [`restore_quarantine`] able to move a quarantined item back to where
/// it came from.
const QUARANTINE_INDEX_FILE: &str = "index.json";

type QuarantineIndex = std::collections::BTreeMap<String, Value>;

/// Read the quarantine index. Fail-soft: a missing or corrupt file yields an
/// empty map rather than an error (mirrors [`read_json_at`]'s fail-soft read).
fn read_index(qdir: &Path) -> QuarantineIndex {
    match std::fs::read(qdir.join(QUARANTINE_INDEX_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => QuarantineIndex::new(),
    }
}

/// Persist the quarantine index (creates `qdir` if needed).
///
/// Writes to a temp file in `qdir` and `rename`s it into place, rather than a
/// bare `std::fs::write`, so a crash/power-loss mid-write can't leave
/// `index.json` truncated or corrupted (a bare write is not atomic: a reader
/// racing the write, or a process death partway through, can observe a
/// partial file). `rename` within the same directory is atomic on the same
/// filesystem, matching the pattern `provision_admin` uses for `users.json`
/// in `src/bin/belay.rs`.
fn write_index(qdir: &Path, index: &QuarantineIndex) -> Result<(), String> {
    std::fs::create_dir_all(qdir).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(index).map_err(|e| e.to_string())?;
    let tmp_path = qdir.join(format!("{QUARANTINE_INDEX_FILE}.tmp"));
    std::fs::write(&tmp_path, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp_path, qdir.join(QUARANTINE_INDEX_FILE)).map_err(|e| e.to_string())
}

/// Current unix time in seconds (fail-soft: 0 if the clock is somehow before
/// the epoch, which never happens in practice but must not panic).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Move `src` to `dst` (file or dir), creating `dst`'s parent dirs first.
/// Tries a plain rename first (cheap, atomic on the same filesystem); if that
/// fails (e.g. cross-filesystem), falls back to a recursive copy followed by
/// removing `src` — and never removes `src` unless the copy fully succeeded,
/// so a failure leaves the original in place rather than losing data.
fn move_path(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    if let Err(e) = copy_tree(src, dst) {
        // Best-effort cleanup of a partial copy; the original (src) is left
        // untouched either way.
        let _ = std::fs::remove_dir_all(dst);
        let _ = std::fs::remove_file(dst);
        return Err(e.to_string());
    }
    if src.is_dir() {
        std::fs::remove_dir_all(src).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(src).map_err(|e| e.to_string())
    }
}

/// Recursively copy a file or directory tree from `src` to `dst`.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                copy_tree(&src_path, &dst_path)?;
            } else if file_type.is_symlink() {
                #[cfg(unix)]
                {
                    let target = std::fs::read_link(&src_path)?;
                    std::os::unix::fs::symlink(&target, &dst_path)?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::copy(&src_path, &dst_path)?;
                }
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        Ok(())
    }
}

/// Sanitize a filename component for use as (part of) a quarantine id: strip
/// any path separators that shouldn't be there in a bare `file_name()` but
/// are rejected defensively anyway.
fn sanitize_component(s: &str) -> String {
    let s = s.replace(['/', '\\'], "_");
    if s.is_empty() {
        "item".to_string()
    } else {
        s
    }
}

/// Generate a fresh, unused quarantine id for `path`: `<basename>-<unix_secs>`,
/// with a `-N` counter appended on collision (against both the index and any
/// same-named entry already on disk under `qdir`).
fn quarantine_id_for(qdir: &Path, index: &QuarantineIndex, path: &Path) -> String {
    let base = path
        .file_name()
        .map(|n| sanitize_component(&n.to_string_lossy()))
        .unwrap_or_else(|| "item".to_string());
    let secs = now_secs();
    let mut candidate = format!("{base}-{secs}");
    let mut n = 1u32;
    while index.contains_key(&candidate) || qdir.join(&candidate).exists() {
        candidate = format!("{base}-{secs}-{n}");
        n += 1;
    }
    candidate
}

/// Move `path` (a file or dir) into `qdir` under a generated id, recording its
/// original location (and kind) in the quarantine index. Returns the id.
/// Pure/testable seam behind [`quarantine_skill`] — takes the quarantine dir
/// explicitly so tests never have to mutate `$HOME`.
pub(crate) fn quarantine_skill_in(qdir: &Path, path: &Path) -> Result<String, String> {
    if !path.exists() {
        return Err(format!("path does not exist: {}", path.display()));
    }
    let kind = if path.is_dir() { "dir" } else { "file" };
    let mut index = read_index(qdir);
    let id = quarantine_id_for(qdir, &index, path);
    let target = qdir.join(&id);

    // Reserve the id + persist the index entry BEFORE moving the path. This
    // is deliberately the reverse of "move then record": if we moved first
    // and the process died (or the index write failed) before recording the
    // entry, the item would sit in `qdir` with no index entry — an orphan
    // that `restore_quarantine` can't look up by id (it can still be
    // rediscovered by `list_quarantine`'s fallback scan, see
    // `list_quarantine_in`, but that path has no `original_path` to restore
    // to). Recording first means a successful move ALWAYS has a matching
    // index entry.
    index.insert(
        id.clone(),
        json!({
            "original_path": path.to_string_lossy(),
            "quarantined_at": rfc3339_utc(now_secs()),
            "kind": kind,
        }),
    );
    write_index(qdir, &index)?;

    if let Err(e) = move_path(path, &target) {
        // The move failed (the original is still at `path` — `move_path`
        // never removes `src` unless the copy fully succeeded). Roll back
        // the reservation so the index doesn't claim an id that was never
        // actually quarantined; best-effort on the rollback write itself —
        // the original move error is what the caller needs to see either way.
        index.remove(&id);
        let _ = write_index(qdir, &index);
        return Err(e);
    }
    Ok(id)
}

/// Move `path` (a file OR dir) into the quarantine dir under a generated id, recording
/// its original location in the store. Returns the id. Reversible via restore_quarantine.
pub fn quarantine_skill(path: &Path) -> Result<String, String> {
    quarantine_skill_in(&quarantine_dir(), path)
}

/// List quarantined items as `QuarantineEntry`-shaped JSON: entries tracked in
/// the index (the common case) plus, best-effort, any loose files sitting in
/// `qdir` that predate the index or otherwise fell out of it.
/// Pure/testable seam behind [`list_quarantine`].
pub(crate) fn list_quarantine_in(qdir: &Path) -> Vec<Value> {
    let index = read_index(qdir);
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut entries: Vec<Value> = index
        .iter()
        .map(|(id, meta)| {
            seen.insert(id.clone());
            json!({
                "id": id,
                "original_path": meta.get("original_path").cloned().unwrap_or(json!("")),
                "quarantined_at": meta.get("quarantined_at").cloned().unwrap_or(json!("")),
                "kind": meta.get("kind").cloned().unwrap_or(json!("file")),
                "rule_id": "",
                "severity": "low",
            })
        })
        .collect();

    if let Ok(rd) = std::fs::read_dir(qdir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == QUARANTINE_INDEX_FILE || seen.contains(&name) {
                continue;
            }
            // A quarantined skill is a DIRECTORY (see `quarantine_skill_in`'s
            // `kind` field), so the orphan fallback must include dirs too —
            // `m.is_file()` alone silently dropped every orphaned skill dir
            // from this listing (still on disk under `qdir`, just invisible
            // to `list_quarantine`/`restore`).
            let meta = match e.metadata() {
                Ok(m) if m.is_file() || m.is_dir() => m,
                _ => continue,
            };
            let quarantined_at = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| rfc3339_utc(d.as_secs()))
                .unwrap_or_default();
            let kind = if meta.is_dir() { "dir" } else { "file" };
            entries.push(json!({
                "id": name,
                "original_path": "",
                "quarantined_at": quarantined_at,
                "kind": kind,
                "rule_id": "",
                "severity": "low",
            }));
        }
    }
    entries
}

/// List files under the quarantine directory as `QuarantineEntry`-shaped JSON.
pub fn list_quarantine() -> Vec<Value> {
    list_quarantine_in(&quarantine_dir())
}

/// Permanently delete a quarantined item (file or dir) by id (its bare
/// directory-entry name), dropping its index entry too.
/// Pure/testable seam behind [`delete_quarantine`].
pub(crate) fn delete_quarantine_in(qdir: &Path, id: &str) -> Result<(), String> {
    // Reject anything but a bare filename (path-traversal guard).
    if id.is_empty() || id.contains('/') || id.contains("..") {
        return Err("invalid quarantine id".to_string());
    }
    let target = qdir.join(id);
    let meta = std::fs::symlink_metadata(&target).map_err(|e| e.to_string())?;
    if meta.is_dir() {
        std::fs::remove_dir_all(&target).map_err(|e| e.to_string())?;
    } else {
        std::fs::remove_file(&target).map_err(|e| e.to_string())?;
    }
    let mut index = read_index(qdir);
    if index.remove(id).is_some() {
        write_index(qdir, &index)?;
    }
    Ok(())
}

/// Permanently delete a quarantined file by id (its bare filename).
pub fn delete_quarantine(id: &str) -> Result<(), String> {
    delete_quarantine_in(&quarantine_dir(), id)
}

/// Restore a quarantined item: look up `id` in the index, move it back to its
/// `original_path` (creating parent dirs as needed), and drop the index
/// entry. Returns the `original_path` on success so [`restore_quarantine`]
/// can mark it trusted. Pure/testable seam behind [`restore_quarantine`] —
/// deliberately does NOT touch the trust store (that store lives under the
/// real `belay_dir()`, not the injected `qdir`; doing it here would leak
/// writes into the real `$HOME/.belay` from hermetic tests that pass a temp
/// `qdir`).
pub(crate) fn restore_quarantine_in(qdir: &Path, id: &str) -> Result<PathBuf, String> {
    // Reject anything but a bare filename (path-traversal guard).
    if id.is_empty() || id.contains('/') || id.contains("..") {
        return Err("invalid quarantine id".to_string());
    }
    let mut index = read_index(qdir);
    let entry = index
        .get(id)
        .cloned()
        .ok_or_else(|| "unknown quarantine id".to_string())?;
    let original_path = entry["original_path"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "corrupt quarantine entry: missing original_path".to_string())?;
    let original_path = PathBuf::from(original_path);
    let source = qdir.join(id);
    move_path(&source, &original_path)?;
    index.remove(id);
    write_index(qdir, &index)?;
    Ok(original_path)
}

/// Restore a quarantined file to its original location.
///
/// Trust-on-restore: after a successful move, marks the restored path
/// trusted (see [`add_trusted_skill`]) so the skill dir-watcher's poller
/// (~30s tick, `app.rs`) doesn't treat the freshly-restored skill as "new"
/// and immediately re-quarantine it — which would otherwise make Restore a
/// no-op in practice. Best-effort: the restore itself already succeeded by
/// this point, so a failure to persist the trust marker is not surfaced as
/// an error (only means the watcher may re-flag it on its next tick).
pub fn restore_quarantine(id: &str) -> Result<(), String> {
    let original_path = restore_quarantine_in(&quarantine_dir(), id)?;
    let _ = add_trusted_skill(&original_path); // kept for backward-compat/audit
    // Phase 2d: record the restored (operator-overridden) content as the
    // approved baseline so content-keyed trust applies — a later in-place
    // tamper drifts from this baseline and is re-flagged by the watcher.
    if original_path.is_dir() {
        if let Some(m) = skillscan::scan_skill(&original_path).manifest {
            let _ = set_skill_baseline(&original_path, &m, "restore");
        }
    }
    Ok(())
}

// ── Skill baselines (Phase 2d: approved-manifest store for drift detection) ──
//
// Maps a skill dir (canonicalized path key, same scheme as trusted_skills)
// to the manifest that was approved for it. `diff_manifests(baseline, current)`
// flags permission/trigger/description drift. The baseline is set on a first
// clean scan and moved ONLY by operator re-approval or restore — never by a
// periodic tick — so a rug-pull update can't launder itself into a new baseline.
const SKILL_BASELINES_FILE: &str = "skill_baselines.json";

/// Deterministic content fingerprint of a skill directory: every regular file
/// under `dir` (bounded depth), by sorted relative path, each read up to a cap,
/// hashed together. Trust is keyed on THIS (not just manifest fields), so any
/// change to the SKILL.md body OR a sibling script drops the skill out of the
/// trusted fast-path and back through the full scan/drift evaluation. Fail-soft:
/// unreadable entries are skipped; a missing dir hashes to a stable value.
pub fn skill_content_hash(dir: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    const PER_FILE_CAP: usize = 1024 * 1024; // 1 MiB/file
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for e in walkdir::WalkDir::new(dir).max_depth(8).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let rel = e.path().strip_prefix(dir).unwrap_or(e.path()).to_string_lossy().to_string();
        let mut bytes = match std::fs::read(e.path()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        bytes.truncate(PER_FILE_CAP);
        entries.push((rel, bytes));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (rel, bytes) in &entries {
        rel.hash(&mut h);
        bytes.hash(&mut h);
    }
    h.finish()
}

/// The approved baseline manifest for `dir`, or `None` if none recorded /
/// the store is missing or corrupt (fail-soft: a missing baseline is the safe
/// default — the next clean scan re-establishes one).
pub fn skill_baseline(dir: &Path) -> Option<skillscan::manifest::Manifest> {
    skill_baseline_in(&belay_dir(), dir)
}

pub(crate) fn skill_baseline_in(cfg_dir: &Path, dir: &Path) -> Option<skillscan::manifest::Manifest> {
    let key = canonical_string(dir);
    let store = read_json_at(cfg_dir, SKILL_BASELINES_FILE, json!({}));
    let manifest = store.get(&key)?.get("manifest")?.clone();
    serde_json::from_value(manifest).ok()
}

/// Record `m` as the approved baseline for `dir`. `source` is
/// `auto_clean_scan | operator_approve | restore` (audit/debug only).
pub fn set_skill_baseline(dir: &Path, m: &skillscan::manifest::Manifest, source: &str) -> Result<(), String> {
    set_skill_baseline_in(&belay_dir(), dir, m, source)
}

pub(crate) fn set_skill_baseline_in(
    cfg_dir: &Path,
    dir: &Path,
    m: &skillscan::manifest::Manifest,
    source: &str,
) -> Result<(), String> {
    let key = canonical_string(dir);
    let mut store = read_json_at(cfg_dir, SKILL_BASELINES_FILE, json!({}));
    let obj = store.as_object_mut().ok_or_else(|| "corrupt skill_baselines store".to_string())?;
    obj.insert(key, json!({
        "manifest": serde_json::to_value(m).map_err(|e| e.to_string())?,
        "content_hash": skill_content_hash(dir),
        "approved_at": rfc3339_utc(now_secs()),
        "source": source,
    }));
    write_json_at(cfg_dir, SKILL_BASELINES_FILE, &store)
}

/// The content hash recorded with `dir`'s approved baseline, or `None` if no
/// baseline / corrupt store. Fail-soft (never panics).
pub fn skill_baseline_content_hash(dir: &Path) -> Option<u64> {
    skill_baseline_content_hash_in(&belay_dir(), dir)
}

pub(crate) fn skill_baseline_content_hash_in(cfg_dir: &Path, dir: &Path) -> Option<u64> {
    let key = canonical_string(dir);
    let store = read_json_at(cfg_dir, SKILL_BASELINES_FILE, json!({}));
    store.get(&key)?.get("content_hash")?.as_u64()
}

// ── Periodic skill re-scan interval (Phase 2c) ──────────────────────────────
const SKILL_RESCAN_FILE: &str = "skill_rescan.json";

/// Seconds between periodic full skill re-scans; default 6h. `0` disables
/// just the periodic loop (the 30s change-watcher is governed separately by
/// `skill_watch_enabled`).
pub fn skill_rescan_interval_secs() -> u64 {
    skill_rescan_interval_secs_at(&belay_dir())
}

fn skill_rescan_interval_secs_at(dir: &Path) -> u64 {
    read_json_at(dir, SKILL_RESCAN_FILE, json!({ "interval_secs": 21600u64 }))["interval_secs"]
        .as_u64()
        .unwrap_or(21600)
}

pub fn set_skill_rescan_interval_secs(secs: u64) -> Result<(), String> {
    write_json(SKILL_RESCAN_FILE, &json!({ "interval_secs": secs }))
}

// ── Skill dir-watcher toggle ─────────────────────────────────────────────────

const SKILL_WATCH_FILE: &str = "skill_watch.json";

/// Default skill dir-watcher config: `{"enabled": true}` — on by default.
pub fn default_skill_watch() -> Value {
    json!({ "enabled": true })
}

/// Whether the skill dir-watcher is enabled (default true).
pub fn skill_watch_enabled() -> bool {
    skill_watch_enabled_at(&belay_dir())
}

/// Test/injectable seam behind [`skill_watch_enabled`]. See [`read_json_at`].
fn skill_watch_enabled_at(dir: &Path) -> bool {
    read_json_at(dir, SKILL_WATCH_FILE, default_skill_watch())["enabled"]
        .as_bool()
        .unwrap_or(true)
}

/// Persist the skill dir-watcher toggle (full replace — single bool field).
/// The off-switch for the Phase-2b auto-quarantine watcher: `belay
/// skill-watch off` (see `src/bin/belay.rs`) calls this. Takes effect on the
/// next daemon start — `app.rs` reads [`skill_watch_enabled`] once, at
/// watch-loop setup, not on every tick.
pub fn set_skill_watch_enabled(enabled: bool) -> Result<(), String> {
    set_skill_watch_enabled_at(&belay_dir(), enabled)
}

/// Test/injectable seam behind [`set_skill_watch_enabled`]. See [`read_json_at`].
fn set_skill_watch_enabled_at(dir: &Path, enabled: bool) -> Result<(), String> {
    write_json_at(dir, SKILL_WATCH_FILE, &json!({ "enabled": enabled }))
}

// ── MCP response-stream secret redaction toggle ─────────────────────────────

const MCP_REDACT_SECRETS_FILE: &str = "mcp_redact_secrets.json";

/// Default MCP secret-redaction config: `{"enabled": true}` — on by default.
/// A high-confidence secret (AWS key, private-key header, GitHub/Slack token)
/// in an MCP tool result is almost never something the agent needs verbatim,
/// so default-on is the right posture; the off switch exists for users who
/// run secrets-manager MCPs that legitimately return credentials.
pub fn default_mcp_redact_secrets() -> Value {
    json!({ "enabled": true })
}

/// Whether the MCP response-stream high-confidence-secret redactor is enabled
/// (default true).
pub fn mcp_redact_secrets_enabled() -> bool {
    mcp_redact_secrets_enabled_at(&belay_dir())
}

/// Test/injectable seam behind [`mcp_redact_secrets_enabled`]. See [`read_json_at`].
fn mcp_redact_secrets_enabled_at(dir: &Path) -> bool {
    read_json_at(dir, MCP_REDACT_SECRETS_FILE, default_mcp_redact_secrets())["enabled"]
        .as_bool()
        .unwrap_or(true)
}

/// Persist the MCP secret-redaction toggle (full replace — single bool field).
/// Read live by the `s2c` task on every response line (unlike
/// `skill_watch_enabled`, which is only read once at watch-loop setup), so
/// flipping this takes effect immediately without a daemon restart.
pub fn set_mcp_redact_secrets_enabled(enabled: bool) -> Result<(), String> {
    set_mcp_redact_secrets_enabled_at(&belay_dir(), enabled)
}

/// Test/injectable seam behind [`set_mcp_redact_secrets_enabled`]. See [`read_json_at`].
fn set_mcp_redact_secrets_enabled_at(dir: &Path, enabled: bool) -> Result<(), String> {
    write_json_at(dir, MCP_REDACT_SECRETS_FILE, &json!({ "enabled": enabled }))
}

// ── Trusted skills (trust-on-restore allowlist) ─────────────────────────────
//
// A restored skill (`restore_quarantine`) moves back to its `original_path`
// on disk — which makes it look "new" to `SkillWatcher`'s poller (it wasn't
// present a moment ago). Without this allowlist, the watcher's next tick
// (~30s, see `app.rs`) would re-scan it, get the same DoNotInstall verdict,
// and re-quarantine it immediately, making Restore useless. Marking a
// restored path "trusted" tells `skills::watch::handle_appeared_skill` to
// skip it entirely (no scan, no move) — see that function's top-of-body
// check.

const TRUSTED_SKILLS_FILE: &str = "trusted_skills.json";

/// Default trusted-skills store: an empty allowlist.
pub fn default_trusted_skills() -> Value {
    json!({ "paths": [] })
}

/// Canonicalize `path` best-effort for use as a stable comparison key:
/// resolves symlinks/`.`/`..` when the path exists and is reachable, and
/// falls back to the path's own string form when canonicalization fails
/// (e.g. the path doesn't exist yet, or a component is unreadable) — the
/// same raw path is always hashed to the same fallback string, so lookups
/// stay consistent even without a successful canonicalize.
fn canonical_string(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

/// Mark `path` as trusted: the skill dir-watcher will not scan or quarantine
/// it. Pure/testable seam behind [`add_trusted_skill`].
pub(crate) fn add_trusted_skill_in(dir: &Path, path: &Path) -> Result<(), String> {
    let canon = canonical_string(path);
    let current = read_json_at(dir, TRUSTED_SKILLS_FILE, default_trusted_skills());
    let mut paths: Vec<String> = current["paths"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if !paths.iter().any(|p| p == &canon) {
        paths.push(canon);
    }
    write_json_at(dir, TRUSTED_SKILLS_FILE, &json!({ "paths": paths }))
}

/// Mark `path` as trusted (see the module-level note above). Best-effort by
/// design at call sites that shouldn't fail an already-successful operation
/// (e.g. [`restore_quarantine`]) just because the trust marker couldn't be
/// persisted.
///
/// v1 note: trust is PATH-based, not content-based. If a trusted skill's
/// files are later edited in place at the same path, the watcher's
/// mtime-change detection still fires, but `handle_appeared_skill`'s
/// top-of-function trust check short-circuits to `Clean` regardless of the
/// new content — i.e. a trusted path is never re-scanned. A future
/// refinement should key trust off a content hash instead, so an in-place
/// tamper after restore is still caught.
pub fn add_trusted_skill(path: &Path) -> Result<(), String> {
    add_trusted_skill_in(&belay_dir(), path)
}

/// Whether `path` is in the trusted-skills allowlist. Pure/testable seam
/// behind [`is_trusted_skill`].
pub(crate) fn is_trusted_skill_in(dir: &Path, path: &Path) -> bool {
    let canon = canonical_string(path);
    let current = read_json_at(dir, TRUSTED_SKILLS_FILE, default_trusted_skills());
    current["paths"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(canon.as_str())))
        .unwrap_or(false)
}

/// Whether `path` is in the trusted-skills allowlist (see the module-level
/// note above `add_trusted_skill`).
pub fn is_trusted_skill(path: &Path) -> bool {
    is_trusted_skill_in(&belay_dir(), path)
}

// ── GateGuard self-approval enforcement toggle ──────────────────────────────

const GATEGUARD_ENFORCE_FILE: &str = "gateguard_enforce.json";

/// Default GateGuard self-approval enforcement config: **enabled wherever
/// `proc_ancestry` can actually resolve a parent pid** - Linux (`/proc`) and
/// Windows (Toolhelp snapshot) - and **off** elsewhere. Off is a neutral no-op
/// rather than a safety gap on those remaining targets: `parent_pid` returns
/// `None` there, so `is_ancestor_of` can never return `Some(true)` regardless of
/// this toggle - self-approval simply can't be *proven* yet on those OSes.
pub fn default_gateguard_enforce() -> Value {
    json!({ "enabled": cfg!(any(target_os = "linux", target_os = "windows")) })
}

/// Whether the self-approval guard is allowed to override a detected
/// self-approval to Deny (default: on where ancestry is supported; overridable).
pub fn gateguard_enforce_enabled() -> bool {
    gateguard_enforce_enabled_at(&belay_dir())
}

/// Test/injectable seam behind [`gateguard_enforce_enabled`]. See [`read_json_at`].
fn gateguard_enforce_enabled_at(dir: &Path) -> bool {
    read_json_at(dir, GATEGUARD_ENFORCE_FILE, default_gateguard_enforce())["enabled"]
        .as_bool()
        .unwrap_or(cfg!(any(target_os = "linux", target_os = "windows")))
}

/// Persist the GateGuard self-approval enforcement toggle (full replace —
/// single bool field).
pub fn set_gateguard_enforce_enabled(enabled: bool) -> Result<(), String> {
    set_gateguard_enforce_enabled_at(&belay_dir(), enabled)
}

/// Test/injectable seam behind [`set_gateguard_enforce_enabled`]. See [`read_json_at`].
fn set_gateguard_enforce_enabled_at(dir: &Path, enabled: bool) -> Result<(), String> {
    write_json_at(dir, GATEGUARD_ENFORCE_FILE, &json!({ "enabled": enabled }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crate-shared guard (see `crate::skills::HOME_ENV_LOCK`) for every
    /// test in this module that mutates the process-global `HOME` env var
    /// via `std::env::set_var` — not just against each other, but against
    /// HOME-sensitive tests in other modules (e.g. `ipc::tests`,
    /// `skills::watch::tests`) too.
    use crate::skills::HOME_ENV_LOCK;

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
    fn restore_quarantine_rejects_traversal() {
        assert!(restore_quarantine("../etc/passwd").is_err());
        assert!(restore_quarantine("a/b").is_err());
        assert!(restore_quarantine("").is_err());
    }

    #[test]
    fn restore_quarantine_unknown_id_is_err() {
        // No real quarantine store is expected to contain this id; a fail-soft
        // (missing/empty) index still yields an honest "unknown id" error.
        assert!(restore_quarantine("definitely-not-a-real-quarantine-id").is_err());
    }

    // ── Quarantine store: pure `*_in` seams, tempdir-only (no $HOME mutation,
    // so these are safe under cargo's parallel test execution). ─────────────

    #[test]
    fn quarantine_and_restore_dir_round_trip() {
        let qdir = tempfile::tempdir().unwrap();
        let src_root = tempfile::tempdir().unwrap();
        let skill = src_root.path().join("proj/.claude/skills/evil");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "---\nname: evil\n---\nbad").unwrap();

        let id = quarantine_skill_in(qdir.path(), &skill).expect("quarantine ok");
        assert!(!skill.exists(), "original should be moved away");

        let listed = list_quarantine_in(qdir.path());
        let entry = listed
            .iter()
            .find(|e| e["id"] == id)
            .expect("quarantined dir must be listed");
        assert_eq!(entry["kind"], json!("dir"));

        restore_quarantine_in(qdir.path(), &id).expect("restore ok");
        assert!(skill.join("SKILL.md").exists(), "restored to original path");
        assert!(
            !qdir.path().join(&id).exists(),
            "quarantine copy removed after restore"
        );
        assert!(
            !read_index(qdir.path()).contains_key(&id),
            "index entry dropped after restore"
        );
    }

    #[test]
    fn quarantine_and_restore_file_round_trip() {
        let qdir = tempfile::tempdir().unwrap();
        let src_root = tempfile::tempdir().unwrap();
        let f = src_root.path().join("standalone.sh");
        std::fs::write(&f, "echo hi").unwrap();

        let id = quarantine_skill_in(qdir.path(), &f).unwrap();
        assert!(!f.exists());
        let entries = list_quarantine_in(qdir.path());
        let entry = entries.iter().find(|e| e["id"] == id).unwrap();
        assert_eq!(entry["kind"], json!("file"));

        restore_quarantine_in(qdir.path(), &id).unwrap();
        assert!(f.exists());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "echo hi");
    }

    #[test]
    fn quarantine_skill_repeated_basename_gets_distinct_ids() {
        let qdir = tempfile::tempdir().unwrap();
        let src_root = tempfile::tempdir().unwrap();
        let a = src_root.path().join("dupe");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("f"), "x").unwrap();
        let id1 = quarantine_skill_in(qdir.path(), &a).unwrap();

        std::fs::create_dir_all(&a).unwrap(); // recreate at the same original path
        std::fs::write(a.join("f"), "y").unwrap();
        let id2 = quarantine_skill_in(qdir.path(), &a).unwrap();

        assert_ne!(id1, id2, "collision on basename must yield a distinct id");
        assert!(qdir.path().join(&id1).exists());
        assert!(qdir.path().join(&id2).exists());
    }

    #[test]
    fn quarantine_skill_missing_path_errs() {
        let qdir = tempfile::tempdir().unwrap();
        let missing = Path::new("/nonexistent/aidefender-quarantine-test-path-xyz");
        assert!(quarantine_skill_in(qdir.path(), missing).is_err());
    }

    #[test]
    fn restore_quarantine_in_unknown_id_errs() {
        let qdir = tempfile::tempdir().unwrap();
        assert!(restore_quarantine_in(qdir.path(), "nope").is_err());
    }

    #[test]
    fn delete_quarantine_in_dir_removes_index_entry() {
        let qdir = tempfile::tempdir().unwrap();
        let src_root = tempfile::tempdir().unwrap();
        let d = src_root.path().join("baddir");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("f"), "x").unwrap();

        let id = quarantine_skill_in(qdir.path(), &d).unwrap();
        delete_quarantine_in(qdir.path(), &id).unwrap();

        assert!(!qdir.path().join(&id).exists());
        assert!(!read_index(qdir.path()).contains_key(&id));
    }

    #[test]
    fn skill_watch_default_shape() {
        let d = default_skill_watch();
        assert_eq!(d["enabled"], json!(true));
    }

    #[test]
    fn skill_watch_enabled_defaults_true() {
        let dir = tempfile::tempdir().unwrap();
        assert!(skill_watch_enabled_at(dir.path()));
    }

    #[test]
    fn skill_watch_enabled_reads_persisted_false() {
        let dir = tempfile::tempdir().unwrap();
        write_json_at(dir.path(), SKILL_WATCH_FILE, &json!({ "enabled": false })).unwrap();
        assert!(!skill_watch_enabled_at(dir.path()));
    }

    // ── Fix 3: skill-watch off-switch round-trip ─────────────────────────────

    #[test]
    fn skill_watch_set_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(skill_watch_enabled_at(dir.path()), "defaults true");
        set_skill_watch_enabled_at(dir.path(), false).expect("write must succeed");
        assert!(!skill_watch_enabled_at(dir.path()));
        set_skill_watch_enabled_at(dir.path(), true).expect("write must succeed");
        assert!(skill_watch_enabled_at(dir.path()));
    }

    // ── MCP secret-redaction toggle ──────────────────────────────────────────

    #[test]
    fn mcp_redact_secrets_default_shape() {
        let d = default_mcp_redact_secrets();
        assert_eq!(d["enabled"], json!(true));
    }

    #[test]
    fn mcp_redact_secrets_enabled_defaults_true() {
        let dir = tempfile::tempdir().unwrap();
        assert!(mcp_redact_secrets_enabled_at(dir.path()));
    }

    #[test]
    fn mcp_redact_secrets_enabled_reads_persisted_false() {
        let dir = tempfile::tempdir().unwrap();
        write_json_at(dir.path(), MCP_REDACT_SECRETS_FILE, &json!({ "enabled": false }))
            .unwrap();
        assert!(!mcp_redact_secrets_enabled_at(dir.path()));
    }

    #[test]
    fn mcp_redact_secrets_set_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(mcp_redact_secrets_enabled_at(dir.path()), "defaults true");
        set_mcp_redact_secrets_enabled_at(dir.path(), false).expect("write must succeed");
        assert!(!mcp_redact_secrets_enabled_at(dir.path()));
        set_mcp_redact_secrets_enabled_at(dir.path(), true).expect("write must succeed");
        assert!(mcp_redact_secrets_enabled_at(dir.path()));
    }

    // ── Fix 4: trusted-skills (trust-on-restore) allowlist ───────────────────

    #[test]
    fn trusted_skill_false_by_default_true_after_add() {
        let dir = tempfile::tempdir().unwrap();
        let skill = dir.path().join("some/skill/path");
        std::fs::create_dir_all(&skill).unwrap();

        assert!(
            !is_trusted_skill_in(dir.path(), &skill),
            "not trusted by default"
        );
        add_trusted_skill_in(dir.path(), &skill).expect("add must succeed");
        assert!(
            is_trusted_skill_in(dir.path(), &skill),
            "trusted after add_trusted_skill"
        );
    }

    #[test]
    fn trusted_skill_add_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let skill = dir.path().join("dupe/skill");
        std::fs::create_dir_all(&skill).unwrap();
        add_trusted_skill_in(dir.path(), &skill).unwrap();
        add_trusted_skill_in(dir.path(), &skill).unwrap();
        let stored = read_json_at(dir.path(), TRUSTED_SKILLS_FILE, default_trusted_skills());
        let paths = stored["paths"].as_array().unwrap();
        assert_eq!(
            paths.len(),
            1,
            "adding the same path twice must not duplicate the entry"
        );
    }

    #[test]
    fn restore_quarantine_marks_original_path_trusted() {
        // Exercises the real belay_dir()-backed restore_quarantine() (not the
        // qdir-injected _in seam) since trust-on-restore intentionally only
        // fires from the public wrapper (see its doc comment). Points HOME at
        // a fresh temp dir first, mirroring the same pattern already used by
        // `skills::watch`'s tests, so this never touches the real $HOME/.belay.
        let _home_guard = HOME_ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        let src_root = tempfile::tempdir().unwrap();
        let skill = src_root.path().join("proj/.claude/skills/restored");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "---\nname: r\n---\nbody").unwrap();

        let id = quarantine_skill(&skill).expect("quarantine ok");
        assert!(!is_trusted_skill(&skill), "not trusted before restore");
        restore_quarantine(&id).expect("restore ok");
        assert!(skill.join("SKILL.md").exists(), "restored to original path");
        assert!(is_trusted_skill(&skill), "trusted after restore_quarantine");
    }

    #[test]
    fn restore_quarantine_sets_a_baseline_for_the_restored_skill() {
        let _home_guard = HOME_ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        // A benign skill dir under a skill root.
        let dir = tmp.path().join("proj/.claude/skills/hello");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"),
            "---\nname: hello\ndescription: greets\nallowed-tools: [Read]\n---\n# Hello").unwrap();
        // Quarantine then restore it.
        let id = quarantine_skill(&dir).expect("quarantine");
        restore_quarantine(&id).expect("restore");
        assert!(dir.exists(), "restored back to disk");
        assert!(skill_baseline(&dir).is_some(), "restore records an approved baseline");
    }

    // ── Skill baselines (Phase 2d) + rescan interval (Phase 2c) ──────────────

    #[test]
    fn skill_baseline_roundtrips_via_in_seam() {
        let dir = tempfile::tempdir().unwrap();
        let skill = std::path::Path::new("/s/alpha");
        let m = skillscan::manifest::Manifest {
            name: Some("alpha".into()),
            permissions: vec!["read".into()],
            ..Default::default()
        };
        set_skill_baseline_in(dir.path(), skill, &m, "auto_clean_scan").unwrap();
        assert_eq!(skill_baseline_in(dir.path(), skill), Some(m));
    }

    #[test]
    fn skill_baseline_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(skill_baseline_in(dir.path(), std::path::Path::new("/s/none")), None);
    }

    #[test]
    fn skill_baseline_corrupt_store_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("skill_baselines.json"), b"not json {").unwrap();
        assert_eq!(skill_baseline_in(dir.path(), std::path::Path::new("/s/x")), None);
    }

    #[test]
    fn skill_baseline_records_and_reads_content_hash() {
        let dir = tempfile::tempdir().unwrap();       // cfg dir
        let skill = tempfile::tempdir().unwrap();      // a real skill dir with a file
        std::fs::write(skill.path().join("SKILL.md"), "---\nname: h\n---\n# body v1").unwrap();
        let m = skillscan::manifest::Manifest { name: Some("h".into()), ..Default::default() };
        set_skill_baseline_in(dir.path(), skill.path(), &m, "auto_clean_scan").unwrap();
        let stored = skill_baseline_content_hash_in(dir.path(), skill.path());
        assert_eq!(stored, Some(skill_content_hash(skill.path())), "stored hash == recomputed");
        // Mutating the body changes the hash (proves body sensitivity).
        std::fs::write(skill.path().join("SKILL.md"), "---\nname: h\n---\n# body v2").unwrap();
        assert_ne!(stored, Some(skill_content_hash(skill.path())), "body edit changes the hash");
    }

    #[test]
    fn skill_rescan_interval_default_and_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(skill_rescan_interval_secs_at(dir.path()), 21600);
        write_json_at(dir.path(), "skill_rescan.json", &json!({ "interval_secs": 120u64 })).unwrap();
        assert_eq!(skill_rescan_interval_secs_at(dir.path()), 120);
    }

    // ── Fix 2: quarantine store durability ────────────────────────────────────

    /// Fix 2a+2c together: after `index.json` is corrupted or deleted
    /// entirely (simulating a crash mid-write, or manual tampering),
    /// `list_quarantine`'s fallback scan must still surface a quarantined
    /// DIRECTORY (not just files — a quarantined skill is always a dir).
    #[test]
    fn list_quarantine_surfaces_orphaned_dir_after_index_loss() {
        let qdir = tempfile::tempdir().unwrap();
        let src_root = tempfile::tempdir().unwrap();
        let skill = src_root.path().join("proj/.claude/skills/orphan");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "---\nname: orphan\n---\nbad").unwrap();

        let id = quarantine_skill_in(qdir.path(), &skill).expect("quarantine ok");
        assert!(list_quarantine_in(qdir.path()).iter().any(|e| e["id"] == id));

        // Corrupt the index (garbage bytes) — read_index() fails soft to empty.
        std::fs::write(qdir.path().join(QUARANTINE_INDEX_FILE), b"{not json").unwrap();
        assert!(read_index(qdir.path()).is_empty());
        let listed = list_quarantine_in(qdir.path());
        assert!(
            listed.iter().any(|e| e["id"] == id && e["kind"] == json!("dir")),
            "orphaned dir must be surfaced (and reported as a dir) after index corruption"
        );

        // Delete the index entirely — same fail-soft guarantee.
        std::fs::remove_file(qdir.path().join(QUARANTINE_INDEX_FILE)).unwrap();
        let listed = list_quarantine_in(qdir.path());
        assert!(
            listed.iter().any(|e| e["id"] == id),
            "orphaned dir must still be surfaced after index deletion"
        );
    }

    // ── GateGuard self-approval enforcement toggle ────────────────────────────

    #[test]
    fn gateguard_enforce_default_shape() {
        let d = default_gateguard_enforce();
        assert_eq!(
            d["enabled"],
            json!(cfg!(any(target_os = "linux", target_os = "windows")))
        );
    }

    #[test]
    fn locale_defaults_to_en_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(locale_at(dir.path()), "en", "default must be en, never empty");
        set_locale_at(dir.path(), "zh-Hans").expect("supported locale must persist");
        assert_eq!(locale_at(dir.path()), "zh-Hans");
    }

    #[test]
    fn unsupported_locale_is_refused_on_write() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            set_locale_at(dir.path(), "../../etc/passwd").is_err(),
            "a locale names a compiled-in catalogue - never accept an arbitrary string"
        );
        assert!(set_locale_at(dir.path(), "fr").is_err(), "fr is not shipped");
        assert_eq!(locale_at(dir.path()), "en", "nothing was written");
    }

    #[test]
    fn hand_edited_unknown_locale_reads_back_as_en() {
        // set_locale refuses these, but the file is plain JSON on disk and a
        // human (or another process) can put anything in it.
        let dir = tempfile::tempdir().unwrap();
        write_json_at(dir.path(), LOCALE_FILE, &json!({ "locale": "klingon" })).unwrap();
        assert_eq!(locale_at(dir.path()), "en", "unknown locale must fall back, not echo");
    }

    // Renamed on the Windows merge: ancestry-based enforcement now defaults ON
    // for Windows too (not just Linux), so the test name reflects the invariant
    // (cfg!(any(linux, windows))) rather than "linux only".
    #[test]
    fn gateguard_enforce_defaults_on_where_ancestry_is_supported() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            gateguard_enforce_enabled_at(dir.path()),
            cfg!(any(target_os = "linux", target_os = "windows"))
        );
    }

    #[test]
    fn gateguard_enforce_enabled_reads_persisted_value() {
        let dir = tempfile::tempdir().unwrap();
        write_json_at(dir.path(), GATEGUARD_ENFORCE_FILE, &json!({ "enabled": true })).unwrap();
        assert!(gateguard_enforce_enabled_at(dir.path()));
        write_json_at(dir.path(), GATEGUARD_ENFORCE_FILE, &json!({ "enabled": false })).unwrap();
        assert!(!gateguard_enforce_enabled_at(dir.path()));
    }

    #[test]
    fn gateguard_enforce_set_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            gateguard_enforce_enabled_at(dir.path()),
            cfg!(any(target_os = "linux", target_os = "windows")),
            "default before any write"
        );
        set_gateguard_enforce_enabled_at(dir.path(), true).expect("write must succeed");
        assert!(gateguard_enforce_enabled_at(dir.path()));
        set_gateguard_enforce_enabled_at(dir.path(), false).expect("write must succeed");
        assert!(!gateguard_enforce_enabled_at(dir.path()));
    }
}
