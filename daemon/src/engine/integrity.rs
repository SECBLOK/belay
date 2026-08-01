//! Startup integrity check: detect when the on-disk `rules/catalog.yaml` has
//! drifted from the copy compiled into this binary. Non-privileged (read+hash
//! only). On a shipped single-binary install there is no on-disk catalog, so
//! the check is a logged no-op; in a source/dev deployment it catches a rules
//! source that was weakened since this binary was built.
use sha2::{Digest, Sha256};
use std::path::Path;

/// sha256 of `rules/catalog.yaml` at the time this binary was built (build.rs).
const EXPECTED: &str = env!("BELAY_CATALOG_SHA256");

#[derive(Debug, PartialEq, Eq)]
pub enum IntegrityStatus {
    Ok,
    Drift { expected: String, actual: String },
    NoOnDiskCopy,
}

pub fn verify_catalog_drift(on_disk: Option<&Path>) -> IntegrityStatus {
    let Some(path) = on_disk else { return IntegrityStatus::NoOnDiskCopy };
    let Ok(bytes) = std::fs::read(path) else { return IntegrityStatus::NoOnDiskCopy };
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual == EXPECTED {
        IntegrityStatus::Ok
    } else {
        IntegrityStatus::Drift { expected: EXPECTED.to_string(), actual }
    }
}

/// Locates an on-disk catalog to monitor, or `None` when there is nothing to
/// watch (the normal case for a shipped single-binary install).
///
/// Resolution order:
///   1. `$BELAY_CATALOG` — explicit, and the only reliable option for a daemon
///      started by a service manager.
///   2. `rules/catalog.yaml` relative to the current working directory.
///   3. `../rules/catalog.yaml` and `../../rules/catalog.yaml` relative to the
///      binary, which covers running straight out of a build tree.
///
/// The cwd probe alone was NOT enough, and shipping it alone made this check
/// silently useless where it mattered most. A systemd/launchd service inherits
/// cwd `/`, so step 2 resolved to `/rules/catalog.yaml`, found nothing, and
/// the periodic check returned immediately — for a source deployment whose
/// rules file was sitting right there in the repo. It looked active and
/// monitored nothing. Hence the explicit override, the exe-relative probes,
/// and the startup log line in [`describe_monitoring`].
pub fn default_on_disk_catalog() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("BELAY_CATALOG") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let cwd = std::path::Path::new("rules/catalog.yaml");
    if cwd.is_file() {
        return Some(cwd.to_path_buf());
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    for up in ["../rules/catalog.yaml", "../../rules/catalog.yaml"] {
        let p = dir.join(up);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// One-line, honest description of what integrity monitoring is actually doing,
/// for the startup log. A security control that is inert must say so out loud;
/// silence reads as "fine".
pub fn describe_monitoring() -> String {
    match default_on_disk_catalog() {
        Some(p) => format!("rules-integrity monitoring ACTIVE on {}", p.display()),
        None => "rules-integrity monitoring INACTIVE: no on-disk rules file found \
                 (normal for a packaged install; for a source deployment set \
                 BELAY_CATALOG=/path/to/rules/catalog.yaml)"
            .to_string(),
    }
}

/// One periodic integrity pass: re-verify the on-disk rules against the hash
/// compiled into this binary, and record an audit row the first time a given
/// drifted content is seen.
///
/// # Why this exists
///
/// Belay's protection of its own rules is text matching over the tool call.
/// That structurally cannot see a write whose target is *computed at runtime*:
///
/// ```text
/// python3 scripts/some-script.py     # inside: parent.parent / "rules" / "catalog.yaml"
/// ```
///
/// Nothing in that command names a protected file, and the script's own source
/// need not contain the path contiguously either, so neither the command match
/// nor script-body extraction is reliable. It is a documented open gap (see
/// `docs/research/2026-07-26-self-tamper-bash-gap.md` and the deliberately
/// failing-open test `indirect_write_via_a_path_joining_script_is_a_known_uncaught_gap`).
///
/// Hashing does not care how the write happened. Any modification, by any
/// amount of indirection, changes the digest.
///
/// # What this is, and is honestly not
///
/// This is **detection, not prevention**, and after the fact: the write has
/// already landed when the next pass notices. It is deliberately alert-only —
/// it does not change any verdict. Two reasons. The running daemon holds its
/// rules in memory and is *unaffected* by an on-disk edit until something
/// rebuilds or reloads, so there is no live bypass to stop. And failing closed
/// on drift would let anyone who can touch a file in a source checkout disable
/// the gate entirely, converting a tamper attempt into a denial of service.
/// Whether a drifted catalog should additionally refuse to *serve* is an
/// operator policy question, deliberately left open rather than assumed here.
///
/// Deduplicated on the drifted digest, so a rules file left drifted alerts once
/// rather than every pass, while a *new* modification alerts again.
pub fn run_periodic_integrity_check() {
    let Some(path) = default_on_disk_catalog() else {
        return;
    };
    let IntegrityStatus::Drift { expected, actual } = verify_catalog_drift(Some(&path)) else {
        return;
    };

    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    // A poisoned mutex must not silence an integrity alert: recover the guard
    // rather than unwrap, and alert on the paranoid side if it cannot be read.
    let fresh = match seen.lock() {
        Ok(mut g) => g.insert(actual.clone()),
        Err(p) => p.into_inner().insert(actual.clone()),
    };
    if !fresh {
        return;
    }

    eprintln!(
        "[belayd] integrity ALERT: {} drifted from the compiled-in rules \
         (expected {expected}, found {actual}); the running binary is UNAFFECTED, but the \
         rules source may have been tampered before a rebuild.",
        path.display()
    );
    crate::skills::watch::write_integrity_audit_row(&path, &expected, &actual);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// An explicit `BELAY_CATALOG` is honoured, which is the only resolution
    /// step that works for a service-managed daemon (cwd `/`).
    #[test]
    fn an_explicit_catalog_override_is_resolved() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "rules: []\n").unwrap();
        // Serialised against other env-mutating tests by construction: this is
        // the only test that touches BELAY_CATALOG.
        unsafe { std::env::set_var("BELAY_CATALOG", f.path()) };
        let got = default_on_disk_catalog();
        unsafe { std::env::remove_var("BELAY_CATALOG") };
        assert_eq!(got.as_deref(), Some(f.path()));
    }

    /// A control that is doing nothing must say so, rather than staying quiet
    /// and reading as healthy.
    #[test]
    fn inactive_monitoring_is_described_as_inactive() {
        let d = describe_monitoring();
        assert!(
            d.starts_with("rules-integrity monitoring ACTIVE")
                || d.contains("INACTIVE"),
            "unexpected description: {d}"
        );
        if d.contains("INACTIVE") {
            assert!(d.contains("BELAY_CATALOG"), "must tell the operator how to fix it");
        }
    }

    #[test]
    fn no_on_disk_copy_is_ok_noop() {
        assert!(matches!(verify_catalog_drift(None), IntegrityStatus::NoOnDiskCopy));
        let missing = std::path::Path::new("/nonexistent/rules/catalog.yaml");
        assert!(matches!(verify_catalog_drift(Some(missing)), IntegrityStatus::NoOnDiskCopy));
    }

    #[test]
    fn matching_on_disk_copy_is_ok() {
        // The repo's own catalog.yaml is exactly what this binary was built from.
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../rules/catalog.yaml");
        assert!(matches!(
            verify_catalog_drift(Some(std::path::Path::new(p))),
            IntegrityStatus::Ok
        ));
    }

    /// The point of the whole mechanism: a write that names no protected path
    /// anywhere in the tool call is still seen, because the digest changes
    /// regardless of how the bytes got there.
    ///
    /// This reproduces the shape of the documented text-matching gap — a
    /// script that assembles the path at runtime out of fragments, so neither
    /// the command nor the script source contains it contiguously — and shows
    /// that hashing is indifferent to it.
    #[test]
    fn a_write_that_never_names_the_path_is_still_detected() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), include_str!("../../../rules/catalog.yaml")).unwrap();
        assert!(
            matches!(verify_catalog_drift(Some(f.path())), IntegrityStatus::Ok),
            "an identical copy must verify clean, or the test below proves nothing"
        );

        // The "script" — path assembled from fragments, exactly as a real
        // patch script does with `parent.parent / "rules" / "catalog.yaml"`.
        // Note that no protected path appears contiguously anywhere here.
        let dir = f.path().parent().unwrap();
        let name = f.path().file_name().unwrap();
        let computed = dir.join(name);
        std::fs::write(&computed, "rules: []  # written via a computed path\n").unwrap();

        match verify_catalog_drift(Some(f.path())) {
            IntegrityStatus::Drift { expected, actual } => assert_ne!(expected, actual),
            other => panic!("a runtime-computed write must still be detected, got {other:?}"),
        }
    }

    #[test]
    fn drifted_on_disk_copy_is_detected() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "rules: []  # tampered").unwrap();
        match verify_catalog_drift(Some(f.path())) {
            IntegrityStatus::Drift { expected, actual } => assert_ne!(expected, actual),
            other => panic!("expected Drift, got {other:?}"),
        }
    }
}
