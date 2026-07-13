//! Platform-agnostic path resolution for Belay runtime data.
//!
//! On Windows: `%PROGRAMDATA%\Belay`  (e.g. `C:\ProgramData\Belay`)
//! On Unix:    `~/.belay`
//!
//! The join-shape is factored into [`layout`] so unit tests can verify the
//! sub-path joins on a fixed base without touching environment variables or
//! the filesystem.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Testable layout helper
// ---------------------------------------------------------------------------

/// Sub-paths rooted at a Belay data directory.
///
/// Produced by [`layout`]; exposed `pub(crate)` so the unit test can call it
/// on a fixed base path without relying on environment variables.
pub(crate) struct Layout {
    pub config: PathBuf,
    pub rules: PathBuf,
    pub logs: PathBuf,
    pub audit: PathBuf,
}

/// Build all Belay sub-paths from a given base directory.
///
/// This is the single authoritative place where join names are written.
/// Both `#[cfg(windows)]` and `#[cfg(unix)]` arms of [`data_dir`] feed into
/// this helper via the public accessors, ensuring the tested logic is the
/// real production logic.
pub(crate) fn layout(base: &Path) -> Layout {
    let logs = base.join("logs");
    Layout {
        config: base.join("config"),
        rules: base.join("rules"),
        audit: base.join("audit.ndjson"),
        logs,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Root data directory for Belay.
///
/// * **Windows** – `%PROGRAMDATA%\Belay`  (falls back to `C:\ProgramData\Belay`)
/// * **Unix**    – `$HOME/.belay`          (falls back to `./.belay`)
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()),
        )
        .join("Belay")
    }
    #[cfg(unix)]
    {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".belay")
    }
}

pub fn config_dir() -> PathBuf { layout(&data_dir()).config }
pub fn rules_dir()  -> PathBuf { layout(&data_dir()).rules }
pub fn logs_dir()   -> PathBuf { layout(&data_dir()).logs }
pub fn audit_path() -> PathBuf { layout(&data_dir()).audit }

/// The daemon control-socket ADDRESS. Honors `BELAY_SOCK` if set (same
/// override semantics as the hook and mcp-proxy clients).
///
/// * **Unix**    – `<data_dir>/belayd.sock`
///   (byte-identical to the original `hook_socket_path()` / `GateConfig::socket_path()`)
/// * **Windows** – `%PROGRAMDATA%\Belay\belayd.sock`
///   The `belay-transport` crate maps the path's basename to
///   `\\.\pipe\<basename>`, making the socket machine-wide and accessible
///   to a LocalSystem service that has no `$HOME`.
pub fn socket_path() -> String {
    socket_path_from(std::env::var("BELAY_SOCK").ok())
}

/// Pure resolver behind [`socket_path`]: a `BELAY_SOCK` override wins,
/// otherwise `<data_dir>/belayd.sock`. Split out so tests exercise both
/// branches WITHOUT mutating the process-global `BELAY_SOCK` env var —
/// `std::env::set_var` is process-wide and races other parallel tests.
pub(crate) fn socket_path_from(sock_override: Option<String>) -> String {
    if let Some(s) = sock_override {
        return s;
    }
    data_dir()
        .join("belayd.sock")
        .to_string_lossy()
        .into_owned()
}

/// Outcome of attempting to migrate the pre-rename data directory.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// The new directory already existed; nothing was done.
    AlreadyMigrated,
    /// The old directory didn't exist; nothing to migrate.
    NothingToMigrate,
    /// The old directory was renamed into place as the new one.
    Migrated,
}

/// One-time migration of the pre-rename `~/.aidefender` data directory to
/// `~/.belay`. Takes `home` explicitly rather than reading `$HOME` itself,
/// since callers running under `sudo` must resolve the real invoking user's
/// home directory first (plain `$HOME` under sudo resolves to root's home).
/// A same-filesystem `rename()` is atomic — safe even for a large audit log —
/// so no recursive copy-then-delete fallback is attempted; a failure surfaces
/// as a clear `io::Error` rather than risking a silent partial copy.
pub fn migrate_legacy_data_dir(home: &Path) -> std::io::Result<MigrationOutcome> {
    let new_dir = home.join(".belay");
    if new_dir.exists() {
        return Ok(MigrationOutcome::AlreadyMigrated);
    }
    let old_dir = home.join(".aidefender");
    if !old_dir.exists() {
        return Ok(MigrationOutcome::NothingToMigrate);
    }
    std::fs::rename(&old_dir, &new_dir)?;
    Ok(MigrationOutcome::Migrated)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The BELAY_SOCK override is returned verbatim. Tests the pure
    /// resolver so it never mutates the process-global env var (which would
    /// race the default-path test running in parallel).
    #[test]
    fn socket_path_honors_env_override() {
        assert_eq!(
            socket_path_from(Some("/tmp/test-override.sock".to_string())),
            "/tmp/test-override.sock"
        );
    }

    /// Without an override, the socket path ends with the expected filename.
    #[test]
    fn socket_path_default_ends_with_sock_filename() {
        let result = socket_path_from(None);
        assert!(
            result.ends_with("belayd.sock"),
            "expected path to end with 'belayd.sock', got: {result}"
        );
    }

    /// Verify the join-shape on a fixed base so this test is identical on
    /// Linux and Windows — no env vars read, no filesystem access.
    #[test]
    fn layout_join_shape() {
        // Use a fixed synthetic base; the actual path need not exist.
        let base = Path::new("/aidefender-test-base");
        let l = layout(base);

        assert_eq!(l.config, base.join("config"),  "config sub-path mismatch");
        assert_eq!(l.rules,  base.join("rules"),   "rules sub-path mismatch");
        assert_eq!(l.logs,   base.join("logs"),    "logs sub-path mismatch");
        assert_eq!(
            l.audit,
            base.join("audit.ndjson"),
            "audit sub-path mismatch"
        );
    }

    /// If `~/.belay` already exists, migration is a no-op and the (possibly
    /// still-present) old directory is left untouched.
    #[test]
    fn migrate_legacy_data_dir_already_migrated() {
        let home = tempfile::tempdir().unwrap();
        let new_dir = home.path().join(".belay");
        let old_dir = home.path().join(".aidefender");
        std::fs::create_dir(&new_dir).unwrap();
        std::fs::create_dir(&old_dir).unwrap();

        let outcome = migrate_legacy_data_dir(home.path()).unwrap();

        assert_eq!(outcome, MigrationOutcome::AlreadyMigrated);
        assert!(old_dir.exists(), "old dir should be left untouched");
        assert!(new_dir.exists());
    }

    /// If neither directory exists, there is nothing to migrate.
    #[test]
    fn migrate_legacy_data_dir_nothing_to_migrate() {
        let home = tempfile::tempdir().unwrap();

        let outcome = migrate_legacy_data_dir(home.path()).unwrap();

        assert_eq!(outcome, MigrationOutcome::NothingToMigrate);
        assert!(!home.path().join(".belay").exists());
        assert!(!home.path().join(".aidefender").exists());
    }

    /// If only the old directory exists, it is renamed in place — the old
    /// path disappears, the new path appears, and a marker file inside
    /// proves it's the same directory (not a freshly created empty one).
    #[test]
    fn migrate_legacy_data_dir_migrates() {
        let home = tempfile::tempdir().unwrap();
        let old_dir = home.path().join(".aidefender");
        std::fs::create_dir(&old_dir).unwrap();
        std::fs::write(old_dir.join("marker.txt"), b"proof").unwrap();

        let outcome = migrate_legacy_data_dir(home.path()).unwrap();

        assert_eq!(outcome, MigrationOutcome::Migrated);
        assert!(!old_dir.exists(), "old dir should no longer exist");
        let new_dir = home.path().join(".belay");
        assert!(new_dir.exists(), "new dir should now exist");
        assert_eq!(
            std::fs::read(new_dir.join("marker.txt")).unwrap(),
            b"proof",
            "marker file should have moved with the directory"
        );
    }
}
