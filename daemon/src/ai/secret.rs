//! Local, owner-only (0600) storage for the BYOK cloud API key.
//!
//! Complements [`crate::ai::config::AiConfig`] (`~/.belay/ai.json`),
//! which deliberately never stores a secret (see that module's doc comment
//! on `save`). The key lives in its own file, `~/.belay/ai_key`,
//! written atomically via a sibling temp file that is created 0600 FROM
//! THE START on unix (never written at looser permissions first), then
//! renamed over the destination.
//!
//! This module is write-only from the IPC surface's point of view: nothing
//! in `crate::ipc` ever serializes the key itself into a response or a log
//! line, only a `key_present: bool` derived from whether [`read_ai_key`]
//! returns `Some`.

use std::path::{Path, PathBuf};

/// Path to the on-disk BYOK cloud API key file: `~/.belay/ai_key`.
pub fn ai_key_path() -> PathBuf {
    crate::paths::data_dir().join("ai_key")
}

/// Persist `key` to `path`, owner-only (0600 on unix), atomically: create a
/// sibling temp file in the same directory already at mode 0600 (on unix,
/// via `OpenOptions::mode`, so the cleartext key is never on disk at looser
/// permissions even transiently), write the key, then rename over `path`.
///
/// An empty or all-whitespace `key` is treated as "clear": any existing file
/// at `path` is removed, and a missing file is left alone (both are `Ok`).
/// This is how the IPC "clear key" affordance works — the key is never
/// written as an empty string.
pub fn write_ai_key(path: &Path, key: &str) -> Result<(), String> {
    if key.trim().is_empty() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    // Create the temp file at 0600 FROM THE START on unix (rather than
    // `write` then `set_permissions` after the fact): the naive
    // write-then-chmod sequence puts the cleartext key on disk at the
    // process umask default (commonly 0644) for the window between the
    // two calls, readable by any co-resident local user who can traverse
    // into this directory. `OpenOptions::mode(0o600)` makes the `open(2)`
    // syscall itself create the file with owner-only permissions, so the
    // secret is never at looser perms at any point.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(key.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().ok();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, key.as_bytes()).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Read the key from `path`, trimming trailing whitespace/newline.
///
/// Returns `None` if the file is missing, unreadable, not valid UTF-8, or
/// empty after trimming — never panics.
pub fn read_ai_key(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique path under the system temp dir, cleaned up on drop. NEVER
    /// the real `$HOME` — hermetic by construction, like
    /// `ai::config::tests::TempJsonFile`.
    struct TempKeyFile {
        path: PathBuf,
    }

    impl TempKeyFile {
        fn new(suffix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "belayd-ai-key-test-{}-{}-{}",
                std::process::id(),
                suffix,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            TempKeyFile { path }
        }
    }

    impl Drop for TempKeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let tmp = TempKeyFile::new("roundtrip");
        write_ai_key(&tmp.path, "sk-test-12345").expect("write must succeed");
        assert_eq!(read_ai_key(&tmp.path), Some("sk-test-12345".to_string()));
    }

    #[test]
    fn read_trims_trailing_whitespace_and_newline() {
        let tmp = TempKeyFile::new("trim");
        // Simulate a key written with a trailing newline (pasted with Enter).
        std::fs::write(&tmp.path, b"sk-test-67890\n").unwrap();
        assert_eq!(read_ai_key(&tmp.path), Some("sk-test-67890".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn write_creates_file_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempKeyFile::new("perms");
        write_ai_key(&tmp.path, "sk-test-perm").expect("write must succeed");
        let mode = std::fs::metadata(&tmp.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ai_key mode was {mode:o}, expected 600");
    }

    #[test]
    fn write_empty_key_clears_existing_file() {
        let tmp = TempKeyFile::new("clear");
        write_ai_key(&tmp.path, "sk-to-be-cleared").expect("write must succeed");
        assert!(tmp.path.exists());
        write_ai_key(&tmp.path, "").expect("clearing must succeed");
        assert!(!tmp.path.exists());
    }

    #[test]
    fn write_empty_key_is_noop_when_file_absent() {
        let tmp = TempKeyFile::new("noop-clear");
        // Deliberately never write a file first.
        write_ai_key(&tmp.path, "").expect("clearing an absent file must be Ok");
        assert!(!tmp.path.exists());
    }

    #[test]
    fn write_blank_whitespace_key_also_clears() {
        let tmp = TempKeyFile::new("blank");
        write_ai_key(&tmp.path, "sk-something").unwrap();
        write_ai_key(&tmp.path, "   \n\t  ").expect("blank key must clear");
        assert!(!tmp.path.exists());
    }

    #[test]
    fn read_missing_file_is_none() {
        let tmp = TempKeyFile::new("missing");
        assert_eq!(read_ai_key(&tmp.path), None);
    }

    #[test]
    fn read_empty_file_is_none() {
        let tmp = TempKeyFile::new("empty");
        std::fs::write(&tmp.path, b"").unwrap();
        assert_eq!(read_ai_key(&tmp.path), None);
    }

    #[test]
    fn write_creates_missing_parent_dir() {
        let base = std::env::temp_dir().join(format!(
            "belayd-ai-key-test-parent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let path = base.join("nested").join("ai_key");
        write_ai_key(&path, "sk-parent-test").expect("write must create missing parent dirs");
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
