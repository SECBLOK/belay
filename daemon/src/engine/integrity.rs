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

/// Best-effort guess at an on-disk catalog path for source/dev runs: the
/// `rules/catalog.yaml` under the current working directory, if present.
/// Returns None for shipped installs (no such file).
pub fn default_on_disk_catalog() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new("rules/catalog.yaml");
    p.exists().then(|| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
