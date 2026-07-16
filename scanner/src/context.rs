//! Build scan context: file cache, manifest, executable script detection.
//!
//! Faithful port of the deleted Python predecessor's `scan/context.py`.

use std::collections::BTreeMap;
use std::path::Path;

use walkdir::WalkDir;

// `pub(crate)` (not private): reused by `analyzers::malware::scan_malware_pass`,
// which walks the scan root directly (not via `FileCache`) and needs the same
// skip-dir pruning to avoid descending into `.git`/`node_modules`/etc.
pub(crate) const SKIP_DIRS: &[&str] = &[
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    // Rust build-artifact directory (Cargo convention). Same threat model as
    // `node_modules` above: a build-tool-owned output directory, not
    // hand-written source, so pruning it is consistent with the existing
    // list rather than a new exception. Also closes a real perf/noise gap in
    // `scan_malware_pass`, which used to walk the entire `target/` tree
    // (potentially gigabytes of object files) on every scan of a Rust repo.
    "target",
];

const BINARY_EXTS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".whl", ".egg", ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
];

const MAX_FILE_BYTES: u64 = 1024 * 1024; // 1 MB

const SCRIPT_EXTS: &[&str] = &[".sh", ".bash", ".zsh", ".py", ".rb", ".pl"];

const WINDOWS_EXEC_EXTS: &[&str] = &[".exe", ".bat", ".cmd", ".ps1"];

/// Context built from a scanned directory.
pub struct Context {
    /// Map of relative path string → file text content.
    pub file_cache: BTreeMap<String, String>,
    /// Parsed YAML frontmatter from `skill.md`/`SKILL.md`, or `{}`.
    pub manifest: serde_json::Value,
    /// True if any file in a script extension has exec bit or starts with `#!`.
    pub has_executable_scripts: bool,
}

/// Walk `dir` and build a `Context`.
///
/// Mirrors `context.py::build_context` exactly.
pub fn build_context(dir: &Path) -> Context {
    let mut file_cache: BTreeMap<String, String> = BTreeMap::new();
    let mut manifest = serde_json::Value::Object(serde_json::Map::new());
    let mut has_executable_scripts = false;
    let mut manifest_found = false;

    let walker = WalkDir::new(dir).into_iter().filter_entry(|e| {
        // Prune skip directories
        if e.file_type().is_dir() {
            let name = e.file_name().to_string_lossy();
            return !SKIP_DIRS.contains(&&*name);
        }
        true
    });

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path: &Path = entry.path();

        // Skip binary extensions
        let ext = path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if BINARY_EXTS.contains(&&*ext) {
            continue;
        }

        // Skip large files
        let size = match path.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if size > MAX_FILE_BYTES {
            continue;
        }

        // Read text (lossy UTF-8, mirrors Python's errors="replace")
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();

        // Compute relative path key (forward slashes, mirrors Python str(fpath.relative_to(root)))
        let rel = match path.strip_prefix(dir) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };

        file_cache.insert(rel.clone(), text.clone());

        // Detect executable scripts
        if !has_executable_scripts && is_executable_script(path, &text, &ext) {
            has_executable_scripts = true;
        }

        // Parse manifest from skill.md / SKILL.md (first found wins)
        if !manifest_found {
            let fname = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if fname == "skill.md" {
                let parsed = parse_frontmatter(&text);
                if !parsed.is_null() && parsed.is_object() {
                    manifest = parsed;
                    manifest_found = true;
                }
            }
        }
    }

    Context {
        file_cache,
        manifest,
        has_executable_scripts,
    }
}

/// Return `true` if the file has exec bit OR starts with a shebang `#!`.
/// Only applies to files with a script extension.
// `path` is only read by the `#[cfg(unix)]` exec-bit check below; on non-Unix
// the executable test falls back to the script extension + shebang, so it's unused there.
#[cfg_attr(not(unix), allow(unused_variables))]
fn is_executable_script(path: &Path, text: &str, ext: &str) -> bool {
    // Windows executable extensions are runnable regardless of POSIX mode bits
    // or a shebang, so flag them before the script-extension gate below.
    if WINDOWS_EXEC_EXTS.contains(&ext) {
        return true;
    }

    if !SCRIPT_EXTS.contains(&ext) {
        return false;
    }

    // Check exec bit (Unix: mode & 0o111)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = path.metadata() {
            if meta.permissions().mode() & 0o111 != 0 {
                return true;
            }
        }
    }

    // Check shebang
    if text.starts_with("#!") {
        return true;
    }

    false
}

/// Parse YAML frontmatter between `---` fences.
/// Mirrors `context.py::_parse_frontmatter`.
fn parse_frontmatter(text: &str) -> serde_json::Value {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() || lines[0].trim() != "---" {
        return serde_json::Value::Null;
    }
    let mut end: Option<usize> = None;
    for (i, line) in lines[1..].iter().enumerate() {
        if line.trim() == "---" {
            end = Some(i + 1);
            break;
        }
    }
    let end = match end {
        Some(e) => e,
        None => return serde_json::Value::Null,
    };
    let yaml_text = lines[1..end].join("\n");
    match serde_yaml::from_str::<serde_yaml::Value>(&yaml_text) {
        Ok(val) => {
            if val.is_mapping() {
                // Convert serde_yaml::Value → serde_json::Value
                match serde_json::to_value(&val) {
                    Ok(json_val) => json_val,
                    Err(_) => serde_json::Value::Null,
                }
            } else {
                serde_json::Value::Null
            }
        }
        Err(_) => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_exec_extensions_flagged() {
        assert!(is_executable_script(Path::new("foo.bat"), "", ".bat"));
        assert!(is_executable_script(Path::new("foo.ps1"), "", ".ps1"));
        assert!(is_executable_script(Path::new("foo.cmd"), "", ".cmd"));
        assert!(is_executable_script(Path::new("foo.exe"), "", ".exe"));
        assert!(!is_executable_script(Path::new("foo.txt"), "", ".txt"));
    }
}
