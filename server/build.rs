// Embeds the git short-SHA this crate was built from as `BELAY_GIT_SHA`, so
// `server/src/source.rs` can serve it from `GET /api/source` (the AGPL §13
// network-use source affordance) via `env!("BELAY_GIT_SHA")`.
//
// `build.rs` output only reaches the crate whose compilation invoked it — the
// workspace-root `build.rs` cannot embed a value that this crate's `env!()`
// macro could read, so this small mirror lives here instead. Style matches
// the workspace-root `build.rs` and `daemon/build.rs` (a `cargo:rustc-env=`
// line, `cargo:rerun-if-changed` on the input that can change the value).
//
// MUST NOT fail the build when git is absent or this isn't a git checkout
// (e.g. a source tarball) — falls back to "unknown".
fn main() {
    // Best-effort: re-run when HEAD (or what it points at) changes, so the
    // embedded sha stays fresh across commits. Resolved via CARGO_MANIFEST_DIR
    // (this crate's dir) rather than a relative path, since build scripts may
    // run with an unspecified CWD.
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let git_dir = std::path::Path::new(&manifest_dir).join("../.git");
        println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    }

    let sha = git_short_sha().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BELAY_GIT_SHA={sha}");
}

/// Run `git rev-parse --short HEAD`. Returns `None` (never panics/fails the
/// build) when `git` is not on `PATH`, this isn't a git checkout, or the
/// command otherwise fails — e.g. building from a source tarball offline.
fn git_short_sha() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let sha = sha.trim();
    if sha.is_empty() {
        None
    } else {
        Some(sha.to_string())
    }
}
