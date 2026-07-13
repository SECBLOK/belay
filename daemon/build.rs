fn main() {
    // `fw` = the `firewall` feature is active AND we are on a target that has the
    // native netfilter/nftables backend (Linux). The firewall feature may be
    // enabled off-Linux (it is in the default set), but rustables/nfq are
    // Linux-only and target-gated out of the build there — so all rustables-
    // backed code is gated on `fw` and degrades cleanly on macOS/Windows.
    println!("cargo::rustc-check-cfg=cfg(fw)");
    if std::env::var_os("CARGO_FEATURE_FIREWALL").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        println!("cargo::rustc-cfg=fw");
    }

    // Select + compress the per-ecosystem advisory bundle. Must run before the
    // eBPF early-return below so it happens on every build.
    emit_advisory_blob();

    // Hash rules/catalog.yaml and embed the hex digest so the runtime can
    // detect on-disk drift from the compiled-in copy (Task 5).
    emit_catalog_hash();

    // Only attempt eBPF compilation when the feature is explicitly enabled.
    if std::env::var("CARGO_FEATURE_EBPF").is_err() {
        return;
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    // Runtime CARGO_MANIFEST_DIR (see emit_advisory_blob) for relocatable builds.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let manifest_path = format!("{manifest}/../daemon-ebpf/Cargo.toml");
    let artifact = format!("{out_dir}/daemon-ebpf");

    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            manifest_path.as_str(),
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Copy the compiled BPF object into OUT_DIR.
            let src =
                format!("{manifest}/../target/bpfel-unknown-none/release/daemon-ebpf");
            if let Err(e) = std::fs::copy(&src, &artifact) {
                println!("cargo:warning=eBPF artifact copy failed ({e}); writing empty stub");
                std::fs::write(&artifact, b"").expect("failed to write stub");
            }
        }
        Ok(s) => {
            println!("cargo:warning=eBPF build exited with {s}; writing empty stub so daemon still compiles");
            std::fs::write(&artifact, b"").expect("failed to write stub");
        }
        Err(e) => {
            println!("cargo:warning=eBPF build failed to launch ({e}); writing empty stub");
            std::fs::write(&artifact, b"").expect("failed to write stub");
        }
    }
}

/// Compute the SHA-256 of `rules/catalog.yaml` (relative to the repo root) and
/// emit it as the `BELAY_CATALOG_SHA256` compile-time env var so the
/// runtime can detect on-disk drift from the compiled-in copy.
fn emit_catalog_hash() {
    use sha2::{Digest, Sha256};
    // Runtime CARGO_MANIFEST_DIR (see emit_advisory_blob) — env! would bake a
    // stale absolute path and panic on the read below after a relocation. This
    // runs on every build (not feature-gated), so it must be relocatable.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let path = std::path::Path::new(&manifest).join("../rules/catalog.yaml");
    println!("cargo::rerun-if-changed={}", path.display());
    let bytes = std::fs::read(&path).expect("reading rules/catalog.yaml for hash");
    let hex = format!("{:x}", Sha256::digest(&bytes));
    println!("cargo::rustc-env=BELAY_CATALOG_SHA256={hex}");
}

/// Map an OSV ecosystem key to its bundled data file. `Debian:12` keeps the
/// legacy `advisories.json` name for backward compatibility; every other
/// ecosystem maps to `advisories.<ecosystem-with-colons-as-dashes>.json`
/// (e.g. `Ubuntu:24.04` → `advisories.Ubuntu-24.04.json`).
fn advisory_file_for(ecosystem: &str) -> String {
    match ecosystem {
        "Debian:12" => "advisories.json".to_string(),
        other => format!("advisories.{}.json", other.replace(':', "-")),
    }
}

/// Resolve the advisory JSON source path for `ecosystem` under `data_dir`.
///
/// Returns the curated per-ecosystem file path when it exists on disk (the paid
/// / vendor-generated data plane). When the curated file is absent (e.g. an
/// open / public checkout that withholds the large blobs), returns the committed
/// seed snapshot `advisories.seed.json` instead so the build succeeds offline.
///
/// This pure helper is intentionally free of I/O side effects so it can be
/// mirrored verbatim in `daemon/src/vuln/mod.rs` for unit testing under
/// `cargo test` (build.rs `#[cfg(test)]` blocks do not run via `cargo test`).
fn resolve_advisory_source(ecosystem: &str, data_dir: &std::path::Path) -> std::path::PathBuf {
    let curated = data_dir.join(advisory_file_for(ecosystem));
    if curated.exists() {
        curated
    } else {
        data_dir.join("advisories.seed.json")
    }
}

/// Compress the selected per-ecosystem advisory bundle (zlib) into OUT_DIR and
/// expose its path via `BELAY_ADVISORIES_BLOB`. The runtime
/// (`vuln::bundled_advisories`) `include_bytes!`s and inflates it once at load.
///
/// Falls back to `data/advisories.seed.json` (a thin committed snapshot) when
/// the curated per-ecosystem blob is absent, so a public checkout compiles and
/// runs offline. A `cargo:warning` is emitted in that case.
fn emit_advisory_blob() {
    use std::io::Write;

    // Read CARGO_MANIFEST_DIR at RUNTIME, not compile time. `env!` bakes the
    // absolute manifest path of wherever the build script was first compiled, so
    // relocating the target dir (or building a moved checkout) makes this read
    // data/ from a dead path and panic. Cargo always sets this env var when
    // running a build script, so `std::env::var` is safe here.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let ecosystem = std::env::var("BELAY_ECOSYSTEM").unwrap_or_else(|_| "Debian:12".to_string());

    let data_dir = std::path::Path::new(&manifest).join("data");
    let curated_path = data_dir.join(advisory_file_for(&ecosystem));
    let seed_path = data_dir.join("advisories.seed.json");

    println!("cargo::rerun-if-env-changed=BELAY_ECOSYSTEM");
    // Watch both the curated file (may not exist yet) and the seed so a
    // subsequent `git checkout` of either triggers a rebuild automatically.
    println!("cargo::rerun-if-changed={}", curated_path.display());
    println!("cargo::rerun-if-changed={}", seed_path.display());

    let src_path = resolve_advisory_source(&ecosystem, &data_dir);

    if src_path == seed_path {
        println!(
            "cargo:warning=Advisory DB: bundling SEED snapshot (best-effort, not curated). \
             Curated file '{}' is absent. Re-run `advisory-gen` or restore the curated blob, \
             then rebuild to ship production advisories. \
             End users can run `belay advisory refresh` for current data.",
            curated_path.display()
        );
    }

    let json = std::fs::read(&src_path)
        .unwrap_or_else(|e| panic!("reading advisory bundle '{}': {e}", src_path.display()));
    let mut enc =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&json).expect("compressing advisory bundle");
    let compressed = enc.finish().expect("finishing advisory compression");

    let blob_path = format!("{out_dir}/advisories.blob");
    std::fs::write(&blob_path, &compressed).expect("writing advisory blob");
    println!("cargo::rustc-env=BELAY_ADVISORIES_BLOB={blob_path}");
}
