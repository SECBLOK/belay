//! Compiles the bundled malware YARA pack (~1331 rules across the first-party
//! starter + baseline sets and the third-party GCTI/ReversingLabs sets) once,
//! at BUILD time, and serializes it (`yara_x::Rules::serialize`) into
//! `${OUT_DIR}/malware_pack.bin`. `scanner/src/analyzers/malware.rs`
//! `include_bytes!`s that blob and `Rules::deserialize`s it once per process
//! (behind a `OnceLock`), instead of recompiling every rule source from
//! scratch on every `belay` invocation — the runtime compile of the full pack
//! took ~27s per process; deserializing the pre-built blob is near-instant.
//!
//! `include!`s `src/pack_build.rs` (a *relative path*, resolved by rustc at
//! compile time against this file's own directory — NOT `env!` — so it stays
//! correct even if the whole crate directory is relocated before a fresh
//! build; see the `pure-rust-no-external-tools` / relocatability lesson: a
//! moved *built* cargo tree can reuse a stale build-script binary compiled
//! with an `env!`-baked absolute path, but a plain `include!` literal has no
//! such runtime path to go stale — its content is spliced in at the compile
//! time of `build.rs` itself). `compile_pack`/`source_compiles` there use only
//! `yara_x` types so they compile identically in this build-script crate and
//! (under `#[cfg(test)]`) in the lib crate.

include!("src/pack_build.rs");

fn main() {
    // Runtime CARGO_MANIFEST_DIR (never `env!`, which would bake this build
    // script's compile-time absolute path and go stale if a *built* cargo
    // tree is later relocated without a recompile — see daemon/build.rs for
    // the same convention). Cargo always sets this for build-script
    // invocations, fresh, regardless of where the crate currently lives.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    let starter_path = format!("{manifest}/../rules/malware/belay-starter.yar");
    let baseline_path = format!("{manifest}/../rules/malware/belay-baseline.yar");
    let gcti_path = format!("{manifest}/../rules/malware/thirdparty/gcti.yar");
    let reversinglabs_path = format!("{manifest}/../rules/malware/thirdparty/reversinglabs.yar");

    for p in [&starter_path, &baseline_path, &gcti_path, &reversinglabs_path] {
        println!("cargo::rerun-if-changed={p}");
    }
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/pack_build.rs");

    let starter = std::fs::read_to_string(&starter_path)
        .unwrap_or_else(|e| panic!("reading '{starter_path}': {e}"));
    let baseline = std::fs::read_to_string(&baseline_path)
        .unwrap_or_else(|e| panic!("reading '{baseline_path}': {e}"));
    let gcti = std::fs::read_to_string(&gcti_path)
        .unwrap_or_else(|e| panic!("reading '{gcti_path}': {e}"));
    let reversinglabs = std::fs::read_to_string(&reversinglabs_path)
        .unwrap_or_else(|e| panic!("reading '{reversinglabs_path}': {e}"));

    // Same shape as the old runtime call: first-party = starter + baseline in
    // the default namespace, third-party sets each isolated in their own
    // namespace and skipped (not fatal) if they fail to compile standalone.
    let rules = compile_pack(
        &[starter.as_str(), baseline.as_str()],
        &[
            ("gcti", gcti.as_str()),
            ("reversinglabs", reversinglabs.as_str()),
        ],
    );

    let bytes = rules.serialize().expect("serializing bundled malware pack");
    let blob_path = format!("{out_dir}/malware_pack.bin");
    std::fs::write(&blob_path, &bytes)
        .unwrap_or_else(|e| panic!("writing '{blob_path}': {e}"));
}
