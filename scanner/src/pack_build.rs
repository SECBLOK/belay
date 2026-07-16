// Shared compile-time YARA pack-building logic.
//
// `scanner/build.rs` `include!`s this file verbatim (a plain relative path,
// resolved at compile time — see the comment in `build.rs`) to compile and
// serialize the bundled malware pack at BUILD time. See
// `analyzers::malware::get_bundled_malware_rules`, which deserializes the
// resulting blob at process-startup time instead of recompiling ~1331 rules
// from source on every `belay` invocation.
//
// The lib crate additionally compiles this same file as `crate::pack_build`
// under `#[cfg(test)]` (see `lib.rs`) so `analyzers::malware`'s unit tests can
// exercise `compile_pack`'s fail-soft third-party-skip behavior directly,
// without duplicating the ~20 lines of logic in two places.
//
// Deliberately uses only `yara_x` types (no `scanner`-crate types) so it
// compiles standalone inside `build.rs`, which is its own crate with no
// access to the lib.
//
// NOTE: this file's leading comment is deliberately `//` (plain), not `//!`
// (inner doc comment) — `//!` is only valid as the very first thing in a file
// or module, and `include!`-ing this file into `build.rs` splices it in AFTER
// build.rs's own top-of-file doc comment, which `rustc` rejects (E0753:
// "expected outer doc comment").

use yara_x::{Compiler, Rules};

/// True if `src` compiles cleanly on its own — used to pre-check a third-party
/// set in an isolated compiler so a broken set can never poison the real pack.
pub fn source_compiles(src: &str) -> bool {
    let mut probe = Compiler::new();
    probe.add_source(src).is_ok()
}

/// Compile the bundled pack. `first_party` sources go in the default namespace
/// and are the baseline of the pack; if any fails the pack falls back to empty
/// (they are ours and expected to compile). Each `(namespace, source)` in
/// `thirdparty` is added ONLY if it compiles standalone, isolated in its own
/// namespace — a broken third-party set is skipped, not fatal, and namespacing
/// prevents rule-name collisions across sets.
pub fn compile_pack(first_party: &[&str], thirdparty: &[(&str, &str)]) -> Rules {
    let mut compiler = Compiler::new();
    let mut fp_ok = true;
    for src in first_party {
        if compiler.add_source(*src).is_err() {
            fp_ok = false;
            break;
        }
    }
    if !fp_ok {
        let mut c2 = Compiler::new();
        let _ = c2.add_source("// empty");
        return c2.build();
    }
    for (ns, src) in thirdparty {
        if source_compiles(src) {
            compiler.new_namespace(ns);
            let _ = compiler.add_source(*src);
        }
    }
    compiler.build()
}
