use scanner::context::build_context;
use scanner::resolve::{resolve, SourceType};
use std::path::Path;

#[test]
fn resolve_dir() {
    let (p, t) = resolve("tests/corpus_scan/benign/hello_skill").unwrap();
    assert_eq!(t, SourceType::Dir);
    assert!(p.is_dir());
}

#[test]
fn ssrf_private_host_blocked() {
    // mirrors resolve.py is_private_host fail-closed
    assert!(scanner::resolve::is_private_host("127.0.0.1"));
    assert!(scanner::resolve::is_private_host("nonexistent.invalid")); // resolution error -> blocked
}

#[test]
fn context_caches_files_and_detects_scripts() {
    let ctx = build_context(Path::new("tests/corpus_scan/malicious/exfil_server"));
    assert!(ctx.file_cache.contains_key("server.py"));
    assert!(ctx.has_executable_scripts); // .py with shebang or exec bit
}

#[test]
fn context_skips_binary_and_skipdirs() {
    let ctx = build_context(Path::new("tests/corpus_scan/benign/util_lib"));
    assert!(ctx.file_cache.keys().all(|k| !k.contains("__pycache__")));
}
