//! Capability model for Least-Privilege: what a manifest DECLARES vs what the
//! bundled scripts OBSERVABLY do. Keyword/regex tables ported from SkillSpector
//! `mcp_least_privilege.py` (Apache-2.0, reimplemented).
//!
//! LIMITATION (Phase 1): capability detection here is regex-based and therefore
//! evadable by reflective/obfuscated code (`getattr(os, 'system')`,
//! string-built imports, base64-then-exec). That is acceptable because such
//! evasions are caught by the scanner's `ast.rs` (reflective sinks) and
//! `taint.rs` (source->sink) analyzers, which run in the same `run_scan`
//! pipeline skillscan plugs into (they are in skillscan's deliberate SKIP list
//! precisely because Belay already covers them). AST-based capability detection
//! is a later hardening.

use std::collections::HashSet;
use crate::manifest::Manifest;
use crate::SkillFile;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Capability { ShellExec, Network, FileRead, FileWrite, EnvAccess, Subprocess, ContainerControl }

const WILDCARDS: &[&str] = &["*", "all", "full", "any"];

/// Map a declared tool/permission token to the capabilities it grants. Recognizes
/// both Agent-Skills tool NAMES (Bash, Read, Write, Edit, Glob, Grep, WebFetch,
/// WebSearch, …) and MCP-style permission keywords (shell/net/write/…). A token
/// may grant several capabilities (e.g. `Bash` => shell + subprocess).
fn caps_for_declared(token: &str) -> Vec<Capability> {
    let t = token.trim().to_ascii_lowercase();
    let has = |kw: &str| t.contains(kw);
    let mut caps = Vec::new();
    if t == "bash" || has("shell") || has("exec") || has("command") {
        // A granted shell can do essentially anything a bundled script does, so
        // declaring it covers every observable OS capability (prevents false
        // "underdeclared" findings on idiomatic skills that shell out).
        caps.push(Capability::ShellExec);
        caps.push(Capability::Subprocess);
        caps.push(Capability::FileRead);
        caps.push(Capability::FileWrite);
        caps.push(Capability::Network);
        caps.push(Capability::EnvAccess);
    }
    if has("process") || has("subprocess") { caps.push(Capability::Subprocess); }
    if t == "webfetch" || t == "websearch" || has("net") || has("http") || has("url") || has("fetch") {
        caps.push(Capability::Network);
    }
    if t == "write" || t == "edit" || t == "multiedit" || t == "notebookedit" || has("write") {
        caps.push(Capability::FileWrite);
    }
    if t == "read" || t == "glob" || t == "grep" || t == "notebookread" || has("read") || has("file") {
        caps.push(Capability::FileRead);
    }
    if has("env") { caps.push(Capability::EnvAccess); }
    if has("docker") || has("container") || has("k8s") || has("kube") {
        caps.push(Capability::ContainerControl);
    }
    caps
}

pub fn declared_caps(m: &Manifest) -> (HashSet<Capability>, bool) {
    let mut caps = HashSet::new();
    let mut wildcard = false;
    for tok in m.allowed_tools.iter().chain(m.permissions.iter()) {
        let t = tok.trim().to_ascii_lowercase();
        if WILDCARDS.contains(&t.as_str()) { wildcard = true; continue; }
        for c in caps_for_declared(&t) { caps.insert(c); }
    }
    (caps, wildcard)
}

pub fn observed_caps(files: &[SkillFile]) -> HashSet<Capability> {
    use regex::Regex;
    let table: &[(Capability, &str)] = &[
        (Capability::Network, r"\b(socket\.socket|requests\.(get|post|put)|urllib|http\.client|aiohttp|fetch\()"),
        (Capability::Subprocess, r"\b(subprocess\.(run|Popen|call|check_output)|os\.system|os\.exec|os\.popen)"),
        (Capability::ShellExec, r"\b(bash|sh)\s+-c\b|shell\s*=\s*True"),
        (Capability::FileWrite, r#"open\([^)]*['"][wa][b+]*['"]|\.write\(|shutil\.(copy|move)"#),
        (Capability::EnvAccess, r"\bos\.environ\b|\bgetenv\("),
        (Capability::ContainerControl, r"--privileged\b|/var/run/docker\.sock|docker\s+run|kubectl\b"),
        (Capability::FileRead, r#"\.read\(|read_text\(|read_bytes\(|open\([^,)]*\)|open\([^)]*['"]rb?['"]|os\.listdir|glob\.glob"#),
    ];
    let mut caps = HashSet::new();
    for (cap, pat) in table {
        let re = Regex::new(pat).expect("static capability regex compiles");
        if files.iter().any(|f| re.is_match(&f.text)) { caps.insert(*cap); }
    }
    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::SkillFile;

    fn m(tools: &[&str], perms: &[&str]) -> Manifest {
        Manifest { allowed_tools: tools.iter().map(|s| s.to_string()).collect(),
                   permissions: perms.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn declared_maps_tools_and_flags_wildcard() {
        let (caps, wild) = declared_caps(&m(&["network", "file-write"], &[]));
        assert!(caps.contains(&Capability::Network));
        assert!(caps.contains(&Capability::FileWrite));
        assert!(!wild);
        let (_c, wild2) = declared_caps(&m(&["*"], &[]));
        assert!(wild2);
    }

    #[test]
    fn observed_detects_socket_and_subprocess() {
        let files = vec![SkillFile { path: "r.py".into(),
            text: "import socket, subprocess\ns=socket.socket()\nsubprocess.run(['ls'])".into() }];
        let caps = observed_caps(&files);
        assert!(caps.contains(&Capability::Network));
        assert!(caps.contains(&Capability::Subprocess));
    }

    #[test]
    fn observed_empty_for_benign() {
        let files = vec![SkillFile { path: "r.py".into(), text: "x = 1 + 2".into() }];
        assert!(observed_caps(&files).is_empty());
    }

    #[test]
    fn observed_detects_binary_file_write() {
        let files = vec![SkillFile { path: "d.py".into(),
            text: "open('/tmp/payload', 'wb').write(data)".into() }];
        assert!(observed_caps(&files).contains(&Capability::FileWrite));
    }

    #[test]
    fn observed_read_mode_is_not_filewrite() {
        let files = vec![SkillFile { path: "d.py".into(),
            text: "open('/tmp/data', 'rb')".into() }];
        assert!(!observed_caps(&files).contains(&Capability::FileWrite));
    }

    #[test]
    fn declared_recognizes_agent_tool_names() {
        let (caps, _) = declared_caps(&m(&["Bash", "Read", "WebFetch"], &[]));
        assert!(caps.contains(&Capability::ShellExec));
        assert!(caps.contains(&Capability::Subprocess));
        assert!(caps.contains(&Capability::FileRead));
        assert!(caps.contains(&Capability::Network));
    }

    #[test]
    fn observed_detects_file_read() {
        let files = vec![SkillFile { path: "r.py".into(), text: "data = open('/etc/hosts').read()".into() }];
        assert!(observed_caps(&files).contains(&Capability::FileRead));
    }

    #[test]
    fn declared_bash_covers_all_os_capabilities() {
        let (caps, _) = declared_caps(&m(&["Bash"], &[]));
        for c in [Capability::ShellExec, Capability::Subprocess, Capability::FileRead,
                  Capability::FileWrite, Capability::Network, Capability::EnvAccess] {
            assert!(caps.contains(&c), "Bash should grant {c:?}");
        }
    }
}
