//! File classification + context-aware finding relevance.
//!
//! The pattern analyzer projects every file line as a `Bash` command and matches
//! it against the shared rule catalog. That conflates two very different things:
//! an *executed* shell command vs. a *mention* of one in prose, a `.gitignore`,
//! a Dockerfile, or sample SQL. The result was that ordinary, well-known repos
//! (every README, Dockerfile, CI file, `.gitignore`) scored 100/100
//! "do not install".
//!
//! This module restores context. Each file gets a [`FileClass`], and each rule
//! is split into two kinds:
//!
//! * **Contextual / devops-normal** rules (`pip install`, a bare `env`, a
//!   `.env` path, `DROP TABLE`, reading an agent config) are only meaningfully
//!   dangerous when they actually *execute* — i.e. inside a real script. In a
//!   README, Dockerfile, lockfile, or `.gitignore` they are noise.
//! * **Behavioural** rules (pipe-to-shell, decode-and-exec, reverse shells,
//!   exfiltration, `rm -rf /`, …) describe an attack wherever they appear and
//!   are kept everywhere.
//!
//! Approach adapted (re-implemented, not copied) from NVIDIA **SkillSpector**
//! (Apache-2.0, github.com/NVIDIA/SkillSpector), which down-weights findings by
//! file type and context to control false positives.

/// Coarse classification of a repository file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// A shell/batch script at a runtime location — content here is executed.
    Script,
    /// Program source code (`.py`, `.go`, `.rs`, `.js`, …).
    Source,
    /// An agent-instruction surface (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, …):
    /// read by an agent as instructions, so behavioural attacks here are real,
    /// but ordinary setup prose ("run `pip install`", "copy `.env`") is not.
    Instruction,
    /// Build / CI / config (`Dockerfile`, `Makefile`, `*.yml`, `*.toml`, JSON).
    Config,
    /// Documentation / prose (`.md`, `.rst`, `.txt`, `LICENSE`).
    Doc,
    /// Data / fixtures (`.sql`, `.csv`, …) — sample schemas, not executed code.
    Data,
    /// Test code & fixtures (`*_test.go`, `test_*.py`, `tests/`, `fixtures/`,
    /// `testdata/`): full of FAKE credentials and sample attacks by design.
    Test,
    /// Maintainer dev/CI/example tooling (`.ci/`, `.github/`, `script(s)/`,
    /// `hack/`, `examples/`, `docs/`): NOT run when a consumer installs/uses the
    /// package, so findings here should not drive the verdict.
    Tooling,
    /// Pure noise that should not be content-scanned at all (`.gitignore`,
    /// `.dockerignore`, lockfiles): they only ever mention paths/deps.
    Noise,
}

/// Rules that describe ordinary developer/devops actions which are only
/// dangerous when they actually execute. Outside a real script these are
/// false positives (a Dockerfile installs packages, a `.gitignore` lists
/// `.env`, a README documents env vars, a sample `.sql` drops a table).
const CONTEXTUAL_RULES: &[&str] = &[
    // pattern-analyzer (catalog) rules
    "rce.untrusted_install",
    "secrets.env_dump",
    "secrets.sensitive_path",
    "secrets.grep_hunt",
    "secrets.cred_store",
    "recon.agent_config_read",
    "recon.fs_secret_sweep",
    "recon.identity_probe",
    "recon.agent_runtime_discovery",
    "persist.shell_profile",
    "persist.sudo",
    "destructive.db_drop",
    "tamper.agent_config_write",
    // MCP dynamic-dispatch indicator: meaningful for a live tool CALL, but a
    // static scan of an MCP server's own source legitimately contains
    // "tool_name"/"dispatch" everywhere — noise outside an executed script.
    "mcp.indirection",
    // YARA equivalents of the devops-normal patterns above (same reasoning):
    // `pip/npm install` and `$AWS_SECRET`-style env reads in CI/docs/config are
    // normal. Behavioural YARA rules (yara.pipe_to_shell, yara.b64_exec) are NOT
    // listed here and remain in force everywhere.
    "yara.risky_install",
    "yara.sensitive_env",
];

/// True if `rule_id` is a contextual / devops-normal rule (see above).
pub fn is_contextual(rule_id: &str) -> bool {
    CONTEXTUAL_RULES.contains(&rule_id)
}

fn basename(rel_path: &str) -> &str {
    rel_path.rsplit(['/', '\\']).next().unwrap_or(rel_path)
}

fn ext_of(name: &str) -> &str {
    match name.rsplit_once('.') {
        // A leading-dot file like ".gitignore" has no real extension.
        Some((stem, e)) if !stem.is_empty() => e,
        _ => "",
    }
}

const NOISE_NAMES: &[&str] = &[
    ".gitignore",
    ".dockerignore",
    ".gitattributes",
    ".gitmodules",
    ".editorconfig",
    ".npmignore",
    ".eslintignore",
    ".prettierignore",
    ".npmrc",
    ".yarnrc",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "gemfile.lock",
    "composer.lock",
    "go.sum",
    "flake.lock",
];

const INSTRUCTION_NAMES: &[&str] = &[
    "skill.md",
    "agents.md",
    "agent.md",
    "claude.md",
    "gemini.md",
    "cursor.md",
    ".cursorrules",
    ".windsurfrules",
];

/// Path segments (any level) marking maintainer dev/CI/example tooling that a
/// package *consumer* never executes.
const TOOLING_DIRS: &[&str] = &[
    ".ci", "ci", ".github", ".gitlab", ".circleci", "script", "scripts", "hack", "tools",
    "tooling", "build", "dist", ".devcontainer", "examples", "example", "samples", "sample",
    "demo", "demos", "docs", "doc", "benchmarks", "bench",
];

/// Path segments marking test code/fixtures (full of fake creds & sample attacks).
const TEST_DIRS: &[&str] = &[
    "test", "tests", "testdata", "test_data", "__tests__", "spec", "specs", "fixtures", "fixture",
    "e2e", "__mocks__", "mocks",
];

fn looks_like_test_name(name: &str) -> bool {
    name == "conftest.py"
        || name.starts_with("test_")
        || name.contains("_test.")
        || name.contains(".test.")
        || name.contains(".spec.")
        || name.contains("_spec.")
}

/// Classify a repository file from its relative path (case-insensitive).
pub fn classify(rel_path: &str) -> FileClass {
    let lower = rel_path.to_ascii_lowercase();
    let name = basename(&lower).to_string();
    let segments: Vec<&str> = lower.split(['/', '\\']).collect();
    // Directory segments only (exclude the basename itself).
    let dirs = &segments[..segments.len().saturating_sub(1)];

    if NOISE_NAMES.contains(&name.as_str()) {
        return FileClass::Noise;
    }
    // Agent-instruction files are an instruction surface wherever they live.
    if INSTRUCTION_NAMES.contains(&name.as_str()) {
        return FileClass::Instruction;
    }
    // Test code/fixtures: fake credentials and sample attacks are expected here.
    if looks_like_test_name(&name) || dirs.iter().any(|d| TEST_DIRS.contains(d)) {
        return FileClass::Test;
    }
    // Maintainer tooling the consumer never runs.
    if dirs.iter().any(|d| TOOLING_DIRS.contains(d)) {
        return FileClass::Tooling;
    }

    // Extensionless build files keyed by name.
    if name == "dockerfile"
        || name.starts_with("dockerfile.")
        || name == "makefile"
        || name == "gnumakefile"
        || name == "containerfile"
        || name == "vagrantfile"
        || name == "jenkinsfile"
        || name == "procfile"
    {
        return FileClass::Config;
    }

    match ext_of(&name) {
        "sh" | "bash" | "zsh" | "ksh" | "fish" | "ps1" | "psm1" | "bat" | "cmd" => {
            FileClass::Script
        }
        "py" | "pyw" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "go" | "rs" | "rb" | "pl"
        | "php" | "java" | "kt" | "kts" | "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "cs"
        | "swift" | "scala" | "lua" | "r" | "groovy" | "dart" | "ex" | "exs" => FileClass::Source,
        "yml" | "yaml" | "toml" | "json" | "json5" | "ini" | "cfg" | "conf" | "xml" | "tf"
        | "tfvars" | "properties" | "gradle" | "cmake" => FileClass::Config,
        "sql" | "csv" | "tsv" | "ndjson" | "parquet" | "avro" => FileClass::Data,
        "md" | "mdx" | "rst" | "txt" | "adoc" | "org" => FileClass::Doc,
        // Unknown extension / extensionless prose (LICENSE, AUTHORS, NOTICE):
        // treat as documentation — low trust for contextual rules, behavioural
        // rules still apply.
        _ => FileClass::Doc,
    }
}

/// Classes that represent code a package *consumer* actually runs — the only
/// place a behavioural attack pattern is a real threat to them.
fn is_runtime(class: FileClass) -> bool {
    matches!(
        class,
        FileClass::Script | FileClass::Source | FileClass::Instruction
    )
}

/// Should a finding for `rule_id` in a file of `class` be kept?
///
/// * Noise files: nothing is kept (never executed; only mention paths/deps).
/// * Contextual / devops-normal rules (`pip install`, `env`, `.env`, `DROP
///   TABLE`, …): kept only in a real runtime [`FileClass::Script`].
/// * Behavioural rules (pipe-to-shell, decode-exec, exfil, …): kept in runtime
///   code (script/source/instruction). In docs, config, data, **test fixtures**
///   and **maintainer tooling** they are examples / non-runtime and are dropped
///   — this is what stopped official repos (a README install one-liner, a fake
///   token in `*_test.go`, a `.ci/*.sh`) from scoring 100/100.
pub fn keep_finding(rule_id: &str, class: FileClass) -> bool {
    if class == FileClass::Noise {
        return false;
    }
    if is_contextual(rule_id) {
        class == FileClass::Script
    } else {
        is_runtime(class)
    }
}

/// High-precision findings emitted by dedicated analyzers that already parse a
/// real structure (not a line-as-command heuristic). They must bypass the
/// file-class filter — e.g. MCP tool poisoning legitimately lives in a JSON
/// tool-definition file, which would otherwise be classified as config/data.
fn is_precise(rule_id: &str) -> bool {
    if matches!(rule_id, "mcp.tool_poisoning" | "mcp.hidden_unicode") {
        return true;
    }
    // Malware findings are precise signatures (EICAR, hash matches, malware-family
    // YARA such as the bundled ReversingLabs/GCTI rules) that must fire wherever
    // they are found — EXCEPT the two broad string/byte heuristics below, which
    // legitimately appear in documentation and security tooling and are therefore
    // context-filtered like any other line/string heuristic.
    if rule_id.starts_with("malware.") {
        return !matches!(
            rule_id,
            "malware.yara.Suspicious_Reverse_Shell_Strings"
                | "malware.yara.Suspicious_Packer_Signatures"
        );
    }
    false
}

/// Path-only relevance for a finding whose file is known from its `location`
/// (used as a central post-analyzer filter across every analyzer — patterns,
/// YARA, AST, taint, MCP-metadata). A missing/empty file is kept (fail-open):
/// behavioural findings that carry no location must survive.
pub fn relevant(rule_id: &str, file: Option<&str>) -> bool {
    if is_precise(rule_id) {
        return true;
    }
    match file {
        Some(f) if !f.is_empty() => keep_finding(rule_id, classify(f)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_files() {
        assert_eq!(classify("install.sh"), FileClass::Script);
        assert_eq!(classify("src/main.go"), FileClass::Source);
        assert_eq!(classify("cmd/server/main.py"), FileClass::Source);
        assert_eq!(classify("SKILL.md"), FileClass::Instruction);
        assert_eq!(classify("CLAUDE.md"), FileClass::Instruction);
        assert_eq!(classify("Dockerfile"), FileClass::Config);
        assert_eq!(classify("Dockerfile.prod"), FileClass::Config);
        assert_eq!(classify("Makefile"), FileClass::Config);
        // CI under .github/ is maintainer tooling, not a plain config file.
        assert_eq!(classify(".github/workflows/ci.yml"), FileClass::Tooling);
        assert_eq!(classify(".goreleaser.yaml"), FileClass::Config);
        assert_eq!(classify("README.md"), FileClass::Doc);
        assert_eq!(classify("LICENSE"), FileClass::Doc);
        assert_eq!(classify("db/schema.sql"), FileClass::Data);
        assert_eq!(classify(".gitignore"), FileClass::Noise);
        assert_eq!(classify(".dockerignore"), FileClass::Noise);
        assert_eq!(classify("package-lock.json"), FileClass::Noise);
        assert_eq!(classify("go.sum"), FileClass::Noise);
    }

    #[test]
    fn classifies_test_and_tooling_paths() {
        assert_eq!(classify("pkg/http/middleware/token_test.go"), FileClass::Test);
        assert_eq!(classify("tests/fixtures/sample.py"), FileClass::Test);
        assert_eq!(classify("src/conftest.py"), FileClass::Test);
        assert_eq!(classify(".ci/publish_pypi_to_ar.sh"), FileClass::Tooling);
        assert_eq!(classify("script/lint"), FileClass::Tooling);
        assert_eq!(classify(".github/workflows/ci.yml"), FileClass::Tooling);
        assert_eq!(classify("docs/SETUP_README.md"), FileClass::Tooling);
        // Runtime code keeps its real class.
        assert_eq!(classify("src/server/main.py"), FileClass::Source);
        assert_eq!(classify("install.sh"), FileClass::Script);
    }

    #[test]
    fn contextual_rules_dropped_outside_scripts() {
        // The exact false positives from the bug report:
        assert!(!keep_finding("secrets.sensitive_path", FileClass::Noise)); // .gitignore .env
        assert!(!keep_finding("secrets.sensitive_path", FileClass::Doc)); // README mentions .env
        assert!(!keep_finding("rce.untrusted_install", FileClass::Config)); // Dockerfile pip install
        assert!(!keep_finding("secrets.env_dump", FileClass::Source)); // main.go env
        assert!(!keep_finding("destructive.db_drop", FileClass::Data)); // sample.sql DROP TABLE
        assert!(!keep_finding("recon.agent_config_read", FileClass::Instruction)); // CLAUDE.md
        assert!(!keep_finding("rce.untrusted_install", FileClass::Tooling)); // .ci/*.sh
    }

    #[test]
    fn contextual_rules_kept_only_in_runtime_scripts() {
        assert!(keep_finding("rce.untrusted_install", FileClass::Script));
        assert!(keep_finding("secrets.env_dump", FileClass::Script));
    }

    #[test]
    fn behavioural_rules_kept_in_runtime_code_only() {
        // Real where actually executed:
        assert!(keep_finding("rce.pipe_to_shell", FileClass::Instruction)); // SKILL.md
        assert!(keep_finding("rce.decode_exec", FileClass::Source)); // run.py
        assert!(keep_finding("rce.pipe_to_shell", FileClass::Script)); // install.sh
        // Examples / non-runtime / fixtures → dropped (the official-repo FPs):
        assert!(!keep_finding("rce.pipe_to_shell", FileClass::Tooling)); // script/lint curl|sh
        assert!(!keep_finding("secrets.github_token", FileClass::Test)); // fake token in *_test.go
        assert!(!keep_finding("rce.pipe_to_shell", FileClass::Doc)); // README install example
        assert!(!keep_finding("destructive.rm_rf", FileClass::Config)); // Dockerfile example
        assert!(!keep_finding("rce.pipe_to_shell", FileClass::Noise));
    }

    #[test]
    fn relevant_central_filter() {
        // YARA false positives from the bug report — dropped centrally.
        assert!(!relevant("yara.risky_install", Some("README.md")));
        assert!(!relevant("yara.sensitive_env", Some(".github/workflows/ci.yml")));
        assert!(!relevant("yara.risky_install", Some("docs/BIGQUERY_README.md")));
        assert!(!relevant("secrets.github_token", Some("pkg/x/token_test.go")));
        assert!(!relevant("rce.pipe_to_shell", Some("script/lint")));
        // Behavioural findings in real runtime code stay.
        assert!(relevant("rce.pipe_to_shell", Some("SKILL.md")));
        assert!(relevant("yara.b64_exec", Some("src/loader.py")));
        // Contextual rules kept in real runtime scripts.
        assert!(relevant("yara.risky_install", Some("install.sh")));
        // No location → fail open (behavioural findings without a file survive).
        assert!(relevant("taint.cred_to_net", None));
        assert!(relevant("yara.sensitive_env", Some("")));
    }

    #[test]
    fn malware_signatures_precise_but_heuristics_context_filtered() {
        // Precise malware signatures fire wherever they are found (even in a doc).
        assert!(relevant("malware.yara.EICAR_Test_File", Some("README.md")));
        assert!(relevant("malware.hash_signature", Some("notes.txt")));
        assert!(relevant("malware.yara.Sliver_Implant_32bit", Some("report.odt")));
        // The two broad heuristics are suppressed in doc/data contexts…
        assert!(!relevant(
            "malware.yara.Suspicious_Reverse_Shell_Strings",
            Some("README.md")
        ));
        assert!(!relevant(
            "malware.yara.Suspicious_Packer_Signatures",
            Some("report.odt")
        ));
        // …but kept in runtime scripts/source.
        assert!(relevant(
            "malware.yara.Suspicious_Reverse_Shell_Strings",
            Some("linpeas.sh")
        ));
    }
}
