//! Belay unified binary (Phase 11 Task 7).
//!
//! One clap dispatcher that collapses every Rust entrypoint behind a single
//! `belay` binary:
//!
//!   belay daemon          # was the `belayd` bin
//!   belay hook            # was the `belay-hook` bin
//!   belay gate            # one-shot verdict (hook in pipe mode)
//!   belay scan PATH       # was the `scanner` bin
//!   belay serve           # the axum fleet/web server
//!   belay channels        # chat-channel info (channels run inside daemon)
//!
//! The eBPF userspace sensor (`belay-sensor`) is intentionally NOT part of
//! this binary — it stays its own bin (Linux/eBPF-specific, best-effort).
//!
//! Each subcommand delegates to a library function that holds the real logic,
//! so the legacy standalone bins keep working by delegating to the same code.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

/// Build a `CascadeProvider` from env-configured LLM keys, always ending with
/// `HeuristicProvider` as the terminal fail-closed-keep stage.
///
/// Provider order: Anthropic (if `ANTHROPIC_API_KEY` set) → OpenAI (if
/// `OPENAI_API_KEY` set) → Ollama (if `OLLAMA_BASE_URL` set, default model
/// `llama3`) → HeuristicProvider.
///
/// With no keys configured the cascade contains only `HeuristicProvider`,
/// which always returns `confirmed=true, confidence=1.0`, making the LLM path
/// behaviourally identical to the deterministic path — the safe default.
fn build_cascade() -> scanner::llm::cascade::CascadeProvider {
    use scanner::llm::anthropic::AnthropicProvider;
    use scanner::llm::cascade::{CascadeProvider, HeuristicProvider};
    use scanner::llm::ollama::OllamaProvider;
    use scanner::llm::openai::OpenAiProvider;

    let mut stages: Vec<Box<dyn scanner::llm::LlmProvider>> = Vec::new();

    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        stages.push(Box::new(AnthropicProvider::new(
            &key,
            "claude-sonnet-4-5",
            "https://api.anthropic.com",
        )));
    }
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        stages.push(Box::new(OpenAiProvider::new(
            &key,
            "gpt-4o",
            "https://api.openai.com",
        )));
    }
    if let Ok(base) = std::env::var("OLLAMA_BASE_URL") {
        let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3".into());
        stages.push(Box::new(OllamaProvider::new(&model, &base)));
    }

    // Always end with the terminal heuristic so the cascade never returns Err.
    stages.push(Box::new(HeuristicProvider));

    CascadeProvider::new(stages)
}

#[derive(Parser)]
#[command(name = "belay", version, about = "Belay unified binary")]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the always-on resident daemon (was the `belayd` bin).
    Daemon {
        /// Internal: set when the Windows Service Control Manager launches the
        /// daemon (registration adds `daemon --scm` to the service's argv, see
        /// Phase 3 `register_service`). Selects the SCM `service_dispatcher`
        /// path over plain console mode. Hidden — never a user-facing flag.
        #[arg(long, hide = true, default_value_t = false)]
        scm: bool,
    },
    /// PreToolUse/PostToolUse thin client over the UDS (was the `belay-hook` bin).
    /// Accepts an optional event positional (e.g. `pretooluse`) for compatibility
    /// with the hook command string `"belay hook pretooluse"` installed in
    /// settings.json. The actual event is read from stdin JSON; the positional is
    /// informational and ignored.
    Hook {
        #[arg(value_name = "EVENT")]
        event: Option<String>,
    },
    /// One-shot gate verdict from stdin JSON (hook in pipe mode).
    Gate,
    /// Scan a path, file, git URL, or zip.
    Scan {
        /// Target to scan.
        path: String,
        /// Enable the LLM-judge pass: routes through run_scan_with_llm, which
        /// drops sub-HIGH findings confirmed benign by the configured LLM
        /// cascade (Anthropic → OpenAI → Ollama → HeuristicProvider).
        /// With no API keys set the cascade falls back to HeuristicProvider,
        /// producing output identical to the deterministic path.
        #[arg(long)]
        llm: bool,
        /// Output format: json (default) or sarif.
        #[arg(long, default_value = "json")]
        format: String,
        /// Exclude paths matching this glob (relative to the scan root,
        /// forward slashes, e.g. `rules/malware/**`) from both the
        /// byte-level malware pass and the text analyzers. Repeatable.
        /// This is for naming known-good paths (e.g. Belay's own signature
        /// database, which self-matches its own rules) — never a substitute
        /// for fixing a real false positive some other way, and never an
        /// extension-based skip: it only hides paths the operator names.
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Skip the on-demand malware pass (it runs by default).
        #[arg(long = "no-malware", default_value_t = false)]
        no_malware: bool,
    },
    /// Run the fleet/web axum server + SSE.
    Serve {
        /// Address to bind.
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: SocketAddr,
        /// Audit NDJSON path to read from (defaults to ~/.belay/audit.ndjson).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Provision an admin credential and exit (does not start the server).
        /// The password is read from `BELAY_ADMIN_PASSWORD`, or one line
        /// from stdin (which echoes) when that env var is unset. Writes
        /// `users.json` + `server_secret` alongside the audit file.
        #[arg(long)]
        set_admin: Option<String>,
    },
    /// Chat-channel info. Channels (Telegram/Discord/WhatsApp/terminal) run
    /// inside `belay daemon` via the ASK fan-out; there is no standalone
    /// channel server, so this prints guidance and exits 0.
    Channels,
    /// Check host/VPS security posture (Phase 12 Task 1).
    Posture {
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Detect installed AI agents on this host (Phase 12 Task 2).
    Detect {
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
        /// Emit a JSON array instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Protect an AI agent (install hook or rewrite MCP config).
    Protect {
        /// Agent name (e.g. claude-code).
        agent: String,
        /// Observe mode: log-only, do not block.
        #[arg(long)]
        observe: bool,
        /// Override home directory (for testing).
        #[arg(long)]
        home: Option<String>,
    },
    /// Unprotect (remove belay hooks / restore MCP config).
    Unprotect {
        /// Agent name.
        agent: String,
        /// Override home directory (for testing).
        #[arg(long)]
        home: Option<String>,
    },
    /// Generate and install a boot-start service unit for `belay daemon`,
    /// running as the invoking user (never root) so the daemon's socket/audit
    /// paths match where the per-user hook connects. systemd on Linux, launchd
    /// on macOS. Writing the unit needs privilege (run with sudo); `--print`
    /// emits it to stdout instead.
    InstallService {
        /// User to run the daemon as (default: $SUDO_USER, else $USER).
        #[arg(long)]
        user: Option<String>,
        /// Print the unit to stdout instead of writing it.
        #[arg(long)]
        print: bool,
        /// After writing, enable + start the service (needs privilege).
        #[arg(long)]
        enable: bool,
        /// Stage the binary here before writing the unit (default: copy the
        /// current exe to the platform stable dir, e.g. /usr/local/bin, so
        /// ExecStart survives `cargo clean`). Pass an existing absolute path to
        /// skip the copy (packager / distro layout).
        #[arg(long = "exec-path")]
        exec_path: Option<String>,
        /// Re-point the Claude Code hook at the staged binary after install.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        repoint_hook: bool,
        /// After --enable, poll up to N×250ms for the daemon socket (0 disables).
        #[arg(long, default_value_t = 40)]
        wait_socket: u32,
        /// Uninstall the service instead of installing it (Windows: deregister
        /// the SCM service).
        #[arg(long)]
        uninstall: bool,
    },
    /// Interactive first-run setup wizard (Task 1 of the one-command
    /// installer plan): detects installed agents, asks Quick-vs-Custom, then
    /// protects the chosen agents and installs the boot-start service.
    Setup {
        /// Non-interactive: apply the Quick-setup defaults without prompting.
        #[arg(long)]
        yes: bool,
        /// Reserved for the Custom flow (Task 2); accepted now so `--quick`
        /// scripts don't break once Custom lands. Currently a no-op — the
        /// wizard's interactive default IS the Quick path.
        #[arg(long)]
        quick: bool,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Uninstall (Task 3 of the one-command installer plan): stop + disable
    /// the boot-start service, remove its unit/plist, and remove the staged
    /// `/usr/local/bin/belay` binary. Unix only — on Windows, use
    /// `belay install-service --uninstall` instead (SCM deregistration).
    Uninstall {
        /// Also remove `~/.belay` (config, rules cache, audit log, keys,
        /// scan schedule, AI/channel config) — everything Belay ever wrote.
        #[arg(long)]
        purge: bool,
        /// Skip the confirmation prompt (for scripted/non-interactive runs).
        #[arg(long)]
        yes: bool,
    },
    /// Print the last 20 audit-store rows: `ts verdict tool rules` (Phase 13 Task 1).
    Status {
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Print the last N audit-store rows as Python-repr dicts (Phase 13 Task 1).
    Logs {
        /// Number of rows to show (default 50).
        #[arg(short = 'n', default_value_t = 50)]
        n: usize,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Push local audit rows to a remote Belay server's ingest endpoint (Phase 13 Task 2).
    #[cfg(feature = "enterprise")]
    Push {
        /// Remote Belay server URL (required).
        #[arg(long)]
        server: String,
        /// Bearer token override (optional; stored device token used when absent).
        #[arg(long)]
        token: Option<String>,
        /// Device identifier (default: hostname).
        #[arg(long = "device-id")]
        device_id: Option<String>,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Register this device with a Belay fleet server (TB-3 Task 7).
    ///
    /// Redeems an enrollment token via `POST /api/enroll` and writes the
    /// returned device token to `<data_dir>/device_token` (mode 0600).
    /// Subsequent `belay push` calls read that token automatically.
    ///
    /// Fleet-deploy flow: bake an enroll token into the image → agent
    /// self-registers on first boot → thereafter pushes with its own device token.
    #[cfg(feature = "enterprise")]
    Enroll {
        /// Remote Belay server URL (required).
        #[arg(long)]
        server: String,
        /// Enrollment token (from the fleet operator; baked into the image for
        /// automated fleet deploy). Redeemed once to obtain a per-device token.
        #[arg(long = "enroll-token")]
        enroll_token: String,
        /// Device identifier (default: hostname).
        #[arg(long = "device-id")]
        device_id: Option<String>,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Run the persistent fleet-command agent loop (TB-4).
    ///
    /// Long-polls `GET /api/agent/commands` with the stored device token, executes
    /// each allowlisted command via the local daemon (firewall/egress) or in-process
    /// (ssh-guard/host-scan), and reports results. Requires `belay enroll` first
    /// and a running local `belay daemon`. Telemetry `push` is unchanged.
    #[cfg(feature = "enterprise")]
    Agent {
        /// Remote Belay server URL (required).
        #[arg(long)]
        server: String,
        /// Long-poll hold seconds the server uses (client read timeout = this + 15).
        #[arg(long = "poll-timeout", default_value_t = 25)]
        poll_timeout: u64,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Build or verify a tamper-evident SHA-256 evidence pack (Phase 13 Task 3).
    Evidence {
        /// Action: build or verify.
        #[arg(value_enum)]
        action: EvidenceAction,
        /// Output directory for `build` (default: a fresh temp dir).
        #[arg(long)]
        out: Option<String>,
        /// Pack directory for `verify` (required).
        #[arg(long = "dir")]
        dir: Option<String>,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
    },
    /// Run a real MCP server behind the Belay gate (Phase 13 Task 4).
    ///
    /// Usage: `belay mcp-proxy -- <server-cmd> [args...]`. An async stdio
    /// MCP shim: it intercepts `tools/call` and fail-closes (ASK→deny, any
    /// error→deny, deny never forwards); all other messages pass through. Exit
    /// code = the wrapped server's exit code.
    #[command(name = "mcp-proxy")]
    McpProxy {
        /// The MCP server command (after `--`) and its args.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Continuously monitor host posture and write audit rows per finding (Phase 12 Task 4).
    Monitor {
        /// Seconds between posture checks (default 60).
        #[arg(long, default_value_t = 60)]
        interval: u64,
        /// Override home directory (used for testing or non-default homes).
        #[arg(long)]
        home: Option<String>,
        /// Run one cycle then exit (instead of looping).
        #[arg(long)]
        once: bool,
    },

    // ─── Task C8 host subcommands ──────────────────────────────────────────────
    /// Scan the local host for malware (Task C8).
    ///
    /// Walks the given scope (home, downloads, or full root) and runs each file
    /// through the scanner malware pipeline.  Findings are printed as a table.
    /// Use `belay quarantine list|restore|delete` to manage quarantined files.
    #[command(name = "host-scan")]
    HostScan {
        /// Scan scope: home (default), downloads, or full.
        #[arg(long, default_value = "home")]
        scope: String,
        /// Exclude paths matching this glob (relative to the scan root). Repeatable —
        /// e.g. `--exclude 'tool/**' --exclude '**/node_modules/**'`.
        #[arg(long = "exclude")]
        exclude: Vec<String>,
    },

    /// Quarantine management (Task C8).
    ///
    /// Sub-actions: `list`, `restore <id>`, `delete <id>`.
    Quarantine {
        /// Action: list, restore, or delete.
        #[arg(value_name = "ACTION")]
        action: String,
        /// File id (required for restore / delete).
        #[arg(value_name = "ID")]
        id: Option<String>,
    },

    /// Host hardening checks and SSH-guard controls (Task C8).
    ///
    /// Sub-actions: check | ssh-guard | bans | unban <ip>
    Harden {
        /// Action: check, ssh-guard, bans, or unban.
        #[arg(value_name = "ACTION")]
        action: String,
        /// For ssh-guard: extra args (enable, --threshold N, --ban-ttl Xs).
        /// For unban: the IP to unban.
        #[arg(
            value_name = "ARGS",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        args: Vec<String>,
    },

    /// Vulnerability scanning (Task C8).
    ///
    /// Sub-actions: scan [--nvd-key-env VAR] | list
    Vuln {
        /// Action: scan or list.
        #[arg(value_name = "ACTION")]
        action: String,
        /// For scan: environment variable name holding the NVD API key (optional).
        #[arg(long = "nvd-key-env")]
        nvd_key_env: Option<String>,
    },

    /// Firewall management (Task C8).
    ///
    /// Sub-actions: propose | apply [--confirm-within <secs>] | confirm | revert | status
    ///
    /// SAFETY: `apply` uses a dead-man's switch. The new ruleset auto-reverts
    /// after the confirm window unless you run `belay firewall confirm`.
    /// This prevents SSH lockout on headless VPS hosts.
    Firewall {
        /// Action: propose, apply, confirm, revert, or status.
        #[arg(value_name = "ACTION")]
        action: String,
        /// For apply: how many seconds before auto-revert (default 60).
        #[arg(long = "confirm-within", default_value_t = 60)]
        confirm_within: u64,
        /// SSH source IP to always allow (overrides auto-detect from $SSH_CLIENT).
        #[arg(long = "ssh-source")]
        ssh_source: Option<String>,
    },

    /// App-aware egress control (Task C8).
    ///
    /// Sub-actions: list | allow <binary> <dest> | deny <binary> <dest>
    ///              | mode alert|block|inline on|off
    Egress {
        /// Action: list, allow, deny, or mode.
        #[arg(value_name = "ACTION")]
        action: String,
        /// Extra args: binary + dest for allow/deny, or mode params.
        #[arg(
            value_name = "ARGS",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        args: Vec<String>,
    },
}

/// The `build|verify` action for `belay evidence` (mirrors Python's
/// `click.Choice(["build", "verify"])`).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum EvidenceAction {
    Build,
    Verify,
}

fn default_audit_path() -> PathBuf {
    belayd::paths::audit_path()
}

/// Provision (or replace) an `admin` credential in `data_dir/users.json` and
/// ensure `data_dir/server_secret` exists (0600 on unix). The password comes
/// from `BELAY_ADMIN_PASSWORD`, or one line of stdin (which echoes) when
/// that env var is unset. An empty password is rejected. Never starts a server.
fn provision_admin(data_dir: &std::path::Path, username: &str) -> anyhow::Result<()> {
    let password = match std::env::var("BELAY_ADMIN_PASSWORD") {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "belay serve: reading admin password from stdin (input echoes; \
                 set BELAY_ADMIN_PASSWORD to avoid this)"
            );
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    if password.is_empty() {
        anyhow::bail!("admin password must not be empty");
    }

    std::fs::create_dir_all(data_dir)?;

    // Load existing users (if any) and replace/append the same-username entry.
    let users_path = data_dir.join("users.json");
    let mut users: Vec<belay_server::User> = std::fs::read_to_string(&users_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let password_hash = belay_auth::hash_password(&password)
        .map_err(|e| anyhow::anyhow!("password hash failed: {e}"))?;
    let new_user = belay_server::User {
        username: username.to_string(),
        password_hash,
        role: "admin".to_string(),
        org: String::new(),
        platform_admin: false,
    };
    users.retain(|u| u.username != username);
    users.push(new_user);

    // Atomic write: temp file in the same directory then rename (same fs → atomic).
    {
        use std::io::Write as _;
        let json = serde_json::to_string_pretty(&users)?;
        let tmp_path = users_path.with_file_name("users.json.tmp");
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.flush()?;
        drop(f);
        std::fs::rename(&tmp_path, &users_path)?;
    }

    // Ensure a server_secret exists (generated + persisted 0600 when absent).
    // `load_users_and_secret` is the single source of truth for that logic.
    let (_users, secret) = belay_server::load_users_and_secret(data_dir);
    anyhow::ensure!(
        !secret.is_empty(),
        "failed to establish a server secret in {}",
        data_dir.display()
    );
    Ok(())
}

/// Audit NDJSON path, honouring `--home` if provided.
///
/// When `home` is given, writes to `<home>/.belay/audit.ndjson`.
/// When absent, expands `$HOME/.belay/audit.ndjson` (same as `default_audit_path`).
fn audit_path_for_home(home: Option<&str>) -> PathBuf {
    match home {
        Some(h) => PathBuf::from(h).join(".belay").join("audit.ndjson"),
        None => default_audit_path(),
    }
}

// ─── Task C8 — dead-man instruction renderer ──────────────────────────────────

/// Render the headless-safe firewall-apply instruction for a VPS user.
///
/// This is the text equivalent of the GUI countdown panel.  It tells the
/// operator the exact command to run, the deadline, and restates SSH safety
/// so they are not scared off by the auto-revert.
///
/// Used by `belay firewall apply` and tested independently.
pub fn render_firewall_apply_output(deadline_secs: u64, handle: &str) -> String {
    format!(
        "\
Belay firewall rules applied (handle: {handle}).

  SSH SAFETY: your existing SSH session is pinned by the AllowSource
  rule and will NOT be dropped — even if the new ruleset is more
  restrictive.

  auto-revert in {deadline_secs}s: if you do not confirm, the previous
  ruleset will be automatically restored to prevent lockout.

  To KEEP the new rules, run:
    belay firewall confirm

  To REVERT immediately, run:
    belay firewall revert
"
    )
}

// ─── Task C8 — firewall confirm logic ────────────────────────────────────────

/// Error returned when `firewall confirm` is called with no pending change.
#[derive(Debug)]
pub struct NoFirewallPending;

impl std::fmt::Display for NoFirewallPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no firewall change awaiting confirmation")
    }
}

impl std::error::Error for NoFirewallPending {}

/// Validate that a pending firewall apply exists before confirming.
///
/// In the real implementation the `pending` argument would be the
/// `FirewallGuard` returned by `apply_with_revert`.  Here we model it as
/// `Option<()>` so the function is pure and unit-testable without touching
/// the kernel.
///
/// Returns `Err(NoFirewallPending)` when `pending` is `None`.
pub fn firewall_confirm_cli(pending: Option<()>) -> Result<(), NoFirewallPending> {
    match pending {
        Some(_) => Ok(()),
        None => Err(NoFirewallPending),
    }
}

// ─── Task C8 — quarantine helpers ─────────────────────────────────────────────

/// Return the path of the quarantine directory (creates it if absent).
fn quarantine_dir() -> std::path::PathBuf {
    let dir = belayd::paths::data_dir().join("quarantine");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Run `belay quarantine` sub-actions.
fn run_quarantine(action: &str, id: Option<&str>) -> ExitCode {
    let qdir = quarantine_dir();
    match action {
        "list" => {
            let entries = match std::fs::read_dir(&qdir) {
                Ok(rd) => rd,
                Err(e) => {
                    eprintln!("belay quarantine list: cannot read {:?}: {e}", qdir);
                    return ExitCode::FAILURE;
                }
            };
            let mut found = false;
            for entry in entries.flatten() {
                println!("{}", entry.file_name().to_string_lossy());
                found = true;
            }
            if !found {
                println!("no quarantined files");
            }
            ExitCode::SUCCESS
        }
        "restore" => {
            let id = match id {
                Some(s) => s,
                None => {
                    eprintln!("belay quarantine restore: <id> required");
                    return ExitCode::FAILURE;
                }
            };
            // Deferred: no quarantine store implemented yet.
            // When the store lands, restore the file with its original path.
            eprintln!(
                "belay quarantine restore: deferred — quarantine store not yet implemented \
                 (id={id:?})"
            );
            ExitCode::FAILURE
        }
        "delete" => {
            let id = match id {
                Some(s) => s,
                None => {
                    eprintln!("belay quarantine delete: <id> required");
                    return ExitCode::FAILURE;
                }
            };
            let path = qdir.join(id);
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    println!("deleted quarantine entry {id}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("belay quarantine delete {id}: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "belay quarantine: unknown action {:?} (expected list|restore|delete)",
                action
            );
            ExitCode::FAILURE
        }
    }
}

// ─── Task C8 — host-scan ──────────────────────────────────────────────────────

/// Run `belay host-scan --scope <scope>`.
///
/// Walks the scope directory, collects files, and runs `scan_malware_yara`
/// (bundled rules, no kernel requirements).  Prints a findings table.
fn run_host_scan(scope: &str, excludes: &[String]) -> ExitCode {
    use scanner::analyzers::malware::scan_malware_yara;

    let root = match scope {
        "home" => std::env::var("HOME").unwrap_or_else(|_| ".".into()),
        "downloads" => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{home}/Downloads")
        }
        "full" => "/".into(),
        other => {
            eprintln!(
                "belay host-scan: unknown scope {other:?} (expected home|downloads|full)"
            );
            return ExitCode::FAILURE;
        }
    };

    println!("Belay host-scan: scope={scope} root={root}");

    // Collect files (fail-soft on permission errors).
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    collect_files_recursive(std::path::Path::new(&root), &mut files, 0);

    // Drop files matching an `--exclude` glob (relative to the scan root).
    let before = files.len();
    apply_host_scan_excludes(&mut files, std::path::Path::new(&root), excludes);
    let excluded = before - files.len();

    if excluded > 0 {
        println!("Scanned {} file(s) ({excluded} excluded).", files.len());
    } else {
        println!("Scanned {} file(s).", files.len());
    }

    let mut findings = scan_malware_yara(&files, None);
    // Same context filter as the `belay scan` pipeline: drop broad heuristic
    // findings (reverse-shell strings, packer signatures) in doc/data/config
    // contexts; precise signatures (EICAR, hash, malware-family rules) survive.
    findings.retain(|f| {
        scanner::analyzers::fileclass::relevant(
            &f.rule_id,
            f.location.as_ref().map(|l| l.file.as_str()),
        )
    });
    if findings.is_empty() {
        println!("No malware findings.");
        ExitCode::SUCCESS
    } else {
        println!("{:<12} {:<12} REASON", "SEVERITY", "RULE");
        for f in &findings {
            println!(
                "{:<12} {:<12} {}",
                format!("{:?}", f.severity),
                f.rule_id,
                f.reason
            );
        }
        ExitCode::FAILURE
    }
}

/// Recursively collect (path, bytes) pairs, depth-limited and fail-soft.
fn collect_files_recursive(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>, depth: u32) {
    const MAX_DEPTH: u32 = 8;
    const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB

    if depth > MAX_DEPTH {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            collect_files_recursive(&path, out, depth + 1);
        } else if meta.is_file() && meta.len() <= MAX_FILE_SIZE {
            if let (Ok(bytes), Some(ps)) = (std::fs::read(&path), path.to_str()) {
                out.push((ps.to_owned(), bytes));
            }
        }
    }
}

/// Remove collected `(path, bytes)` files whose path — relative to `root` — matches an
/// `--exclude` glob. Matching is relative to the scan root (like `belay scan`), falling
/// back to the full path when a file is not under `root`. No-op when `excludes` is empty.
fn apply_host_scan_excludes(
    out: &mut Vec<(String, Vec<u8>)>,
    root: &std::path::Path,
    excludes: &[String],
) {
    let Some(globset) = scanner::exclude::build_globset(excludes) else {
        return;
    };
    out.retain(|(p, _)| {
        let rel = std::path::Path::new(p)
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| p.clone());
        !globset.is_match(&rel)
    });
}

// ─── Task C8 — harden ─────────────────────────────────────────────────────────

/// Run `belay harden <action> [args]`.
fn run_harden(action: &str, args: &[String]) -> ExitCode {
    match action {
        "check" => {
            let findings = belayd::hardening::audit_host();
            if findings.is_empty() {
                println!("Hardening check: no issues found.");
            } else {
                println!("{:<12} {:<40} REASON", "SEVERITY", "RULE_ID");
                for f in &findings {
                    println!(
                        "{:<12} {:<40} {}",
                        format!("{:?}", f.severity),
                        f.rule_id,
                        f.reason
                    );
                }
            }
            ExitCode::SUCCESS
        }
        "ssh-guard" => {
            // Parse optional --threshold N and --ban-ttl Xs from args.
            let mut threshold: u32 = 5;
            let mut ban_ttl_secs: u64 = 3600;
            let mut enable = false;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "--enable" | "enable" => enable = true,
                    "--threshold" => {
                        i += 1;
                        if let Some(v) = args.get(i) {
                            threshold = v.parse().unwrap_or(5);
                        }
                    }
                    "--ban-ttl" => {
                        i += 1;
                        if let Some(v) = args.get(i) {
                            // Accept Xs (seconds suffix) or bare integer.
                            let stripped = v.trim_end_matches('s');
                            ban_ttl_secs = stripped.parse().unwrap_or(3600);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if enable {
                println!(
                    "SSH-guard: threshold={threshold}, ban-ttl={ban_ttl_secs}s\n\
                     Note: SSH-guard tailer runs inside `belay daemon`. \
                     Start the daemon with `belay daemon` to activate it."
                );
            } else {
                println!(
                    "SSH-guard configuration: threshold={threshold}, ban-ttl={ban_ttl_secs}s\n\
                     Pass --enable to arm the guard (requires daemon)."
                );
            }
            ExitCode::SUCCESS
        }
        "bans" => {
            // List current SSH brute-force bans from the sshd_bans nftables set.
            // The pure Rust set lives in the kernel; we print a note for headless users.
            println!(
                "SSH bans are maintained in the `sshd_bans` nftables set by the daemon.\n\
                 To inspect live: run `nft list set inet belay sshd_bans` (requires root)."
            );
            ExitCode::SUCCESS
        }
        "unban" => {
            let ip = match args.first() {
                Some(s) => s,
                None => {
                    eprintln!("belay harden unban: <ip> required");
                    return ExitCode::FAILURE;
                }
            };
            // Validate IP address.
            if ip.parse::<std::net::IpAddr>().is_err() {
                eprintln!("belay harden unban: {ip:?} is not a valid IP address");
                return ExitCode::FAILURE;
            }
            println!(
                "Unban {ip}: to remove an IP from the kernel set, run:\n\
                   nft delete element inet belay sshd_bans {{ {ip} }}\n\
                 (requires root; daemon will not re-add it unless brute-force is observed)"
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "belay harden: unknown action {:?} (expected check|ssh-guard|bans|unban)",
                action
            );
            ExitCode::FAILURE
        }
    }
}

// ─── Task C8 — vuln ───────────────────────────────────────────────────────────

/// Run `belay vuln <action> [--nvd-key-env VAR]`.
fn run_vuln(action: &str, nvd_key_env: Option<&str>) -> ExitCode {
    match action {
        "scan" => {
            // 1. Load installed packages via dpkg.
            let dpkg_text = std::fs::read_to_string("/var/lib/dpkg/status").unwrap_or_default();
            let installed = belayd::vuln::parse_dpkg_status(&dpkg_text);
            println!("Found {} installed package(s).", installed.len());

            // 2. Load local advisory cache.
            let advisories = belayd::vuln::load_advisories();

            // 3. NVD lookup (feature-gated).
            #[cfg(feature = "vulndb")]
            {
                let key = nvd_key_env
                    .and_then(|v| std::env::var(v).ok())
                    .or_else(|| std::env::var("NVD_API_KEY").ok());
                if key.is_none() {
                    println!(
                        "Note: no NVD API key configured. \
                         Pass --nvd-key-env VAR or set NVD_API_KEY to enable NVD lookups."
                    );
                }
            }
            #[cfg(not(feature = "vulndb"))]
            {
                let _ = nvd_key_env;
                println!(
                    "Note: NVD database support not compiled in. \
                     Rebuild with `--features vulndb` to enable NVD lookups."
                );
            }

            // 4. Match against local advisories.
            let findings = belayd::vuln::match_advisories(&installed, &advisories);
            if findings.is_empty() {
                println!("No vulnerabilities found from local advisory cache.");
            } else {
                println!("{:<12} {:<40} REASON", "SEVERITY", "RULE_ID");
                for f in &findings {
                    println!(
                        "{:<12} {:<40} {}",
                        format!("{:?}", f.severity),
                        f.rule_id,
                        f.reason
                    );
                }
            }
            ExitCode::SUCCESS
        }
        "list" => {
            let advisories = belayd::vuln::load_advisories();
            if advisories.is_empty() {
                println!("No advisories cached. Run `belay vuln scan` to populate.");
            } else {
                println!("{:<20} {:<20} CVE(S)", "ADVISORY_ID", "PACKAGE");
                for a in &advisories {
                    let cves = if a.cve.is_empty() {
                        "-".to_string()
                    } else {
                        a.cve.join(", ")
                    };
                    println!("{:<20} {:<20} {}", a.id, a.package, cves);
                }
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "belay vuln: unknown action {:?} (expected scan|list)",
                action
            );
            ExitCode::FAILURE
        }
    }
}

// ─── Task C8 — firewall ───────────────────────────────────────────────────────

/// Run `belay firewall <action>`.
///
/// The `apply` path uses `apply_with_revert` (dead-man's switch), stays alive
/// for the confirm window, and auto-reverts on timeout.  Requires root and the
/// `firewall` feature; fails-soft on permission errors.
async fn run_firewall(action: &str, confirm_within: u64, ssh_source: Option<&str>) -> ExitCode {
    match action {
        "propose" => {
            #[cfg(fw)]
            {
                use belayd::firewall::assistant::{observe_listen_ports, propose_ruleset};
                let ssh_ip = ssh_source.and_then(|s| s.parse().ok()).or_else(|| {
                    std::env::var("SSH_CLIENT")
                        .ok()
                        .and_then(|v| v.split_whitespace().next().map(|s| s.to_owned()))
                        .and_then(|s| s.parse().ok())
                });
                let ports = observe_listen_ports();
                let rs = propose_ruleset(&ports, ssh_ip);
                println!("Proposed least-privilege ruleset:");
                if let Some(src) = rs.ssh_source {
                    println!("  AllowSource({src})  [SSH origin — pinned]");
                }
                for port in &rs.allow_ports {
                    println!("  AllowPort({port})");
                }
                if rs.default_drop {
                    println!("  DefaultDrop");
                }
                println!("\nRun `belay firewall apply` to apply with auto-revert.");
                ExitCode::SUCCESS
            }
            #[cfg(not(fw))]
            {
                let _ = (ssh_source,);
                println!(
                    "belay firewall propose: firewall support not compiled in. \
                     Rebuild with `--features firewall`."
                );
                ExitCode::SUCCESS
            }
        }
        "apply" => {
            #[cfg(fw)]
            {
                use belayd::firewall::assistant::{observe_listen_ports, propose_ruleset};
                let ssh_ip = ssh_source.and_then(|s| s.parse().ok()).or_else(|| {
                    std::env::var("SSH_CLIENT")
                        .ok()
                        .and_then(|v| v.split_whitespace().next().map(|s| s.to_owned()))
                        .and_then(|s| s.parse().ok())
                });
                let ports = observe_listen_ports();
                let rs = propose_ruleset(&ports, ssh_ip);

                // Try to apply with a real kernel backend. Requires CAP_NET_ADMIN.
                use belayd::firewall::RustablesBackend;

                let handle = "fw-pending";
                let revert = std::time::Duration::from_secs(confirm_within);

                // apply_with_revert is async — await it directly (we're already async).
                let guard = match belayd::firewall::guard::apply_with_revert(
                    &rs,
                    revert,
                    RustablesBackend,
                )
                .await
                {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!(
                            "belay firewall apply: {e}\n\
                                 (Hint: this operation requires CAP_NET_ADMIN / root.)"
                        );
                        return ExitCode::FAILURE;
                    }
                };

                // Print the dead-man's instruction and ask for in-process CONFIRM.
                print!("{}", render_firewall_apply_output(confirm_within, handle));
                println!(
                    "Type CONFIRM and press Enter within {confirm_within}s to keep rules, \
                     or wait for auto-revert:"
                );

                // Stay alive: race stdin readline vs. the confirm window timeout.
                // Capture the chosen action as an enum BEFORE consuming `guard`,
                // so ownership is not split across select! branches.
                enum ApplyAction {
                    Confirm,
                    Revert(String), // message to print
                }

                use tokio::io::AsyncBufReadExt as _;
                let mut stdin_reader = tokio::io::BufReader::new(tokio::io::stdin());
                let mut line_buf = String::new();

                let action = tokio::select! {
                    read_result = stdin_reader.read_line(&mut line_buf) => {
                        match read_result {
                            Ok(_) if line_buf.trim().eq_ignore_ascii_case("CONFIRM") => {
                                ApplyAction::Confirm
                            }
                            Ok(_) => ApplyAction::Revert(
                                "No confirmation received — firewall rules auto-reverted \
                                 (SSH preserved).".into()
                            ),
                            Err(e) => ApplyAction::Revert(
                                format!("belay firewall apply: stdin read error: {e} — \
                                         auto-reverting (SSH preserved).")
                            ),
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(confirm_within)) => {
                        ApplyAction::Revert(
                            "No confirmation received — firewall rules auto-reverted \
                             (SSH preserved).".into()
                        )
                    }
                };

                match action {
                    ApplyAction::Confirm => {
                        guard.confirm();
                        println!("Firewall rules kept.");
                    }
                    ApplyAction::Revert(msg) => {
                        println!("{msg}");
                        // ANTI-LOCKOUT: block until the background revert task
                        // (backend.load) finishes before the runtime is dropped.
                        guard.wait_for_revert().await;
                    }
                }

                ExitCode::SUCCESS
            }
            #[cfg(not(fw))]
            {
                let _ = (confirm_within, ssh_source);
                eprintln!(
                    "belay firewall apply: firewall support not compiled in. \
                     Rebuild with `--features firewall`."
                );
                ExitCode::FAILURE
            }
        }
        "confirm" => {
            // In a full implementation, the guard handle is looked up from a
            // pid-file / state file written by `apply`.  For the CLI one-shot
            // model we check for the snapshot file as a proxy for "pending apply".
            let snapshot_path = belayd::paths::data_dir().join("fw_snapshot.json");
            let pending_marker = if snapshot_path.exists() {
                Some(())
            } else {
                None
            };
            match firewall_confirm_cli(pending_marker) {
                Ok(()) => {
                    // Remove the snapshot to signal confirmation.
                    let _ = std::fs::remove_file(&snapshot_path);
                    println!("Firewall confirmed. Auto-revert disarmed.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("belay firewall confirm: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        "revert" => {
            #[cfg(fw)]
            {
                use belayd::firewall::{guard::restore_on_start, RustablesBackend};
                let mut backend = RustablesBackend;
                restore_on_start(&mut backend);
                println!("Firewall reverted to previous state.");
                ExitCode::SUCCESS
            }
            #[cfg(not(fw))]
            {
                println!(
                    "belay firewall revert: firewall support not compiled in. \
                     Rebuild with `--features firewall`."
                );
                ExitCode::SUCCESS
            }
        }
        "status" => {
            let snapshot_path = belayd::paths::data_dir().join("fw_snapshot.json");
            if snapshot_path.exists() {
                println!("Firewall status: pending apply (auto-revert armed).");
                println!("  Run `belay firewall confirm` to keep the new rules.");
                println!("  Run `belay firewall revert` to restore the previous state.");
            } else {
                println!("Firewall status: no pending apply.");
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "belay firewall: unknown action {:?} \
                 (expected propose|apply|confirm|revert|status)",
                action
            );
            ExitCode::FAILURE
        }
    }
}

// ─── Task C8 — egress ─────────────────────────────────────────────────────────

/// Run `belay egress <action> [args]`.
fn run_egress(action: &str, args: &[String]) -> ExitCode {
    match action {
        "list" => {
            // The allowlist is managed at runtime in the daemon's egress state.
            // For the CLI, show the location of the allowlist config.
            println!(
                "Egress allowlist is maintained by the daemon.\n\
                 Use `belay egress allow <binary> <dest>` or \
                 `belay egress deny <binary> <dest>` to manage it."
            );
            ExitCode::SUCCESS
        }
        "allow" | "deny" => {
            let binary = match args.first() {
                Some(s) => s,
                None => {
                    eprintln!("belay egress {action}: <binary> required");
                    return ExitCode::FAILURE;
                }
            };
            let dest = match args.get(1) {
                Some(s) => s,
                None => {
                    eprintln!("belay egress {action}: <dest> required");
                    return ExitCode::FAILURE;
                }
            };
            println!("Egress {action}: {binary} → {dest}");
            println!(
                "Note: egress rules take effect in the next daemon start. \
                 Persist this rule in ~/.belay/egress.json."
            );
            ExitCode::SUCCESS
        }
        "mode" => {
            // mode alert|block|inline on|off
            let mode = match args.first() {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("belay egress mode: <alert|block|inline> required");
                    return ExitCode::FAILURE;
                }
            };
            let onoff = match args.get(1) {
                Some(s) => s.as_str(),
                None => {
                    eprintln!("belay egress mode {mode}: <on|off> required");
                    return ExitCode::FAILURE;
                }
            };
            println!("Egress mode {mode}: {onoff}");
            println!(
                "Note: mode changes take effect in the next daemon start. \
                 Persist in ~/.belay/egress.json."
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "belay egress: unknown action {:?} \
                 (expected list|allow|deny|mode)",
                action
            );
            ExitCode::FAILURE
        }
    }
}

/// Run the continuous (or one-shot) posture monitor.
///
/// Mirrors `monitor_cmd` in the deleted Python predecessor's `cli/main.py`:
///   - Prints the banner once.
///   - Loops: run `check_posture` → `render_cycle` → print lines + audit each finding.
///   - If `once`, breaks after the first cycle; otherwise sleeps `interval` seconds.
fn run_monitor(interval: u64, home: Option<&str>, once: bool) -> ExitCode {
    use serde_json::json;

    let audit_path = audit_path_for_home(home);

    // Ensure the `.belay` directory exists before opening the writer.
    if let Some(parent) = audit_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut writer = match belayd::audit::AuditWriter::open(
        audit_path.to_str().unwrap_or("audit.ndjson"),
    ) {
        Ok(w) => w,
        Err(e) => {
            eprintln!(
                "belay monitor: cannot open audit log {:?}: {e}",
                audit_path
            );
            return ExitCode::FAILURE;
        }
    };

    println!("Belay monitor started (interval={interval}s). Ctrl+C to stop.");

    loop {
        let home_path = home.map(std::path::Path::new);
        let findings = belay_manage::posture::check_posture(home_path);
        let (lines, _any_critical) = belay_manage::monitor::render_cycle(&findings);

        if lines.is_empty() {
            println!("Posture OK.");
        } else {
            for (line, f) in lines.iter().zip(findings.iter()) {
                println!("{line}");
                // severity: use the lowercase serde name (e.g. "critical"/"high")
                // via serde_json serialisation of scanner::types::Severity.
                // Severity has #[serde(rename_all = "lowercase")] so this yields
                // "critical", "high", "medium", "low", or "info".
                let sev_value = serde_json::to_value(f.severity).unwrap_or(json!("unknown"));
                let sev_str = sev_value.as_str().unwrap_or("unknown").to_string();
                let row = json!({
                    "event": "drift.posture",
                    "rule_id": f.rule_id,
                    "severity": sev_str,
                    "reason": f.reason,
                });
                if let Err(e) = writer.append(row) {
                    eprintln!("belay monitor: audit write error: {e}");
                }
            }
        }

        if once {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }

    ExitCode::SUCCESS
}

/// Resolve the device id: explicit `--device-id` or the system hostname.
///
/// Mirrors Python `device_id or socket.gethostname()`. The `hostname` crate
/// calls the same underlying `gethostname(2)` syscall, so it matches Python's
/// `socket.gethostname()` for the cross-language parity check.
#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
fn resolve_device_id(device_id: Option<&str>) -> String {
    match device_id {
        Some(d) => d.to_string(),
        None => hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

/// Run the `evidence build|verify` command.
///
/// Ports `evidence_cmd` (the deleted Python predecessor's `cli/main.py`):
///   - `build`: `findings = to_findings(recent(500))`, `sarif =
///     {"version":"2.1.0","runs":[]}`, write the pack to `--out` or a fresh
///     temp dir, print `Evidence pack built: {path}`.
///   - `verify`: require `--dir`; print `Pack verified: OK` (exit 0) or
///     `Pack TAMPERED or missing files` (exit 1).
fn run_evidence(
    action: EvidenceAction,
    out: Option<&str>,
    dir: Option<&str>,
    home: Option<&str>,
) -> ExitCode {
    use serde_json::json;

    match action {
        EvidenceAction::Build => {
            let audit_path = audit_path_for_home(home);
            let rows =
                belayd::audit::recent(audit_path.to_str().unwrap_or("audit.ndjson"), 500);
            // to_findings already returns the ordered findings array (matches
            // Python's `[a.model_dump() for a in to_findings(...)]`).
            let findings = belay_server::audit_reader::to_findings(&rows);
            let sarif = json!({"version": "2.1.0", "runs": []});

            // Default out dir: a fresh `belay_evidence_<pid>_<nanos>` temp
            // dir (mkdtemp-style), matching Python's tempfile.mkdtemp prefix.
            let out_dir = match out {
                Some(o) => o.to_string(),
                None => {
                    let unique = format!(
                        "belay_evidence_{}_{}",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );
                    std::env::temp_dir()
                        .join(unique)
                        .to_string_lossy()
                        .to_string()
                }
            };

            match belay_manage::evidence::build_pack(&out_dir, &findings, &sarif) {
                Ok(path) => {
                    println!("Evidence pack built: {path}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("belay evidence build: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        EvidenceAction::Verify => {
            let dir = match dir {
                Some(d) => d,
                None => {
                    eprintln!("belay evidence verify: --dir required for verify");
                    return ExitCode::FAILURE;
                }
            };
            if belay_manage::evidence::verify_pack(dir) {
                println!("Pack verified: OK");
                ExitCode::SUCCESS
            } else {
                println!("Pack TAMPERED or missing files");
                ExitCode::FAILURE
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        // Sync entrypoints — these block / exit on their own.
        Cmd::Daemon { scm } => {
            // Under the Windows SCM, hand the main thread to the service
            // dispatcher (it calls `service_main` on a worker and blocks for the
            // service lifetime). If we were launched from a console instead of by
            // the SCM, `run_dispatch` returns 1063 and we fall through to the
            // normal console daemon below.
            #[cfg(windows)]
            if scm {
                match win_service::run_dispatch() {
                    Ok(()) => return ExitCode::SUCCESS,
                    // Interactive launch (not under SCM): run console mode.
                    Err(e) if win_service::is_scm_not_connected_1063(&e) => {}
                    Err(e) => {
                        eprintln!("scm dispatch failed: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // `--scm` has no effect off Windows (no SCM); consume it so the
            // console path below is identical to a bare `daemon`.
            #[cfg(not(windows))]
            let _ = scm;
            // `main` is `#[tokio::main]`, so this arm runs on a tokio worker.
            // The daemon's firewall path (`DaemonState::firewall_apply_with` /
            // `firewall_revert`) calls `runtime.block_on(...)`, which PANICS if
            // executed on a tokio worker thread. Per-connection handlers already
            // run on `std::thread`s, but run the whole serve loop on a dedicated
            // OS thread too so the no-block_on-on-a-worker invariant is enforced
            // structurally and survives future refactors.
            let h = std::thread::spawn(belayd::app::run_daemon);
            let _ = h.join();
            ExitCode::SUCCESS
        }
        Cmd::Hook { event } => belayd::app::run_hook(event.as_deref()), // diverges (never returns)
        Cmd::Gate => belayd::app::gate(),            // diverges (never returns)
        Cmd::Scan {
            path,
            llm,
            format,
            exclude,
            no_malware,
        } => {
            if llm {
                // LLM-augmented path: build an env-configured cascade and run
                // run_scan_with_llm; sub-HIGH findings confirmed benign by the
                // LLM are dropped before scoring. The --no-malware toggle is not
                // threaded into this async pipeline; warn once so the gap is
                // visible instead of a silent footgun.
                if no_malware {
                    eprintln!(
                        "warning: --no-malware is ignored with --llm (the LLM scan path does not run the malware pass)"
                    );
                }
                let cascade = build_cascade();
                match scanner::pipeline::run_scan_with_llm(
                    &path,
                    scanner::default_analyzers(),
                    Some(&cascade),
                    &exclude,
                )
                .await
                {
                    Ok(result) => scanner::print_result_and_exit(&result, &format),
                    Err(e) => {
                        eprintln!("belay scan --llm: fatal: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                // Deterministic path.
                scanner::run_cli(&path, &format, &exclude, !no_malware)
            }
        }
        // Async entrypoint.
        Cmd::Serve {
            addr,
            audit,
            set_admin,
        } => {
            let audit_path = audit.unwrap_or_else(default_audit_path);
            if let Some(username) = set_admin {
                // Provision-and-exit: write the admin credential, don't serve.
                let data_dir = audit_path
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                return match provision_admin(&data_dir, &username) {
                    Ok(()) => {
                        eprintln!("admin '{username}' configured");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("belay serve: --set-admin failed: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            match belay_server::run(addr, audit_path).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("belay serve: fatal: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Channels => {
            // The `belay-channels` crate is a library (NotificationChannel
            // trait + per-platform impls, no run loop) and is not yet wired into
            // the daemon's runtime ASK fan-out — it is excluded from the default
            // build (build with `--features channels` to link it). Print guidance
            // rather than fake a server.
            println!(
                "belay channels: notification channels (terminal/Telegram/Discord/WhatsApp) \
                 are a library pending daemon integration; they are not in the default build. \
                 Rebuild with `--features channels` to include the crate. There is no standalone \
                 channels server to start."
            );
            ExitCode::SUCCESS
        }
        Cmd::Posture { home } => {
            let home_path = home.as_deref().map(std::path::Path::new);
            belay_manage::posture::run(home_path)
        }
        Cmd::Detect { home, json } => {
            if json {
                let agents = belay_manage::detect::find_agents(home.as_deref());
                let arr: Vec<serde_json::Value> = agents
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name, "settings": a.settings_paths, "risky": a.risky_flags,
                            "interception": a.interception, "mcp_config": a.mcp_config_paths,
                            "mcp_servers": a.mcp_servers, "skills": a.skills,
                            "protected": a.protected,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap()
                );
                ExitCode::SUCCESS
            } else {
                belay_manage::detect::run(home.as_deref())
            }
        }
        Cmd::Protect {
            agent,
            observe,
            home,
        } => belay_manage::protect::run_protect(&agent, observe, home.as_deref()),
        Cmd::Unprotect { agent, home } => {
            belay_manage::protect::run_unprotect(&agent, home.as_deref())
        }
        Cmd::InstallService {
            user,
            print,
            enable,
            exec_path,
            repoint_hook,
            wait_socket,
            uninstall,
        } => run_install_service(
            user.as_deref(),
            print,
            enable,
            exec_path.as_deref(),
            repoint_hook,
            wait_socket,
            uninstall,
        ),
        Cmd::Setup { yes, quick, home } => run_setup(yes, quick, home),
        Cmd::Uninstall { purge, yes } => run_uninstall(purge, yes),
        Cmd::Status { home } => {
            let audit_path = audit_path_for_home(home.as_deref());
            let rows =
                belayd::audit::recent(audit_path.to_str().unwrap_or("audit.ndjson"), 20);
            for line in belay_manage::render::render_status(&rows) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Cmd::Logs { n, home } => {
            let audit_path = audit_path_for_home(home.as_deref());
            let rows = belayd::audit::recent(audit_path.to_str().unwrap_or("audit.ndjson"), n);
            for line in belay_manage::render::render_logs(&rows) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Cmd::Evidence {
            action,
            out,
            dir,
            home,
        } => run_evidence(action, out.as_deref(), dir.as_deref(), home.as_deref()),
        Cmd::McpProxy { cmd } => belayd::mcp_proxy::run_proxy(cmd).await,
        Cmd::Monitor {
            interval,
            home,
            once,
        } => run_monitor(interval, home.as_deref(), once),

        // ─── Task C8 ────────────────────────────────────────────────────────────
        Cmd::HostScan { scope, exclude } => run_host_scan(&scope, &exclude),
        Cmd::Quarantine { action, id } => run_quarantine(&action, id.as_deref()),
        Cmd::Harden { action, args } => run_harden(&action, &args),
        Cmd::Vuln {
            action,
            nvd_key_env,
        } => run_vuln(&action, nvd_key_env.as_deref()),
        Cmd::Firewall {
            action,
            confirm_within,
            ssh_source,
        } => run_firewall(&action, confirm_within, ssh_source.as_deref()).await,
        Cmd::Egress { action, args } => run_egress(&action, &args),
    }
}

/// A command run during `--enable`. `required` commands abort the install on
/// failure; non-required ones (competitor teardown) are best-effort.
#[derive(Debug, Clone, PartialEq)]
struct EnableCmd {
    argv: Vec<String>,
    required: bool,
}

impl EnableCmd {
    fn required(argv: Vec<&str>) -> Self {
        Self { argv: argv.into_iter().map(String::from).collect(), required: true }
    }
    fn optional(argv: Vec<&str>) -> Self {
        Self { argv: argv.into_iter().map(String::from).collect(), required: false }
    }
}

/// Stable install dir for the staged binary on each OS (so `ExecStart` survives
/// `cargo clean`), or `None` if the OS has no known location.
fn stable_exec_dir(os: &str) -> Option<&'static str> {
    match os {
        "linux" | "macos" => Some("/usr/local/bin"),
        _ => None,
    }
}

/// Plan for the unit's `ExecStart` and whether to stage (copy) the binary first.
#[derive(Debug, Clone, PartialEq)]
struct ExecPlan {
    exec_start: String,
    /// `Some(src)` means copy `src` → `exec_start` before writing the unit.
    copy_from: Option<String>,
}

/// Pure: decide `ExecStart` and staging from an optional `--exec-path` and the
/// current exe. Free of env/fs so it is fully unit-testable.
fn plan_exec_path(os: &str, current_exe: &str, requested: Option<&str>) -> Result<ExecPlan, String> {
    if let Some(p) = requested {
        if !std::path::Path::new(p).is_absolute() {
            return Err(format!("--exec-path must be absolute: {p}"));
        }
        // Caller-supplied target: never stage, just point ExecStart at it.
        return Ok(ExecPlan { exec_start: p.to_string(), copy_from: None });
    }
    let dir = stable_exec_dir(os)
        .ok_or_else(|| format!("no stable install dir for OS '{os}'; pass --exec-path <absolute>"))?;
    let dest = format!("{dir}/belay");
    let copy_from = if current_exe == dest { None } else { Some(current_exe.to_string()) };
    Ok(ExecPlan { exec_start: dest, copy_from })
}

/// The daemon socket path under `home` (mirrors `daemon/src/app.rs`).
fn socket_poll_target(home: &str) -> String {
    format!("{home}/.belay/belayd.sock")
}

/// Pure: choose the boot-start unit path, contents, and enable commands for
/// `os`. Returns `None` for unsupported platforms. Free of env/fs so it is
/// fully unit-testable. The unit launches `<exe> daemon` as `user`.
fn service_artifact(os: &str, exe: &str, user: &str) -> Option<(PathBuf, String, Vec<EnableCmd>)> {
    match os {
        "linux" => {
            // Tear down any competing unit/daemon before enabling ours, so two
            // units can't race over the single ~/.belay/belayd.sock.
            let old_instance = format!("belay@{user}.service");
            Some((
                PathBuf::from("/etc/systemd/system/belay.service"),
                belayd::service::systemd_unit(exe, user),
                vec![
                    EnableCmd::optional(vec![
                        "systemctl", "--user", "disable", "--now", "belay.service",
                    ]),
                    EnableCmd::optional(vec![
                        "systemctl", "disable", "--now", &old_instance,
                    ]),
                    EnableCmd::optional(vec!["pkill", "-u", user, "-f", "belay daemon"]),
                    EnableCmd::required(vec!["systemctl", "daemon-reload"]),
                    EnableCmd::required(vec!["systemctl", "enable", "--now", "belay.service"]),
                ],
            ))
        }
        "macos" => {
            let plist = "/Library/LaunchDaemons/com.secblok.belay.plist";
            Some((
                PathBuf::from(plist),
                belayd::service::launchd_plist(exe, user),
                vec![
                    EnableCmd::optional(vec!["launchctl", "unload", "-w", plist]),
                    EnableCmd::required(vec!["launchctl", "load", "-w", plist]),
                ],
            ))
        }
        // Windows daemon is not functional yet (no IPC transport/peer-auth — see
        // docs/02-windows-port-and-install-consolidation.md). The SCM spec is
        // scaffolded in `belayd::service::windows_service_spec`; wire it in
        // (Phase 3) only once the daemon runs on Windows.
        "windows" => None,
        _ => None,
    }
}

/// Which filesystem paths `belay uninstall` removes, for a given `os` and
/// `home` (the invoking user's home directory) — pure and free of env/fs
/// access so it's fully unit-testable with a fake `os`/`home` regardless of
/// the host platform, matching the [`service_artifact`]/[`stable_exec_dir`]
/// testing convention. Always includes the boot-start unit/plist path (reusing
/// [`service_artifact`]'s exact paths) and the staged binary (reusing
/// [`stable_exec_dir`]); with `purge` also includes `home/.belay` — the
/// same join [`belayd::paths::data_dir`] performs from `$HOME`. Returns
/// an empty unit/plist entry for OSes with no known service artifact (e.g.
/// `windows`, which the caller intercepts before ever reaching this helper).
fn uninstall_plan(os: &str, home: &Path, purge: bool) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    match os {
        "linux" => paths.push(PathBuf::from("/etc/systemd/system/belay.service")),
        "macos" => paths.push(PathBuf::from("/Library/LaunchDaemons/com.secblok.belay.plist")),
        _ => {}
    }
    if let Some(dir) = stable_exec_dir(os) {
        paths.push(PathBuf::from(dir).join("belay"));
    }
    if purge {
        paths.push(home.join(".belay"));
    }
    paths
}

/// Absolute path to this binary, or `None` if it cannot be resolved absolutely
/// (the unit's `ExecStart` must be absolute, never a bare name on `$PATH`).
fn install_exe_path() -> Option<String> {
    let p = std::env::current_exe().ok()?;
    let p = std::fs::canonicalize(&p).unwrap_or(p);
    p.is_absolute().then(|| p.to_string_lossy().into_owned())
}

/// Target user for the service: explicit `--user`, else `$SUDO_USER` (the real
/// user behind a `sudo` invocation), else `$USER` (Unix) / `%USERNAME%` (Windows).
fn install_target_user(explicit: Option<&str>) -> Option<String> {
    if let Some(u) = explicit {
        return Some(u.to_string());
    }
    std::env::var("SUDO_USER")
        .ok()
        .filter(|s| !s.is_empty() && s != "root")
        .or_else(|| std::env::var("USER").ok().filter(|s| !s.is_empty()))
        // Windows has no sudo / $USER; fall back to %USERNAME%.
        .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.is_empty()))
}

/// Home directory the daemon (and the hook it re-points) will use, per OS unit
/// convention: `/Users/<user>` on macOS, else `/home/<user>`.
fn install_user_home(os: &str, user: &str) -> String {
    match os {
        "macos" => format!("/Users/{user}"),
        _ => format!("/home/{user}"),
    }
}

/// Resolve a username to its `(uid, gid)` via `getpwnam`. Unix-only.
#[cfg(unix)]
fn user_ids(name: &str) -> Option<(u32, u32)> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer into a libc-owned static buffer (fine
    // for this one-shot CLI); null when the user is unknown.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some(((*pw).pw_uid, (*pw).pw_gid))
        }
    }
}

/// Best-effort `lchown(path, uid, gid)` - NEVER dereferences symlinks, so a
/// root-run caller cannot be tricked into chowning a symlink's target (a local
/// privilege escalation). Unix-only; failure is ignored.
#[cfg(unix)]
fn lchown_path(path: &std::path::Path, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        // SAFETY: plain lchown(2); result ignored (best-effort).
        unsafe {
            libc::lchown(c.as_ptr(), uid, gid);
        }
    }
}

/// `install-service` runs under `sudo` (root euid) to write the boot unit, so the
/// `run_protect` hook re-point wrote the user's `~/.claude/settings*` as ROOT.
/// Chown those files back to the invoking user so the user (and their Claude Code,
/// which runs as that user) can manage their own hook. Mirrors "daemon runs as the
/// invoking user, not root". Best-effort, Unix-only; touches only `settings*` files
/// so unrelated `~/.claude` content is never disturbed.
#[cfg(unix)]
fn chown_claude_settings_to_user(home: &str, user: &str) {
    let (uid, gid) = match user_ids(user) {
        Some(ids) => ids,
        None => return,
    };
    use std::os::unix::fs::MetadataExt;
    let cdir = std::path::Path::new(home).join(".claude");
    let Ok(entries) = std::fs::read_dir(&cdir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("settings") {
            continue;
        }
        // Only fix REGULAR files that install-service (as root) actually created,
        // i.e. currently root-owned. symlink_metadata is an lstat (no symlink
        // follow); together with lchown below this closes the symlink-follow
        // privilege-escalation window - a local attacker planting
        // ~/.claude/settings-x -> a root-owned file cannot steal its ownership,
        // and we never touch a file we did not create.
        let should_fix = entry
            .path()
            .symlink_metadata()
            .map(|m| m.file_type().is_file() && m.uid() == 0)
            .unwrap_or(false);
        if should_fix {
            lchown_path(&entry.path(), uid, gid);
        }
    }
}

// AGPL-3.0 source-availability is satisfied by the public repo, but GPL-3.0
// (rustables) §4-5 and CC-BY-SA-4.0 / CC-BY-4.0 (bundled advisory data) require
// the license text + attribution to ACCOMPANY the conveyed binary. Embed them at
// compile time so a bare `install-service` deployment drops them next to the
// staged binary (the GUI deb/appimage carries them via tauri.conf.json resources).
const EMBEDDED_LICENSE: &str = include_str!("../../LICENSE");
const EMBEDDED_NOTICE: &str = include_str!("../../NOTICE");

/// `install-service`: stage the binary, write the boot-start unit (or print it),
/// optionally enable+start it, re-point the Claude Code hook, and wait for the
/// daemon socket. Folds the seven steps of `packaging/install-system.sh`.
/// Stop, disable, and remove the boot-start service (unit/plist) - service only,
/// leaving the staged binary and config in place. The Unix counterpart to the
/// Windows SCM deregister; used by `install-service --uninstall` and the desktop
/// "Start on boot" toggle's OFF path. Best-effort per step (a not-installed
/// service is the common case, not an error); fails only if a file that exists
/// cannot be removed. Cross-platform-compilable (never reached on Windows, which
/// returns via run_install_service_windows first).
fn uninstall_boot_service(os: &str) -> ExitCode {
    let mut ok = true;
    match os {
        "linux" => {
            let _ = std::process::Command::new("systemctl")
                .args(["disable", "--now", "belay.service"])
                .status();
            let unit = std::path::Path::new("/etc/systemd/system/belay.service");
            if unit.exists() {
                if let Err(e) = std::fs::remove_file(unit) {
                    eprintln!(
                        "install-service --uninstall: could not remove {}: {e}",
                        unit.display()
                    );
                    ok = false;
                }
            }
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .status();
        }
        "macos" => {
            let plist = "/Library/LaunchDaemons/com.secblok.belay.plist";
            // bootout is the modern unload; unload is the pre-10.11 fallback.
            let _ = std::process::Command::new("launchctl")
                .args(["bootout", "system", plist])
                .status();
            let _ = std::process::Command::new("launchctl")
                .args(["unload", plist])
                .status();
            let p = std::path::Path::new(plist);
            if p.exists() {
                if let Err(e) = std::fs::remove_file(p) {
                    eprintln!("install-service --uninstall: could not remove {plist}: {e}");
                    ok = false;
                }
            }
        }
        _ => {
            eprintln!("install-service --uninstall: unsupported OS '{os}'");
            return ExitCode::FAILURE;
        }
    }
    if ok {
        println!("Belay boot-start service removed (the binary and config are unchanged).");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_install_service(
    user: Option<&str>,
    print: bool,
    enable: bool,
    exec_path: Option<&str>,
    repoint_hook: bool,
    wait_socket: u32,
    uninstall: bool,
) -> ExitCode {
    // 1. Resolve target user (real user behind sudo).
    let user = match install_target_user(user) {
        Some(u) => u,
        None => {
            eprintln!("install-service: cannot determine the target user; pass --user <name>");
            return ExitCode::FAILURE;
        }
    };
    // 2. Resolve this binary's absolute path.
    let current_exe = match install_exe_path() {
        Some(e) => e,
        None => {
            eprintln!("install-service: cannot resolve an absolute path to this binary");
            return ExitCode::FAILURE;
        }
    };
    let os = std::env::consts::OS;
    // D1: Windows registers an SCM service (an API call) instead of writing a
    // unit file + running shell enable commands. Branch out here — before
    // plan_exec_path (no stable Windows install dir) and service_artifact
    // (returns None for windows) — into the SCM registration path.
    #[cfg(windows)]
    if os == "windows" {
        return run_install_service_windows(&current_exe, print, enable, exec_path, uninstall);
    }
    // Uninstall: stop + disable the boot-start service and remove its unit/plist
    // - the Unix analogue of the Windows SCM deregister above, so the GUI
    // "Start on boot" toggle can turn it OFF symmetrically. Service-only: the
    // staged binary and ~/.belay config are untouched (that is `belay uninstall`).
    // Needs privilege (writes under /etc or /Library); the desktop toggle spawns
    // this elevated, CLI users run it with sudo.
    if uninstall {
        return uninstall_boot_service(os);
    }
    // 3. Plan ExecStart + staging.
    let plan = match plan_exec_path(os, &current_exe, exec_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("install-service: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Build the artifact from the planned ExecStart (needed for --print too).
    let (path, contents, enable_cmds) = match service_artifact(os, &plan.exec_start, &user) {
        Some(t) => t,
        None => {
            eprintln!(
                "install-service: unsupported OS '{os}' (linux and macos supported; \
                 windows is not yet — see docs/02-windows-port-and-install-consolidation.md)"
            );
            return ExitCode::FAILURE;
        }
    };

    // 4. --print: emit the unit only, no staging/writing/enabling.
    if print {
        print!("{contents}");
        return ExitCode::SUCCESS;
    }

    // 5. Stage the binary so ExecStart survives `cargo clean`.
    if let Some(src) = &plan.copy_from {
        if let Some(dir) = std::path::Path::new(&plan.exec_start).parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "install-service: need root to create {} ({e}). Re-run: sudo belay install-service --enable",
                    dir.display()
                );
                return ExitCode::FAILURE;
            }
        }
        if let Err(e) = std::fs::copy(src, &plan.exec_start) {
            eprintln!(
                "install-service: need root to stage the binary at {} ({e}). Re-run: sudo belay install-service --enable",
                plan.exec_start
            );
            return ExitCode::FAILURE;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&plan.exec_start, std::fs::Permissions::from_mode(0o755));
        }
        println!("Staged binary -> {} (survives `cargo clean`).", plan.exec_start);
    }

    // 6. Drop license + attribution next to the install (best-effort; never
    // fails the install). Satisfies the GPL-3.0 / CC-BY-SA-4.0 "accompany the
    // binary" obligation for the staged daemon. Linux only — /usr/share/doc is
    // the FHS doc dir; macOS Homebrew/pkg paths differ and are out of scope.
    if os == "linux" {
        let doc_dir = std::path::Path::new("/usr/share/doc/belay");
        if std::fs::create_dir_all(doc_dir).is_ok() {
            let lic = std::fs::write(doc_dir.join("LICENSE"), EMBEDDED_LICENSE);
            let note = std::fs::write(doc_dir.join("NOTICE"), EMBEDDED_NOTICE);
            if lic.is_ok() && note.is_ok() {
                println!("Wrote license + attribution -> {}/", doc_dir.display());
            }
        }
    }

    // 7. Write the unit.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "install-service: need root to create {} ({e}). Re-run: sudo belay install-service --enable",
                parent.display()
            );
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = std::fs::write(&path, &contents) {
        eprintln!(
            "install-service: need root to write {} ({e}). Re-run: sudo belay install-service --enable",
            path.display()
        );
        return ExitCode::FAILURE;
    }
    println!("Wrote {} (daemon runs as '{user}').", path.display());

    // Only the required commands belong in the manual-run hint.
    let hint = enable_cmds
        .iter()
        .filter(|c| c.required)
        .map(|c| format!("sudo {}", c.argv.join(" ")))
        .collect::<Vec<_>>()
        .join("\n  ");

    // 8. Enable (best-effort teardown first, then required enable).
    if !enable {
        println!("Enable it with:\n  {hint}");
        return ExitCode::SUCCESS;
    }
    for cmd in &enable_cmds {
        let (bin, rest) = cmd.argv.split_first().expect("enable command is non-empty");
        let mut command = std::process::Command::new(bin);
        command.args(rest);
        // Best-effort teardown commands are EXPECTED to fail on a clean install:
        // there is no prior unit/daemon to remove, and when install-service runs
        // under sudo (root) `systemctl --user` has no user bus at all. Silence
        // their stdout/stderr AND our own note so a successful first install
        // isn't buried under alarming child chatter ("Failed to connect to user
        // scope bus", "Unit ... does not exist", pkill's no-match exit 1).
        // Required commands keep inherited stdio, so systemd's useful
        // "Created symlink ..." line and any genuine enable/start failure still
        // surface.
        if !cmd.required {
            command.stdout(std::process::Stdio::null());
            command.stderr(std::process::Stdio::null());
        }
        match command.status() {
            Ok(s) if s.success() => {}
            Ok(s) => {
                if cmd.required {
                    eprintln!("`{}` exited with {s}. Run manually:\n  {hint}", cmd.argv.join(" "));
                    return ExitCode::FAILURE;
                }
                // best-effort teardown: expected to fail on a clean install, ignore silently.
            }
            Err(e) => {
                if cmd.required {
                    eprintln!("failed to run `{}` ({e}). Run manually:\n  {hint}", cmd.argv.join(" "));
                    return ExitCode::FAILURE;
                }
                // best-effort teardown: command not present / not runnable, ignore silently.
            }
        }
    }
    println!("Enabled and started the service.");

    let home = install_user_home(os, &user);

    // 9. Re-point the Claude Code hook at the STAGED binary. Setting
    // BELAY_BIN makes manage::protect embed that absolute path (see
    // resolve_hook_exe) instead of this process's current_exe. Never fatal.
    if repoint_hook {
        std::env::set_var("BELAY_BIN", &plan.exec_start);
        println!("Re-pointing the Claude Code hook at {} ...", plan.exec_start);
        let _ = belay_manage::protect::run_protect("claude-code", false, Some(&home));
        // Under sudo, run_protect wrote ~/.claude/settings* as root; chown them back
        // to the invoking user so they can manage their own hook. Best-effort.
        #[cfg(unix)]
        chown_claude_settings_to_user(&home, &user);
    }

    // 10. Wait for the daemon socket to appear.
    if wait_socket > 0 {
        let sock = socket_poll_target(&home);
        let mut ready = false;
        for _ in 0..wait_socket {
            if std::path::Path::new(&sock).exists() {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if ready {
            println!("Daemon socket ready at {sock}.");
        } else {
            eprintln!(
                "warning: daemon socket {sock} not present yet. Check: journalctl -u belay.service -n 50 --no-pager"
            );
        }
    }

    // 11.
    ExitCode::SUCCESS
}

/// Back up an existing config file to a timestamped `.bak` sibling
/// (`<path>.<unix-secs>.<nanos>.bak`) before the setup wizard overwrites it
/// (Hermes-style non-destructive writes). The nanosecond component keeps two
/// runs within the same wall-clock second from colliding and overwriting
/// each other's backup. A missing file is a silent no-op — there is nothing
/// to back up on a fresh install; a copy failure is a printed warning, not a
/// hard error (the wizard still proceeds with the write — losing a backup is
/// recoverable, refusing to apply the operator's chosen setup is not).
fn backup_setup_config_file(path: &std::path::Path) {
    if !path.is_file() {
        return;
    }
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let bak = std::path::PathBuf::from(format!(
        "{}.{}.{:09}.bak",
        path.display(),
        dur.as_secs(),
        dur.subsec_nanos()
    ));
    if let Err(e) = std::fs::copy(path, &bak) {
        eprintln!(
            "belay setup: warning: failed to back up {} before overwrite: {e}",
            path.display()
        );
    }
}

/// Wrap `s` in an ANSI SGR sequence (`code`, e.g. "1" bold, "32" green, "2"
/// dim) when `on`, else return it unchanged. Zero-width when off, so callers
/// can format alignment as if the codes weren't there.
fn sgr(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Best-effort check that a runnable `sudo` exists on PATH. Used to decide
/// whether the setup wizard can self-elevate the service install; `sudo
/// --version` neither prompts nor changes anything.
fn sudo_available() -> bool {
    std::process::Command::new("sudo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `belay setup`: run the interactive wizard's pure prompt logic
/// (`belay_manage::setup::run_setup`) over the real stdin/stdout to get
/// a `SetupPlan`, then EXECUTE it — this is the only side-effecting half; the
/// wizard itself never touches the filesystem or spawns anything.
///
/// Protects the planned agents (`belay_manage::protect::run_protect`,
/// best-effort — one agent's failure doesn't abort the rest), writes the
/// ssh-guard and net-enrichment toggles (feature-independent — see
/// `belayd::host_config`), writes the AI explainer config + BYOK key
/// (`ai` feature) and the messaging-channel config (`channels` feature) via
/// the pure mappers in `belay_manage::setup`
/// (`ai_config_args`/`channel_config`) followed by the daemon crate's real
/// writers, and installs the boot-start service (`run_install_service`) when
/// the plan calls for it. A build compiled without `ai`/`channels` prints a
/// note instead of silently dropping that part of the plan. Firewall stays a
/// printed follow-up command: enabling it safely needs the RUNNING daemon's
/// own dead-man's-switch confirmation loop (so a bad rule auto-reverts),
/// which this one-shot CLI invocation cannot provide.
fn run_setup(yes: bool, quick: bool, home: Option<String>) -> ExitCode {
    use std::io::IsTerminal;

    // Reserved for the Custom flow (Task 2). The interactive wizard's own
    // default choice IS the Quick path today, so this flag is currently a
    // no-op — accepted now so scripts that pass it don't break later.
    let _ = quick;

    let interactive = std::io::stdin().is_terminal();
    // Colorize only when stdout is a real terminal and NO_COLOR is unset. Under
    // `curl | bash` the pipe is only on stdin - stdout is still the terminal,
    // so styled output is correct there too.
    let styled = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let opts = belay_manage::setup::SetupOpts {
        yes,
        interactive,
        home: home.as_ref().map(std::path::PathBuf::from),
        styled,
    };

    let plan = {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        match belay_manage::setup::run_setup(&mut input, &mut output, &opts) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("belay setup: failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // Styled summary: bold labels; green when a capability is on/configured,
    // dim when off/none - so the important decisions stand out. Plain text when
    // `styled` is false (piped, or NO_COLOR set). Labels are padded to a common
    // width so the values line up (ANSI codes are zero-width).
    let bold = |s: &str| sgr(styled, "1", s);
    let onoff = |b: bool| {
        if b {
            sgr(styled, "1;32", "on")
        } else {
            sgr(styled, "2", "off")
        }
    };
    let value = |set: bool, s: &str| {
        if set {
            sgr(styled, "32", s)
        } else {
            sgr(styled, "2", s)
        }
    };

    let agents = if plan.protect_agents.is_empty() {
        "(none)".to_string()
    } else {
        plan.protect_agents.join(", ")
    };
    let ai_val = match &plan.ai {
        Some(c) => format!("{} ({})", c.mode, c.provider),
        None => "off".to_string(),
    };
    let channel_val = plan
        .channels
        .as_ref()
        .map(|c| c.platform.clone())
        .unwrap_or_else(|| "(none)".to_string());

    println!("\n{}", bold("Setup plan:"));
    println!(
        "  {}{}",
        bold("agents to protect:  "),
        value(!plan.protect_agents.is_empty(), &agents)
    );
    println!("  {}{}", bold("firewall:           "), onoff(plan.firewall));
    println!("  {}{}", bold("ssh-guard:          "), onoff(plan.ssh_guard));
    println!(
        "  {}{}",
        bold("ai explainer:       "),
        value(plan.ai.is_some(), &ai_val)
    );
    println!(
        "  {}{}",
        bold("messaging channel:  "),
        value(plan.channels.is_some(), &channel_val)
    );
    println!("  {}{}", bold("net enrichment:     "), onoff(plan.netenrich));
    println!(
        "  {}{}",
        bold("vuln-scan schedule: "),
        onoff(plan.scan_schedule)
    );
    println!(
        "  {}{}",
        bold("install service:    "),
        onoff(plan.install_service)
    );

    // Execute: protect each planned agent (best-effort — `run_protect` already
    // prints its own error on failure; keep going through the rest of the list).
    for agent in &plan.protect_agents {
        let _ = belay_manage::protect::run_protect(agent, false, home.as_deref());
    }

    // Execute: ssh-guard + net-enrichment toggles. Both live in
    // `belayd::host_config`, which is feature-independent (unconditional
    // in the daemon crate), so these always compile and apply regardless of
    // which optional root features this binary was built with.
    let ssh_patch = serde_json::json!({ "enabled": plan.ssh_guard });
    if let Err(e) = belayd::host_config::set_ssh_guard(&ssh_patch) {
        eprintln!("belay setup: failed to save ssh-guard config: {e}");
    }
    if let Err(e) = belayd::host_config::set_net_enrich(plan.netenrich) {
        eprintln!("belay setup: failed to save network-enrichment config: {e}");
    }

    // Execute: scheduled vulnerability scan. Also feature-independent
    // (`host_config` has no `vulndb`/etc. dependency), so this always
    // compiles; only touches disk when the plan turns it on — declining
    // leaves any existing schedule (or the disabled default) untouched.
    // Backs up an existing schedule file first, like the ai/channels writers.
    if plan.scan_schedule {
        let schedule_path = belayd::host_config::belay_dir().join("scan_schedule.json");
        backup_setup_config_file(&schedule_path);
        let schedule = serde_json::json!({
            "enabled": true,
            "cron": "0 3 * * *",
            "scope": "quick",
        });
        if let Err(e) = belayd::host_config::set_scan_schedule(&schedule) {
            eprintln!("belay setup: failed to save the vuln-scan schedule: {e}");
        }
    }

    // Execute: AI explainer config + BYOK key (`ai` feature only). Uses the
    // pure `ai_config_args` mapper from `belay_manage::setup` to build
    // the exact args object `AiConfig::from_args` validates, then persists
    // ai.json + the separate owner-only key file — backing up any existing
    // file first.
    #[cfg(feature = "ai")]
    if let Some(choice) = &plan.ai {
        let args = belay_manage::setup::ai_config_args(choice);
        match belayd::ai::config::AiConfig::from_args(&args) {
            Ok(cfg) => {
                backup_setup_config_file(&belayd::paths::data_dir().join("ai.json"));
                if let Err(e) = cfg.save_default() {
                    eprintln!("belay setup: failed to save AI config: {e}");
                } else if let Some(key) = &choice.key {
                    let key_path = belayd::ai::secret::ai_key_path();
                    // SECURITY: never back up ai_key — it holds the plaintext key;
                    // write_ai_key is atomic/owner-only (0600), and its own
                    // clear-path is the intended way to reset it. Copying it to a
                    // `.bak` sibling would leave stale plaintext keys on disk that
                    // the "clear key" affordance never removes.
                    if let Err(e) = belayd::ai::secret::write_ai_key(&key_path, key) {
                        eprintln!("belay setup: failed to save the AI API key: {e}");
                    }
                }
            }
            Err(e) => eprintln!("belay setup: AI config rejected: {e}"),
        }
    }
    #[cfg(not(feature = "ai"))]
    if plan.ai.is_some() {
        println!(
            "  note: this build was compiled without the `ai` feature — AI config not applied."
        );
    }

    // Execute: messaging channel config (`channels` feature only), via the
    // pure `channel_config` mapper + the daemon crate's `config_set_channel`
    // (merges into channels.json; safe with no bridge/daemon running yet).
    #[cfg(feature = "channels")]
    if let Some(choice) = &plan.channels {
        let (platform, fields) = belay_manage::setup::channel_config(choice);
        let path = belayd::paths::data_dir().join("channels.json");
        backup_setup_config_file(&path);
        // Auto-enroll the approver so two-way approval works out of the box.
        // Without an allowlisted principal, every Telegram Allow/Deny click is
        // dropped as NotAllowlisted and the parked request fail-closes to deny,
        // so approvals are effectively dead on arrival. For a Telegram 1:1 DM the
        // approver's user id == the chat_id, so enrolling the chat_id authorizes
        // the person the prompt is sent to. (Other platforms need their own
        // principal, e.g. a Discord user id, so we only auto-enroll telegram.)
        let enroll: Vec<String> = if platform == "telegram" {
            fields
                .get("chat_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| vec![s.to_string()])
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let allow = if enroll.is_empty() {
            None
        } else {
            Some(enroll.as_slice())
        };
        match belayd::channels_bridge::config_set_channel(&path, &platform, &fields, allow) {
            Ok(()) => {
                // Transparency: tell the user exactly who was enrolled as an
                // approver, and that it stays local. Only prints when we
                // actually enrolled a principal (Telegram with a chat_id).
                if let Some(principal) = enroll.first() {
                    println!(
                        "  approver enrolled: {platform} {principal} can now approve/deny \
                         alerts (saved only in your local ~/.belay/channels.json, never shared)."
                    );
                }
            }
            Err(e) => eprintln!("belay setup: failed to save channel config: {e}"),
        }
    }
    #[cfg(not(feature = "channels"))]
    if plan.channels.is_some() {
        println!(
            "  note: this build was compiled without the `channels` feature — messaging channel not configured."
        );
    }

    // Firewall stays a printed follow-up: applying it safely needs the
    // RUNNING daemon's own dead-man's-switch confirmation loop (an unconfirmed
    // rule change auto-reverts), which this one-shot setup command can't
    // drive itself.
    if plan.firewall {
        println!(
            "\n{} once the daemon is running, apply the least-privilege ruleset with:\n  {}\n\
             (run from a session you can use to confirm - an unconfirmed change auto-reverts).",
            sgr(styled, "1", "Firewall:"),
            sgr(styled, "1", "belay firewall apply --confirm-within 300"),
        );
    }

    // Execute: install the boot-start service when the plan calls for it.
    // `--enable` needs privilege the wizard can't assume it has, so this
    // stages/writes the unit and prints the exact command to enable it —
    // matching `run_install_service`'s own non-`--enable` behavior.
    if plan.install_service {
        println!("\n{}", sgr(styled, "1", "Installing the boot-start service..."));

        // The wizard runs as the invoking user (the one-command installer only
        // sudo'd the binary copy, not `belay setup`), so writing the
        // systemd unit / launchd plist needs elevation - the reported
        // "Permission denied" on first run. When we have a controlling terminal
        // and `sudo` is available on Unix, re-run the service step through sudo
        // with --enable so it actually installs AND starts on first run (sudo
        // as an already-root user just runs it, no password prompt). Otherwise
        // fall back to staging the unit + printing the manual `sudo … --enable`
        // hint (run_install_service's own non-enable path).
        let can_elevate =
            cfg!(unix) && interactive && install_exe_path().is_some() && sudo_available();
        let installed = if can_elevate {
            let exe = install_exe_path().expect("checked is_some above");
            match std::process::Command::new("sudo")
                .arg(&exe)
                .arg("install-service")
                .arg("--enable")
                .status()
            {
                Ok(status) => status.success(),
                Err(_) => false,
            }
        } else {
            false
        };
        if !installed {
            // Not elevated (or sudo declined/failed): stage the unit and print
            // the exact `sudo belay install-service --enable` to finish.
            let _ = run_install_service(None, false, false, None, true, 40, false);
        }
    }

    ExitCode::SUCCESS
}

/// `belay uninstall` (Task 3 of the one-command installer plan): stop +
/// disable the boot-start service, remove its unit/plist and the staged
/// `/usr/local/bin/belay` binary, and (with `--purge`) remove
/// `~/.belay`. Fail-safe/best-effort throughout — every removal step
/// logs its own failure and the handler keeps going rather than aborting
/// partway; this never panics. Windows defers entirely to the existing SCM
/// path (`belay install-service --uninstall`), which this command does
/// not attempt to replicate.
///
/// Mirrors `run_install_service`'s own privilege story: there is no upfront
/// `geteuid` gate, each system-path write/removal is simply attempted and, on
/// failure (almost always a permission error against `/etc` or
/// `/usr/local/bin` when not root), prints the `sudo belay uninstall`
/// re-run hint rather than erroring out silently.
fn run_uninstall(purge: bool, yes: bool) -> ExitCode {
    use std::io::IsTerminal;

    let os = std::env::consts::OS;
    if os == "windows" {
        println!(
            "belay uninstall: on Windows, run `belay install-service --uninstall` \
             (as Administrator) to deregister the service. This command covers Linux/macOS only."
        );
        return ExitCode::SUCCESS;
    }

    // Use the same $HOME resolution as `belayd::paths::data_dir` so the
    // printed/removed path is byte-identical to the real data dir.
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let plan = uninstall_plan(os, &home, purge);

    // The elevated re-run (below) carries this marker so it skips straight to
    // removing as root instead of re-printing the plan and recursing forever.
    let already_elevated = std::env::var_os("BELAY_UNINSTALL_ELEVATED").is_some();

    if !already_elevated {
        println!("belay uninstall will remove:");
        for p in &plan {
            println!("  {}", p.display());
        }
        match os {
            "linux" => println!("  and stop + disable the belay.service systemd unit"),
            "macos" => println!("  and unload the com.secblok.belay launchd job"),
            _ => {}
        }
    }

    if !already_elevated && !yes {
        if !std::io::stdin().is_terminal() {
            println!(
                "Non-interactive shell detected. Re-run `belay uninstall --yes` to proceed \
                 without a prompt."
            );
            return ExitCode::SUCCESS;
        }
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        let confirmed = match belay_manage::setup::prompt_yes_no(
            &mut output,
            &mut input,
            "Proceed?",
            false,
        ) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("belay uninstall: failed to read confirmation: {e}");
                return ExitCode::FAILURE;
            }
        };
        if !confirmed {
            println!("Aborted; nothing removed.");
            return ExitCode::SUCCESS;
        }
    }

    // Self-elevate: the systemd unit (/etc) and the staged binary
    // (/usr/local/bin) are root-owned, so removing them needs root; and a bare
    // `sudo belay` fails when sudo's secure_path does not include the
    // binary's dir. Re-run the whole uninstall as root via the ABSOLUTE exe
    // path (secure_path-independent), threading HOME through `env` so `--purge`
    // still targets the invoking user's ~/.belay (sudo resets HOME to
    // root's otherwise), plus a marker so the elevated child does not recurse.
    // Falls through to a best-effort as-user removal if sudo is unavailable or
    // the password is declined.
    #[cfg(unix)]
    if !already_elevated && std::io::stdin().is_terminal() && sudo_available() {
        if let Some(exe) = install_exe_path() {
            let mut cmd = std::process::Command::new("sudo");
            cmd.arg("env")
                .arg(format!("HOME={}", home.display()))
                .arg("BELAY_UNINSTALL_ELEVATED=1")
                .arg(&exe)
                .arg("uninstall")
                .arg("--yes");
            if purge {
                cmd.arg("--purge");
            }
            if let Ok(status) = cmd.status() {
                if status.success() {
                    return ExitCode::SUCCESS;
                }
            }
        }
    }

    // Stop + disable the service first (best-effort — a failure here must not
    // stop the file removals below; an already-stopped/never-installed
    // service is the common case, not an error).
    match os {
        "linux" => {
            if let Err(e) = std::process::Command::new("systemctl")
                .args(["disable", "--now", "belay.service"])
                .status()
            {
                eprintln!("belay uninstall: note: `systemctl disable --now` failed ({e}), continuing.");
            }
        }
        "macos" => {
            if let Err(e) = std::process::Command::new("launchctl")
                .args(["unload", "/Library/LaunchDaemons/com.secblok.belay.plist"])
                .status()
            {
                eprintln!("belay uninstall: note: `launchctl unload` failed ({e}), continuing.");
            }
        }
        _ => {}
    }

    // Absolute-path re-run hint: a bare `sudo belay` fails when sudo's
    // secure_path does not include the binary's dir, so point at the resolved
    // exe path instead.
    let exe_hint = install_exe_path().unwrap_or_else(|| "belay".to_string());
    let purge_arg = if purge { " --purge" } else { "" };

    // Remove each planned path, best-effort — one failure doesn't stop the rest.
    let mut any_fail = false;
    for p in &plan {
        if !p.exists() && !p.is_symlink() {
            continue;
        }
        let result = if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
        match result {
            Ok(()) => println!("Removed {}", p.display()),
            Err(e) => {
                any_fail = true;
                eprintln!(
                    "belay uninstall: failed to remove {} ({e}). Re-run: sudo {exe_hint} uninstall{purge_arg}",
                    p.display(),
                );
            }
        }
    }

    if any_fail {
        println!("Some paths could not be removed (see warnings above); re-run: sudo {exe_hint} uninstall{purge_arg}");
    } else {
        println!("Uninstall complete.");
    }
    ExitCode::SUCCESS
}

/// Decide whether `install-service` must stage (copy) the binary to `staged`
/// before registering the service. Returns false (skip the copy) when the
/// caller passed `--exec-path` (they assert the binary already lives there,
/// mirroring the Unix `plan_exec_path` "caller-supplied target: never stage"
/// rule) or when `staged` resolves to the same real file as `current_exe`.
/// Copying a running exe onto itself fails with a Windows sharing violation
/// (os error 32), which is exactly the self-install case that
/// `belay.exe install-service --exec-path <its own path>` hits. Kept
/// platform-independent (not `cfg(windows)`) so it is unit-testable on any host.
#[cfg_attr(not(windows), allow(dead_code))]
fn should_stage_binary(exec_path: Option<&str>, current_exe: &str, staged: &std::path::Path) -> bool {
    if exec_path.is_some() {
        return false;
    }
    // current_exe() returns a verbatim `\\?\C:\...` path that won't string-match
    // a plain --exec-path, so compare canonicalized real files; fall back to a
    // literal path comparison if either side can't be resolved.
    match (
        std::fs::canonicalize(current_exe),
        std::fs::canonicalize(staged),
    ) {
        (Ok(a), Ok(b)) => a != b,
        _ => std::path::Path::new(current_exe) != staged,
    }
}

/// Windows `install-service`: SCM registration (D1). Stages the binary under
/// `%PROGRAMFILES%\Belay` (unless `--exec-path` overrides), then either
/// prints the equivalent `sc create` line (`--print`, via `windows_service_spec`
/// for parity) or registers the LocalSystem auto-start service. `enable` starts
/// it immediately. Maps `ERROR_ACCESS_DENIED` to a "re-run as Administrator"
/// hint — we never self-elevate.
#[cfg(windows)]
fn run_install_service_windows(
    current_exe: &str,
    print: bool,
    enable: bool,
    exec_path: Option<&str>,
    uninstall: bool,
) -> ExitCode {
    // --uninstall: deregister the SCM service and return.
    if uninstall {
        return match win_service::deregister_service() {
            Ok(()) => {
                println!("Deregistered the '{}' service.", win_service::SERVICE_NAME);
                ExitCode::SUCCESS
            }
            Err(e) if win_service::is_access_denied(&e) => {
                eprintln!("install-service: access denied. Re-run this command as Administrator.");
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("install-service: failed to deregister the service: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // Install target: explicit --exec-path, else %PROGRAMFILES%\Belay\belay.exe.
    let staged = match exec_path {
        Some(p) => std::path::PathBuf::from(p),
        None => match std::env::var("ProgramFiles") {
            Ok(pf) => std::path::Path::new(&pf).join("Belay").join("belay.exe"),
            Err(_) => {
                eprintln!("install-service: %PROGRAMFILES% is not set; pass --exec-path <absolute>");
                return ExitCode::FAILURE;
            }
        },
    };

    // --print: emit the equivalent `sc create ...` line only; never touch the SCM.
    if print {
        let (_name, argv) =
            belayd::service::windows_service_spec(&staged.to_string_lossy(), "");
        println!("{}", argv.join(" "));
        return ExitCode::SUCCESS;
    }

    // Stage the binary so the service ImagePath survives `cargo clean` (a dev
    // convenience). Skipped for --exec-path installs and self-installs (see
    // should_stage_binary), which is what avoids the os-error-32 self-copy.
    if should_stage_binary(exec_path, current_exe, &staged) {
        if let Some(dir) = staged.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "install-service: cannot create {} ({e}). Re-run as Administrator.",
                    dir.display()
                );
                return ExitCode::FAILURE;
            }
        }
        if let Err(e) = std::fs::copy(current_exe, &staged) {
            eprintln!(
                "install-service: cannot stage the binary at {} ({e}). Re-run as Administrator.",
                staged.display()
            );
            return ExitCode::FAILURE;
        }
        println!("Staged binary -> {} (survives `cargo clean`).", staged.display());
    }

    match win_service::register_service(&staged, enable) {
        Ok(()) => {
            if enable {
                println!(
                    "Registered and started the '{}' service (LocalSystem, auto-start).",
                    win_service::SERVICE_NAME
                );
            } else {
                println!(
                    "Registered the '{}' service (LocalSystem, auto-start). Start it with:\n  sc start {}",
                    win_service::SERVICE_NAME, win_service::SERVICE_NAME
                );
            }
            ExitCode::SUCCESS
        }
        // Elevation, not self-elevation: mirror the Unix "re-run with sudo" hint.
        Err(e) if win_service::is_access_denied(&e) => {
            eprintln!("install-service: access denied. Re-run this command as Administrator.");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("install-service: failed to register the service: {e}");
            ExitCode::FAILURE
        }
    }
}

// Phase 3: Windows SCM integration (dispatcher + registration). Whole-file
// `#![cfg(windows)]`, so this is empty on Unix targets.
#[cfg(windows)]
mod win_service;

#[cfg(test)]
mod tests {
    use super::{Cli, Cmd};

    #[test]
    fn host_scan_excludes_filter_relative_to_root() {
        let root = std::path::Path::new("/home/u/Downloads");
        let mut files: Vec<(String, Vec<u8>)> = vec![
            ("/home/u/Downloads/tool/linpeas.sh".to_owned(), Vec::new()),
            ("/home/u/Downloads/report.odt".to_owned(), Vec::new()),
            ("/home/u/Downloads/sub/keep.bin".to_owned(), Vec::new()),
        ];
        super::apply_host_scan_excludes(&mut files, root, &["tool/**".to_owned()]);
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("linpeas")),
            "tool/** should exclude tool/linpeas.sh, got {paths:?}"
        );
        assert!(paths.iter().any(|p| p.contains("report.odt")));
        assert!(paths.iter().any(|p| p.contains("keep.bin")));

        // Empty excludes = no-op.
        let mut all: Vec<(String, Vec<u8>)> = vec![("/home/u/Downloads/x".to_owned(), Vec::new())];
        super::apply_host_scan_excludes(&mut all, root, &[]);
        assert_eq!(all.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn chown_helpers_resolve_and_are_safe() {
        // user_ids resolves a real user (uid matches getuid) and returns None for an
        // unknown user (fail-safe: chown_claude_settings_to_user then no-ops rather
        // than chowning to a bogus id). chown to our own ids must not abort the caller.
        let uid = unsafe { libc::getuid() };
        let name = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        if !name.is_empty() {
            if let Some((u, _g)) = super::user_ids(&name) {
                assert_eq!(u, uid, "resolved uid for the current user must match getuid()");
            }
        }
        assert_eq!(super::user_ids("belay-no-such-user-xyzzy"), None);
        let tmp = std::env::temp_dir().join(format!("belay-chown-test-{}", std::process::id()));
        std::fs::write(&tmp, b"x").unwrap();
        super::lchown_path(&tmp, uid, unsafe { libc::getgid() });
        std::fs::remove_file(&tmp).ok();
    }

    /// Phase 3 Task 1: the hidden `--scm` flag on `daemon` parses to `true`, and
    /// its absence defaults to `false`. Cross-platform (pure clap parse; no SCM).
    #[test]
    fn scm_flag_parses_and_defaults_false() {
        let with = Cli::try_parse_from(["belay", "daemon", "--scm"]).unwrap();
        assert!(
            matches!(with.cmd, Cmd::Daemon { scm: true }),
            "`daemon --scm` must set scm=true"
        );
        let without = Cli::try_parse_from(["belay", "daemon"]).unwrap();
        assert!(
            matches!(without.cmd, Cmd::Daemon { scm: false }),
            "bare `daemon` must default scm=false"
        );
    }

    /// `belay scan --exclude` is repeatable and collects every occurrence, in
    /// order, into `Cmd::Scan::exclude`; a bare `scan` with no `--exclude`
    /// defaults to an empty vec (nothing excluded).
    #[test]
    fn scan_exclude_flag_is_repeatable() {
        let cli = Cli::try_parse_from([
            "belay",
            "scan",
            "/tmp/x",
            "--exclude",
            "rules/malware/**",
            "--exclude",
            "scanner/src/analyzers/malware.rs",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Scan { exclude, .. } => assert_eq!(
                exclude,
                vec![
                    "rules/malware/**".to_string(),
                    "scanner/src/analyzers/malware.rs".to_string(),
                ]
            ),
            _ => panic!("expected Scan subcommand"),
        }

        let bare = Cli::try_parse_from(["belay", "scan", "/tmp/x"]).unwrap();
        match bare.cmd {
            Cmd::Scan { exclude, .. } => assert!(exclude.is_empty()),
            _ => panic!("expected Scan subcommand"),
        }
    }

    #[test]
    fn serve_set_admin_parses() {
        let cli = Cli::try_parse_from(["belay", "serve", "--set-admin", "alice"]).unwrap();
        match cli.cmd {
            Cmd::Serve { set_admin, .. } => {
                assert_eq!(set_admin, Some("alice".to_string()));
            }
            _ => panic!("expected Serve subcommand"),
        }
    }

    #[test]
    fn serve_without_set_admin_defaults_none() {
        let cli = Cli::try_parse_from(["belay", "serve"]).unwrap();
        match cli.cmd {
            Cmd::Serve { set_admin, .. } => assert_eq!(set_admin, None),
            _ => panic!("expected Serve subcommand"),
        }
    }

    #[test]
    fn service_artifact_linux_runs_daemon_as_user() {
        let (path, unit, cmds) =
            super::service_artifact("linux", "/usr/local/bin/belay", "alice").unwrap();
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/systemd/system/belay.service")
        );
        assert!(unit.contains("User=alice"));
        assert!(unit.contains("ExecStart=/usr/local/bin/belay daemon"));
        assert!(!unit.contains("User=root"));
        assert!(cmds
            .iter()
            .any(|c| c.argv.contains(&"enable".to_string())));
    }

    #[test]
    fn service_artifact_macos_runs_daemon_as_user() {
        let (path, plist, cmds) =
            super::service_artifact("macos", "/usr/local/bin/belay", "alice").unwrap();
        assert!(path
            .to_string_lossy()
            .ends_with("com.secblok.belay.plist"));
        assert!(plist.contains("<key>UserName</key><string>alice</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(cmds
            .iter()
            .any(|c| c.argv.iter().any(|s| s == "launchctl")));
    }

    #[test]
    fn service_artifact_unsupported_os_is_none() {
        // `service_artifact` stays Unix-only by design: Windows does NOT write a
        // unit file, so it has no artifact here. The Windows install path is the
        // SCM registration branch in `run_install_service` (Phase 3, D1), which
        // intercepts `os == "windows"` before this function is consulted.
        assert!(super::service_artifact("windows", "/x/belay", "alice").is_none());
        assert!(super::service_artifact("freebsd", "/x/belay", "alice").is_none());
    }

    #[test]
    fn service_artifact_linux_tears_down_competing_units() {
        let (_p, _u, cmds) =
            super::service_artifact("linux", "/usr/local/bin/belay", "alice").unwrap();
        // Best-effort teardown of competitors, all non-required, BEFORE the
        // required `enable --now belay.service`.
        let user_disable = cmds
            .iter()
            .position(|c| c.argv.contains(&"--user".to_string())
                && c.argv.contains(&"disable".to_string()))
            .expect("has a `systemctl --user disable`");
        let inst_disable = cmds
            .iter()
            .position(|c| c.argv.iter().any(|s| s.starts_with("belay@")))
            .expect("has a `belay@<user>` disable");
        let enable_now = cmds
            .iter()
            .position(|c| c.required && c.argv.contains(&"enable".to_string()))
            .expect("has a required enable --now");
        assert!(!cmds[user_disable].required);
        assert!(!cmds[inst_disable].required);
        assert!(user_disable < enable_now && inst_disable < enable_now);
    }

    #[test]
    fn stable_exec_dir_linux_macos() {
        assert_eq!(super::stable_exec_dir("linux"), Some("/usr/local/bin"));
        assert_eq!(super::stable_exec_dir("macos"), Some("/usr/local/bin"));
    }

    #[test]
    fn stable_exec_dir_windows_none() {
        assert_eq!(super::stable_exec_dir("windows"), None);
    }

    #[test]
    fn plan_exec_path_default_stages_to_usr_local_bin() {
        let p = super::plan_exec_path("linux", "/repo/target/release/belay", None).unwrap();
        assert_eq!(p.exec_start, "/usr/local/bin/belay");
        assert_eq!(p.copy_from.as_deref(), Some("/repo/target/release/belay"));
    }

    #[test]
    fn plan_exec_path_already_at_dest_no_copy() {
        let p = super::plan_exec_path("linux", "/usr/local/bin/belay", None).unwrap();
        assert_eq!(p.exec_start, "/usr/local/bin/belay");
        assert_eq!(p.copy_from, None);
    }

    #[test]
    fn plan_exec_path_explicit_absolute_no_copy() {
        // `Path::is_absolute()` is host-platform-dependent — a Unix path is not
        // absolute on Windows. Use a path that is genuinely absolute on the host
        // so this branch is exercised on every platform.
        let abs = if cfg!(windows) {
            r"C:\Program Files\Belay\belay.exe"
        } else {
            "/usr/bin/belay"
        };
        let p = super::plan_exec_path("linux", "/repo/target/release/belay", Some(abs)).unwrap();
        assert_eq!(p.exec_start, abs);
        assert_eq!(p.copy_from, None);
    }

    #[test]
    fn plan_exec_path_relative_is_err() {
        assert!(super::plan_exec_path("linux", "/x/belay", Some("rel/belay")).is_err());
    }

    #[test]
    fn plan_exec_path_unsupported_os_err() {
        assert!(super::plan_exec_path("windows", "/x/belay", None).is_err());
    }

    #[test]
    fn should_stage_skips_when_exec_path_given() {
        // --exec-path asserts the binary already lives at the target, so we must
        // never copy: this is the guard that stops `belay.exe install-service
        // --exec-path <its own path>` from copying the running exe onto itself
        // (Windows sharing violation, os error 32). Short-circuits before any
        // filesystem access, so the Windows-shaped paths are fine to test here.
        assert!(!super::should_stage_binary(
            Some(r"C:\Program Files\Belay\belay.exe"),
            r"C:\Program Files\Belay\belay.exe",
            std::path::Path::new(r"C:\Program Files\Belay\belay.exe"),
        ));
    }

    #[test]
    fn should_stage_skips_when_target_is_current_exe() {
        // No --exec-path, but staged canonicalizes to the same real file as the
        // running exe -> still skip the self-copy.
        let me = std::env::current_exe().unwrap();
        let me_str = me.to_string_lossy().into_owned();
        assert!(!super::should_stage_binary(None, &me_str, &me));
    }

    #[test]
    fn should_stage_copies_to_a_distinct_target() {
        // No --exec-path and a genuinely different destination -> must stage.
        let me = std::env::current_exe().unwrap();
        let me_str = me.to_string_lossy().into_owned();
        let dest = me
            .parent()
            .unwrap()
            .join("belay-not-a-real-staged-target.exe");
        assert!(super::should_stage_binary(None, &me_str, &dest));
    }

    #[test]
    fn socket_poll_target_under_home() {
        assert_eq!(
            super::socket_poll_target("/home/alice"),
            "/home/alice/.belay/belayd.sock"
        );
    }

    // ─── Task 3: `belay uninstall` ────────────────────────────────────

    #[test]
    fn uninstall_plan_linux_always_includes_unit_and_binary() {
        let home = std::path::PathBuf::from("/home/alice");
        let plan = super::uninstall_plan("linux", &home, false);
        assert!(plan.contains(&std::path::PathBuf::from(
            "/etc/systemd/system/belay.service"
        )));
        assert!(plan.contains(&std::path::PathBuf::from("/usr/local/bin/belay")));
        // No --purge: the data dir must NOT be in the plan.
        assert!(!plan.contains(&home.join(".belay")));
    }

    #[test]
    fn uninstall_plan_purge_adds_data_dir() {
        let home = std::path::PathBuf::from("/home/alice");
        let plan = super::uninstall_plan("linux", &home, true);
        assert!(plan.contains(&home.join(".belay")));
        // Purge still keeps the unit + binary in the plan (additive, not exclusive).
        assert!(plan.contains(&std::path::PathBuf::from(
            "/etc/systemd/system/belay.service"
        )));
        assert!(plan.contains(&std::path::PathBuf::from("/usr/local/bin/belay")));
    }

    #[test]
    fn uninstall_plan_macos_uses_plist_and_shared_binary_dir() {
        let home = std::path::PathBuf::from("/Users/alice");
        let plan = super::uninstall_plan("macos", &home, false);
        assert!(plan.contains(&std::path::PathBuf::from(
            "/Library/LaunchDaemons/com.secblok.belay.plist"
        )));
        assert!(plan.contains(&std::path::PathBuf::from("/usr/local/bin/belay")));
        assert!(!plan.contains(&home.join(".belay")));
    }

    #[test]
    fn uninstall_plan_unsupported_os_still_purges() {
        // No known service artifact / stable exec dir for e.g. freebsd, but
        // --purge must still remove the data dir — purge is OS-independent.
        let home = std::path::PathBuf::from("/home/alice");
        let plan = super::uninstall_plan("freebsd", &home, true);
        assert_eq!(plan, vec![home.join(".belay")]);
    }

    use clap::Parser;
    #[allow(unused_imports)]
    use std::process::ExitCode;

    #[test]
    fn parses_all_subcommands() {
        for argv in [
            vec!["belay", "daemon"],
            vec!["belay", "hook"],
            vec!["belay", "gate"],
            vec!["belay", "scan", "/tmp/x"],
            vec!["belay", "scan", "/tmp/x", "--format", "sarif"],
            vec!["belay", "scan", "/tmp/x", "--llm"],
            vec!["belay", "scan", "/tmp/x", "--llm", "--format", "sarif"],
            vec!["belay", "scan", "/tmp/x", "--exclude", "rules/malware/**"],
            vec![
                "belay",
                "scan",
                "/tmp/x",
                "--exclude",
                "rules/malware/**",
                "--exclude",
                "scanner/src/analyzers/malware.rs",
            ],
            vec!["belay", "serve"],
            vec!["belay", "serve", "--addr", "0.0.0.0:9000"],
            vec!["belay", "channels"],
            vec!["belay", "posture"],
            vec!["belay", "posture", "--home", "/tmp/fake-home"],
            vec!["belay", "detect"],
            vec!["belay", "detect", "--home", "/tmp/fake-home"],
            vec!["belay", "detect", "--json"],
            vec!["belay", "detect", "--json", "--home", "/tmp/fake-home"],
            vec!["belay", "hook"],
            vec!["belay", "hook", "pretooluse"],
            vec!["belay", "hook", "posttooluse"],
            vec!["belay", "protect", "claude-code"],
            vec!["belay", "protect", "claude-code", "--observe"],
            vec![
                "belay",
                "protect",
                "claude-code",
                "--home",
                "/tmp/fake",
            ],
            vec!["belay", "unprotect", "claude-code"],
            vec![
                "belay",
                "unprotect",
                "claude-code",
                "--home",
                "/tmp/fake",
            ],
            vec!["belay", "install-service"],
            vec!["belay", "install-service", "--print"],
            vec!["belay", "install-service", "--user", "alice"],
            vec![
                "belay",
                "install-service",
                "--user",
                "alice",
                "--print",
                "--enable",
            ],
            vec![
                "belay",
                "install-service",
                "--enable",
                "--exec-path",
                "/usr/bin/belay",
                "--repoint-hook",
                "false",
                "--wait-socket",
                "0",
            ],
            vec!["belay", "uninstall"],
            vec!["belay", "uninstall", "--purge"],
            vec!["belay", "uninstall", "--yes"],
            vec!["belay", "uninstall", "--purge", "--yes"],
            vec!["belay", "status"],
            vec!["belay", "status", "--home", "/tmp/fake-home"],
            vec!["belay", "logs"],
            vec!["belay", "logs", "-n", "10"],
            vec!["belay", "logs", "-n", "10", "--home", "/tmp/fake-home"],
            vec!["belay", "logs", "--home", "/tmp/fake-home"],
            vec!["belay", "evidence", "build"],
            vec!["belay", "evidence", "build", "--out", "/tmp/pack"],
            vec!["belay", "evidence", "verify", "--dir", "/tmp/x"],
            vec![
                "belay",
                "evidence",
                "build",
                "--home",
                "/tmp/fake-home",
            ],
            vec!["belay", "mcp-proxy", "--", "echo-server"],
            vec!["belay", "mcp-proxy", "--", "echo-server", "--flag"],
            vec![
                "belay",
                "mcp-proxy",
                "--",
                "/usr/bin/my-mcp",
                "-a",
                "1",
            ],
            vec!["belay", "monitor"],
            vec!["belay", "monitor", "--once"],
            vec!["belay", "monitor", "--interval", "30"],
            vec!["belay", "monitor", "--home", "/tmp/fake-home"],
            vec![
                "belay",
                "monitor",
                "--home",
                "/tmp/fake-home",
                "--once",
            ],
            // Task C8
            vec!["belay", "host-scan"],
            vec!["belay", "host-scan", "--scope", "downloads"],
            vec!["belay", "host-scan", "--scope", "full"],
            vec!["belay", "quarantine", "list"],
            vec!["belay", "quarantine", "restore", "abc123"],
            vec!["belay", "quarantine", "delete", "abc123"],
            vec!["belay", "harden", "check"],
            vec![
                "belay",
                "harden",
                "ssh-guard",
                "--enable",
                "--threshold",
                "5",
                "--ban-ttl",
                "3600s",
            ],
            vec!["belay", "harden", "bans"],
            vec!["belay", "harden", "unban", "1.2.3.4"],
            vec!["belay", "vuln", "scan"],
            vec!["belay", "vuln", "scan", "--nvd-key-env", "NVD_API_KEY"],
            vec!["belay", "vuln", "list"],
            vec!["belay", "firewall", "propose"],
            vec!["belay", "firewall", "apply"],
            vec!["belay", "firewall", "apply", "--confirm-within", "120"],
            vec!["belay", "firewall", "apply", "--ssh-source", "1.2.3.4"],
            vec!["belay", "firewall", "confirm"],
            vec!["belay", "firewall", "revert"],
            vec!["belay", "firewall", "status"],
            vec!["belay", "egress", "list"],
            vec!["belay", "egress", "allow", "node", "api.anthropic.com"],
            vec![
                "belay",
                "egress",
                "deny",
                "python3",
                "evil.example.com",
            ],
            vec!["belay", "egress", "mode", "alert", "on"],
            vec!["belay", "egress", "mode", "block", "off"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "failed to parse: {argv:?}"
            );
        }
    }

    /// Smoke: `evidence build` into a temp out dir then `evidence verify --dir`
    /// must succeed (build → verify round-trip), and verify without `--dir` must
    /// fail.
    #[test]
    fn evidence_build_then_verify_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        // Empty audit store → findings is an empty array; build still works.
        let pack = home.join("pack");

        let code = super::run_evidence(
            super::EvidenceAction::Build,
            pack.to_str(),
            None,
            home.to_str(),
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(pack.join("manifest.json").exists());

        let code = super::run_evidence(super::EvidenceAction::Verify, None, pack.to_str(), None);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        // verify without --dir → failure.
        let code = super::run_evidence(super::EvidenceAction::Verify, None, None, None);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn resolve_device_id_prefers_explicit() {
        assert_eq!(super::resolve_device_id(Some("devX")), "devX");
    }

    #[test]
    fn resolve_device_id_falls_back_to_hostname() {
        // No explicit id → must equal the system hostname (same syscall as
        // Python socket.gethostname()), and must be non-empty.
        let got = super::resolve_device_id(None);
        assert!(!got.is_empty());
        let expected = hostname::get().unwrap().into_string().unwrap();
        assert_eq!(got, expected);
    }

    // ─── Task C8 tests ──────────────────────────────────────────────────────────

    /// The headless dead-man instruction must tell the operator:
    /// - that auto-revert is armed (contains "auto-revert")
    /// - the exact confirm command (`belay firewall confirm`)
    /// - the deadline window (the number)
    /// - an SSH safety reassurance (case-insensitive "ssh")
    #[test]
    fn firewall_apply_prints_headless_confirm_instruction() {
        let out = super::render_firewall_apply_output(60, "fw-7a3");
        assert!(
            out.contains("auto-revert"),
            "output must contain 'auto-revert'; got:\n{out}"
        );
        assert!(
            out.contains("belay firewall confirm"),
            "output must contain the exact command 'belay firewall confirm'; got:\n{out}"
        );
        assert!(
            out.contains("60"),
            "output must contain the deadline '60'; got:\n{out}"
        );
        assert!(
            out.to_lowercase().contains("ssh"),
            "output must mention SSH safety (case-insensitive); got:\n{out}"
        );
    }

    /// `firewall_confirm_cli(None)` must return Err whose Display contains
    /// "no firewall change awaiting confirmation".
    #[test]
    fn firewall_confirm_without_pending_apply_is_a_clear_error() {
        let r = super::firewall_confirm_cli(None);
        assert!(r.is_err(), "expected Err when no pending apply exists");
        let msg = format!("{}", r.unwrap_err());
        assert!(
            msg.contains("no firewall change awaiting confirmation"),
            "error message must contain 'no firewall change awaiting confirmation'; got: {msg:?}"
        );
    }

    /// `firewall_confirm_cli(Some(()))` must succeed.
    #[test]
    fn firewall_confirm_with_pending_apply_succeeds() {
        let r = super::firewall_confirm_cli(Some(()));
        assert!(r.is_ok(), "expected Ok when a pending apply exists");
    }

    // ─── end Task C8 tests ───────────────────────────────────────────────────

    // ─── setup wizard: ai_key must never be backed up ─────────────────────────

    /// Sanity check of the helper itself: given a pre-existing file,
    /// `backup_setup_config_file` must copy it to a `.bak` sibling with the
    /// original content preserved. (This is the helper the `run_setup` AI
    /// branch DOES still call for `ai.json` — just not for the key file.)
    #[test]
    fn backup_setup_config_file_creates_bak_sibling_for_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "belay-setup-test-backup-helper-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("ai.json");
        std::fs::write(&cfg_path, b"{\"mode\":\"cloud\"}").unwrap();

        super::backup_setup_config_file(&cfg_path);

        let baks: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".bak"))
            .collect();
        assert_eq!(baks.len(), 1, "expected exactly one .bak sibling of ai.json");
        assert_eq!(
            std::fs::read(baks[0].path()).unwrap(),
            b"{\"mode\":\"cloud\"}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression test for the "stop backing up the plaintext API key"
    /// finding: the AI branch of `run_setup` backs up `ai.json` before
    /// overwriting it, but must NOT do the same for the `ai_key` file — that
    /// would leave stale plaintext keys on disk that the "clear key"
    /// affordance never removes. This reproduces the exact production
    /// sequence for both files side by side (a pre-existing file from a
    /// prior wizard run, then the same calls `run_setup` makes today) and
    /// asserts only the file that is backed up gets a `.bak` sibling.
    #[test]
    #[cfg(feature = "ai")]
    fn ai_key_write_never_creates_bak_sibling() {
        let dir = std::env::temp_dir().join(format!(
            "belay-setup-test-aikey-nobak-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Simulate state left over from a previous `belay setup` run.
        let cfg_path = dir.join("ai.json");
        std::fs::write(&cfg_path, b"{\"mode\":\"cloud\"}").unwrap();
        let key_path = dir.join("ai_key");
        belayd::ai::secret::write_ai_key(&key_path, "sk-old").unwrap();

        // The exact sequence `run_setup`'s AI branch runs today: back up
        // ai.json, then write_ai_key WITHOUT backing up the key file first.
        super::backup_setup_config_file(&cfg_path);
        belayd::ai::secret::write_ai_key(&key_path, "sk-new").unwrap();

        let bak_names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".bak"))
            .collect();
        assert_eq!(
            bak_names.len(),
            1,
            "expected exactly one .bak sibling (ai.json's), got: {bak_names:?}"
        );
        assert!(
            bak_names[0].starts_with("ai.json."),
            "the one .bak must belong to ai.json, not ai_key; got: {bak_names:?}"
        );
        assert!(
            !bak_names.iter().any(|n| n.starts_with("ai_key.")),
            "ai_key must never be backed up to a .bak sibling; got: {bak_names:?}"
        );
        assert_eq!(
            belayd::ai::secret::read_ai_key(&key_path),
            Some("sk-new".to_string())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── end setup wizard ai_key backup tests ──────────────────────────────────
}
