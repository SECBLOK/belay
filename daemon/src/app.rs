//! Callable entrypoints for the daemon and hook, factored out of the
//! `main_daemon.rs` / `main_hook.rs` binaries so the unified `belay`
//! binary (Phase 11 Task 7) can call them directly while the standalone
//! `belayd` / `belay-hook` bins keep working by delegating here.
//!
//! Behaviour is identical to the original `fn main()` bodies — this is a pure
//! move, not a rewrite.

use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::engine::decide::decide;
use crate::engine::rules::RuleSet;
use crate::engine::types::{Decision, SessionState, ToolCall};
use crate::ipc::{read_frame, write_frame};
use serde_json::{json, Value};

// ──────────────────────────────────────────────────────────────
// Daemon
// ──────────────────────────────────────────────────────────────

fn daemon_socket_path() -> PathBuf {
    PathBuf::from(crate::paths::socket_path())
}

/// Run the always-on resident daemon (was `belayd`'s `fn main()`).
///
/// Best-effort eBPF sensor startup (compiled out without the `ebpf` feature),
/// then blocks serving the UDS IPC server. Exits the process with code 1 on a
/// fatal IPC error, matching the original binary's behaviour.
///
/// Thin wrapper over [`run_daemon_with_shutdown`] with a never-set flag, so the
/// serve loop blocks exactly as before.
pub fn run_daemon() {
    run_daemon_with_shutdown(Arc::new(AtomicBool::new(false)));
}

/// True only when this process is the LocalSystem SCM service (`<exe> daemon
/// --scm`). Phase-2 Tier-2 subsystems (ETW real-time detect, WFP egress block)
/// MUST be gated on this: they need the service's LocalSystem privilege and the
/// admin-once install, and must NEVER start in the ordinary per-user console
/// daemon. The SCM always launches the service with `--scm` in its argv
/// (`win_service.rs::register_service`, `launch_arguments`), and `std::env::args`
/// reflects the real OS command line regardless of clap having parsed it.
pub fn running_as_service() -> bool {
    std::env::args().any(|a| a == "--scm")
}

/// Same as [`run_daemon`] but honours a shared `shutdown` signal: when it is
/// set (and the accept loop is woken — see `ipc::serve_mode_with_shutdown`), the
/// serve loop returns and this function returns instead of running forever. The
/// Windows SCM dispatcher (Phase 3) owns the flag so a Stop control can unblock
/// the daemon and let the service report `Stopped`.
pub fn run_daemon_with_shutdown(shutdown: Arc<AtomicBool>) {
    // Startup integrity check: alert if the on-disk rules/catalog.yaml has drifted
    // from the hash compiled into this binary. Alert-only — the running binary is
    // unaffected; only the rules source on disk may have been tampered.
    match crate::engine::integrity::verify_catalog_drift(
        crate::engine::integrity::default_on_disk_catalog().as_deref(),
    ) {
        crate::engine::integrity::IntegrityStatus::Drift { expected, actual } => {
            eprintln!(
                "[belayd] integrity ALERT: rules/catalog.yaml on disk drifted from the \
                 compiled-in rules (expected {expected}, found {actual}); the running binary is \
                 UNAFFECTED, but the rules source may have been tampered before a rebuild."
            );
        }
        crate::engine::integrity::IntegrityStatus::Ok
        | crate::engine::integrity::IntegrityStatus::NoOnDiskCopy => {}
    }

    let path = daemon_socket_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    // eBPF kernel sensor — best-effort, never blocks startup.
    // In non-ebpf builds start_or_degrade() always returns None (the non-ebpf
    // `start()` immediately returns Err::Unsupported); the block below is
    // feature-gated so it is compiled out entirely in the default build,
    // preventing dead-code / unused-import warnings.
    let _sensor = crate::ebpf::start_or_degrade();
    #[cfg(feature = "ebpf")]
    {
        if let Some(sensor) = _sensor {
            // Spawn the eBPF drain loop on a background thread so it does not
            // block the IPC server.  Uses APIs that only exist with the `ebpf`
            // feature (into_bpf, ringbuf::drain).
            use crate::engine::{evaluate_event, types::SessionState};
            use crate::honeypot::Honeypot;
            use crate::reflex::{Reflex, SignalKiller, Sink};

            struct LogSink;
            impl Sink for LogSink {
                fn escalate(&mut self, row: serde_json::Value) {
                    eprintln!("[belayd] escalate: {row}");
                }
                fn audit(&mut self, row: serde_json::Value) {
                    eprintln!("[belayd] audit: {row}");
                }
            }

            let hp = Honeypot::plant(&crate::paths::data_dir()).ok();
            let mut bpf = sensor.into_bpf();
            std::thread::spawn(move || {
                let mut state = SessionState::new("ebpf_boot");
                let mut reflex = Reflex::new(SignalKiller, LogSink);
                loop {
                    let events = crate::ebpf::ringbuf::drain(&mut bpf);
                    for ev in &events {
                        let verdict = hp
                            .as_ref()
                            .and_then(|h| h.classify_access(ev))
                            .unwrap_or_else(|| evaluate_event(ev, &mut state));
                        reflex.react(ev, &verdict, "ebpf_boot");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
        } else {
            eprintln!("[belayd] eBPF disabled — hook/proxy enforcement only");
        }
    }
    #[cfg(not(feature = "ebpf"))]
    {
        eprintln!("[belayd] eBPF disabled (built without ebpf feature) — hook/proxy enforcement only");
    }

    // Phase-1 Windows honeytoken canary (Tier 1 — no admin, no driver). The
    // Windows counterpart of the eBPF block above: same shape (plant honeypot →
    // observe → classify_access → react), but the *source* is a last-access poll
    // instead of a kernel ring buffer. This is the only signal Belay can produce
    // on the CLOSED desktop apps (Claude Desktop, ChatGPT/Codex desktop), since
    // the target app reads the decoy itself — no hook, no privilege. DETECTION
    // ONLY: it records the read, it cannot prevent it (see watch_win.rs).
    #[cfg(windows)]
    {
        use crate::honeypot::{watch_win, Honeypot};

        match Honeypot::plant(&crate::paths::data_dir()) {
            Ok(mut hp) => {
                // Placement = coverage. The baseline decoys live under
                // %PROGRAMDATA%\Belay, which the desktop apps never scan; ALSO
                // plant one where an agent actually roams (the user profile) so a
                // real credential-scan trips it. Best-effort — a failure here just
                // narrows coverage, never blocks daemon startup.
                if let Some(home) = std::env::var_os("USERPROFILE") {
                    let decoy = std::path::Path::new(&home).join(".env");
                    if let Err(e) = hp.plant_decoy_at(&decoy) {
                        eprintln!("[belayd] canary extra-decoy plant failed ({}): {e}", decoy.display());
                    }
                }
                let paths = hp.canary_paths.clone();
                eprintln!(
                    "[belayd] canary armed (detection-only): {} decoy path(s) watched",
                    paths.len()
                );
                let mut watcher = watch_win::CanaryWatcher::new(&paths);
                std::thread::spawn(move || loop {
                    for ev in watcher.poll() {
                        if let Some(verdict) = hp.classify_access(&ev) {
                            watch_win::record_canary_trip(&ev, &verdict);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                });
            }
            Err(e) => eprintln!("[belayd] canary disabled — could not plant decoys: {e}"),
        }
    }

    // Phase-2 Tier-2: ETW real-time DETECT — SERVICE-ONLY (needs LocalSystem for a
    // kernel real-time session; the per-user console daemon must never start it).
    // Mirrors the eBPF block: open session → drain records → decode → classify →
    // honest detect-row. DETECT-ONLY (ETW cannot block); the read/exec/connect has
    // already completed. Activates end-to-end once TDH path extraction fills
    // `RawEtwRecord.detail` (see etw::session TODO(tdh)); until then records flow
    // but decode drops empty-detail ones, so no false rows.
    #[cfg(windows)]
    if running_as_service() {
        use crate::engine::{evaluate_event, types::SessionState};
        use crate::etw::{decode, EtwSession};
        use crate::honeypot::Honeypot;

        match EtwSession::open() {
            Ok(session) => {
                eprintln!("[belayd] ETW real-time detect armed (service, detection-only)");
                let (tx, rx) = std::sync::mpsc::channel();
                let etw_shutdown = shutdown.clone();
                std::thread::spawn(move || session.run(tx, etw_shutdown));

                let hp = Honeypot::plant(&crate::paths::data_dir()).ok();
                std::thread::spawn(move || {
                    let mut state = SessionState::new("etw");
                    while let Ok(rec) = rx.recv() {
                        let Some(ev) = decode(&rec) else { continue };
                        let verdict = hp
                            .as_ref()
                            .and_then(|h| h.classify_access(&ev))
                            .unwrap_or_else(|| evaluate_event(&ev, &mut state));
                        // Only surface findings (skip benign Allow verdicts).
                        if verdict.decision != crate::engine::types::Decision::Allow {
                            crate::etw::record_detection(&ev, &verdict);
                        }
                    }
                });
            }
            Err(e) => eprintln!(
                "[belayd] ETW detect disabled (open failed: {e}) — need LocalSystem/admin"
            ),
        }
    }

    eprintln!("belayd: listening on {}", path.display());
    if let Err(e) = crate::ipc::serve_mode_with_shutdown(
        path.to_str().unwrap(),
        crate::ipc::Mode::Enforce,
        shutdown,
    ) {
        eprintln!("belayd: fatal: {e}");
        std::process::exit(1);
    }
}

// ──────────────────────────────────────────────────────────────
// Hook / gate
// ──────────────────────────────────────────────────────────────

fn hook_socket_path() -> String {
    crate::paths::socket_path()
}

/// The Claude/codex PreToolUse `hookSpecificOutput` verdict payload. Pure (no
/// I/O) so the wire shape - crucially the `hookEventName` - stays unit-tested:
/// this is a PreToolUse-only shape and must never be emitted from a post event
/// (see `post_event_stdout`).
fn claude_pre_response(decision: &str, reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
}

fn emit(decision: &str, reason: &str) -> ! {
    println!("{}", claude_pre_response(decision, reason));
    std::process::exit(0);
}

/// Hermes's `pre_tool_call` hook honors a DIFFERENT wire shape than Claude Code:
/// it reads the hook's stdout and BLOCKS the tool call only when it sees a
/// top-level `{"decision":"block","reason":...}` (or `{"action":"block",...}`);
/// anything else — including empty stdout — allows the call to proceed
/// (verified against hermes `agent/shell_hooks.py::_parse_response`). So we emit
/// a block directive on deny and NOTHING on allow. Pure (no I/O) for testing.
fn hermes_response(decision: &str, reason: &str) -> Option<Value> {
    if decision == "allow" {
        None
    } else {
        Some(json!({ "decision": "block", "reason": reason }))
    }
}

/// Emit a verdict in hermes's hook format and exit 0 (hermes treats a non-zero
/// exit as fail-open, so we always exit 0 and rely on stdout to block).
fn emit_hermes(decision: &str, reason: &str) -> ! {
    if let Some(out) = hermes_response(decision, reason) {
        println!("{out}");
    }
    std::process::exit(0);
}

/// Cursor Hooks read a JSON verdict on stdout: `{"permission":"allow"|"deny"}`
/// (+ optional messages). Unlike hermes, we emit an EXPLICIT allow so behaviour
/// is unambiguous. Pure (no I/O) for testing.
fn cursor_response(decision: &str, reason: &str) -> Value {
    if decision == "allow" {
        json!({ "permission": "allow" })
    } else {
        json!({ "permission": "deny", "agent_message": reason, "user_message": reason })
    }
}

fn emit_cursor(decision: &str, reason: &str) -> ! {
    println!("{}", cursor_response(decision, reason));
    std::process::exit(0);
}

/// Which agent's hook wire-shape to emit, selected from the `hook <event>`
/// positional. Claude Code and codex share the `hookSpecificOutput` shape.
#[derive(Clone, Copy)]
enum HookFmt {
    Claude,
    Hermes,
    Cursor,
}

fn hook_fmt(event: Option<&str>) -> HookFmt {
    match event {
        Some("hermes-pretool") | Some("hermes-posttool") => HookFmt::Hermes,
        Some("cursor-pre") => HookFmt::Cursor,
        _ => HookFmt::Claude,
    }
}

/// Format-aware terminal emit — the gate verdict is identical across agents;
/// only the stdout wire-shape differs.
fn do_emit(fmt: HookFmt, decision: &str, reason: &str) -> ! {
    match fmt {
        HookFmt::Claude => emit(decision, reason),
        HookFmt::Hermes => emit_hermes(decision, reason),
        HookFmt::Cursor => emit_cursor(decision, reason),
    }
}

/// Cursor's native hook payloads use per-event field names — NOT Claude Code's
/// `{tool_name, tool_input}`. `beforeShellExecution` carries `command`,
/// `beforeReadFile` a file path, and `beforeMCPExecution` already carries
/// `tool_name`/`tool_input`. Without translation the gate would decode an empty
/// tool and DEFAULT-ALLOW every call (a silent bypass), so translate the
/// documented shapes into the `{session_id, tool_name, tool_input}` the gate
/// understands. Unknown shapes pass through unchanged (the gate's own fail-safe
/// plus Cursor's `failClosed` then apply). This is based on Cursor's DOCUMENTED
/// hook schema; validate it against a live payload sample.
fn normalize_cursor_stdin(raw: &str) -> String {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return raw.to_string(),
    };
    // Already tool-shaped (beforeMCPExecution / preToolUse) → pass through.
    if v.get("tool_name")
        .and_then(|t| t.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return raw.to_string();
    }
    let session = v
        .get("session_id")
        .or_else(|| v.get("conversation_id"))
        .and_then(|s| s.as_str())
        .unwrap_or("cursor");
    let (tool_name, tool_input): (&str, Value) =
        if let Some(cmd) = v.get("command").and_then(|c| c.as_str()) {
            ("Bash", json!({ "command": cmd })) // beforeShellExecution
        } else if let Some(fp) = v
            .get("file_path")
            .or_else(|| v.get("path"))
            .and_then(|p| p.as_str())
        {
            ("Read", json!({ "file_path": fp })) // beforeReadFile
        } else {
            return raw.to_string(); // unrecognized shape — don't fabricate
        };
    json!({ "session_id": session, "tool_name": tool_name, "tool_input": tool_input }).to_string()
}

/// Audit-log path — the NDJSON file the desktop Live Feed / dashboard tails.
fn hook_audit_path() -> PathBuf {
    crate::paths::audit_path()
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::host_config::rfc3339_utc(secs)
}

/// (session, tool) parsed from the hook stdin JSON, for the audit row.
fn session_tool(stdin: &str) -> (String, String) {
    serde_json::from_str::<Value>(stdin)
        .ok()
        .map(|v| {
            let s = v
                .get("session_id")
                .and_then(|x| x.as_str())
                .unwrap_or("default")
                .to_string();
            let t = v
                .get("tool_name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            (s, t)
        })
        .unwrap_or_else(|| ("default".into(), String::new()))
}

/// Append one hook gate verdict to the audit log so the Live Feed shows agent
/// activity in real time. Best-effort — never blocks or fails the gate; skips
/// non-tool events (empty tool). Mirrors the per-call append the MCP proxy does.
#[allow(clippy::too_many_arguments)]
fn audit_hook(
    session: &str,
    tool: &str,
    verdict: &str,
    reason: &str,
    rules: Value,
    input: &Value,
    severity: &str,
    category: Option<&str>,
    explain: Option<Value>,
) {
    if tool.is_empty() {
        return;
    }
    let path = hook_audit_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            // Still best-effort (never fails the gate), but no longer silent: a
            // Windows ACL split (SYSTEM-owned data dir vs user-context hook) would
            // otherwise drop every row while the gate keeps working - leaving the
            // dashboard mysteriously empty. Surfacing it makes that diagnosable.
            eprintln!("belay: audit dir create failed ({}): {e}", parent.display());
        }
    }
    match crate::audit::AuditWriter::open(&path.to_string_lossy()) {
        Ok(mut w) => {
            if let Err(e) = w.append(hook_audit_row(
                &now_rfc3339(),
                session,
                tool,
                verdict,
                reason,
                rules,
                input,
                severity,
                category,
                explain,
            )) {
                eprintln!("belay: audit append failed ({}): {e}", path.display());
            }
        }
        Err(e) => eprintln!("belay: audit open failed ({}): {e}", path.display()),
    }
}

/// Build one `hook/pretooluse` audit row. Pure (no I/O, no clock) so the row
/// shape — including the `input` payload the Live Feed renders — is unit
/// testable without touching `$HOME` or the audit file.
#[allow(clippy::too_many_arguments)]
fn hook_audit_row(
    ts: &str,
    session: &str,
    tool: &str,
    verdict: &str,
    reason: &str,
    rules: Value,
    input: &Value,
    severity: &str,
    category: Option<&str>,
    explain: Option<Value>,
) -> Value {
    json!({
        "ts": ts,
        "event": "hook/pretooluse",
        "session": session,
        "tool": tool,
        "verdict": verdict,
        "reason": reason,
        "rules": rules,
        // The raw tool payload (command / file_path / url). Persisted so the
        // Live Feed can describe what an ALLOWED action actually was instead
        // of the engine's bare "no findings". The live gate wire already
        // carries `tool_input`; this stops it being dropped before audit.
        "input": input,
        // Curated explanation metadata (additive; Explain & Advise Phase A). The
        // Live Feed / desktop notification renders `explain.summary` and colours
        // the row by `severity` instead of re-deriving copy from the rule id.
        "severity": severity,
        "category": category,
        "explain": explain,
    })
}

fn try_socket(stdin: &str) -> Option<Value> {
    let data: Value = serde_json::from_str(stdin).ok()?;
    let req = json!({
        "type": "gate",
        "session": data.get("session_id").and_then(|v| v.as_str()).unwrap_or("default"),
        "tool": data.get("tool_name").and_then(|v| v.as_str()).unwrap_or(""),
        "input": data.get("tool_input").cloned().unwrap_or(Value::Null),
    });
    let mut stream = belay_transport::connect(&hook_socket_path()).ok()?;
    write_frame(&mut stream, req.to_string().as_bytes()).ok()?;
    let resp = read_frame(&mut stream).ok()?;
    serde_json::from_slice(&resp).ok()
}

/// In-process Rust engine fallback — evaluates the gate request using the
/// daemon's own rule engine when the UDS socket is unreachable.
///
/// Returns `Some((decision, reason))` where `decision` is `"allow"` or
/// `"deny"`. Returns `None` on any error (malformed stdin, ruleset load
/// failure, etc.) so the caller's fail-closed default fires — a `None` here
/// NEVER allows a present tool through.
fn rust_fallback(stdin: &str) -> Option<FallbackVerdict> {
    let data: Value = serde_json::from_str(stdin).ok()?;
    let tc = ToolCall {
        session: data["session_id"].as_str().unwrap_or("default").to_owned(),
        tool: data["tool_name"].as_str().unwrap_or("").to_owned(),
        input: data["tool_input"].clone(),
    };
    // Fail-closed: any load error → None → caller denies if a tool is present.
    let rs = RuleSet::load().ok()?;
    let mut state = SessionState::new(&tc.session);
    let v = decide(&rs, &tc, &mut state);
    // Map Ask→deny conservatively (same as socket path).
    let hook_decision: &'static str = if v.decision == Decision::Allow {
        "allow"
    } else {
        "deny"
    };
    Some(FallbackVerdict {
        decision: hook_decision,
        reason: v.reason,
        severity: v.severity.as_wire_str(),
        category: v.category,
        explain: v
            .explain
            .as_ref()
            .and_then(|e| serde_json::to_value(e).ok()),
    })
}

/// The in-process (UDS-down) verdict surfaced to the hook emit + audit row.
struct FallbackVerdict {
    decision: &'static str,
    reason: String,
    severity: &'static str,
    category: Option<String>,
    explain: Option<Value>,
}

/// True for hook events that fire AFTER a tool executed (Claude `PostToolUse`,
/// Hermes `post_tool`). These run post-execution, so they cannot gate or block —
/// and the daemon parks on any ASK verdict regardless of event, so re-running the
/// gate for them would park a DUPLICATE approval for a call the user already
/// decided at PreToolUse. They must never touch the parking gate.
fn is_post_event(event: Option<&str>) -> bool {
    matches!(event, Some("posttooluse") | Some("hermes-posttool"))
}

/// What a post-event hook writes to stdout: NOTHING.
///
/// PostToolUse / hermes post_tool run AFTER the tool executed and cannot gate.
/// The gate's terminal emit for Claude is a PreToolUse-shaped payload
/// (`hookSpecificOutput.hookEventName = "PreToolUse"`). Printing THAT from a
/// PostToolUse hook makes Claude Code reject the hook with "expected
/// 'PostToolUse' but got 'PreToolUse'", and that hook error nudges the agent to
/// RETRY the tool call - firing a SECOND PreToolUse approval for a call the user
/// already decided (the duplicate alert seen only on Allow; a Deny blocks the
/// tool so PostToolUse never fires). An empty stdout + exit 0 is the valid no-op
/// for both Claude PostToolUse and hermes post_tool, so a post event emits
/// nothing. Pure so the regression stays unit-tested.
fn post_event_stdout() -> Option<String> {
    None
}

/// PreToolUse thin UDS client (was `belay-hook`'s `fn main()`).
///
/// Reads the hook request as JSON from stdin, asks the daemon over the UDS for
/// a verdict, prints the `permissionDecision`, and always exits the process
/// (never returns). On socket failure falls back to the in-process Rust engine,
/// then to a fail-closed default.
pub fn run_hook(event: Option<&str>) -> ! {
    let mut stdin = String::new();
    io::stdin().read_to_string(&mut stdin).ok();

    // Each agent invokes us with a different `hook <event>` positional and
    // expects its own stdout shape (Claude/codex hookSpecificOutput, hermes
    // {"decision":"block"}, cursor {"permission":"deny"}). The gate verdict is
    // identical — only the terminal emit (and, for cursor, the INPUT shape) differ.
    let fmt = hook_fmt(event);

    // PostToolUse (and Hermes's post_tool) runs AFTER the tool executed: it cannot
    // gate or block, and the daemon parks on any ASK verdict regardless of event.
    // Re-running the gate here fired a SECOND approval prompt for a call already
    // decided at PreToolUse. It does no audit/redaction either, so emit the
    // post-event no-op (nothing) and exit BEFORE touching the parking gate.
    //
    // Emitting the PreToolUse-shaped allow payload here (the old `do_emit(fmt,
    // "allow", "")`) was itself the duplicate's cause: Claude Code rejected the
    // wrong `hookEventName` ("expected 'PostToolUse' but got 'PreToolUse'"), and
    // that hook error made the agent retry the call, re-parking a second time on
    // every Allow. See `post_event_stdout`.
    if is_post_event(event) {
        if let Some(s) = post_event_stdout() {
            println!("{s}");
        }
        std::process::exit(0);
    }

    // Cursor's payload uses per-event field names; normalize it to the gate's
    // {tool_name, tool_input} shape BEFORE any parsing, so the shell/file
    // controls actually evaluate instead of decoding empty and default-allowing.
    let stdin = if matches!(fmt, HookFmt::Cursor) {
        normalize_cursor_stdin(&stdin)
    } else {
        stdin
    };

    // Record one audit row per gated tool call so the Live Feed reflects agent
    // activity. Only PreToolUse carries the verdict; PostToolUse re-runs this
    // entrypoint, so skip it to avoid a duplicate row per call.
    let (session, tool) = session_tool(&stdin);
    // The raw tool payload, parsed once for the audit row's `input` field so the
    // Live Feed can describe an allowed action (the command/path/url that ran).
    // Hermes uses the same Claude-compatible `tool_input` key.
    let input = serde_json::from_str::<Value>(&stdin)
        .ok()
        .and_then(|v| v.get("tool_input").cloned())
        .unwrap_or(Value::Null);
    let audit = !is_post_event(event);

    if let Some(v) = try_socket(&stdin) {
        let decision = v.get("decision").and_then(|d| d.as_str()).unwrap_or("deny");
        // The hook protocol only knows allow|deny; map ask->deny conservatively
        // (the desktop/channel ASK round-trip is Phase 8).
        let hook_decision = if decision == "allow" { "allow" } else { "deny" };
        let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or("");
        if audit {
            let rules = v.get("rules").cloned().unwrap_or_else(|| json!([]));
            // The gate wire carries the full serialized Verdict (Task 2), so the
            // curated explain/severity/category ride along without re-deriving.
            let severity = v.get("severity").and_then(|s| s.as_str()).unwrap_or("info");
            let category = v.get("category").and_then(|c| c.as_str());
            let explain = v.get("explain").filter(|e| !e.is_null()).cloned();
            audit_hook(
                &session,
                &tool,
                hook_decision,
                reason,
                rules,
                &input,
                severity,
                category,
                explain,
            );
        }
        do_emit(fmt, hook_decision, reason);
    }

    // Socket down: evaluate in-process using the Rust engine (protection never drops).
    if let Some(fb) = rust_fallback(&stdin) {
        if audit {
            audit_hook(
                &session,
                &tool,
                fb.decision,
                &fb.reason,
                json!([]),
                &input,
                fb.severity,
                fb.category.as_deref(),
                fb.explain.clone(),
            );
        }
        do_emit(fmt, fb.decision, &fb.reason);
    }

    // No socket and engine error: fail safe. Deny if a tool was requested.
    let has_tool = !tool.is_empty();
    let decision = if has_tool { "deny" } else { "allow" };
    let reason = "fail-closed: core unreachable";
    if audit {
        audit_hook(
            &session,
            &tool,
            decision,
            reason,
            json!([]),
            &input,
            "info",
            None,
            None,
        );
    }
    do_emit(fmt, decision, reason);
}

/// One-shot gate verdict — alias of [`run_hook`].
///
/// The hook binary already operates in "pipe mode": it reads a single gate
/// request as JSON from stdin and prints the verdict. There is no separate
/// stdin protocol for `gate`, so `gate` and `hook` share the same code path.
/// Kept as a distinct entrypoint so the dispatcher CLI surface matches the
/// plan (`belay gate`) and so future divergence has a home.
pub fn gate() -> ! {
    run_hook(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_events_never_gate() {
        // Regression: the daemon parks on any ASK verdict regardless of event, and
        // run_hook used to re-run the gate for PostToolUse too, firing a SECOND
        // approval prompt for an already-decided call (conflicting replies made the
        // outcome nondeterministic). Post events must be classified as post so
        // run_hook no-ops before the parking gate.
        assert!(is_post_event(Some("posttooluse")));
        assert!(is_post_event(Some("hermes-posttool")));
        // Pre / gate / cursor events DO gate — they must not be treated as post.
        assert!(!is_post_event(Some("pretooluse")));
        assert!(!is_post_event(Some("hermes-pretool")));
        assert!(!is_post_event(Some("beforeShellExecution")));
        assert!(!is_post_event(None)); // `belay gate` one-shot verdict
    }

    #[test]
    fn post_event_emits_nothing() {
        // Regression: a post event used to emit the PreToolUse-shaped allow
        // payload (`hookSpecificOutput.hookEventName = "PreToolUse"`). Claude Code
        // rejects that on a PostToolUse hook ("expected 'PostToolUse' but got
        // 'PreToolUse'"), and the resulting hook error made the agent RETRY the
        // call - a SECOND PreToolUse approval on every Allow (Deny blocks the tool
        // so PostToolUse never fires: the Allow=2 / Deny=1 asymmetry). A post event
        // must write nothing to stdout.
        assert_eq!(post_event_stdout(), None);
        // The PreToolUse emit shape, by contrast, MUST carry PreToolUse - it is
        // only ever reached on pre/gate events, never a post event.
        assert_eq!(claude_pre_response("allow", "")["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn hermes_response_blocks_on_deny_and_is_silent_on_allow() {
        // Allow → no stdout directive (hermes lets the tool proceed).
        assert!(hermes_response("allow", "ok").is_none());
        // Deny/ask → a top-level block directive hermes honors.
        let deny =
            hermes_response("deny", "rm -rf blocked").expect("deny must produce a directive");
        assert_eq!(deny["decision"], "block");
        assert_eq!(deny["reason"], "rm -rf blocked");
        // Anything not "allow" (e.g. a mapped ask) also blocks — fail-safe.
        assert_eq!(
            hermes_response("ask", "needs review").unwrap()["decision"],
            "block"
        );
    }

    #[test]
    fn normalize_cursor_maps_shell_and_read_and_passes_through_mcp() {
        // beforeShellExecution: `command` -> a Bash tool the engine can gate.
        let shell = normalize_cursor_stdin(
            r#"{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/"}"#,
        );
        let sv: Value = serde_json::from_str(&shell).unwrap();
        assert_eq!(sv["tool_name"], "Bash");
        assert_eq!(sv["tool_input"]["command"], "rm -rf /");
        // Round-trips through the same session_tool the gate uses.
        assert_eq!(session_tool(&shell).1, "Bash");

        // beforeReadFile: a file path -> a Read tool.
        let read = normalize_cursor_stdin(
            r#"{"hook_event_name":"beforeReadFile","file_path":"/home/u/.ssh/id_rsa"}"#,
        );
        let rv: Value = serde_json::from_str(&read).unwrap();
        assert_eq!(rv["tool_name"], "Read");
        assert_eq!(rv["tool_input"]["file_path"], "/home/u/.ssh/id_rsa");

        // beforeMCPExecution: already tool-shaped -> unchanged passthrough.
        let mcp_in = r#"{"tool_name":"search","tool_input":{"q":"x"}}"#;
        assert_eq!(normalize_cursor_stdin(mcp_in), mcp_in);
    }

    #[test]
    fn cursor_response_shapes_allow_and_deny() {
        assert_eq!(cursor_response("allow", "ok")["permission"], "allow");
        let d = cursor_response("deny", "blocked");
        assert_eq!(d["permission"], "deny");
        assert_eq!(d["agent_message"], "blocked");
        // Fail-safe: any non-allow verdict denies.
        assert_eq!(cursor_response("ask", "review")["permission"], "deny");
    }

    #[test]
    fn hook_audit_row_carries_input_payload() {
        // A clean ALLOW still yields reason "no findings" (decide.rs unchanged),
        // but the row must now also carry the raw command so the Live Feed can
        // describe the action instead of showing the generic reason.
        let input = json!({"command": "cargo build --release"});
        let row = hook_audit_row(
            "2026-06-30T12:00:00Z",
            "s1",
            "Bash",
            "allow",
            "no findings",
            json!([]),
            &input,
            "info",
            None,
            None,
        );
        assert_eq!(row["event"], "hook/pretooluse");
        assert_eq!(row["verdict"], "allow");
        assert_eq!(row["reason"], "no findings");
        assert_eq!(row["input"]["command"], "cargo build --release");
        // Additive Explain & Advise fields present even on a clean allow.
        assert_eq!(row["severity"], "info");
        assert!(row["category"].is_null());
        assert!(row["explain"].is_null());
    }

    #[test]
    fn hook_audit_row_carries_severity_and_explain() {
        let explain = json!({"summary":"x","what":"y","why_risky":"z","normal_use":"n","suggested_action":"a"});
        let row = hook_audit_row(
            "ts",
            "s",
            "Bash",
            "deny",
            "reason",
            json!([]),
            &json!({"command":"rm -rf /"}),
            "critical",
            Some("destructive"),
            Some(explain.clone()),
        );
        assert_eq!(row["severity"], "critical");
        assert_eq!(row["category"], "destructive");
        assert_eq!(row["explain"]["summary"], "x");
    }

    #[test]
    fn rust_fallback_dangerous_bash_denies() {
        let stdin = r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
        let result = rust_fallback(stdin);
        assert!(result.is_some(), "dangerous rm -rf / must return Some");
        let fb = result.unwrap();
        assert_eq!(fb.decision, "deny", "rm -rf / must be denied");
        // The winning-rule metadata rides along on the fallback path too.
        assert_eq!(fb.severity, "critical");
        assert_eq!(fb.category.as_deref(), Some("destructive"));
        assert!(fb.explain.is_some(), "rm -rf explain must be surfaced");
    }

    #[test]
    fn rust_fallback_malformed_stdin_returns_none() {
        let result = rust_fallback("not valid json }{");
        assert!(
            result.is_none(),
            "malformed stdin must return None (fail-closed)"
        );
    }

    #[test]
    fn rust_fallback_empty_object_returns_some() {
        // An empty tool_name request — engine should allow (no rule triggered)
        let stdin = r#"{"session_id":"s2","tool_name":"","tool_input":{}}"#;
        let result = rust_fallback(stdin);
        // Should return Some; the exact decision depends on what the engine returns
        // but it must not panic or silently error.
        assert!(result.is_some(), "empty tool_name must still return Some");
    }

    #[test]
    fn rust_fallback_benign_read_tool_returns_some() {
        // A benign read-only request — should return a consistent decision
        let stdin =
            r#"{"session_id":"s3","tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
        let result = rust_fallback(stdin);
        assert!(result.is_some(), "benign Read must return Some");
        let fb = result.unwrap();
        // Must be allow or deny — not something unexpected
        assert!(
            fb.decision == "allow" || fb.decision == "deny",
            "decision must be allow or deny, got: {}",
            fb.decision
        );
    }

    #[test]
    fn rust_fallback_ruleset_load_fail_closed() {
        // We can't easily break RuleSet::load() (catalog is compiled in), but we
        // verify that the function signature returns Option and returns None on any
        // parse failure — tested indirectly via malformed stdin above.
        // Additional contract test: the function must never panic on empty string.
        let result = rust_fallback("");
        assert!(result.is_none(), "empty stdin must return None");
    }
}
