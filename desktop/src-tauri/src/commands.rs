//! Tauri commands that feed the React dashboard REAL data.
//!
//! Data is read LOCALLY from `~/.belay/audit.ndjson` and processed with the
//! already-public audit-reader functions — NOT via the daemon (whose `get_posture`
//! is a hardcoded stub). The command JSON intentionally matches what the web
//! `/api/*` routes (`server/src/lib.rs`) return, so the existing React views render
//! unchanged inside the desktop window.
//!
//! The pure data logic is factored into `*_from_rows(rows: &[Value])` functions so
//! it is testable under `cargo test --no-default-features` (no Tauri runtime needed).

use serde_json::Value;

use belay_server::audit_reader;

/// The web routes (`server/src/lib.rs::load_rows`) read the *entire* audit file with
/// no row cap. We mirror that by reading all rows via `belayd::audit::recent`
/// with an effectively-unbounded `n`.
#[cfg_attr(not(feature = "tauri"), allow(dead_code))]
const ROW_LIMIT: usize = usize::MAX;

/// Path to the local audit store the daemon writes. Resolved through the
/// daemon's own path helper so the LocalSystem daemon and the user desktop always
/// read the SAME file: `~/.belay/audit.ndjson` on Unix,
/// `%PROGRAMDATA%\Belay\audit.ndjson` on Windows.
/// Only used by the Tauri command wrappers (compiled with the `tauri` feature).
#[cfg_attr(not(feature = "tauri"), allow(dead_code))]
fn audit_path() -> String {
    belayd::paths::audit_path().to_string_lossy().into_owned()
}

/// Read the last `n` audit rows (oldest-first). Missing file -> empty vec (never panics).
#[cfg_attr(not(feature = "tauri"), allow(dead_code))]
fn rows(n: usize) -> Vec<Value> {
    belayd::audit::recent(&audit_path(), n)
}

// ──────────────────────────────────────────────────────────────
// Pure data-layer functions (testable without a Tauri runtime)
// ──────────────────────────────────────────────────────────────

/// Posture summary — matches `GET /api/posture`.
pub fn posture_from_rows(rows: &[Value]) -> Value {
    serde_json::to_value(audit_reader::summarize(rows)).unwrap_or_else(|_| serde_json::json!({}))
}

/// Findings list (reversed) — matches `GET /api/findings`.
pub fn findings_from_rows(rows: &[Value]) -> Value {
    audit_reader::to_findings(rows)
}

/// Sessions list — matches `GET /api/sessions`.
pub fn sessions_from_rows(rows: &[Value]) -> Value {
    audit_reader::sessions(rows)
}

/// Fleet summary — matches `GET /api/fleet`. Enterprise-only (paid plane).
#[cfg(feature = "enterprise")]
pub fn fleet_from_rows(rows: &[Value]) -> Value {
    audit_reader::fleet_summary(rows)
}

/// Egress map — matches `GET /api/egress`.
pub fn egress_from_rows(rows: &[Value]) -> Value {
    audit_reader::egress(rows)
}

// ──────────────────────────────────────────────────────────────
// Tauri command wrappers (thin; only compiled with the `tauri` feature)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "tauri")]
#[tauri::command]
pub async fn get_posture() -> Value {
    posture_from_rows(&rows(ROW_LIMIT))
}

#[cfg(feature = "tauri")]
#[tauri::command]
pub async fn get_findings() -> Value {
    findings_from_rows(&rows(ROW_LIMIT))
}

#[cfg(feature = "tauri")]
#[tauri::command]
pub async fn get_sessions() -> Value {
    sessions_from_rows(&rows(ROW_LIMIT))
}

#[cfg(all(feature = "tauri", feature = "enterprise"))]
#[tauri::command]
pub async fn get_fleet() -> Value {
    fleet_from_rows(&rows(ROW_LIMIT))
}

#[cfg(feature = "tauri")]
#[tauri::command]
pub async fn get_egress() -> Value {
    egress_from_rows(&rows(ROW_LIMIT))
}

// ──────────────────────────────────────────────────────────────
// Live-approval commands (talk to the daemon over UDS)
// ──────────────────────────────────────────────────────────────
//
// These three are the desktop side of the daemon's interactive-approval queue.
// They issue a `command` frame via `crate::uds::request` and return the JSON the
// daemon replies with. Fail-soft for the UI: if the daemon is unreachable,
// `get_pending` degrades to an empty queue rather than erroring the dashboard.

/// Pending approvals snapshot — `{"pending":[...]}`. Daemon-unreachable ⇒ `{"pending":[]}`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_pending() -> Value {
    let frame = serde_json::json!({"type":"command","name":"get_pending","args":{}});
    match crate::uds::request(&frame).await {
        Ok(v) => v,
        Err(_) => serde_json::json!({"pending": []}),
    }
}

/// Resolve a parked approval. Returns the daemon's `{"ok":...}` reply, or an
/// `{"ok":false,"error":...}` string-mapped error if the daemon is unreachable.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn respond_approval(id: String, decision: String, scope: String) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"respond_approval",
        "args":{"id":id,"decision":decision,"scope":scope}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Toggle daemon protection (`on:false` = observe mode). Returns `{"ok":true,"protection":on}`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_protection(on: bool) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"set_protection","args":{"on":on}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// On-demand AI explanation for a flagged action. Daemon without the `ai`
/// feature answers `{"error":"unknown command"}`, which the web treats as
/// "AI unavailable". Owner-gating is inherited from the 0600 daemon socket.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn explain_action(tool: String, input: Value, rule: Option<String>) -> Value {
    let frame = serde_json::json!({
        "type":"command","name":"explain_action",
        "args":{"tool":tool,"input":input,"rule":rule}
    });
    crate::uds::request(&frame).await.unwrap_or_else(|_| serde_json::json!({"ok": false}))
}

/// Whether the daemon has AI explanations enabled. Fail-soft to disabled.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn ai_status() -> Value {
    let frame = serde_json::json!({"type":"command","name":"ai_status","args":{}});
    crate::uds::request(&frame).await.unwrap_or_else(|_| serde_json::json!({"ok": false, "enabled": false}))
}

/// Fetch the AI explainer settings (mode/provider/model/consent + `key_present`).
/// Daemon without the `ai` feature answers `{"error":"unknown command"}`, which the
/// settings panel renders as unavailable. Owner-gating is inherited from the 0600
/// daemon socket, same as `explain_action`/`ai_status` above.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_ai_config() -> Value {
    let frame = serde_json::json!({"type":"command","name":"get_ai_config","args":{}});
    crate::uds::request(&frame).await.unwrap_or_else(|_| serde_json::json!({"ok": false}))
}

/// Persist AI explainer settings. The daemon re-validates (cloud mode requires
/// `cloud_consent`), so a UI bug can never bypass the consent gate — this proxy
/// adds no extra logic, it only forwards.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_ai_config(config: Value) -> Value {
    let frame = serde_json::json!({
        "type":"command","name":"set_ai_config","args":{"config":config}
    });
    crate::uds::request(&frame)
        .await
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "ipc failed"}))
}

/// Persist (or clear, with an empty string) the BYOK cloud API key. Write-only:
/// the daemon stores it owner-only 0600 on disk and never returns it — the
/// response only ever carries `key_present`. This proxy adds no extra logic,
/// it only forwards, same as `set_ai_config` above.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_ai_key(key: String) -> Value {
    let frame = serde_json::json!({
        "type":"command","name":"set_ai_key","args":{"key":key}
    });
    crate::uds::request(&frame)
        .await
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "ipc failed"}))
}

// ──────────────────────────────────────────────────────────────
// Network destination enrichment (owner-gated daemon IPC; feature `netenrich`)
// ──────────────────────────────────────────────────────────────
//
// Display-only owner/ASN/country lookups for egress destinations. A daemon
// built WITHOUT the `netenrich` feature answers `{"error":"unknown
// command"}`, which these fail-soft to a benign "no enrichment"/"disabled"
// shape — same precedent as the AI proxies above. Never gates anything.

/// Enrich `dest` (host[:port]) with owner/ASN/country info. Fail-soft to
/// `{"ok":false}` if the daemon is unreachable or errors.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn enrich_dest(dest: String) -> Value {
    let frame = serde_json::json!({
        "type":"command","name":"enrich_dest","args":{"dest":dest}
    });
    crate::uds::request(&frame).await.unwrap_or_else(|_| serde_json::json!({"ok": false}))
}

/// Whether destination enrichment is currently enabled. Fail-soft to disabled.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_net_enrich() -> Value {
    let frame = serde_json::json!({"type":"command","name":"get_net_enrich","args":{}});
    crate::uds::request(&frame)
        .await
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "enabled": false}))
}

/// Toggle destination enrichment on/off.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_net_enrich(enabled: bool) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"set_net_enrich","args":{"enabled":enabled}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

// ──────────────────────────────────────────────────────────────
// Messaging channels (owner-gated daemon IPC; channels build only)
// ──────────────────────────────────────────────────────────────
//
// These proxy the daemon's owner-gated channel commands. The daemon socket is
// already 0600 + peer-uid checked, so no extra gating is added here. A daemon
// built WITHOUT the channels feature answers `{"ok":false,"error":"unknown
// command"}` / `"channels not enabled"`, which the Messaging view renders as a
// disabled state. Never carries secrets: get_channels returns a redacted view.

/// Redacted channels config (platforms / allowlist / inbound shape — no secrets).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_channels() -> Value {
    let frame = serde_json::json!({"type":"command","name":"get_channels","args":{}});
    crate::uds::request(&frame)
        .await
        .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "daemon unreachable"}))
}

/// Enroll a `(platform, principal)` into the allowlist (live + persisted).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn channel_allow_add(platform: String, principal: String) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"channel_allow_add",
        "args":{"platform":platform,"principal":principal}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Unenroll a `(platform, principal)` from the allowlist (live + persisted).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn channel_allow_remove(platform: String, principal: String) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"channel_allow_remove",
        "args":{"platform":platform,"principal":principal}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Start an interactive pairing for `platform`; returns `{ok,code,instructions}`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn channel_pair_start(platform: String) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"channel_pair_start","args":{"platform":platform}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Upsert a connector's config (credentials) + optionally replace its allowlist.
/// `config` is the platform's field object; `allow` is a list of principal ids.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_channel(
    platform: String,
    config: Value,
    allow: Option<Vec<String>>,
) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"set_channel",
        "args":{"platform":platform,"config":config,"allow":allow}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Remove a connector's config + its allowlist entries.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn remove_channel(platform: String) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"remove_channel","args":{"platform":platform}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Set (or clear, with `null`) the inbound-receiver config block.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_inbound(inbound: Value) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"set_inbound","args":{"inbound":inbound}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Administratively enable/disable a configured connector (credentials are kept;
/// only the adapter/verifier is skipped on next start). Mirrors Hermes's platform
/// enable Switch, backed by a real toggle rather than a decorative one.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_channel_enabled(platform: String, enabled: bool) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"set_channel_enabled","args":{"platform":platform,"enabled":enabled}
    });
    crate::uds::request(&frame).await.map_err(|e| e.to_string())
}

/// Open a URL in the OS's default browser — never the app's own webview, which
/// would navigate the UI away to that page. Used by the Messaging setup guide /
/// per-field docs links. Only ever called with static, hardcoded reference URLs
/// baked into the frontend (never a user-supplied/remote value), but the guard
/// below still fails closed on anything that isn't a plain https:// URL.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn open_external_url(url: String) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("refusing to open a non-https URL".into());
    }
    tokio::task::spawn_blocking(move || open::that(&url).map_err(|e| e.to_string()))
        .await
        .map_err(|e| format!("open task panicked: {e}"))?
}

/// Restart the daemon so a channels.json change takes effect: ask it to exit
/// (it acks, then exits ~300ms later), wait for the socket to free, then respawn
/// a fresh daemon that re-reads the config. Used by the Messaging save flow.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn restart_daemon() -> Result<Value, String> {
    let frame = serde_json::json!({"type":"command","name":"shutdown","args":{}});
    let _ = crate::uds::request(&frame).await; // best-effort; may already be down
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    ensure_daemon().await;
    Ok(serde_json::json!({"ok": true}))
}

// ──────────────────────────────────────────────────────────────
// Host / EDR commands (daemon IPC over UDS — piece 2 stateful path + reads)
// ──────────────────────────────────────────────────────────────
//
// Each issues a `command` frame via `crate::uds::request` to the daemon.
// READS fail soft (daemon-unreachable ⇒ a benign default so the dashboard
// renders); MUTATIONS surface a string error so the UI can toast it. Daemon
// command names and arg shapes mirror `daemon/src/ipc.rs::host_command_stateful`
// and the piece-1 read handlers; the TS contract is `web/src/lib/hostTypes.ts`.

/// Read a daemon `command`, returning `default` if the daemon is unreachable.
#[cfg(all(feature = "tauri", feature = "tokio"))]
async fn host_read(name: &str, default: Value) -> Value {
    let frame = serde_json::json!({"type":"command","name":name,"args":{}});
    crate::uds::request(&frame).await.unwrap_or(default)
}

/// Hardening posture (`HardeningPosture`). Default ⇒ perfect score, no checks.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_hardening_posture() -> Value {
    host_read("get_hardening_posture", serde_json::json!({"score":100,"checks":[]})).await
}

/// Vulnerability posture (`VulnPosture`). Returns the last `scan_host_vuln`
/// result (stamped with `scanned_at`/`job_id`) if one exists, else proxies the
/// daemon; default ⇒ empty posture.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_vuln_posture() -> Value {
    if let Some(v) = vuln_cache().lock().ok().and_then(|c| c.clone()) {
        return v;
    }
    host_read(
        "get_vuln_posture",
        serde_json::json!({"scanned_at":null,"job_id":null,"total":0,
                           "critical":0,"high":0,"medium":0,"low":0,"findings":[]}),
    )
    .await
}

/// Least-privilege firewall proposal (`ProposedRuleset`). Default ⇒ empty.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_proposed_ruleset() -> Value {
    host_read(
        "get_proposed_ruleset",
        serde_json::json!({"description":"unavailable","rules":[],"generated_at":""}),
    )
    .await
}

/// One-click auto-setup proposal (`ProposedRuleset`): auto-detect the system and
/// propose a least-privilege ruleset pre-filled for confirm. Default ⇒ empty.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_auto_proposed_ruleset() -> Value {
    host_read(
        "get_auto_proposed_ruleset",
        serde_json::json!({"description":"unavailable","rules":[],"generated_at":""}),
    )
    .await
}

/// Live firewall status (`FirewallStatus`). Default ⇒ inactive/off.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_firewall_status() -> Value {
    host_read(
        "get_firewall_status",
        serde_json::json!({"active":false,"mode":"off","handle":null,
                           "revert_deadline":null,"rule_count":0}),
    )
    .await
}

/// Operator egress allowlist (`EgressRule[]`). Default ⇒ empty array.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn get_egress_allowlist() -> Value {
    host_read("get_egress_allowlist", serde_json::json!([])).await
}

/// Active SSH bans (`Ban[]`). Default ⇒ empty array.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn list_bans() -> Value {
    host_read("get_ssh_bans", serde_json::json!([])).await
}

/// Send a mutating daemon command and require `{"ok":true}` in the reply.
#[cfg(all(feature = "tauri", feature = "tokio"))]
async fn host_mutate_ok(name: &str, args: Value) -> Result<(), String> {
    let frame = serde_json::json!({"type":"command","name":name,"args":args});
    let reply = crate::uds::request(&frame).await.map_err(|e| e.to_string())?;
    if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("daemon rejected the request")
            .to_string())
    }
}

/// Apply a firewall ruleset with the dead-man's-switch. Returns
/// `{revertDeadline, handle}` (camelCase per the TS contract) on success.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn apply_firewall(ruleset: Value) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"firewall_apply","args":{"ruleset":ruleset}
    });
    let reply = crate::uds::request(&frame).await.map_err(|e| e.to_string())?;
    if reply.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(serde_json::json!({
            "revertDeadline": reply.get("revert_deadline").cloned().unwrap_or(Value::Null),
            "handle": reply.get("handle").cloned().unwrap_or(Value::Null),
        }))
    } else {
        Err(reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("firewall apply failed")
            .to_string())
    }
}

/// Confirm a pending firewall change (keep it; cancel the auto-revert).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn confirm_firewall(handle: String) -> Result<(), String> {
    host_mutate_ok("firewall_confirm", serde_json::json!({"handle":handle})).await
}

/// Revert a pending firewall change immediately.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn revert_firewall(handle: String) -> Result<(), String> {
    host_mutate_ok("firewall_revert", serde_json::json!({"handle":handle})).await
}

/// Add an egress allowlist rule; returns the stored `EgressRule` (with id).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn add_egress_rule(rule: Value) -> Result<Value, String> {
    let frame = serde_json::json!({
        "type":"command","name":"egress_add","args":{"rule":rule}
    });
    let reply = crate::uds::request(&frame).await.map_err(|e| e.to_string())?;
    // egress_add returns the rule DTO on success, or {"ok":false,"error":...}.
    if reply.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return Err(reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("egress rule rejected")
            .to_string());
    }
    Ok(reply)
}

/// Remove an egress allowlist rule by id.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn remove_egress_rule(id: String) -> Result<(), String> {
    host_mutate_ok("egress_remove", serde_json::json!({"id":id})).await
}

/// Set the egress mode ("off" | "monitor" | "enforce").
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_egress_mode(mode: String) -> Result<(), String> {
    host_mutate_ok("egress_mode", serde_json::json!({"mode":mode})).await
}

/// Toggle inline NFQUEUE egress enforcement.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn set_inline_egress(enabled: bool) -> Result<(), String> {
    host_mutate_ok("set_inline_egress", serde_json::json!({"enabled":enabled})).await
}

/// Lift an SSH ban by id.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn unban(id: String) -> Result<(), String> {
    host_mutate_ok("ssh_unban", serde_json::json!({"id":id})).await
}

// ──────────────────────────────────────────────────────────────
// Host scan / quarantine / ssh-guard / schedule (in-process, daemon-free)
// ──────────────────────────────────────────────────────────────
//
// These operate on `~/.belay/` state directly (the desktop binary links
// `belayd` + `belay-server`), so they do not round-trip the daemon:
//   - host scan reuses `belay_server::run_host_scan_json` — the SAME bounded
//     YARA scan + JSON mapping the `POST /api/host/scan` route uses;
//   - quarantine lists/removes files under `~/.belay/quarantine`;
//   - the ssh-guard config and scan schedule are small JSON files that round-trip
//     get/set, with sensible defaults when absent — delegated to the shared
//     `belayd::host_config` module so they match the server routes exactly.
// TS contract: `web/src/lib/hostTypes.ts` (HostFinding, QuarantineEntry,
// SshGuardConfig, ScanSchedule).

// ── Host scan ─────────────────────────────────────────────────────────────────

/// In-process cache shared between `run_host_scan` and `get_scan_results`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn scan_cache() -> &'static std::sync::Mutex<Vec<Value>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<Value>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Run a bounded malware scan over `$HOME`, cache the findings, and return a job
/// handle. Mirrors `POST /api/host/scan` but in-process (no daemon round-trip).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn run_host_scan(options: Value) -> Result<Value, String> {
    let _ = options; // {quick?} reserved — the scan is the bounded user-home walk
    // User profile root: %USERPROFILE% on Windows (no $HOME there), else $HOME.
    let scope = std::path::PathBuf::from(
        std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .unwrap_or_else(|_| ".".into()),
    );
    // CPU-bound (file reads + YARA) — keep it off the async runtime threads.
    let findings =
        tokio::task::spawn_blocking(move || belay_server::run_host_scan_json(&scope, 200))
            .await
            .map_err(|e| format!("host scan task failed: {e}"))?;
    if let Ok(mut cache) = scan_cache().lock() {
        *cache = findings;
    }
    Ok(serde_json::json!({ "jobId": "host-scan" }))
}

/// Return the findings from the most recent `run_host_scan` (`HostFinding[]`).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn get_scan_results(job_id: Option<String>) -> Value {
    let _ = job_id; // single in-process cache; the handle is informational
    let results = scan_cache().lock().map(|c| c.clone()).unwrap_or_default();
    Value::Array(results)
}

// ── Vulnerability scan ──────────────────────────────────────────────────────────

/// In-process cache holding the last `scan_host_vuln` posture, served by
/// `get_vuln_posture` so the dashboard shows the last scan's stamps.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn vuln_cache() -> &'static std::sync::Mutex<Option<Value>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Option<Value>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

/// Refresh the vuln posture: recompute in-process from dpkg + the cached advisory
/// DB (the same `build_vuln_posture` the daemon runs; no separate live NVD sync
/// exists yet), stamp `scanned_at`/`job_id`, cache it for `get_vuln_posture`, and
/// return a `{ jobId }` handle. Mirrors `POST /api/host/vuln/scan`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn scan_host_vuln() -> Result<Value, String> {
    // dpkg parse + advisory match is blocking I/O — keep it off the runtime.
    let mut posture = tokio::task::spawn_blocking(|| {
        serde_json::to_value(belayd::host_api::build_vuln_posture())
    })
    .await
    .map_err(|e| format!("vuln scan task failed: {e}"))?
    .map_err(|e| format!("vuln posture serialize failed: {e}"))?;

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let job_id = format!("vuln-{secs}");
    if let Some(obj) = posture.as_object_mut() {
        let ts = belayd::host_config::rfc3339_utc(secs);
        obj.insert("scanned_at".into(), Value::String(ts));
        obj.insert("job_id".into(), Value::String(job_id.clone()));
    }
    if let Ok(mut cache) = vuln_cache().lock() {
        *cache = Some(posture);
    }
    Ok(serde_json::json!({ "jobId": job_id }))
}

// ── Scan schedule ─────────────────────────────────────────────────────────────

/// Read the persisted scan schedule (`ScanSchedule`), or defaults when unset.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn get_host_scan_schedule() -> Value {
    belayd::host_config::scan_schedule()
}

/// Persist the scan schedule.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn set_host_scan_schedule(schedule: Value) -> Result<(), String> {
    belayd::host_config::set_scan_schedule(&schedule)
}

// ── Quarantine ────────────────────────────────────────────────────────────────

/// List files currently under `~/.belay/quarantine` as `QuarantineEntry[]`.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn list_quarantine() -> Value {
    Value::Array(belayd::host_config::list_quarantine())
}

/// Restore a quarantined file (unavailable until the metadata store lands).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn restore_quarantine(id: String) -> Result<(), String> {
    belayd::host_config::restore_quarantine(&id)
}

/// Permanently delete a quarantined file by id (its filename).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn delete_quarantine(id: String) -> Result<(), String> {
    belayd::host_config::delete_quarantine(&id)
}

// ── SSH guard ─────────────────────────────────────────────────────────────────

/// Read the persisted SSH-guard config (`SshGuardConfig`), or defaults when unset.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn get_ssh_guard() -> Value {
    belayd::host_config::ssh_guard()
}

/// Persist an SSH-guard config patch (merged over the current/default config).
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn set_ssh_guard(config: Value) -> Result<(), String> {
    belayd::host_config::set_ssh_guard(&config)
}

// ──────────────────────────────────────────────────────────────
// Shell-out commands (invoke the `belay` binary, no heavy crate deps)
// ──────────────────────────────────────────────────────────────

/// Result of `belay scan <path> --format json`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: String,
    pub reason: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ScanResult {
    pub score: i64,
    pub severity: String,
    pub recommendation: String,
    pub findings: Vec<ScanFinding>,
}

/// Result of one element from `belay detect --json`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DetectedAgentDto {
    pub name: String,
    pub settings: Vec<String>,
    pub risky: Vec<String>,
    pub interception: String,
    pub mcp_config: Vec<String>,
    // `default` keeps this tolerant of an older `belay` binary that
    // predates these fields (the sidecar should match, but be defensive).
    #[serde(default)]
    pub mcp_servers: Vec<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub protected: bool,
}

/// Search `path_var` (a `$PATH`-style value) for an executable named `name` and
/// return its ABSOLUTE path. Pure over its input so it is unit-testable.
///
/// Resolving the fallback to an absolute path matters: the spawned `belay`
/// then runs `protect`, which embeds *its own* path into the agent hook. If we
/// spawn a bare name, a hook installed off a non-absolute path can fail later
/// with "belay: not found". Returning an absolute path keeps the whole
/// chain anchored regardless of the caller's runtime `$PATH`.
fn which_in(name: &str, path_var: Option<std::ffi::OsString>) -> Option<std::path::PathBuf> {
    let paths = path_var?;
    for dir in std::env::split_paths(&paths) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(std::fs::canonicalize(&cand).unwrap_or(cand));
        }
    }
    None
}

/// `which_in` against the live `$PATH`.
fn which_in_path(name: &str) -> Option<std::path::PathBuf> {
    which_in(name, std::env::var_os("PATH"))
}

/// The daemon binary's file name for this platform. `belay.exe` on Windows
/// (the sidecar and the built binary both carry the `.exe` suffix), else
/// `belay`. Pure — unit-testable without env/fs.
#[cfg_attr(not(feature = "tauri"), allow(dead_code))]
fn belay_bin_name() -> &'static str {
    if cfg!(windows) {
        "belay.exe"
    } else {
        "belay"
    }
}

/// Resolve the `belay` binary path using a four-step priority:
///  (a) `$BELAY_BIN` env var (absolute path or name);
///  (b) sibling of the current executable (desktop app bundle layout);
///  (c) absolute path resolved from `$PATH`;
///  (d) bare `"belay"` (last-resort PATH lookup at spawn time).
fn belay_bin() -> std::path::PathBuf {
    // (a) explicit env override
    if let Ok(val) = std::env::var("BELAY_BIN") {
        return std::path::PathBuf::from(val);
    }
    // (b) sibling of current exe (`.exe` suffix on Windows)
    if let Some(parent) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        let candidate = parent.join(belay_bin_name());
        if candidate.is_file() {
            return candidate;
        }
    }
    // (c) resolve via $PATH to an ABSOLUTE path (so an installed hook can't end
    // up anchored to a bare name that fails at the agent's runtime)
    if let Some(abs) = which_in_path("belay") {
        return abs;
    }
    // (d) last resort: bare name (spawn-time PATH lookup)
    std::path::PathBuf::from("belay")
}

/// On launch, make sure the daemon is reachable; if its UDS socket can't be
/// connected, spawn `belay daemon` so the host features work out of the box
/// (status, firewall proposals, scans, approval queue) instead of failing with
/// "daemon is not running".
///
/// NOTE: a desktop-spawned daemon runs UNPRIVILEGED. Firewall *enforcement*
/// (applying rules via netfilter) needs root — install the systemd unit
/// (`packaging/belay.service`) for that. This fallback still powers every
/// read path and surfaces a clear permission error on apply rather than ENOENT.
#[cfg(all(feature = "tauri", feature = "tokio"))]
pub async fn ensure_daemon() {
    // Already reachable (e.g. systemd already runs it)? A cheap unauthenticated
    // read the daemon answers — avoids double-spawning.
    let probe = serde_json::json!({"type": "command", "name": "get_posture", "args": {}});
    if crate::uds::request(&probe).await.is_ok() {
        return;
    }
    let bin = belay_bin();
    // Detached: the child keeps running after this handle drops (tokio does not
    // kill on drop by default), and the daemon binds the socket on startup.
    match tokio::process::Command::new(&bin).arg("daemon").spawn() {
        Ok(_child) => eprintln!("belay: auto-started daemon ({bin:?})"),
        Err(e) => eprintln!("belay: could not auto-start daemon ({bin:?}): {e}"),
    }
}

/// Parse `belay scan` stdout into a `ScanResult`.
///
/// The scanner intentionally exits 1 when risk score > 50 while still printing
/// valid JSON to stdout. So we attempt to parse stdout FIRST; if it deserialises
/// we return `Ok` regardless of `status_ok`. Only when stdout cannot be parsed
/// do we return `Err` (include the first stderr line for context).
pub fn parse_scan_output(stdout: &[u8], _status_ok: bool, stderr: &str) -> Result<ScanResult, String> {
    match serde_json::from_slice::<ScanResult>(stdout) {
        Ok(result) => Ok(result),
        Err(e) => {
            let stderr_first = stderr.lines().next().unwrap_or("(no stderr)");
            Err(format!("Failed to parse scan output: {e}; stderr: {stderr_first}"))
        }
    }
}

/// Run `belay scan <target> --format json` and parse the result.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn run_scan(target: String) -> Result<ScanResult, String> {
    let bin = belay_bin();
    let out = tokio::process::Command::new(&bin)
        .args(["scan", &target, "--format", "json"])
        .output()
        .await
        .map_err(|e| format!("Failed to launch belay: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    parse_scan_output(&out.stdout, out.status.success(), &stderr)
}

/// Run `belay detect --json` and parse the agent list.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn list_agents() -> Result<Vec<DetectedAgentDto>, String> {
    let bin = belay_bin();
    let out = tokio::process::Command::new(&bin)
        .args(["detect", "--json"])
        .output()
        .await
        .map_err(|e| format!("Failed to launch belay: {e}"))?;
    if !out.status.success() {
        let stderr_first = String::from_utf8_lossy(&out.stderr)
            .lines()
            .next()
            .unwrap_or("(no stderr)")
            .to_string();
        return Err(format!("belay detect failed: {stderr_first}"));
    }
    serde_json::from_slice::<Vec<DetectedAgentDto>>(&out.stdout)
        .map_err(|e| {
            let stderr_first = String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("(no stderr)")
                .to_string();
            format!("Failed to parse detect output: {e}; stderr: {stderr_first}")
        })
}

/// Run `belay protect <name>` and return trimmed stdout on success.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn protect_agent(name: String) -> Result<String, String> {
    let bin = belay_bin();
    let out = tokio::process::Command::new(&bin)
        .args(["protect", &name])
        .output()
        .await
        .map_err(|e| format!("Failed to launch belay: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("belay protect failed: {stderr}"));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if stdout.is_empty() {
        format!("Protected {name}")
    } else {
        stdout
    })
}

/// Run `belay unprotect <name>` and return trimmed stdout on success.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub async fn unprotect_agent(name: String) -> Result<String, String> {
    let bin = belay_bin();
    let out = tokio::process::Command::new(&bin)
        .args(["unprotect", &name])
        .output()
        .await
        .map_err(|e| format!("Failed to launch belay: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("belay unprotect failed: {stderr}"));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(if stdout.is_empty() {
        format!("Unprotected {name}")
    } else {
        stdout
    })
}

/// Surface the main window from the tray popover's "Open dashboard" button.
/// Hides the popover after bringing the main window to the foreground.
#[cfg(feature = "tauri")]
#[tauri::command]
pub fn focus_main(app: tauri::AppHandle) {
    use tauri::Manager;
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.unminimize();
        let _ = main.show();
        let _ = main.set_focus();
    }
    if let Some(pop) = app.get_webview_window("popover") {
        let _ = pop.hide();
    }
}

/// Hide the bottom-right toast window. Called by the toast UI once its
/// auto-dismiss timer elapses (or the user clicks it away).
#[cfg(feature = "tauri")]
#[tauri::command]
pub fn hide_toast(app: tauri::AppHandle) {
    use tauri::Manager;
    if let Some(toast) = app.get_webview_window("toast") {
        let _ = toast.hide();
    }
}

/// Recent audit rows (newest-first) to seed the Live Feed when it opens, before
/// the live `audit-event` stream takes over. The streamed events only cover
/// activity that happens *after* the view is open, so without this snapshot a
/// freshly-opened feed looks empty even when recent activity exists. Missing
/// file → empty list (never an error). Capped at 500.
#[cfg(all(feature = "tauri", feature = "tokio"))]
#[tauri::command]
pub fn get_recent_audit(limit: Option<usize>) -> Vec<Value> {
    let n = limit.unwrap_or(200).min(500);
    let mut r = rows(n); // oldest-first
    r.reverse(); // newest-first to match the live feed's prepend order
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn belay_bin_name_has_exe_on_windows() {
        let name = belay_bin_name();
        if cfg!(windows) {
            assert_eq!(name, "belay.exe");
        } else {
            assert_eq!(name, "belay");
        }
    }

    fn synthetic_rows() -> Vec<Value> {
        vec![
            json!({"ts":"2026-06-26T14:00:00Z","event":"gate","session":"s1","tool":"Bash",
                   "verdict":"deny","reason":"destructive","rules":["destructive.rm_rf"]}),
            json!({"ts":"2026-06-26T14:01:00Z","event":"gate","session":"s1","tool":"Read",
                   "verdict":"allow","reason":"","rules":[]}),
            json!({"ts":"2026-06-26T14:02:00Z","event":"gate","session":"s2","tool":"Write",
                   "verdict":"ask","reason":"sensitive path","rules":["persistence.cron"]}),
        ]
    }

    /// Write rows as NDJSON to a temp file and read them back via the same
    /// `belayd::audit::recent` path the commands use.
    fn write_temp_ndjson(rows: &[Value]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        for r in rows {
            writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
        }
        f.flush().unwrap();
        f
    }

    #[test]
    fn which_in_returns_absolute_path_or_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("belay");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        // Found in a PATH that includes the dir → absolute, canonicalized path.
        let path_var = std::env::join_paths([dir.path()]).unwrap();
        let got = which_in("belay", Some(path_var)).expect("should find");
        assert!(got.is_absolute(), "resolved path must be absolute: {got:?}");
        assert_eq!(got, std::fs::canonicalize(&bin).unwrap());

        // Not present in PATH → None (caller falls through to bare name).
        let empty = tempfile::tempdir().expect("tempdir2");
        let path_var2 = std::env::join_paths([empty.path()]).unwrap();
        assert_eq!(which_in("belay", Some(path_var2)), None);

        // No PATH at all → None.
        assert_eq!(which_in("belay", None), None);
    }

    #[test]
    fn posture_from_rows_matches_audit_reader() {
        let rows = synthetic_rows();
        let got = posture_from_rows(&rows);
        let want = serde_json::to_value(audit_reader::summarize(&rows)).unwrap();
        assert_eq!(got, want);
        // Sanity-check the shape: 3 total, 1 each verdict.
        assert_eq!(got["total"], json!(3));
        assert_eq!(got["allow"], json!(1));
        assert_eq!(got["ask"], json!(1));
        assert_eq!(got["deny"], json!(1));
        // score = 100 - 1*15 - 1*5 = 80
        assert_eq!(got["score"], json!(80));
    }

    #[test]
    fn findings_from_rows_matches_audit_reader_and_is_reversed() {
        let rows = synthetic_rows();
        let got = findings_from_rows(&rows);
        assert_eq!(got, audit_reader::to_findings(&rows));
        // Reversed: last synthetic row (ask) comes first.
        assert_eq!(got[0]["verdict"], json!("ask"));
        assert_eq!(got[2]["verdict"], json!("deny"));
    }

    #[test]
    fn sessions_from_rows_groups_by_session() {
        let rows = synthetic_rows();
        let got = sessions_from_rows(&rows);
        assert_eq!(got, audit_reader::sessions(&rows));
        // s1 has 2 events, s2 has 1.
        let arr = got.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn egress_and_fleet_match_audit_reader() {
        let rows = synthetic_rows();
        assert_eq!(egress_from_rows(&rows), audit_reader::egress(&rows));
        #[cfg(feature = "enterprise")]
        assert_eq!(fleet_from_rows(&rows), audit_reader::fleet_summary(&rows));
    }

    #[test]
    fn reads_rows_back_through_recent() {
        let rows = synthetic_rows();
        let f = write_temp_ndjson(&rows);
        let read = belayd::audit::recent(f.path().to_str().unwrap(), usize::MAX);
        assert_eq!(read.len(), 3);
        assert_eq!(posture_from_rows(&read), posture_from_rows(&rows));
    }

    #[test]
    fn missing_file_returns_empty_zero_shapes() {
        // recent() on a nonexistent path -> empty vec, never panics.
        let empty = belayd::audit::recent("/nonexistent/belay/audit.ndjson", usize::MAX);
        assert!(empty.is_empty());

        let posture = posture_from_rows(&empty);
        assert_eq!(posture["total"], json!(0));
        assert_eq!(posture["allow"], json!(0));
        assert_eq!(posture["ask"], json!(0));
        assert_eq!(posture["deny"], json!(0));
        assert_eq!(posture["score"], json!(100));

        assert_eq!(findings_from_rows(&empty), json!([]));
        assert_eq!(sessions_from_rows(&empty), json!([]));
        assert_eq!(egress_from_rows(&empty), json!([]));
    }

    /// parse_scan_output: valid JSON + non-zero exit (exit code 1) → Ok(ScanResult).
    /// This mirrors the real scanner behaviour: exits 1 when risk > 50 but still
    /// prints full JSON to stdout.
    #[test]
    fn parse_scan_output_nonzero_exit_valid_json_returns_ok() {
        let raw = r#"{
            "score": 80,
            "severity": "HIGH",
            "recommendation": "DO_NOT_INSTALL",
            "findings": [
                {
                    "rule_id": "rce.pipe_to_shell",
                    "severity": "CRITICAL",
                    "reason": "pipes to interpreter"
                }
            ]
        }"#;
        // status_ok=false simulates exit code 1
        let result = parse_scan_output(raw.as_bytes(), false, "");
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let r = result.unwrap();
        assert_eq!(r.score, 80);
        assert_eq!(r.recommendation, "DO_NOT_INSTALL");
        assert_eq!(r.findings.len(), 1);
    }

    /// parse_scan_output: garbage stdout + non-zero exit → Err containing stderr.
    #[test]
    fn parse_scan_output_garbage_stdout_returns_err() {
        let result = parse_scan_output(b"not json at all", false, "binary not found");
        assert!(result.is_err(), "expected Err, got: {result:?}");
        let msg = result.unwrap_err();
        assert!(msg.contains("Failed to parse scan output"), "message: {msg}");
        assert!(msg.contains("binary not found"), "stderr not in message: {msg}");
    }

    /// Pure parse test: scan JSON captured from the real binary → ScanResult.
    #[test]
    fn parse_scan_result_from_captured_json() {
        let raw = r#"{
            "score": 100,
            "severity": "HIGH",
            "recommendation": "DO_NOT_INSTALL",
            "findings": [
                {
                    "rule_id": "rce.pipe_to_shell",
                    "severity": "CRITICAL",
                    "reason": "downloads and pipes to an interpreter [file: x.py]"
                }
            ]
        }"#;
        let result: ScanResult = serde_json::from_str(raw).expect("parse ScanResult");
        assert_eq!(result.score, 100);
        assert_eq!(result.severity, "HIGH");
        assert_eq!(result.recommendation, "DO_NOT_INSTALL");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule_id, "rce.pipe_to_shell");
        assert_eq!(result.findings[0].severity, "CRITICAL");
        assert_eq!(result.findings[0].reason, "downloads and pipes to an interpreter [file: x.py]");
    }

    /// Pure parse test: detect --json array → Vec<DetectedAgentDto>.
    #[test]
    fn parse_detected_agents_from_captured_json() {
        let raw = r#"[
            {
                "name": "claude-code",
                "settings": ["/home/user/.claude/settings.json"],
                "risky": ["bypassPermissions"],
                "interception": "hook",
                "mcp_config": []
            },
            {
                "name": "cursor",
                "settings": [],
                "risky": [],
                "interception": "mcp-proxy",
                "mcp_config": ["/home/user/.cursor/mcp.json"]
            }
        ]"#;
        let agents: Vec<DetectedAgentDto> = serde_json::from_str(raw).expect("parse DetectedAgentDto[]");
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].name, "claude-code");
        assert_eq!(agents[0].settings, vec!["/home/user/.claude/settings.json"]);
        assert_eq!(agents[0].risky, vec!["bypassPermissions"]);
        assert_eq!(agents[0].interception, "hook");
        assert!(agents[0].mcp_config.is_empty());
        assert_eq!(agents[1].name, "cursor");
        assert_eq!(agents[1].interception, "mcp-proxy");
    }
}
