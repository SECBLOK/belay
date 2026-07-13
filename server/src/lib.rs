pub mod audit_reader;
pub mod auth;
pub mod stream;















use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};

// ──────────────────────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub platform_admin: bool,
}

// ──────────────────────────────────────────────────────────────
// AppState
// ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub audit_path: PathBuf,
    broadcast: tokio::sync::broadcast::Sender<Value>,
    pub users: Vec<User>,
    pub auth_secret: String,
    /// In-memory cache of the last host scan results (TS `HostFinding` JSON).
    /// Written by `POST /api/host/scan`, read by `GET /api/host/scan/results`.
    pub scan_cache: Arc<std::sync::Mutex<Vec<Value>>>,
    /// In-memory cache of the last vuln posture (TS `VulnPosture` JSON), stamped
    /// with `scanned_at`/`job_id`. Written by `POST /api/host/vuln/scan`,
    /// preferred by `GET /api/host/vuln` so the dashboard shows the last scan.
    pub vuln_cache: Arc<std::sync::Mutex<Option<Value>>>,
}

impl AppState {
    pub fn new(audit_path: PathBuf) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(256);
        Self {
            audit_path,
            broadcast: tx,
            users: vec![],
            auth_secret: String::new(),
            scan_cache: Arc::new(std::sync::Mutex::new(vec![])),
            vuln_cache: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn with_users(audit_path: PathBuf, users: Vec<User>, secret: String) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(256);
        Self {
            audit_path,
            broadcast: tx,
            users,
            auth_secret: secret,
            scan_cache: Arc::new(std::sync::Mutex::new(vec![])),
            vuln_cache: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn broadcast(&self) -> tokio::sync::broadcast::Sender<Value> {
        self.broadcast.clone()
    }

    pub fn test() -> Self {
        let unique = format!(
            "belay-test-{}-{}.ndjson",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        );
        let audit_path = std::env::temp_dir().join(unique);
        let (tx, _rx) = tokio::sync::broadcast::channel(256);
        Self {
            audit_path,
            broadcast: tx,
            users: vec![],
            auth_secret: String::new(),
            scan_cache: Arc::new(std::sync::Mutex::new(vec![])),
            vuln_cache: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

type SharedState = Arc<AppState>;

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

/// Load the single-user auth config from `data_dir` (the directory holding
/// `audit.ndjson`). Reads `users.json` (a JSON array of [`User`]) and
/// `server_secret` (a trimmed hex string). An absent, empty, or unparseable
/// `users.json` yields no users → open-access loopback mode (unchanged).
///
/// When users exist but no `server_secret` file does, a fresh secret is
/// generated, persisted to `data_dir/server_secret` (mode `0600` on unix), and
/// returned so the same signing key survives restarts. With no users, returns
/// `(vec![], String::new())`. The secret is never logged.
pub fn load_users_and_secret(data_dir: &std::path::Path) -> (Vec<User>, String) {
    let users: Vec<User> = std::fs::read_to_string(data_dir.join("users.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if users.is_empty() {
        return (vec![], String::new());
    }

    let secret_path = data_dir.join("server_secret");
    let secret = match std::fs::read_to_string(&secret_path) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            let fresh = belay_auth::generate_secret();
            write_secret_file(&secret_path, &fresh);
            fresh
        }
    };

    (users, secret)
}

/// Persist a signing secret to `path` with mode 0600 on unix (best-effort on
/// other platforms). On unix the file is created with 0600 at open time via
/// [`OpenOptionsExt::mode`] so there is no world-readable window; a same-directory
/// temp file + rename makes the write atomic. Failures are non-fatal — a
/// warning is emitted to stderr but the secret is still usable for this run.
fn write_secret_file(path: &std::path::Path, secret: &str) {
    if write_secret_file_inner(path, secret).is_err() {
        eprintln!(
            "belay serve: WARNING — could not persist server secret; \
             tokens will not survive a restart"
        );
    }
}

fn write_secret_file_inner(path: &std::path::Path, secret: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    // Same-directory temp so rename() stays on the same filesystem (atomic swap).
    let tmp_path = {
        let name = path
            .file_name()
            .map(|n| {
                let mut s = n.to_os_string();
                s.push(".tmp");
                s
            })
            .unwrap_or_else(|| std::ffi::OsString::from("secret.tmp"));
        path.with_file_name(name)
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp_path)?;
    f.write_all(secret.as_bytes())?;
    f.flush()?;
    drop(f);
    std::fs::rename(&tmp_path, path)
}

pub(crate) fn load_rows(audit_path: &PathBuf) -> Vec<Value> {
    match std::fs::read_to_string(audit_path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
        Err(_) => vec![],
    }
}

// ──────────────────────────────────────────────────────────────
// Route handlers
// ──────────────────────────────────────────────────────────────

async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

async fn posture(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let rows = load_rows(&state.audit_path);
    let summary = audit_reader::summarize(&rows);
    Json(serde_json::to_value(summary).unwrap())
}

async fn findings(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let rows = load_rows(&state.audit_path);
    Json(audit_reader::to_findings(&rows))
}

async fn sessions_ep(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let rows = load_rows(&state.audit_path);
    Json(audit_reader::sessions(&rows))
}

async fn egress_ep(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let rows = load_rows(&state.audit_path);
    Json(audit_reader::egress(&rows))
}

async fn stream_ep(
    State(s): State<SharedState>,
    _auth: auth::AuthClaims,
) -> impl axum::response::IntoResponse {
    stream::stream(s.broadcast())
}

// ──────────────────────────────────────────────────────────────
// Interactive-approval proxy (bridges the browser dashboard → daemon)
// ──────────────────────────────────────────────────────────────
//
// The approval queue lives in the resident daemon (`belay daemon`), not in
// this read-only audit server, so these endpoints proxy a single length-prefixed
// JSON command frame to the daemon's UDS (`~/.belay/belayd.sock`) — the
// same protocol the desktop app uses. Read is fail-soft (no daemon ⇒ empty
// queue, dashboard stays usable); write is fail-closed (no daemon ⇒ 503).

fn daemon_socket_path() -> PathBuf {
    PathBuf::from(belayd::paths::socket_path())
}

/// Map a UDS connect failure (socket missing / refused) to a clear message so
/// the 503 body reads "daemon not running" instead of a raw "No such file or
/// directory (os error 2)".
fn daemon_down(e: std::io::Error) -> std::io::Error {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    match e.kind() {
        NotFound | ConnectionRefused => std::io::Error::new(
            e.kind(),
            "Belay daemon is not running — start it with `belay daemon`",
        ),
        _ => e,
    }
}

/// Connect, write one length-prefixed (4-byte BE u32) JSON frame, read one reply.
#[cfg(unix)]
async fn daemon_request(frame: &Value) -> std::io::Result<Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut sock = UnixStream::connect(daemon_socket_path())
        .await
        .map_err(daemon_down)?;
    let body = serde_json::to_vec(frame)?;
    sock.write_all(&(body.len() as u32).to_be_bytes()).await?;
    sock.write_all(&body).await?;
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    sock.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Connect, write one length-prefixed (4-byte BE u32) JSON frame, read one reply.
///
/// Windows: same framing as the Unix path but over a named pipe (via
/// `belay_transport::connect`).  The transport's `CreateFileW` call
/// carries `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` so the daemon can
/// run `ImpersonateNamedPipeClient` for caller-identity auth.  We run the
/// blocking I/O on a `spawn_blocking` thread so the async caller is unblocked.
#[cfg(not(unix))]
async fn daemon_request(frame: &Value) -> std::io::Result<Value> {
    use std::io::{Read, Write};

    let addr = daemon_socket_path()
        .to_str()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 socket path")
        })?
        .to_owned();
    let body = serde_json::to_vec(frame)?;

    let result = tokio::task::spawn_blocking(move || -> std::io::Result<Value> {
        let mut sock = belay_transport::connect(&addr).map_err(daemon_down)?;
        sock.write_all(&(body.len() as u32).to_be_bytes())?;
        sock.write_all(&body)?;
        let mut len = [0u8; 4];
        sock.read_exact(&mut len)?;
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        sock.read_exact(&mut buf)?;
        Ok(serde_json::from_slice(&buf)?)
    })
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    result
}

/// GET /api/decisions/pending — snapshot of parked approvals from the daemon.
/// Daemon unreachable ⇒ `{"pending":[]}` (fail-soft).
async fn decisions_pending(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_pending", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!({"pending": []})),
    }
}

/// POST /api/decisions/{id} — resolve a parked approval via the daemon. Requires
/// operator role when auth is enabled. Daemon unreachable ⇒ 503 (fail-closed: we
/// must never report a resolution that did not happen).
async fn decisions_respond(
    State(_state): State<SharedState>,
    _auth: auth::RequireOperator,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let decision = body
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("deny");
    let scope = body.get("scope").and_then(|v| v.as_str()).unwrap_or("once");
    let frame = json!({
        "type": "command", "name": "respond_approval",
        "args": {"id": id, "decision": decision, "scope": scope}
    });
    match daemon_request(&frame).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": format!("daemon unreachable: {e}")})),
        )),
    }
}

// ──────────────────────────────────────────────────────────────
// Host/EDR read routes (piece 1)
// ──────────────────────────────────────────────────────────────
//
// Four routes proxy a single command frame to the daemon (same UDS protocol as
// /api/decisions/*). Each fail-softs to a sensible default JSON when the daemon
// is unreachable, so the dashboard stays usable. The fifth (host scan) runs the
// scanner in this process — the daemon cannot depend on `scanner` (cycle).

/// Seconds since the Unix epoch — used to mint scan job ids.
fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// RFC3339 UTC timestamp — used by scan results. No chrono dependency.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Walk `scope_dir` non-recursively and collect up to `cap` files as
/// `(path_string, bytes)`. Skips files > 10 MiB and stops after `cap` files —
/// this bounds memory and avoids walking the whole filesystem.
fn collect_scan_files(scope_dir: &std::path::Path, cap: usize) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let Ok(walker) = std::fs::read_dir(scope_dir) else {
        return files;
    };
    for entry in walker.flatten() {
        if files.len() >= cap {
            break;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() > 10 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        files.push((path.to_string_lossy().into_owned(), bytes));
    }
    files
}

/// Map a `scanner::Finding` → the TS `HostFinding` JSON shape.
fn finding_to_host_json(f: &scanner::Finding, idx: usize, ts: &str) -> Value {
    let verdict = match f.decision {
        scanner::Decision::Deny => "malicious",
        scanner::Decision::Ask => "suspicious",
        scanner::Decision::Allow => "clean",
    };
    // Use the serde representation (Severity is #[serde(rename_all = "lowercase")]),
    // which is a stable contract, rather than Debug formatting which is not.
    let severity = serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "low".to_owned());
    json!({
        "id": format!("scan-{idx}"),
        "path": f.location.as_ref().map(|l| l.file.clone()).unwrap_or_default(),
        "rule_id": f.rule_id,
        "severity": severity,
        "verdict": verdict,
        "reason": f.reason,
        "ts": ts,
    })
}

/// GET /api/host/hardening — proxy get_hardening_posture; fail-soft.
async fn host_hardening(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_hardening_posture", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!({"score": 100, "checks": []})),
    }
}

/// GET /api/host/vuln — return the last scan's cached posture if one exists
/// (so `scanned_at`/`job_id` are shown), else proxy get_vuln_posture; fail-soft.
async fn host_vuln(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    if let Ok(cache) = state.vuln_cache.lock() {
        if let Some(v) = cache.as_ref() {
            return Json(v.clone());
        }
    }
    let frame = json!({"type": "command", "name": "get_vuln_posture", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!({
            "scanned_at": null, "job_id": null,
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "findings": []
        })),
    }
}

/// POST /api/host/vuln/scan — refresh the vuln posture. Recomputes in-process
/// from dpkg + the cached advisory DB (the same `build_vuln_posture` the daemon
/// runs; no separate live NVD sync exists yet), stamps `scanned_at`/`job_id`,
/// caches it for `GET /api/host/vuln`, and returns a `{ jobId }` handle.
async fn host_vuln_scan(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let mut posture = tokio::task::spawn_blocking(|| {
        serde_json::to_value(belayd::host_api::build_vuln_posture())
            .unwrap_or_else(|_| json!({}))
    })
    .await
    .unwrap_or_else(|_| json!({}));

    let job_id = format!("vuln-{}", now_unix_secs());
    if let Some(obj) = posture.as_object_mut() {
        obj.insert("scanned_at".into(), json!(now_rfc3339()));
        obj.insert("job_id".into(), json!(job_id));
    }
    if let Ok(mut cache) = state.vuln_cache.lock() {
        *cache = Some(posture);
    }
    Json(json!({ "jobId": job_id }))
}

/// GET /api/host/firewall/proposed — proxy get_proposed_ruleset; fail-soft.
async fn host_firewall_proposed(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_proposed_ruleset", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => {
            Json(json!({"description": "Daemon unavailable", "rules": [], "generated_at": ""}))
        }
    }
}

/// GET /api/host/firewall/auto-proposed — proxy get_auto_proposed_ruleset
/// (one-click auto setup: auto-detect system + propose ruleset); fail-soft.
async fn host_firewall_auto_proposed(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_auto_proposed_ruleset", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => {
            Json(json!({"description": "Daemon unavailable", "rules": [], "generated_at": ""}))
        }
    }
}

/// GET /api/host/firewall/status — proxy get_firewall_status; fail-soft.
async fn host_firewall_status(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_firewall_status", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!({
            "active": false, "mode": "off", "handle": null,
            "revert_deadline": null, "rule_count": 0
        })),
    }
}

/// GET /api/host/egress/allowlist — proxy get_egress_allowlist; fail-soft.
/// Read-only view of the daemon-held operator egress allowlist (mutations are
/// desktop-only via the Tauri IPC bridge).
async fn host_egress_allowlist(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_egress_allowlist", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!([])),
    }
}

/// GET /api/host/ssh-guard/bans — proxy get_ssh_bans; fail-soft.
async fn host_ssh_bans(_auth: auth::AuthClaims) -> Json<Value> {
    let frame = json!({"type": "command", "name": "get_ssh_bans", "args": {}});
    match daemon_request(&frame).await {
        Ok(v) => Json(v),
        Err(_) => Json(json!([])),
    }
}

// Read-only host-config routes for web parity with the desktop app. They read
// this host's `~/.belay` state directly via the shared `host_config`
// module (same defaults the desktop commands use). Mutations stay desktop-only.

/// GET /api/host/quarantine — list quarantined files (`QuarantineEntry[]`).
async fn host_quarantine(_auth: auth::AuthClaims) -> Json<Value> {
    Json(Value::Array(belayd::host_config::list_quarantine()))
}

/// GET /api/host/ssh-guard — current SSH-guard config (`SshGuardConfig`).
async fn host_ssh_guard(_auth: auth::AuthClaims) -> Json<Value> {
    Json(belayd::host_config::ssh_guard())
}

/// GET /api/host/scan/schedule — current scan schedule (`ScanSchedule`).
async fn host_scan_schedule(_auth: auth::AuthClaims) -> Json<Value> {
    Json(belayd::host_config::scan_schedule())
}

/// PUT /api/host/ssh-guard — persist an SSH-guard config patch (operator-gated).
/// Returns the merged config. The write is local to this host's `~/.belay`.
async fn host_ssh_guard_set(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match belayd::host_config::set_ssh_guard(&body) {
        Ok(()) => Ok(Json(belayd::host_config::ssh_guard())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e})),
        )),
    }
}

/// PUT /api/host/scan/schedule — persist the scan schedule (operator-gated).
/// Returns the stored schedule.
async fn host_scan_schedule_set(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match belayd::host_config::set_scan_schedule(&body) {
        Ok(()) => Ok(Json(belayd::host_config::scan_schedule())),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": e})),
        )),
    }
}

// ──────────────────────────────────────────────────────────────
// Host/EDR mutation routes (operator-gated)
// ──────────────────────────────────────────────────────────────
//
// The daemon-held mutations (firewall guard, egress allowlist, ssh bans) proxy
// a command frame to the daemon over the UDS, fail-CLOSED: if the daemon is
// unreachable we return 503 rather than reporting a change that did not happen.
// The firewall dead-man's-switch still protects a web operator who applies a
// rule that severs their own connection — the auto-revert fires when the confirm
// never arrives. Quarantine restore/delete are local filesystem ops via the
// shared `host_config` module (no daemon needed).

/// Proxy a mutating daemon command that replies `{"ok": bool, ...}`.
/// `ok:true` → 200 (the full reply); `ok:false` → 400; daemon down → 503.
async fn proxy_ok(frame: Value) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match daemon_request(&frame).await {
        Ok(v) if v.get("ok").and_then(|b| b.as_bool()) == Some(true) => Ok(Json(v)),
        Ok(v) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": v.get("error").cloned().unwrap_or_else(|| json!("daemon rejected the request")),
            })),
        )),
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": format!("daemon unreachable: {e}")})),
        )),
    }
}

/// POST /api/host/firewall/apply — apply a ruleset with the dead-man's-switch.
/// Returns `{revertDeadline, handle}` (camelCase, matching the TS contract).
async fn host_firewall_apply(
    _auth: auth::RequireOperator,
    Json(ruleset): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let frame = json!({"type": "command", "name": "firewall_apply", "args": {"ruleset": ruleset}});
    match daemon_request(&frame).await {
        Ok(v) if v.get("ok").and_then(|b| b.as_bool()) == Some(true) => Ok(Json(json!({
            "revertDeadline": v.get("revert_deadline").cloned().unwrap_or(Value::Null),
            "handle": v.get("handle").cloned().unwrap_or(Value::Null),
        }))),
        Ok(v) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": v.get("error").cloned().unwrap_or_else(|| json!("firewall apply failed")),
            })),
        )),
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": format!("daemon unreachable: {e}")})),
        )),
    }
}

/// POST /api/host/firewall/confirm — keep a pending ruleset (cancel auto-revert).
async fn host_firewall_confirm(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let handle = body.get("handle").and_then(|v| v.as_str()).unwrap_or("");
    proxy_ok(json!({"type": "command", "name": "firewall_confirm", "args": {"handle": handle}}))
        .await
}

/// POST /api/host/firewall/revert — revert a pending ruleset immediately.
async fn host_firewall_revert(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let handle = body.get("handle").and_then(|v| v.as_str()).unwrap_or("");
    proxy_ok(json!({"type": "command", "name": "firewall_revert", "args": {"handle": handle}}))
        .await
}

/// POST /api/host/egress/allowlist — add an egress rule; returns the stored rule.
async fn host_egress_add(
    _auth: auth::RequireOperator,
    Json(rule): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let frame = json!({"type": "command", "name": "egress_add", "args": {"rule": rule}});
    match daemon_request(&frame).await {
        // egress_add returns the rule DTO on success, or {"ok":false,...}.
        Ok(v) if v.get("ok").and_then(|b| b.as_bool()) == Some(false) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": v.get("error").cloned().unwrap_or_else(|| json!("egress rule rejected")),
            })),
        )),
        Ok(v) => Ok(Json(v)),
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": format!("daemon unreachable: {e}")})),
        )),
    }
}

/// DELETE /api/host/egress/allowlist/{id} — remove an egress rule.
async fn host_egress_remove(
    _auth: auth::RequireOperator,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    proxy_ok(json!({"type": "command", "name": "egress_remove", "args": {"id": id}})).await
}

/// PUT /api/host/egress/mode — set the egress mode ("off"|"monitor"|"enforce").
async fn host_egress_mode(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("off");
    proxy_ok(json!({"type": "command", "name": "egress_mode", "args": {"mode": mode}})).await
}

/// PUT /api/host/egress/inline — toggle inline NFQUEUE egress.
async fn host_egress_inline(
    _auth: auth::RequireOperator,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    proxy_ok(json!({"type": "command", "name": "set_inline_egress", "args": {"enabled": enabled}}))
        .await
}

/// DELETE /api/host/ssh-guard/bans/{id} — lift an SSH ban.
async fn host_unban(
    _auth: auth::RequireOperator,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    proxy_ok(json!({"type": "command", "name": "ssh_unban", "args": {"id": id}})).await
}

/// POST /api/host/quarantine/{id}/restore — restore a quarantined file.
/// (Currently an honest 400 until the quarantine metadata store lands.)
async fn host_quarantine_restore(
    _auth: auth::RequireOperator,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match belayd::host_config::restore_quarantine(&id) {
        Ok(()) => Ok(Json(json!({"ok": true}))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e})),
        )),
    }
}

/// DELETE /api/host/quarantine/{id} — permanently delete a quarantined file.
async fn host_quarantine_delete(
    _auth: auth::RequireOperator,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match belayd::host_config::delete_quarantine(&id) {
        Ok(()) => Ok(Json(json!({"ok": true}))),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": e})),
        )),
    }
}

/// Run a bounded malware scan over `scope_dir` (non-recursive, ≤ `cap` files,
/// ≤ 10 MiB each) and return the findings as `HostFinding`-shaped JSON values.
///
/// Public so in-process consumers that link this crate (the Tauri desktop app)
/// can reuse the exact same scan + JSON mapping the HTTP route uses, rather than
/// shelling out or re-implementing it. This is CPU-bound and synchronous — async
/// callers should wrap it in `spawn_blocking`.
pub fn run_host_scan_json(scope_dir: &std::path::Path, cap: usize) -> Vec<Value> {
    let files = collect_scan_files(scope_dir, cap);
    let findings = scanner::analyzers::malware::scan_malware_yara(&files, None);
    let ts = now_rfc3339();
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| finding_to_host_json(f, i, &ts))
        .collect::<Vec<_>>()
}

/// POST /api/host/scan — run a bounded malware scan over `$HOME` (non-recursive,
/// ≤ 200 files, ≤ 10 MiB each), cache the results, and return them directly.
async fn host_scan_run(State(state): State<SharedState>, _auth: auth::AuthClaims) -> Json<Value> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let scope_dir = std::path::PathBuf::from(home);
    let scan_cache = state.scan_cache.clone();

    // CPU-bound work (file reads + YARA) on a blocking thread.
    let findings_json = tokio::task::spawn_blocking(move || run_host_scan_json(&scope_dir, 200))
        .await
        .unwrap_or_else(|e| {
            eprintln!("belay host scan: blocking task failed: {e}");
            Vec::new()
        });

    if let Ok(mut cache) = scan_cache.lock() {
        *cache = findings_json.clone();
    }

    Json(Value::Array(findings_json))
}

/// GET /api/host/scan/results — return the last cached scan results.
async fn host_scan_results(
    State(state): State<SharedState>,
    _auth: auth::AuthClaims,
) -> Json<Value> {
    let results = state
        .scan_cache
        .lock()
        .map(|c| c.clone())
        .unwrap_or_default();
    Json(Value::Array(results))
}

// ──────────────────────────────────────────────────────────────
// Router
// ──────────────────────────────────────────────────────────────

pub fn create_app(state: AppState) -> Router {
    let shared = Arc::new(state);
    let router = Router::new()
        .route("/api/health", get(health))
        .route("/api/posture", get(posture))
        .route("/api/findings", get(findings))
        .route("/api/sessions", get(sessions_ep))
        .route("/api/egress", get(egress_ep))
        .route("/api/stream", get(stream_ep))
        .route("/api/decisions/pending", get(decisions_pending))
        .route("/api/decisions/:id", post(decisions_respond))
        // ── Host/EDR read endpoints (piece 1) ──
        .route("/api/host/hardening", get(host_hardening))
        .route("/api/host/vuln", get(host_vuln))
        .route("/api/host/vuln/scan", post(host_vuln_scan))
        .route("/api/host/firewall/proposed", get(host_firewall_proposed))
        .route(
            "/api/host/firewall/auto-proposed",
            get(host_firewall_auto_proposed),
        )
        .route("/api/host/firewall/status", get(host_firewall_status))
        .route(
            "/api/host/egress/allowlist",
            get(host_egress_allowlist).post(host_egress_add),
        )
        .route("/api/host/egress/allowlist/:id", delete(host_egress_remove))
        .route("/api/host/egress/mode", put(host_egress_mode))
        .route("/api/host/egress/inline", put(host_egress_inline))
        .route("/api/host/ssh-guard/bans", get(host_ssh_bans))
        .route("/api/host/ssh-guard/bans/:id", delete(host_unban))
        .route("/api/host/quarantine", get(host_quarantine))
        .route("/api/host/quarantine/:id", delete(host_quarantine_delete))
        .route(
            "/api/host/quarantine/:id/restore",
            post(host_quarantine_restore),
        )
        .route("/api/host/firewall/apply", post(host_firewall_apply))
        .route("/api/host/firewall/confirm", post(host_firewall_confirm))
        .route("/api/host/firewall/revert", post(host_firewall_revert))
        .route(
            "/api/host/ssh-guard",
            get(host_ssh_guard).put(host_ssh_guard_set),
        )
        .route(
            "/api/host/scan/schedule",
            get(host_scan_schedule).put(host_scan_schedule_set),
        )
        .route("/api/host/scan", post(host_scan_run))
        .route("/api/host/scan/results", get(host_scan_results));

    let router = router.merge(auth::open_auth_routes());


    router.with_state(shared)
}

/// Whether binding a given address is permitted under the current auth config.
#[derive(Debug, PartialEq, Eq)]
enum BindPolicy {
    /// Loopback, or auth is configured — safe to bind.
    Allow,
    /// Non-loopback + open-access, but explicitly overridden — bind with a warning.
    WarnInsecure,
    /// Non-loopback + open-access + no override — refuse (would expose audit data).
    Refuse,
}

/// Open-access mode (no users configured) leaves `/api/*` unauthenticated, which
/// is fine on loopback but would expose audit data, sessions, and the egress map
/// to the whole network on a non-loopback bind. Refuse that combination unless the
/// operator explicitly opts in.
fn bind_policy(is_loopback: bool, has_users: bool, insecure_override: bool) -> BindPolicy {
    if is_loopback || has_users {
        BindPolicy::Allow
    } else if insecure_override {
        BindPolicy::WarnInsecure
    } else {
        BindPolicy::Refuse
    }
}

fn insecure_override_set() -> bool {
    std::env::var("BELAY_INSECURE_NO_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Bind `addr` and serve the audit/web API (the `axum::serve` glue the unified
/// `belay serve` subcommand needs — the crate is otherwise a library with
/// no run loop). Reads audit rows from `audit_path`; loads users from
/// `users.json` and enforces JWT authentication when users are configured.
/// Without users, access is open but restricted to loopback by default.
///
/// Refuses to bind a non-loopback address while auth is open (see [`bind_policy`])
/// unless `BELAY_INSECURE_NO_AUTH=1` is set.
pub async fn run(addr: std::net::SocketAddr, audit_path: PathBuf) -> anyhow::Result<()> {
    // users.json / server_secret sit alongside audit.ndjson in the data dir.
    let data_dir = audit_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let (users, secret) = load_users_and_secret(&data_dir);
    let state = if users.is_empty() {
        AppState::new(audit_path)
    } else {
        AppState::with_users(audit_path, users, secret)
    };
    match bind_policy(
        addr.ip().is_loopback(),
        !state.users.is_empty(),
        insecure_override_set(),
    ) {
        BindPolicy::Refuse => anyhow::bail!(
            "refusing to bind {addr}: the dashboard has no authentication configured \
             (open-access mode) and {} is not loopback, which would expose audit data, \
             sessions, and the egress map to the network. Bind 127.0.0.1, configure users, \
             or set BELAY_INSECURE_NO_AUTH=1 to override.",
            addr.ip()
        ),
        BindPolicy::WarnInsecure => eprintln!(
            "belay serve: WARNING — binding {addr} with NO authentication; the dashboard \
             (audit data, sessions, egress map) is exposed to the network."
        ),
        BindPolicy::Allow => {}
    }
    let app = create_app(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("belay serve: API + SSE backend on http://{addr} (JSON/SSE, not a web page)");
    eprintln!("belay serve: open the desktop app for the dashboard UI, or run the web frontend in dev (`npm --prefix web run dev`)");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod bind_policy_tests {
    use super::*;

    #[test]
    fn loopback_open_access_is_allowed() {
        assert_eq!(bind_policy(true, false, false), BindPolicy::Allow);
    }

    #[test]
    fn non_loopback_with_users_is_allowed() {
        assert_eq!(bind_policy(false, true, false), BindPolicy::Allow);
    }

    #[test]
    fn non_loopback_open_access_is_refused() {
        assert_eq!(bind_policy(false, false, false), BindPolicy::Refuse);
    }

    #[test]
    fn non_loopback_open_access_with_override_warns() {
        assert_eq!(bind_policy(false, false, true), BindPolicy::WarnInsecure);
    }
}

#[cfg(test)]
mod load_users_tests {
    use super::*;

    fn unique_tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "belay-load-users-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loads_admin_and_persists_secret() {
        let dir = unique_tmp();
        let hash = belay_auth::hash_password("s3cret").expect("hash");
        let users = serde_json::json!([{
            "username": "admin",
            "password_hash": hash,
            "role": "admin",
        }]);
        std::fs::write(dir.join("users.json"), users.to_string()).unwrap();

        let (loaded, secret) = load_users_and_secret(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].username, "admin");
        assert_eq!(loaded[0].role, "admin");
        assert!(!secret.is_empty(), "a secret should be generated");

        let secret_path = dir.join("server_secret");
        assert!(secret_path.exists(), "server_secret must be persisted");
        assert_eq!(
            std::fs::read_to_string(&secret_path).unwrap().trim(),
            secret,
            "persisted secret must match the returned one"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&secret_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "server_secret must be 0600");
        }

        // Reload reuses the same persisted secret (does not regenerate).
        let (_again, secret2) = load_users_and_secret(&dir);
        assert_eq!(secret, secret2, "secret should be stable across reloads");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dir_yields_empty_and_bind_refuses() {
        let dir = std::env::temp_dir().join(format!(
            "belay-absent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let (users, secret) = load_users_and_secret(&dir);
        assert!(users.is_empty());
        assert!(secret.is_empty());
        // No users → a non-loopback bind still refuses.
        assert_eq!(
            bind_policy(false, !users.is_empty(), false),
            BindPolicy::Refuse
        );
    }
}
