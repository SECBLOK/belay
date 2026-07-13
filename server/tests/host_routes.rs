//! Tests for the host/EDR read routes added in piece 1.
//! Verifies: (1) routes exist (no 404); (2) fail-soft defaults when the daemon
//! is unreachable (HOME isolated to an empty tmp dir); (3) POST /api/host/scan
//! over a dir containing an EICAR file returns a malicious finding.

use belay_server::{create_app, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;
use tower::ServiceExt;

// Every test in this file mutates the process-global HOME env var. Serialise
// them so a parallel test cannot clobber HOME mid-request (the scan handler and
// daemon-proxy handlers both read $HOME). A tokio Mutex is used (not std) so the
// guard can be held across `.await` without tripping clippy::await_holding_lock;
// its guard is also Send, so a multi-thread test runtime is fine.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Isolate HOME so the daemon socket path resolves to an empty tmp dir (no real
/// daemon), forcing the fail-soft default branch in every proxy route.
fn make_app() -> axum::Router {
    let tmp = std::env::temp_dir().join(format!("host-routes-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).ok();
    std::env::set_var("HOME", &tmp);
    create_app(AppState::test())
}

async fn get_json(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn put_json(app: &axum::Router, path: &str, body: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

/// Isolate HOME to a unique (test-private) tmp dir so write tests do not pollute
/// the shared read-test dir. Returns an app whose host-config writes land there.
fn make_app_isolated(tag: &str) -> axum::Router {
    let tmp = std::env::temp_dir().join(format!("host-routes-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).ok();
    std::env::set_var("HOME", &tmp);
    create_app(AppState::test())
}

#[tokio::test]
async fn host_hardening_returns_200_and_default_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/hardening").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.get("score").is_some(), "missing score: {v}");
    assert!(
        v.get("checks").map(|c| c.is_array()).unwrap_or(false),
        "missing checks array: {v}"
    );
}

#[tokio::test]
async fn host_vuln_returns_200_and_default_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/vuln").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.get("total").is_some(), "missing total: {v}");
    assert!(v.get("findings").is_some(), "missing findings: {v}");
}

#[tokio::test]
async fn host_firewall_proposed_returns_200_and_default_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/firewall/proposed").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.get("description").is_some(), "missing description: {v}");
    assert!(
        v.get("rules").map(|r| r.is_array()).unwrap_or(false),
        "missing rules array: {v}"
    );
}

#[tokio::test]
async fn host_firewall_status_returns_200_and_default_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/firewall/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        v["active"].as_bool(),
        Some(false),
        "default active=false: {v}"
    );
    assert_eq!(v["mode"].as_str(), Some("off"), "default mode=off: {v}");
}

#[tokio::test]
async fn host_egress_allowlist_returns_200_and_empty_array_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/egress/allowlist").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_array(), "egress allowlist must be an array: {v}");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn host_ssh_bans_returns_200_and_empty_array_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/ssh-guard/bans").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_array(), "ssh bans must be an array: {v}");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn host_quarantine_returns_200_and_empty_array_on_fresh_install() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app(); // HOME isolated to an empty tmp dir → no quarantine dir
    let (status, v) = get_json(&app, "/api/host/quarantine").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_array(), "quarantine must be an array: {v}");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn host_ssh_guard_returns_200_and_default_config() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app(); // no ssh_guard.json → defaults
    let (status, v) = get_json(&app, "/api/host/ssh-guard").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["enabled"].as_bool(), Some(true), "{v}");
    assert_eq!(v["ban_threshold"].as_u64(), Some(5), "{v}");
    assert_eq!(v["permit_root_login"].as_bool(), Some(false), "{v}");
}

#[tokio::test]
async fn host_scan_schedule_returns_200_and_default() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app(); // no scan_schedule.json → defaults
    let (status, v) = get_json(&app, "/api/host/scan/schedule").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["enabled"].as_bool(), Some(false), "{v}");
    assert_eq!(v["scope"].as_str(), Some("quick"), "{v}");
}

#[tokio::test]
async fn host_ssh_guard_put_persists_and_merges_patch() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app_isolated("put-ssh");
    let (status, v) = put_json(
        &app,
        "/api/host/ssh-guard",
        r#"{"enabled":false,"ban_threshold":9}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // patched fields applied
    assert_eq!(v["enabled"].as_bool(), Some(false), "{v}");
    assert_eq!(v["ban_threshold"].as_u64(), Some(9), "{v}");
    // un-patched field keeps its default (merge, not replace)
    assert_eq!(v["permit_root_login"].as_bool(), Some(false), "{v}");
    // a subsequent GET reflects the persisted value
    let (_, g) = get_json(&app, "/api/host/ssh-guard").await;
    assert_eq!(g["ban_threshold"].as_u64(), Some(9), "{g}");
}

#[tokio::test]
async fn host_scan_schedule_put_persists() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app_isolated("put-sched");
    let (status, v) = put_json(
        &app,
        "/api/host/scan/schedule",
        r#"{"enabled":true,"cron":"0 2 * * *","scope":"full"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["enabled"].as_bool(), Some(true), "{v}");
    assert_eq!(v["scope"].as_str(), Some("full"), "{v}");
    let (_, g) = get_json(&app, "/api/host/scan/schedule").await;
    assert_eq!(g["cron"].as_str(), Some("0 2 * * *"), "{g}");
}

// ── Mutation routes ───────────────────────────────────────────────────────────

async fn send(app: &axum::Router, method: &str, path: &str, body: Option<&str>) -> StatusCode {
    let mut b = Request::builder().method(method).uri(path);
    let req = match body {
        Some(s) => {
            b = b.header("content-type", "application/json");
            b.body(Body::from(s.to_owned())).unwrap()
        }
        None => b.body(Body::empty()).unwrap(),
    };
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn firewall_apply_proxy_returns_503_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app(); // HOME isolated → no daemon socket → unreachable
    let status = send(
        &app,
        "POST",
        "/api/host/firewall/apply",
        Some(r#"{"rules":[]}"#),
    )
    .await;
    // Route exists (not 404) and fails closed (daemon unreachable → 503).
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn egress_add_proxy_returns_503_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let status = send(
        &app,
        "POST",
        "/api/host/egress/allowlist",
        Some(r#"{"host":"x","action":"deny"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn unban_proxy_returns_503_when_daemon_down() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let status = send(&app, "DELETE", "/api/host/ssh-guard/bans/1.2.3.4", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn quarantine_delete_and_restore_work_without_daemon() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app_isolated("quar-mut");
    // Seed a fake quarantined file under the isolated HOME.
    let qdir =
        std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".belay/quarantine");
    std::fs::create_dir_all(&qdir).unwrap();
    std::fs::write(qdir.join("badfile"), b"x").unwrap();

    // Delete it → 200 (local fs op, no daemon).
    assert_eq!(
        send(&app, "DELETE", "/api/host/quarantine/badfile", None).await,
        StatusCode::OK
    );
    assert!(!qdir.join("badfile").exists());
    // Deleting a missing file → 400.
    assert_eq!(
        send(&app, "DELETE", "/api/host/quarantine/gone", None).await,
        StatusCode::BAD_REQUEST
    );
    // Restore is an honest 400 (store not implemented).
    assert_eq!(
        send(&app, "POST", "/api/host/quarantine/x/restore", None).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn host_scan_results_returns_200_and_empty_array_initially() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app();
    let (status, v) = get_json(&app, "/api/host/scan/results").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_array(), "scan results must be an array: {v}");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn host_scan_eicar_returns_malicious_finding() {
    let _g = ENV_LOCK.lock().await;
    // Write an EICAR file to a temp dir; point HOME at it so the scan walks it.
    let tmp = tempfile::tempdir().unwrap();
    let eicar_path = tmp.path().join("eicar.com");
    std::fs::write(
        &eicar_path,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    std::env::set_var("HOME", tmp.path());

    let app = create_app(AppState::test());
    let req = Request::builder()
        .method("POST")
        .uri("/api/host/scan")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let findings = v.as_array().expect("must be array");
    assert!(
        !findings.is_empty(),
        "expected at least one finding for EICAR file"
    );
    let malicious = findings
        .iter()
        .any(|f| f.get("verdict").and_then(|v| v.as_str()) == Some("malicious"));
    assert!(malicious, "expected a malicious verdict: {findings:?}");
}

async fn post_json(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn host_vuln_scan_returns_job_id_and_caches_stamped_posture() {
    let _g = ENV_LOCK.lock().await;
    let app = make_app_isolated("vuln-scan"); // fresh HOME → empty advisory cache

    // The scan recomputes the posture in-process and returns a { jobId } handle.
    let (status, v) = post_json(&app, "/api/host/vuln/scan").await;
    assert_eq!(status, StatusCode::OK);
    let job_id = v["jobId"].as_str().expect("missing jobId");
    assert!(job_id.starts_with("vuln-"), "unexpected jobId: {v}");

    // GET now serves the cached scan: the posture is stamped with that job_id and
    // a non-null scanned_at (proving the read prefers the last scan, not a fresh
    // daemon proxy which would return null stamps).
    let (status, p) = get_json(&app, "/api/host/vuln").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        p["job_id"].as_str(),
        Some(job_id),
        "posture not stamped: {p}"
    );
    assert!(p["scanned_at"].is_string(), "scanned_at not stamped: {p}");
    assert!(p.get("total").is_some(), "missing total: {p}");
    assert!(p["findings"].is_array(), "missing findings array: {p}");
}
