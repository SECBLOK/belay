//! Phase B inbound-webhook HTTP receiver (channels build only).
//!
//! A tiny hyper HTTP/1 server, bound to **loopback by default**, that accepts
//! platform callbacks at `POST /hook/<platform>`. For each request it looks up
//! the matching [`InboundVerifier`], which authenticates the request (per-platform
//! HMAC over the raw body) and normalizes it into [`belay_channels::InboundReply`]
//! values. Those are handed to [`ChannelBridge::process_reply`] — the SAME authz
//! gate the polled adapters use — so the inbound path inherits DM-only ∧ allowlist
//! ∧ rate-limit ∧ dedup ∧ exact-nonce for free; the receiver only adds request
//! authentication and transport.
//!
//! ## Deployment / trust
//! TLS + public exposure are the operator's reverse proxy (Caddy / Cloudflare
//! Tunnel / nginx); the daemon speaks plain HTTP on loopback. Authenticity does
//! NOT depend on TLS — a forged request fails the verifier's signature check and
//! is answered `401` without touching the approval queue. Bodies are size-capped;
//! only `POST /hook/<platform>` is handled; every other request is refused. A
//! valid signature is answered `200` even if the gate ultimately rejects the
//! reply, so the platform does not retry a decision we deliberately dropped.

use crate::channels_bridge::{ChannelBridge, ChannelsConfig};
use belay_channels::inbound::{InboundVerifier, LineVerifier, SlackVerifier};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Reject bodies larger than this (webhook payloads are small; this bounds a
/// flood and any decompression/parse cost).
const MAX_BODY: usize = 64 * 1024;

/// Max concurrent inbound connections (slowloris / fd-exhaustion bound).
const MAX_CONNS: usize = 64;
/// Hard wall-clock cap on serving one connection (defeats a stalled peer).
const CONN_TIMEOUT: Duration = Duration::from_secs(15);
/// Cap on how long we wait for request headers (slowloris).
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the enabled inbound verifiers from config (Line today; more to come).
pub fn build_verifiers(cfg: &ChannelsConfig) -> Vec<Arc<dyn InboundVerifier>> {
    let mut out: Vec<Arc<dyn InboundVerifier>> = Vec::new();
    if let Some(inb) = &cfg.inbound {
        if let Some(secret) = &inb.line_channel_secret {
            out.push(Arc::new(LineVerifier::new(secret.clone())));
        }
        // Gated by "slack" (not a separate "line" entry — Line has no outbound
        // adapter/GUI row yet): disabling the Slack connector stops BOTH its
        // outbound adapter and its inbound interactivity verifier.
        if crate::channels_bridge::platform_enabled(cfg, "slack") {
            if let Some(secret) = &inb.slack_signing_secret {
                out.push(Arc::new(SlackVerifier::new(secret.clone())));
            }
        }
    }
    out
}

/// Bind `bind` and serve until the runtime is dropped. A bind failure is logged
/// and returns (never aborts the daemon — the outbound channels keep working).
pub async fn serve(
    bind: String,
    verifiers: Arc<Vec<Arc<dyn InboundVerifier>>>,
    bridge: Arc<ChannelBridge>,
) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("belay channels: inbound receiver bind {bind} failed: {e}");
            return;
        }
    };
    eprintln!("belay channels: inbound webhook receiver listening on {bind}");
    serve_on(listener, verifiers, bridge).await;
}

/// Accept loop over an already-bound listener (split out so tests can bind an
/// ephemeral port and read its address).
async fn serve_on(
    listener: TcpListener,
    verifiers: Arc<Vec<Arc<dyn InboundVerifier>>>,
    bridge: Arc<ChannelBridge>,
) {
    let limit = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                // Back off on a persistent accept() error (e.g. fd exhaustion) so
                // it cannot busy-spin, matching the polled adapters' behaviour.
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        // Bound concurrent connections (slowloris / fd exhaustion). If we're at the
        // cap, drop the new connection rather than queue unboundedly.
        let permit = match limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // stream dropped → connection closed
        };
        let io = TokioIo::new(stream);
        let v = verifiers.clone();
        let b = bridge.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection task ends
            let svc = service_fn(move |req| handle(req, v.clone(), b.clone()));
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(io, svc);
            // Hard wall-clock cap so a stalled peer cannot hold the slot forever.
            let _ = tokio::time::timeout(CONN_TIMEOUT, conn).await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    verifiers: Arc<Vec<Arc<dyn InboundVerifier>>>,
    bridge: Arc<ChannelBridge>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(route(req, verifiers, bridge).await)
}

async fn route(
    req: Request<Incoming>,
    verifiers: Arc<Vec<Arc<dyn InboundVerifier>>>,
    bridge: Arc<ChannelBridge>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::POST {
        return empty(StatusCode::METHOD_NOT_ALLOWED);
    }
    let platform = match req.uri().path().strip_prefix("/hook/") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return empty(StatusCode::NOT_FOUND),
    };
    // Unknown platform is answered 401 (same as a bad signature) so an
    // unauthenticated caller cannot distinguish which inbound platforms are
    // enabled from the response code.
    let verifier = match verifiers.iter().find(|v| v.platform() == platform) {
        Some(v) => v.clone(),
        None => return empty(StatusCode::UNAUTHORIZED),
    };
    // Lowercased header map — the verifier trait is HTTP-library-agnostic.
    let mut headers = HashMap::new();
    for (k, val) in req.headers() {
        if let Ok(s) = val.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }
    // Size-capped body read; oversize → 413 (no parse attempted).
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return empty(StatusCode::PAYLOAD_TOO_LARGE),
    };
    match verifier.verify_and_parse(&headers, &body) {
        Some(replies) => {
            for r in &replies {
                let outcome = bridge.process_reply(r);
                crate::ipc::audit_approval(serde_json::json!({
                    "event": "approval.inbound_reply",
                    "ts_ms": crate::pending::now_ms(),
                    "platform": r.platform,
                    "principal": r.principal,
                    "outcome": format!("{outcome:?}"),
                }));
            }
            // Valid signature ⇒ ack even if the gate rejected the reply, so the
            // platform does not retry a decision we deliberately dropped.
            empty(StatusCode::OK)
        }
        // Unauthenticated ⇒ nothing reached the queue.
        None => empty(StatusCode::UNAUTHORIZED),
    }
}

fn empty(code: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .expect("static empty response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels_bridge::{AllowEntry, ChannelsConfig, InboundCfg};
    use crate::pending::{now_ms, Approvals, ParkOutcome, PendingNotice};
    use belay_channels::inbound::b64_hmac_sha256;
    use serde_json::json;
    use std::sync::Mutex;
    use std::time::Duration;

    fn line_cfg(secret: &str, principal: &str) -> ChannelsConfig {
        ChannelsConfig {
            allow: vec![AllowEntry {
                platform: "line".into(),
                principal: principal.into(),
            }],
            inbound: Some(InboundCfg {
                bind: "127.0.0.1:0".into(),
                line_channel_secret: Some(secret.into()),
                slack_signing_secret: None,
            }),
            ..Default::default()
        }
    }

    /// End-to-end: a park emits its nonce, a correctly-signed Line webhook POST to
    /// the running receiver resolves that park to ALLOW.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn line_webhook_resolves_park() {
        let approvals = Approvals::with_timeout(Duration::from_secs(3));
        let (tx, rx) = std::sync::mpsc::channel::<PendingNotice>();
        let tx = Arc::new(Mutex::new(tx));
        approvals.set_notifier(Arc::new(move |n: PendingNotice| {
            let _ = tx.lock().unwrap().send(n);
        }));
        let cfg = line_cfg("sekret", "Uapprover");
        let bridge = Arc::new(ChannelBridge::new(approvals.clone(), &cfg));
        let verifiers = Arc::new(build_verifiers(&cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_on(listener, verifiers, bridge));

        // Park on a blocking thread; the notifier hands us the nonce.
        let a2 = approvals.clone();
        let parker = std::thread::spawn(move || {
            a2.park(
                "s",
                "Bash",
                &json!({"c": 1}),
                "r",
                "rule.x",
                now_ms(),
                "info",
                None,
                None,
            )
        });
        let notice = rx.recv_timeout(Duration::from_secs(2)).expect("parked → notified");

        let body = serde_json::to_vec(&json!({
            "events": [{
                "type": "message",
                "message": {"type": "text", "id": "m1", "text": format!("allow {}", notice.nonce)},
                "source": {"type": "user", "userId": "Uapprover"}
            }]
        }))
        .unwrap();
        let sig = b64_hmac_sha256(b"sekret", &body);
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/hook/line"))
            .header("x-line-signature", sig)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        assert_eq!(parker.join().unwrap(), ParkOutcome::Allow);
    }

    /// A forged signature is answered 401 and never resolves the park (times out
    /// → DENY). Proves the inbound path is fail-closed on authentication.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forged_signature_is_401_and_park_denies() {
        let approvals = Approvals::with_timeout(Duration::from_millis(400));
        let (tx, rx) = std::sync::mpsc::channel::<PendingNotice>();
        let tx = Arc::new(Mutex::new(tx));
        approvals.set_notifier(Arc::new(move |n: PendingNotice| {
            let _ = tx.lock().unwrap().send(n);
        }));
        let cfg = line_cfg("sekret", "Uapprover");
        let bridge = Arc::new(ChannelBridge::new(approvals.clone(), &cfg));
        let verifiers = Arc::new(build_verifiers(&cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_on(listener, verifiers, bridge));

        let a2 = approvals.clone();
        let parker = std::thread::spawn(move || {
            a2.park(
                "s",
                "Bash",
                &json!({"c": 1}),
                "r",
                "rule.x",
                now_ms(),
                "info",
                None,
                None,
            )
        });
        let notice = rx.recv_timeout(Duration::from_secs(2)).expect("parked → notified");

        let body = serde_json::to_vec(&json!({
            "events": [{
                "type": "message",
                "message": {"type": "text", "id": "m1", "text": format!("allow {}", notice.nonce)},
                "source": {"type": "user", "userId": "Uapprover"}
            }]
        }))
        .unwrap();
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/hook/line"))
            .header("x-line-signature", "not-a-valid-signature")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        assert_eq!(
            parker.join().unwrap(),
            ParkOutcome::Deny,
            "forged webhook must never resolve a park"
        );
    }
}
