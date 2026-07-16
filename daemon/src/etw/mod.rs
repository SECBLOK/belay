//! Phase-2 Tier-2 ETW real-time DETECTION (service-only, admin-once, no driver).
//!
//! A user-mode ETW consumer subscribed to the kernel file/process/network
//! providers gives Belay real-time visibility into activity by ANY app —
//! including the CLOSED Claude/ChatGPT desktop apps whose in-process file reads
//! today produce zero audit entries. Records decode into the existing
//! [`ObservedEvent`] seam and flow through `engine::evaluate_event` +
//! `honeypot::classify_access` + `Reflex`.
//!
//! **ETW IS DETECT-ONLY — it can never block.** `ProcessTrace` delivers events to
//! the consumer's own thread AFTER the kernel already completed the operation
//! (feasibility doc §1); there is no callback path back into the syscall. So this
//! subsystem escalates + audits (and may kill-after, honestly labelled), but the
//! read/exec/connect has already happened. Every UI string must say "detected,
//! not blocked".
//!
//! Split for testability (per the plan): [`decode`] is a pure provider→kind
//! mapping unit-tested off-Windows with synthetic records; the native session
//! ([`EtwSession`], `#[cfg(windows)]`) that produces those records is authored
//! against the verified `windows` 0.59 ETW API and paired with an `#[ignore]`
//! on-box smoke test — never a guess.

use crate::observe::{EventKind, ObservedEvent};

/// Which kernel provider a record came from. The native session resolves this
/// from the record's provider GUID (GUIDs are stable + documented), so [`decode`]
/// stays a pure mapping with no unconfirmed opcode literals in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EtwProvider {
    /// Microsoft-Windows-Kernel-File — file create/open.
    KernelFile,
    /// Microsoft-Windows-Kernel-Process — process start.
    KernelProcess,
    /// Microsoft-Windows-Kernel-Network — TCP connect.
    KernelNetwork,
    /// Any provider we subscribed to but don't map to a Belay event kind.
    Other,
}

/// One decoded ETW record handed from the native session to [`decode`]. The
/// native session is responsible for (a) resolving `provider` from the GUID and
/// (b) FILTERING to the relevant opcode before emitting (so decode need not
/// hardcode opcode/event-id values it cannot confirm off-box). `opcode` is
/// retained for diagnostics and future finer mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEtwRecord {
    pub provider: EtwProvider,
    pub opcode: u8,
    pub pid: u32,
    /// Path (file), image name (process), or "ip:port" (network). May be empty
    /// if the native session could not extract it — decode drops those.
    pub detail: String,
}

/// Map a raw ETW record to a Belay [`ObservedEvent`]. Pure: provider → kind.
/// Returns `None` for providers we don't map or records with no detail string.
pub fn decode(rec: &RawEtwRecord) -> Option<ObservedEvent> {
    let kind = match rec.provider {
        EtwProvider::KernelFile => EventKind::Open,
        EtwProvider::KernelProcess => EventKind::Exec,
        EtwProvider::KernelNetwork => EventKind::Connect,
        EtwProvider::Other => return None,
    };
    if rec.detail.trim().is_empty() {
        return None;
    }
    Some(ObservedEvent {
        pid: rec.pid,
        kind,
        detail: rec.detail.clone(),
    })
}

#[cfg(test)]
impl RawEtwRecord {
    pub fn synthetic_file_open(pid: u32, path: &str) -> Self {
        RawEtwRecord {
            provider: EtwProvider::KernelFile,
            opcode: 0,
            pid,
            detail: path.to_string(),
        }
    }
    pub fn synthetic_process_start(pid: u32, image: &str) -> Self {
        RawEtwRecord {
            provider: EtwProvider::KernelProcess,
            opcode: 1,
            pid,
            detail: image.to_string(),
        }
    }
    pub fn synthetic_connect(pid: u32, addr: &str) -> Self {
        RawEtwRecord {
            provider: EtwProvider::KernelNetwork,
            opcode: 12,
            pid,
            detail: addr.to_string(),
        }
    }
}

/// Append an HONEST, hash-chained ETW-detection row to the real `audit.ndjson`
/// (the same chain the hook path uses, so it renders in the Live Feed). ETW is
/// DETECT-ONLY: the row is `verdict:"detected"` / `prevented:false`, never a
/// `deny` — the read/exec/connect already completed before ETW delivered it.
///
/// Deliberately NOT `Reflex::react`: Reflex's `reflex_kill`/`deny` row asserts a
/// block that did not happen (same honesty call as the Phase-1 canary). The event
/// still flows through the engine seam (`classify_access`/`evaluate_event`); only
/// the final sink is an honest detect-row instead of a kill-row.
pub fn record_detection(ev: &ObservedEvent, verdict: &crate::engine::types::Verdict) {
    use serde_json::json;
    let kind = match ev.kind {
        EventKind::Open => "read",
        EventKind::Exec => "started",
        EventKind::Connect => "connected out",
        _ => "did",
    };
    let reason = format!(
        "ETW detected an app (pid {}) that {} {} - Belay's system monitor SAW this but did NOT block it (Tier-2 detection-only)",
        ev.pid, kind, ev.detail
    );
    let row = json!({
        "ts": crate::host_config::rfc3339_utc(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs()),
        "event": "etw/detected",
        "session": "etw",
        "tool": "etw",
        "verdict": "detected",
        "reason": reason,
        "rules": verdict.rules,
        "input": { "detail": ev.detail, "pid": ev.pid, "prevented": false },
        "severity": verdict.severity.as_wire_str(),
        "category": verdict.category,
        "explain": verdict.explain.as_ref().and_then(|e| serde_json::to_value(e).ok()),
    });
    let path = crate::paths::audit_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match crate::audit::AuditWriter::open(&path.to_string_lossy()) {
        Ok(mut w) => {
            if let Err(e) = w.append(row) {
                eprintln!("[belayd] etw audit append failed: {e}");
            }
        }
        Err(e) => eprintln!("[belayd] etw audit open failed: {e}"),
    }
}

// The native real-time ETW session lives in a submodule so the pure decode above
// compiles + unit-tests on every platform, while the Win32 FFI is Windows-only.
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub use session::EtwSession;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_file_open_becomes_open_event() {
        let rec = RawEtwRecord::synthetic_file_open(4242, r"C:\Users\x\.env");
        let ev = decode(&rec).unwrap();
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.kind, EventKind::Open);
        assert_eq!(ev.detail, r"C:\Users\x\.env");
    }

    #[test]
    fn decode_process_start_becomes_exec_event() {
        let rec = RawEtwRecord::synthetic_process_start(99, r"C:\Windows\notepad.exe");
        let ev = decode(&rec).unwrap();
        assert_eq!(ev.pid, 99);
        assert_eq!(ev.kind, EventKind::Exec);
        assert_eq!(ev.detail, r"C:\Windows\notepad.exe");
    }

    #[test]
    fn decode_connect_becomes_connect_event() {
        let rec = RawEtwRecord::synthetic_connect(7, "203.0.113.5:443");
        let ev = decode(&rec).unwrap();
        assert_eq!(ev.kind, EventKind::Connect);
        assert_eq!(ev.detail, "203.0.113.5:443");
    }

    #[test]
    fn decode_other_provider_is_dropped() {
        let rec = RawEtwRecord {
            provider: EtwProvider::Other,
            opcode: 0,
            pid: 1,
            detail: "whatever".into(),
        };
        assert!(decode(&rec).is_none());
    }

    #[test]
    fn decode_empty_detail_is_dropped() {
        // The native session couldn't extract a path — don't emit a blank event.
        let rec = RawEtwRecord::synthetic_file_open(1, "   ");
        assert!(decode(&rec).is_none());
    }
}
