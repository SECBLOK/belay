//! On-box ETW smoke test (Task 1, step 2/5). `#[ignore]` so CI/Linux skip it;
//! run manually on an ELEVATED Windows shell (ETW kernel real-time sessions need
//! admin/LocalSystem — that is why Phase 2 is gated to the SCM service):
//!
//!   cargo test -p belayd --test etw_smoke -- --ignored --nocapture
//!
//! It opens the Belay ETW session, subscribes to the kernel providers, spawns
//! `notepad.exe`, and asserts at least one record arrives within 5 s. Proves the
//! session + callback deliver records (pid + provider); path extraction (TDH) is
//! the separate next step tracked in `etw::session`.

#![cfg(windows)]

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
#[ignore = "needs an elevated Windows shell (ETW kernel session requires admin)"]
fn etw_session_delivers_records_when_a_process_starts() {
    let session = match belayd::etw::EtwSession::open() {
        Ok(s) => s,
        Err(e) => panic!(
            "EtwSession::open failed ({e}). Run this test from an ELEVATED shell; \
             kernel ETW providers require admin/LocalSystem."
        ),
    };

    let (tx, rx) = channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let run_shutdown = shutdown.clone();
    let pump = std::thread::spawn(move || session.run(tx, run_shutdown));

    // Give ProcessTrace a beat to start, then generate activity.
    std::thread::sleep(Duration::from_millis(500));
    let mut child = std::process::Command::new("notepad.exe")
        .spawn()
        .expect("spawn notepad.exe");

    // Expect at least one record within 5 s.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = false;
    while Instant::now() < deadline {
        if rx.recv_timeout(Duration::from_millis(250)).is_ok() {
            got = true;
            break;
        }
    }

    let _ = child.kill();
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = pump.join();

    assert!(got, "no ETW records arrived within 5s — session or callback broken");
}
