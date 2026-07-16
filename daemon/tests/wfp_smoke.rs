//! On-box WFP smoke test (Task 5). `#[ignore]` — run from an ELEVATED Windows
//! shell (adding WFP filters needs admin; that is why Phase 2 is service-gated):
//!
//!   cargo test -p belayd --test wfp_smoke -- --ignored --nocapture
//!
//! Verifies the block/unblock round-trip against a real exe path: `block_exe`
//! adds the v4+v6 ALE-connect BLOCK filters and returns an id; `unblock_exe`
//! deletes them. If `curl.exe` is present it additionally checks that an outbound
//! request is refused while blocked and succeeds after unblock (the behavioral
//! proof) — skipped with a note if curl or network is unavailable.

#![cfg(windows)]

use std::process::Command;

fn curl_can_connect(exe: &str) -> Option<bool> {
    // -m 5: cap at 5s; returns exit 0 on success, non-zero on blocked/refused.
    let out = Command::new(exe)
        .args(["-s", "-o", "NUL", "-m", "5", "https://example.com"])
        .status()
        .ok()?;
    Some(out.success())
}

#[test]
#[ignore = "needs an elevated Windows shell (adding WFP filters requires admin)"]
fn block_exe_round_trips_and_optionally_blocks_egress() {
    let curl = r"C:\Windows\System32\curl.exe";
    let have_curl = std::path::Path::new(curl).exists();

    // Baseline (only meaningful if curl exists + network is up).
    let baseline = if have_curl { curl_can_connect(curl) } else { None };

    let id = match belayd::wfp::block_exe(curl) {
        Ok(id) => id,
        Err(e) => panic!(
            "block_exe failed ({e}). Run elevated — FwpmFilterAdd0 needs admin."
        ),
    };
    assert!(id != 0, "block_exe returned a null filter id");

    // Behavioral check (best-effort): while blocked, curl should NOT connect.
    if have_curl && baseline == Some(true) {
        let blocked = curl_can_connect(curl);
        assert_eq!(
            blocked,
            Some(false),
            "curl still connected while a WFP block filter was active"
        );
    } else {
        eprintln!("NOTE: skipping behavioral egress assertion (no curl / no baseline network)");
    }

    belayd::wfp::unblock_exe(id).expect("unblock_exe should delete the filters");

    // After unblock, egress should work again (only asserted if baseline worked).
    if have_curl && baseline == Some(true) {
        assert_eq!(
            curl_can_connect(curl),
            Some(true),
            "curl could not connect after unblock — filter not fully removed"
        );
    }
}
