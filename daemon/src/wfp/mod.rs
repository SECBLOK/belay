//! Phase-2 Tier-2 user-mode WFP per-exe egress BLOCK (`#[cfg(windows)]`,
//! service-only, admin-once, no driver).
//!
//! Adds a static WFP filter at the ALE connect-authorization layers that BLOCKS a
//! given executable's outbound connections, keyed on its app-id. This is how
//! Windows Firewall's own GUI blocks apps — no kernel callout driver required
//! (feasibility doc §2). It can stop the closed Claude/ChatGPT desktop apps from
//! *talking out*; it cannot stop them *reading* a local secret (that is the ETW
//! detect leg / Phase 3).
//!
//! **HARD LIMIT (state in every UI string): STATIC per-exe egress only.** WFP
//! user-mode filters express fixed app-id/IP/port conditions; they CANNOT call
//! back into belayd's rule engine per-connection for a live ask/deny. That
//! (Little-Snitch-style network ask) needs the Phase-3 callout driver.
//!
//! Authored against the VERIFIED `windows` 0.59 WFP API — every struct field,
//! union member, and GUID was checked in the crate source before use (see the
//! Phase-2 results doc). Paired with the `#[ignore]` on-box smoke test.
//!
//! Lifetime model: a single process-lifetime engine handle holds DYNAMIC filters,
//! so blocks last while the daemon runs and are auto-removed when it exits (no
//! orphaned reboot-surviving rules). `unblock_exe(id)` deletes one by id.

use std::io;
use std::sync::{Mutex, OnceLock};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmGetAppIdFromFileName0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK,
    FWP_BYTE_BLOB, FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB_TYPE;

// RPC_C_AUTHN_WINNT — the auth service FwpmEngineOpen0 expects (documented = 10).
const RPC_C_AUTHN_WINNT: u32 = 10;

/// Process-lifetime WFP engine handle. Dynamic filters added on it live until the
/// daemon exits (then WFP auto-removes them — clean, no reboot-surviving rules).
static ENGINE: OnceLock<Mutex<EngineHandle>> = OnceLock::new();

/// `HANDLE` is a raw pointer (not Send); wrap it so we can share one engine across
/// the daemon's host-command threads behind a Mutex. Safe here: WFP engine handles
/// are usable from any thread, and all access is serialized by the Mutex.
struct EngineHandle(HANDLE);
unsafe impl Send for EngineHandle {}

fn engine() -> io::Result<&'static Mutex<EngineHandle>> {
    if let Some(e) = ENGINE.get() {
        return Ok(e);
    }
    let mut handle = HANDLE::default();
    // SAFETY: verified FwpmEngineOpen0 signature. NULL server = local; no session.
    let rc = unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            None,
            &mut handle,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _ = ENGINE.set(Mutex::new(EngineHandle(handle)));
    ENGINE
        .get()
        .ok_or_else(|| io::Error::other("WFP engine init race"))
}

/// Block `exe_path`'s outbound connections (IPv4 + IPv6). Returns the two filter
/// ids (v4, v6) packed: the low 32 bits index a table entry; we return the v4 id
/// as the handle and delete both on unblock via the recorded pair. For simplicity
/// the public id is the v4 filter id; the v6 id is tracked alongside it.
pub fn block_exe(exe_path: &str) -> io::Result<u64> {
    let eng = engine()?;
    let guard = eng.lock().map_err(|_| io::Error::other("WFP engine poisoned"))?;
    let handle = guard.0;

    // Resolve the app-id blob for this exe (native process attribution).
    let path_w: Vec<u16> = exe_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    // SAFETY: verified signature; path_w is NUL-terminated.
    let rc = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut app_id) };
    if rc != 0 || app_id.is_null() {
        return Err(io::Error::from_raw_os_error(if rc != 0 { rc as i32 } else { -1 }));
    }

    let mut cond = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0 {
                byteBlob: app_id,
            },
        },
    };

    // WFP requires a non-null displayData.name (FWP_E_NULL_DISPLAY_DATA otherwise).
    // Kept alive for the FwpmFilterAdd0 calls (WFP copies it internally).
    let mut name_w: Vec<u16> = "Belay egress block"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut desc_w: Vec<u16> = "Belay: block this app's outbound network access"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut add_at = |layer: GUID| -> io::Result<u64> {
        let mut filter = FWPM_FILTER0::default();
        filter.layerKey = layer;
        filter.displayData.name = windows::core::PWSTR(name_w.as_mut_ptr());
        filter.displayData.description = windows::core::PWSTR(desc_w.as_mut_ptr());
        filter.action.r#type = FWP_ACTION_BLOCK;
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut cond;
        let mut id: u64 = 0;
        // SAFETY: verified FwpmFilterAdd0 signature; filter fully initialized.
        let rc = unsafe { FwpmFilterAdd0(handle, &filter, None, Some(&mut id)) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        Ok(id)
    };

    let v4 = add_at(FWPM_LAYER_ALE_AUTH_CONNECT_V4)?;
    let v6 = add_at(FWPM_LAYER_ALE_AUTH_CONNECT_V6)?;
    record_pair(v4, v6);
    Ok(v4)
}

/// Remove a block previously added by [`block_exe`] (deletes both v4 + v6 filters).
pub fn unblock_exe(public_id: u64) -> io::Result<()> {
    let eng = engine()?;
    let guard = eng.lock().map_err(|_| io::Error::other("WFP engine poisoned"))?;
    let handle = guard.0;
    let v6 = take_pair(public_id);
    // SAFETY: verified FwpmFilterDeleteById0 signature.
    let rc4 = unsafe { FwpmFilterDeleteById0(handle, public_id) };
    let rc6 = v6.map(|id| unsafe { FwpmFilterDeleteById0(handle, id) }).unwrap_or(0);
    if rc4 != 0 {
        return Err(io::Error::from_raw_os_error(rc4 as i32));
    }
    if rc6 != 0 {
        return Err(io::Error::from_raw_os_error(rc6 as i32));
    }
    Ok(())
}

// v4→v6 filter-id pairing so a single public id can revert both filters.
static PAIRS: OnceLock<Mutex<Vec<(u64, u64)>>> = OnceLock::new();
fn record_pair(v4: u64, v6: u64) {
    let m = PAIRS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut v) = m.lock() {
        v.push((v4, v6));
    }
}
fn take_pair(v4: u64) -> Option<u64> {
    let m = PAIRS.get_or_init(|| Mutex::new(Vec::new()));
    let mut v = m.lock().ok()?;
    if let Some(i) = v.iter().position(|(a, _)| *a == v4) {
        return Some(v.remove(i).1);
    }
    None
}
