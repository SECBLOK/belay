//! Windows Service Control Manager (SCM) integration for the unified
//! `belay` binary — the structural analogue of the Linux `systemd_unit` /
//! macOS `launchd_plist` boot-start path.
//!
//! Two halves, both Windows-only:
//!   * Task 3 (this commit): the runtime `service_dispatcher` entered from the
//!     `daemon --scm` arm. `service_dispatcher::start` takes over the main
//!     thread and calls `service_main` on a worker; `service_main` reports
//!     `Running` FAST, runs the daemon until an SCM Stop, then reports
//!     `Stopped`.
//!   * Task 4: `register_service` / `deregister_service` (install/uninstall).
//!
//! Whole-file `#![cfg(windows)]` so it compiles only on Windows targets; the
//! Unix builds never see `windows-service`.
#![cfg(windows)]

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// SCM service name. Matches the Phase 0 `windows_service_spec()` name and the
/// future machine-wide pipe identity (`\\.\pipe\Belay`, Phase 4).
pub const SERVICE_NAME: &str = "Belay";
/// User-facing name shown in `services.msc` / `sc query`.
const DISPLAY_NAME: &str = "Belay resident core";

/// Convert a `windows_service::Error` into `std::io::Error`, **preserving** the
/// underlying Win32 code (`raw_os_error()`) when the error came from a winapi
/// call. Callers branch on that code (1063 console-fallback, 5 ACCESS_DENIED),
/// so we must not flatten it through `io::Error::other` (which drops the code).
pub fn to_io(e: windows_service::Error) -> std::io::Error {
    match e {
        windows_service::Error::Winapi(io) => io,
        other => std::io::Error::other(other),
    }
}

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063): `service_dispatcher::start`
/// returns this when the process was launched from a console rather than by the
/// SCM. The `daemon --scm` arm treats it as "not under SCM → run console mode".
pub fn is_scm_not_connected_1063(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(1063)
}

/// `ERROR_ACCESS_DENIED` (5): `create_service` / failure-action updates require
/// Administrator. The installer maps this to a "re-run as Administrator" hint
/// (the Windows analogue of Unix "re-run with sudo"). We do NOT self-elevate.
pub fn is_access_denied(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(5)
}

/// `ERROR_SERVICE_DOES_NOT_EXIST` (1060): used to make `deregister_service`
/// idempotent — uninstalling an already-absent service succeeds silently
/// rather than erroring (a repeated `--uninstall`, or one run from a
/// provisioning script that doesn't track prior install state).
fn is_not_found(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(1060)
}

define_windows_service!(ffi_service_main, service_main);

/// SCM entrypoint (runs on a dispatcher worker thread). The launch arguments
/// (`daemon --scm`) arrive via `std::env::args` and were already consumed by
/// clap before we got here — `_args` (the SCM's own argv) is intentionally
/// unused.
fn service_main(_args: Vec<OsString>) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = Arc::clone(&shutdown);

    let event_handler = move |control| match control {
        // Mandatory: the SCM health probe. Must return NoError.
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        // Stop / machine shutdown: signal the daemon and unblock its accept().
        ServiceControl::Stop | ServiceControl::Shutdown => {
            sd.store(true, Ordering::SeqCst);
            // The flag alone does not wake the blocked accept(); poke the pipe
            // with a throwaway self-connection so `serve_mode_with_shutdown`
            // rechecks the flag and returns. Connect to the exact address the
            // daemon bound — `paths::socket_path()` (Phase 4), the single source
            // of truth for the control-pipe address.
            let _ = belay_transport::connect(&belayd::paths::socket_path());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(h) => h,
        // No handle ⇒ nothing to report Stopped to; the process will exit.
        Err(_) => return,
    };

    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    // Report Running FAST — BEFORE the slow daemon startup (integrity check,
    // eBPF, pipe bind) — or the SCM's ~30 s start timeout force-kills us.
    let _ = status_handle.set_service_status(running.clone());

    // Under the SCM there is no console, so the daemon's eprintln!/println!
    // diagnostics would write to an invalid STD_ERROR handle and PANIC ("failed
    // printing to stderr"). Redirect both std streams to a log file BEFORE the
    // daemon starts.
    redirect_std_to_log();

    // Blocks until the Stop handler sets `shutdown` and wakes the accept loop.
    belayd::app::run_daemon_with_shutdown(shutdown);

    let stopped = ServiceStatus {
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        ..running
    };
    let _ = status_handle.set_service_status(stopped);
}

/// Point the process's STD_ERROR and STD_OUTPUT handles at
/// `%PROGRAMDATA%\Belay\logs\daemon.log` so the daemon's `eprintln!` /
/// `println!` diagnostics land in a file instead of panicking on the invalid
/// console handle a Windows service has. Best-effort: any failure leaves the
/// (broken-but-inert) default handles in place; we never fail the service.
fn redirect_std_to_log() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    let dir = belayd::paths::logs_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("daemon.log"))
    {
        Ok(f) => f,
        Err(_) => return,
    };
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: `handle` is a valid, open file handle. We `forget` `file` below so
    // the OS handle stays open for the whole process lifetime (the std streams
    // now reference it); SetStdHandle just swaps the process std handles.
    unsafe {
        SetStdHandle(STD_ERROR_HANDLE, handle);
        SetStdHandle(STD_OUTPUT_HANDLE, handle);
    }
    std::mem::forget(file);
}

/// Enter the SCM `service_dispatcher`. Blocks for the service lifetime and
/// returns `Ok(())` after a clean stop. When launched interactively (not by the
/// SCM) it returns `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063); the caller
/// uses [`is_scm_not_connected_1063`] to fall back to console mode.
pub fn run_dispatch() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(to_io)
}

/// Register `<exe> daemon --scm` as an auto-start LocalSystem SCM service — the
/// structural analogue of writing + `systemctl enable`ing the systemd unit.
///
/// * **LocalSystem** (`account_name: None`): machine-wide, survives logoff, no
///   stored user credential (better EDR posture; a stored password breaks on
///   password change). `NT AUTHORITY\SYSTEM` is the fail-closed identity.
/// * **AutoStart**: boot-start (the `WantedBy=multi-user.target` / launchd
///   `RunAtLoad` analogue).
/// * **Failure actions** (`Restart`, 2 s delay, 60 s reset window) + restart on
///   non-crash exits: the systemd `Restart=on-failure` / launchd `KeepAlive`
///   analogue.
///
/// Needs Administrator; on `ERROR_ACCESS_DENIED` the caller prints a
/// "re-run as Administrator" hint. `start_now` mirrors `--enable`.
pub fn register_service(exe: &std::path::Path, start_now: bool) -> std::io::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(to_io)?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        // The SCM launches the service with this argv; `--scm` selects the
        // dispatcher path (see the `Cmd::Daemon` arm).
        launch_arguments: vec![OsString::from("daemon"), OsString::from("--scm")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(to_io)?;

    // Best-effort keep-alive: restart 2 s after a failure, reset the failure
    // count after 60 s of health. Also restart on clean-but-unexpected exits.
    let _ = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(2),
        }]),
    });
    let _ = service.set_failure_actions_on_non_crash_failures(true);

    if start_now {
        service.start::<&std::ffi::OsStr>(&[]).map_err(to_io)?;
    }
    Ok(())
}

/// Uninstall: open the service with `DELETE` and remove it. Used by
/// `install-service --uninstall`. Needs Administrator. Idempotent: uninstalling
/// an already-absent service is a silent success (see [`is_not_found`]).
pub fn deregister_service() -> std::io::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(to_io)?;
    let service = match manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .map_err(to_io)
    {
        Ok(s) => s,
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(e) => return Err(e),
    };

    // `delete()` (Win32 `DeleteService`) only MARKS a still-running service for
    // deletion — the SCM keeps the entry (and the process keeps running, so its
    // binary stays locked) until the service actually stops. Stop it first so
    // `--uninstall` leaves nothing behind for the operator to clean up by hand.
    //
    // Always attempt stop() rather than gating it on a prior query_status()
    // check: that would be a TOCTOU (the service could stop on its own, or
    // already be mid-stop, between the check and the call). Instead just
    // swallow the two expected non-error outcomes: 1061
    // (ERROR_SERVICE_CANNOT_ACCEPT_CTRL — a stop is already in flight, e.g. a
    // scripted `sc stop` immediately followed by `--uninstall`, or the
    // register-time failure-action restart loop overlapping an uninstall) and
    // 1062 (ERROR_SERVICE_NOT_ACTIVE — already stopped). Either way, the poll
    // below still runs and returns immediately once the state is Stopped.
    match service.stop().map_err(to_io) {
        Ok(_) => {}
        Err(e) if matches!(e.raw_os_error(), Some(1061) | Some(1062)) => {}
        Err(e) => return Err(e),
    }
    // Poll for the STOPPED transition; bounded so a hung stop can't wedge the
    // CLI. 5 s at 250 ms matches the polling style already used by
    // `run_install_service`'s socket wait.
    for _ in 0..20 {
        if service.query_status().map_err(to_io)?.current_state == ServiceState::Stopped {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    service.delete().map_err(to_io)?;
    Ok(())
}
