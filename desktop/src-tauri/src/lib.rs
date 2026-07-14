pub mod audit;
pub mod commands;
pub mod notify;
pub mod tray;
pub mod uds;

#[cfg(feature = "tauri")]
use tauri::{Emitter, Manager};
#[cfg(all(feature = "tauri", feature = "tokio"))]
use tokio::io::{AsyncBufReadExt, BufReader};

// Same audit store the daemon writes, via the daemon's own path helper (Unix
// `~/.belay/audit.ndjson`, Windows `%PROGRAMDATA%\Belay\audit.ndjson`)
// so the desktop tails exactly the file the LocalSystem daemon appends to.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn audit_path() -> std::path::PathBuf {
    belayd::paths::audit_path()
}

/// The rule CATEGORY is the prefix before the first `.` of the first rule id
/// (e.g. `secrets.aws_credentials` -> `secrets`). Used ONLY to pick privacy-safe
/// notification copy — never the path/command/argument.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn row_category(row: &audit::AuditRow) -> &str {
    row.rules
        .first()
        .map(|r| r.split('.').next().unwrap_or(r))
        .unwrap_or("")
}

/// Actionable = the gate asked for a decision or denied the action.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn is_actionable(verdict: &str) -> bool {
    verdict == "deny" || verdict == "ask"
}

/// Best-effort, privacy-safe notification for an actionable+backgrounded event.
/// Show ONE coalesced toast for a poll cycle's actionable rows in our own
/// always-on-top window, anchored bottom-right.
///
/// Never panics the tail loop; never includes the path/command/argument. A
/// burst of new actionable rows collapses to a single digest line, and a single
/// reusable window is repositioned + content-swapped each time — so it can never
/// tile the screen the way a flood of native notifications did.
#[cfg(all(feature = "tauri", feature = "tokio"))]
fn notify_cycle(app: &tauri::AppHandle, rows: &[audit::AuditRow]) {
    let frontmost = app
        .get_webview_window("main")
        .and_then(|w| w.is_focused().ok())
        .unwrap_or(false);
    let actionable: Vec<&audit::AuditRow> =
        rows.iter().filter(|r| is_actionable(&r.verdict)).collect();
    if frontmost || actionable.is_empty() {
        return;
    }
    // Exactly one actionable row → prefer its curated, path-free explain summary
    // (Explain & Advise); a burst still collapses to a single digest line so a
    // flood can never tile the screen.
    let (title, body) = if actionable.len() == 1 {
        let row = actionable[0];
        let summary = row
            .explain
            .as_ref()
            .and_then(|e| e.get("summary"))
            .and_then(|s| s.as_str());
        (
            "Belay".to_string(),
            notify::notification_copy_for(summary, row_category(row)),
        )
    } else {
        notify::digest_copy(actionable.len())
    };
    if let Some(win) = app.get_webview_window("toast") {
        // Hand the copy to the toast UI, anchor bottom-right, then reveal it
        // WITHOUT stealing focus from the user's active window.
        let _ = app.emit_to("toast", "toast", serde_json::json!({ "title": title, "body": body }));
        tray::position_toast(&win);
        let _ = win.show();
    }
}

/// Tail the audit log like `tail -f`: track the byte offset and only process
/// **newly-appended** lines. The previous implementation reopened the file from
/// offset 0 every cycle and re-notified for every historical row, flooding the
/// screen with toasts. We now prime the existing backlog into the UI without
/// notifying (it is history), then notify only for genuinely new rows.
#[cfg(all(feature = "tauri", feature = "tokio"))]
async fn tail_audit(app: tauri::AppHandle) {
    use tokio::io::AsyncSeekExt;

    let path = audit_path();
    let mut offset: u64 = 0;
    // First pass is the historical backlog: surface it to the UI but do NOT
    // raise notifications for it. Only rows appended after start-up notify.
    let mut primed = false;

    loop {
        // Detect truncation/rotation: if the file shrank below our offset, the
        // log was rotated/cleared — restart from the beginning and re-prime.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            if meta.len() < offset {
                offset = 0;
                primed = false;
            }
        }

        if let Ok(mut f) = tokio::fs::File::open(&path).await {
            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                let mut reader = BufReader::new(f);
                let mut line = String::new();
                let mut batch: Vec<audit::AuditRow> = Vec::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            // Only consume COMPLETE lines. A line without a
                            // trailing newline is a half-written append; leave
                            // the offset so we re-read it once fully flushed.
                            if !line.ends_with('\n') {
                                break;
                            }
                            offset += n as u64;
                            if let Some(row) = audit::parse_audit_line(line.trim_end()) {
                                batch.push(row);
                            }
                        }
                        Err(_) => break,
                    }
                }

                // Surface every new row to the UI (history + fresh alike).
                for row in &batch {
                    let _ = app.emit("audit-event", row.clone());
                }
                // Notify only once primed (i.e. skip the start-up backlog).
                if primed {
                    notify_cycle(&app, &batch);
                }
            }
        }

        primed = true;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[cfg(all(feature = "tauri", feature = "tokio"))]
pub fn run() {
    // WebKitGTK 2.4x defaults to a hardware-accelerated DMABUF/GBM compositor.
    // Inside VMs (VMware/VirtualBox) and other hosts without a working GL stack
    // that path composites to nothing, leaving a blank white webview while the
    // native window itself renders fine. Disabling it forces a software render
    // path that works everywhere. Set BEFORE WebKit initializes; only override
    // when the user hasn't already chosen a value. Linux-only (no-op elsewhere).
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
        // Companion workaround: even with DMABUF disabled, some VM GL stacks blank
        // the webview when WebKit promotes a layer to a compositing surface (a
        // larger DOM, a fixed/overlay element, a big box-shadow). Forcing the
        // non-accelerated compositing path keeps repaints on the software
        // renderer so swapping to a content-heavy view (e.g. Firewall) cannot
        // composite to an empty buffer. Only set when the user hasn't chosen one.
        if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
    }

    tauri::Builder::default()
        // Single-instance MUST be the first plugin: a second launch fires this
        // callback in the ALREADY-running instance (focus its window) and exits
        // the duplicate, instead of spawning a second process + tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(main) = app.get_webview_window("main") {
                let _ = main.unminimize();
                let _ = main.show();
                let _ = main.set_focus();
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Create the popover window once, hidden. The tray toggle will show/hide it.
            // NOT transparent — transparency was removed from the main window to fix
            // blank WebKitGTK rendering in VMs (WEBKIT_DISABLE_DMABUF_RENDERER=1 covers
            // the software-render workaround). The popover uses an opaque dark bg in CSS.
            use tauri::{WebviewWindowBuilder, WebviewUrl};
            let popover = WebviewWindowBuilder::new(
                app, "popover", WebviewUrl::App("index.html#popover".into()))
                .title("Belay")
                .inner_size(320.0, 400.0)
                .resizable(false)
                .decorations(false)
                .always_on_top(true)
                .skip_taskbar(true)
                .visible(false)
                .build()?;
            // Transient: hide when focus is lost (click-away dismiss).
            let ph = popover.clone();
            popover.on_window_event(move |e| {
                if let tauri::WindowEvent::Focused(false) = e { let _ = ph.hide(); }
            });

            // Custom notification toast: a single small, borderless, always-on-top
            // window anchored bottom-right (see notify_cycle / tray::position_toast).
            // Replaces native OS notifications so placement is ours, not the
            // desktop notification daemon's. Non-focusable so showing it never
            // steals the user's keyboard focus; one reusable window means a burst
            // can never tile the screen.
            let _toast = WebviewWindowBuilder::new(
                app, "toast", WebviewUrl::App("index.html#toast".into()))
                .title("Belay")
                .inner_size(360.0, 96.0)
                .resizable(false)
                .decorations(false)
                .always_on_top(true)
                .skip_taskbar(true)
                .focused(false)
                .visible(false)
                .build()?;

            tray::build_tray(app.handle())?;

            // Close-to-tray: hide the main window on close instead of destroying
            // it. Destroying left get_webview_window("main") == None, so "Open
            // dashboard" (focus_main) and the tray could no longer reopen it -
            // the user had to launch a second Belay. Now closing hides it and it
            // reopens instantly; full quit is the tray menu's "Quit Belay".
            {
                use tauri::Manager;
                if let Some(main) = app.get_webview_window("main") {
                    let mc = main.clone();
                    main.on_window_event(move |e| {
                        if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                            api.prevent_close();
                            let _ = mc.hide();
                        }
                    });
                }
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(tail_audit(handle));
            // Ensure the resident daemon is running so host features work on a
            // fresh launch instead of erroring with "daemon is not running".
            tauri::async_runtime::spawn(commands::ensure_daemon());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_posture,
            commands::get_findings,
            commands::get_sessions,
            #[cfg(feature = "enterprise")]
            commands::get_fleet,
            commands::get_egress,
            commands::get_pending,
            commands::respond_approval,
            commands::set_protection,
            commands::explain_action,
            commands::ai_status,
            commands::get_ai_config,
            commands::set_ai_config,
            commands::set_ai_key,
            // Network destination enrichment (owner-gated daemon IPC; feature `netenrich`)
            commands::enrich_dest,
            commands::get_net_enrich,
            commands::set_net_enrich,
            // Messaging channels (owner-gated daemon IPC)
            commands::get_channels,
            commands::channel_allow_add,
            commands::channel_allow_remove,
            commands::channel_pair_start,
            commands::set_channel,
            commands::remove_channel,
            commands::set_channel_enabled,
            commands::set_inbound,
            commands::restart_daemon,
            // Boot-start (autostart) toggle - tray popover + dashboard.
            commands::get_boot_start,
            commands::set_boot_start,
            // In-app updater (check + signature-verified install).
            commands::check_update,
            commands::install_update,
            commands::open_external_url,
            commands::focus_main,
            commands::run_scan,
            commands::hide_toast,
            commands::get_recent_audit,
            commands::list_agents,
            commands::protect_agent,
            commands::unprotect_agent,
            // Host / EDR daemon-IPC bridge (piece 2 stateful firewall path + reads)
            commands::get_hardening_posture,
            commands::get_vuln_posture,
            commands::get_proposed_ruleset,
            commands::get_auto_proposed_ruleset,
            commands::get_firewall_status,
            commands::get_egress_allowlist,
            commands::list_bans,
            commands::apply_firewall,
            commands::confirm_firewall,
            commands::revert_firewall,
            commands::add_egress_rule,
            commands::remove_egress_rule,
            commands::set_egress_mode,
            commands::set_inline_egress,
            commands::unban,
            // Host scan / quarantine / ssh-guard / schedule (in-process)
            commands::run_host_scan,
            commands::get_scan_results,
            commands::scan_host_vuln,
            commands::get_host_scan_schedule,
            commands::set_host_scan_schedule,
            commands::list_quarantine,
            commands::restore_quarantine,
            commands::delete_quarantine,
            commands::get_ssh_guard,
            commands::set_ssh_guard,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
