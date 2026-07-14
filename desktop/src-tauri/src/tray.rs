//! Menu-bar / tray icon state + builder.
//!
//! The visual state is expressed as a **glyph + opacity** mapping that is calm by
//! default: color is only used for real alerts (`action`/`blocked`). The pure
//! `tray_state` mapping is testable under `cargo test --no-default-features`; the
//! `build_tray` wiring compiles under the `tauri` default feature.

#[derive(Debug, PartialEq)]
pub struct TrayState {
    pub glyph: &'static str,
    pub opacity: f32,
    pub colored: bool,
}

/// Calm by default: color only for real alerts (action/blocked).
pub fn tray_state(status: &str) -> TrayState {
    match status {
        "protected" => TrayState { glyph: "shield.fill", opacity: 0.70, colored: false },
        "monitoring" => TrayState { glyph: "shield.lefthalf.filled", opacity: 0.55, colored: false },
        "action" => TrayState { glyph: "exclamationmark.shield.fill", opacity: 1.0, colored: true },
        "blocked" => TrayState { glyph: "xmark.shield.fill", opacity: 1.0, colored: true },
        _ => TrayState { glyph: "shield", opacity: 0.40, colored: false },
    }
}

/// Bottom-right anchor for a toast of `win_w`×`win_h` on a `mon_w`×`mon_h`
/// monitor, leaving `margin` px of inset. Clamped so a window larger than the
/// monitor still lands on-screen (never a negative coordinate). Pure math, so
/// it is unit-testable without a real window.
pub fn bottom_right_xy(
    mon_w: f64,
    mon_h: f64,
    win_w: f64,
    win_h: f64,
    margin: f64,
) -> (f64, f64) {
    let x = (mon_w - win_w - margin).max(margin);
    let y = (mon_h - win_h - margin).max(margin);
    (x, y)
}

/// Position the 320×400 popover near the tray click, clamped on-screen.
/// Tray may be at the top or bottom of the screen; we place the popover
/// below the click by default and flip above if it would overflow the screen.
#[cfg(feature = "tauri")]
fn position_popover(win: &tauri::WebviewWindow, click: tauri::PhysicalPosition<f64>) {
    let (w, h) = (320.0_f64, 400.0_f64);
    let mut x = click.x - w / 2.0; // center under cursor
    let mut y = click.y + 8.0;     // just below the tray
    if let Ok(Some(mon)) = win.current_monitor() {
        let sz = mon.size();
        let (mw, mh) = (sz.width as f64, sz.height as f64);
        if x < 0.0 { x = 8.0; }
        if x + w > mw { x = mw - w - 8.0; }
        if y + h > mh { y = (click.y - h - 8.0).max(8.0); } // tray at bottom -> open above
    }
    let _ = win.set_position(tauri::PhysicalPosition::new(x, y));
}

/// Anchor the toast window to the bottom-right of its current monitor.
#[cfg(feature = "tauri")]
pub fn position_toast(win: &tauri::WebviewWindow) {
    if let Ok(Some(mon)) = win.current_monitor() {
        let sz = mon.size();
        // Use the *outer* window size so the inset is correct even with shadows.
        let (w, h) = match win.outer_size() {
            Ok(s) => (s.width as f64, s.height as f64),
            Err(_) => (360.0, 96.0),
        };
        let (x, y) = bottom_right_xy(sz.width as f64, sz.height as f64, w, h, 16.0);
        let _ = win.set_position(tauri::PhysicalPosition::new(x, y));
    }
}

/// Build the menu-bar/tray icon. A left-click TOGGLES the 320×400 frameless
/// popover window (show if hidden, hide if visible). The popover auto-hides on
/// focus loss (wired in lib.rs::setup). On Linux, blur-hide races with the
/// click toggle are addressed by relying on blur-hide as the primary dismiss
/// path; the click serves as an open/toggle. No additional debounce is added
/// (the brief calls it optional and we cannot observe GUI behavior in CI).
/// Show + focus the main dashboard window (and hide the popover). Works after a
/// close now that the window is hidden-not-destroyed (close-to-tray in lib.rs).
#[cfg(feature = "tauri")]
fn show_main(app: &tauri::AppHandle) {
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

#[cfg(feature = "tauri")]
pub fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::Manager;

    // Right-click context menu. Left-click still toggles the popover (below), so
    // the menu is right-click only (show_menu_on_left_click(false)). "Quit" is
    // the ONLY way to fully exit now that closing the window hides-to-tray.
    let open_i = MenuItem::with_id(app, "tray_open", "Open Dashboard", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "tray_quit", "Quit Belay", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&open_i, &PredefinedMenuItem::separator(app)?, &quit_i],
    )?;

    let mut builder = TrayIconBuilder::with_id("belay-tray")
        .tooltip("Belay")
        .menu(&menu)
        .show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "tray_open" => show_main(app),
            "tray_quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                position,
                ..
            } = event {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("popover") {
                    if win.is_visible().unwrap_or(false) {
                        let _ = win.hide();
                    } else {
                        position_popover(&win, position);
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                }
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tray_is_monochrome_until_a_real_alert() {
        assert!(!tray_state("protected").colored);
        assert!(tray_state("blocked").colored);
    }

    #[test]
    fn toast_anchors_to_bottom_right_with_inset() {
        // 1920×1080 monitor, 360×96 toast, 16px inset.
        let (x, y) = bottom_right_xy(1920.0, 1080.0, 360.0, 96.0, 16.0);
        assert_eq!((x, y), (1920.0 - 360.0 - 16.0, 1080.0 - 96.0 - 16.0));
    }

    #[test]
    fn toast_position_never_goes_offscreen_on_tiny_monitor() {
        // Window bigger than the monitor → clamp to the margin, never negative.
        let (x, y) = bottom_right_xy(300.0, 200.0, 360.0, 96.0, 16.0);
        assert_eq!(x, 16.0);
        assert_eq!(y, 200.0 - 96.0 - 16.0);
        assert!(x >= 0.0 && y >= 0.0);
    }
}
