//! Paw-shaped toast window.
//!
//! On Windows this uses `SetWindowRgn`, which sets the region for the whole
//! HWND (child windows included) and needs no transparency or compositor
//! support. The equivalent X11 attempt (XShape) failed on Linux/WebKitGTK
//! after four approaches - see the 2026-07-20 session notes - so the shape is
//! deliberately Windows-only for now rather than half-working everywhere.
//!
//! The geometry is a pure function of the window size and carries no platform
//! types, so it is unit-testable under `--no-default-features`.

/// One ellipse of the paw, in fractions of the window box: (cx, cy, rx, ry).
/// Four toe pads across the top, one large main pad below.
const PADS: [(f64, f64, f64, f64); 5] = [
    // main pad
    (0.500, 0.700, 0.360, 0.270),
    // toe pads, outer ones lower and smaller, like a real paw.
    // The two inner toes must NOT overlap or the toes merge into one blob and
    // the silhouette stops reading as a paw (see the inner-gap test).
    (0.155, 0.415, 0.125, 0.150),
    (0.375, 0.255, 0.120, 0.175),
    (0.625, 0.255, 0.120, 0.175),
    (0.845, 0.415, 0.125, 0.150),
];

/// Is `(px, py)` inside any pad of a `w` x `h` paw?
fn in_paw(px: f64, py: f64, w: f64, h: f64) -> bool {
    PADS.iter().any(|(cx, cy, rx, ry)| {
        let dx = (px - cx * w) / (rx * w);
        let dy = (py - cy * h) / (ry * h);
        dx * dx + dy * dy <= 1.0
    })
}

/// Scan-convert the paw into horizontal runs: `(x, y, width, height=1)`.
pub fn paw_rects(w: i32, h: i32) -> Vec<(i32, i32, i32, i32)> {
    let mut rects = Vec::new();
    if w <= 0 || h <= 0 {
        return rects;
    }
    let (wf, hf) = (w as f64, h as f64);
    for y in 0..h {
        let py = y as f64 + 0.5;
        let mut run_start: Option<i32> = None;
        for x in 0..w {
            let inside = in_paw(x as f64 + 0.5, py, wf, hf);
            match (inside, run_start) {
                (true, None) => run_start = Some(x),
                (false, Some(s)) => {
                    rects.push((s, y, x - s, 1));
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            rects.push((s, y, w - s, 1));
        }
    }
    rects
}

/// Where the toast's copy may live, as a fraction of the window box:
/// `(x, y, w, h)`. This is the inscribed box of the MAIN pad only - text must
/// never stray into a toe pad or the shape clips it away.
///
/// Derived from the main pad ellipse (cx .500, cy .700, rx .360, ry .270) with
/// margin: for a centred box of half-extents (a, b) the corners are inside when
/// (a/rx)^2 + (b/ry)^2 <= 1. Here a=.24, b=.17 gives .444 + .396 = .840.
pub const MAIN_PAD_TEXT_BOX: (f64, f64, f64, f64) = (0.260, 0.530, 0.480, 0.340);

/// Clip the toast window to the paw silhouette (Windows only).
///
/// `SetWindowRgn` takes ownership of the region handle on success, so the HRGN
/// must NOT be deleted afterwards. Passing `true` for `bRedraw` repaints
/// immediately. Re-applied on every show because a resize resets the region.
#[cfg(all(feature = "tauri", target_os = "windows"))]
pub fn install_paw_shape(win: &tauri::WebviewWindow) {
    // `SetWindowRgn` lives in `Graphics::Gdi` in this crate, not
    // `UI::WindowsAndMessaging` - verified against the crate source before use
    // (a first attempt at the latter failed to compile: no such item there).
    // `win.hwnd()` already returns tauri's own `windows::Win32::Foundation::HWND`.
    // This crate pins `windows = "0.61"` specifically to match what tauri
    // itself pulls transitively (see Cargo.toml) so the two resolve to the
    // SAME crate instance and this HWND is used directly, no reconstruction.
    use windows::Win32::Graphics::Gdi::{CombineRgn, CreateRectRgn, DeleteObject, SetWindowRgn, HRGN, RGN_OR};

    let hwnd = match win.hwnd() {
        Ok(h) => h,
        Err(e) => {
            crate::toast_debug_log(&format!("install_paw_shape: hwnd() failed: {e:?}"));
            return;
        }
    };
    let size = match win.inner_size() {
        Ok(s) => s,
        Err(e) => {
            crate::toast_debug_log(&format!("install_paw_shape: inner_size() failed: {e:?}"));
            return;
        }
    };
    let (w, h) = (size.width as i32, size.height as i32);
    if w <= 0 || h <= 0 {
        crate::toast_debug_log(&format!("install_paw_shape: non-positive size w={w} h={h}, skipping"));
        return;
    }

    unsafe {
        // Start from an empty region and OR each scanline run into it.
        let combined: HRGN = CreateRectRgn(0, 0, 0, 0);
        for (x, y, rw, rh) in paw_rects(w, h) {
            let run = CreateRectRgn(x, y, x + rw, y + rh);
            let _ = CombineRgn(Some(combined), Some(combined), Some(run), RGN_OR);
            let _ = DeleteObject(run.into());
        }
        // On success the window owns `combined`; do not delete it.
        let rgn_result = SetWindowRgn(hwnd, Some(combined), true);
        crate::toast_debug_log(&format!(
            "install_paw_shape: w={w} h={h} SetWindowRgn returned {rgn_result}"
        ));
    }
}

/// Non-Windows: the toast stays rectangular. The X11 equivalent was attempted
/// and abandoned - see the module docs.
#[cfg(all(feature = "tauri", not(target_os = "windows")))]
pub fn install_paw_shape(_win: &tauri::WebviewWindow) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_box_yields_no_rects() {
        assert!(paw_rects(0, 0).is_empty());
        assert!(paw_rects(-5, 10).is_empty());
    }

    #[test]
    fn paw_covers_the_main_pad_centre_and_leaves_corners_out() {
        let (w, h) = (300.0, 300.0);
        assert!(in_paw(0.5 * w, 0.7 * h, w, h));
        for (px, py) in [(1.0, 1.0), (w - 1.0, 1.0), (1.0, h - 1.0), (w - 1.0, h - 1.0)] {
            assert!(!in_paw(px, py, w, h), "corner ({px},{py}) must be outside");
        }
    }

    #[test]
    fn all_four_toe_pads_are_present() {
        let (w, h) = (300.0, 300.0);
        for (cx, cy, _, _) in PADS.iter().skip(1) {
            assert!(in_paw(cx * w, cy * h, w, h), "toe pad at {cx},{cy} missing");
        }
        // The gap BETWEEN the inner toes must stay open, or they merge.
        assert!(!in_paw(0.5075 * w, 0.20 * h, w, h), "inner toe gap closed");
    }

    #[test]
    fn text_box_stays_inside_the_paw() {
        let (w, h) = (340.0, 300.0);
        let (bx, by, bw, bh) = MAIN_PAD_TEXT_BOX;
        for (fx, fy) in [(bx, by), (bx + bw, by), (bx, by + bh), (bx + bw, by + bh)] {
            assert!(
                in_paw(fx * w, fy * h, w, h),
                "text box corner ({fx},{fy}) falls outside the paw"
            );
        }
    }

    #[test]
    fn rects_are_within_bounds_and_non_empty() {
        let rects = paw_rects(200, 200);
        assert!(!rects.is_empty());
        for (x, y, w, h) in rects {
            assert!(x >= 0 && y >= 0 && w > 0 && h == 1);
            assert!(x + w <= 200 && y < 200);
        }
    }
}
