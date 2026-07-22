/**
 * Toast — the content of the custom bottom-right notification window.
 *
 * The native window is created hidden by the Rust side (label "toast") and is
 * shown/positioned (bottom-right) whenever `notify_cycle` emits a "toast" event.
 * This component renders that event's copy, auto-dismisses after a few seconds
 * by calling the `hide_toast` command, and lets the user click through to the
 * dashboard. One reusable window + content-swap means a burst can never tile
 * the screen the way a flood of native notifications did.
 *
 * Opaque dark background — NOT transparent (same WebKitGTK-in-VM reasoning as
 * the tray popover).
 */
import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useLingui } from "@lingui/react/macro";

// `paw` is true only on a build that actually clips the window to the paw
// silhouette (Windows, via SetWindowRgn - see desktop/src-tauri/src/shape.rs).
// The same component ships to Linux/macOS, which get no clip, so it must fall
// back to the plain rounded-card look there rather than an unclipped black
// rectangle with text positioned for a shape that was never applied.
type ToastMsg = { title: string; body: string; paw?: boolean };

// How long a toast stays on screen before auto-dismissing.
const DISMISS_MS = 6000;

export default function Toast() {
  const { t } = useLingui();
  const [msg, setMsg] = useState<ToastMsg | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function dismiss() {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
    setMsg(null);
    invoke("hide_toast").catch(() => {});
  }

  useEffect(() => {
    const unlisten = listen<ToastMsg>("toast", (event) => {
      setMsg(event.payload);
      // Restart the dismiss timer each time new copy arrives (so a fresh event
      // keeps the toast up rather than dismissing mid-display).
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(dismiss, DISMISS_MS);
    });
    return () => {
      unlisten.then((f) => f()).catch(() => {});
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  async function openDashboard() {
    try {
      await invoke("focus_main");
    } catch {
      // non-fatal
    }
    dismiss();
  }

  if (!msg) return null;

  // `paw` builds are clipped to the actual paw silhouette by the native window
  // region (SetWindowRgn, Windows only - see shape.rs). Everything outside the
  // MAIN_PAD_TEXT_BOX fraction of the window (the plan's geometry, verbatim -
  // change one, change both) is invisible there, so:
  //   - no rounded corners / border - the region itself IS the silhouette now.
  //   - no oversized watermark paw - it was a stand-in for the shape this build
  //     no longer needs to fake.
  //   - no circular badge - too little safe area in the pad for it; text only.
  //   - copy (and the dismiss control) must stay INSIDE that box, or the clip
  //     eats them.
  const paw = msg.paw === true;

  return (
    <div
      role="alert"
      onClick={openDashboard}
      style={{
        width: "100vw",
        height: "100vh",
        boxSizing: "border-box",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        gap: "14px",
        padding: paw ? 0 : "20px 22px",
        position: "relative",
        // Opaque frosted-dark glass: a notification must stay readable over any
        // wallpaper, so this is never see-through - the "glass" is the gradient
        // + specular rim, not transparency.
        background: "linear-gradient(160deg, #26262B 0%, #17171A 100%)",
        color: "#FFFFFF",
        fontFamily: "var(--font-sans, system-ui, sans-serif)",
        borderRadius: paw ? 0 : "22px",
        border: paw ? "none" : "1px solid rgba(255,255,255,0.14)",
        boxShadow: paw ? "none" : "0 2px 6px rgba(0,0,0,0.35), 0 16px 40px -8px rgba(0,0,0,0.55)",
        cursor: "pointer",
        userSelect: "none",
        overflow: "hidden",
      }}
    >
      {!paw && (
        <>
          {/* Oversized paw bleeding off the right edge: reads as "big dog paw"
              at a glance without competing with the copy. Decorative only -
              only rendered on builds with no real shape clip to fake. */}
          <img
            src="/mascot/paw.png"
            alt=""
            aria-hidden
            style={{
              position: "absolute",
              right: "-26px",
              top: "50%",
              transform: "translateY(-50%) rotate(-12deg)",
              width: "132px",
              height: "132px",
              opacity: 0.07,
              pointerEvents: "none",
            }}
          />
          {/* Identity row: paw badge + title. */}
          <div style={{ display: "flex", alignItems: "center", gap: "13px", position: "relative" }}>
            <div
              style={{
                flexShrink: 0,
                width: "56px",
                height: "56px",
                borderRadius: "50%",
                background: "rgba(255,255,255,0.07)",
                border: "1px solid rgba(255,255,255,0.10)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <img src="/mascot/paw.png" alt="" width={34} height={34} style={{ display: "block", opacity: 0.95 }} />
            </div>
            <div
              data-testid="toast-title"
              style={{ fontWeight: 700, fontSize: "16px", letterSpacing: "0.01em", minWidth: 0 }}
            >
              {msg.title}
            </div>
          </div>
          {/* The window has a 200px floor (WebKitGTK), so there is room for the
              full reason on two lines instead of one ellipsized line. */}
          <div
            data-testid="toast-body"
            style={{
              fontSize: "13px",
              lineHeight: 1.45,
              color: "#C7C7CC",
              display: "-webkit-box",
              WebkitLineClamp: 3,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
              position: "relative",
            }}
          >
            {msg.body}
          </div>
          <button
            data-testid="toast-dismiss"
            onClick={(e) => {
              e.stopPropagation();
              dismiss();
            }}
            aria-label={t`Dismiss`}
            style={{
              position: "absolute",
              top: "10px",
              right: "12px",
              background: "transparent",
              border: "none",
              // Deliberately NOT --text-tertiary: this sits on the near-black toast,
              // where the light grey reads 5.49:1 and the darker one would be 3.43:1.
              color: "var(--text-tertiary-on-dark, #8E8E93)",
              fontSize: "18px",
              lineHeight: 1,
              cursor: "pointer",
              padding: "2px 4px",
            }}
          >
            ×
          </button>
        </>
      )}
      {paw && (
        // MAIN_PAD_TEXT_BOX verbatim (shape.rs): the inscribed box of the main
        // pad ellipse. The dismiss control is nested INSIDE this box (not
        // window corners - the paw's corners are outside the clip) so it stays
        // inside the same safe area as the copy.
        <div
          style={{
            position: "absolute",
            left: "26%",
            top: "53%",
            width: "48%",
            height: "34%",
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            gap: "4px",
            textAlign: "center",
          }}
        >
          <div
            data-testid="toast-title"
            style={{ fontWeight: 700, fontSize: "14px", letterSpacing: "0.01em" }}
          >
            {msg.title}
          </div>
          <div
            data-testid="toast-body"
            style={{
              fontSize: "11px",
              lineHeight: 1.35,
              color: "#C7C7CC",
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}
          >
            {msg.body}
          </div>
          <button
            data-testid="toast-dismiss"
            onClick={(e) => {
              e.stopPropagation();
              dismiss();
            }}
            aria-label={t`Dismiss`}
            style={{
              position: "absolute",
              top: "-4px",
              right: "2px",
              background: "transparent",
              border: "none",
              color: "var(--text-tertiary-on-dark, #8E8E93)",
              fontSize: "15px",
              lineHeight: 1,
              cursor: "pointer",
              padding: "2px 4px",
            }}
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}
