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

type ToastMsg = { title: string; body: string };

// How long a toast stays on screen before auto-dismissing.
const DISMISS_MS = 6000;

export default function Toast() {
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

  return (
    <div
      role="alert"
      onClick={openDashboard}
      style={{
        width: "100vw",
        height: "100vh",
        boxSizing: "border-box",
        display: "flex",
        alignItems: "center",
        gap: "12px",
        padding: "14px 16px",
        background: "#1C1C1E",
        color: "#FFFFFF",
        fontFamily: "system-ui, sans-serif",
        borderRadius: "12px",
        border: "1px solid rgba(255,255,255,0.10)",
        boxShadow: "0 8px 28px rgba(0,0,0,0.45)",
        cursor: "pointer",
        userSelect: "none",
        overflow: "hidden",
      }}
    >
      <span style={{ fontSize: "22px", lineHeight: 1, flexShrink: 0 }}>🛡</span>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          data-testid="toast-title"
          style={{
            fontWeight: 700,
            fontSize: "13px",
            letterSpacing: "0.02em",
            marginBottom: "2px",
          }}
        >
          {msg.title}
        </div>
        <div
          data-testid="toast-body"
          style={{
            fontSize: "12px",
            color: "#C7C7CC",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {msg.body}
        </div>
      </div>
      <button
        data-testid="toast-dismiss"
        onClick={(e) => {
          e.stopPropagation();
          dismiss();
        }}
        aria-label="Dismiss"
        style={{
          flexShrink: 0,
          background: "transparent",
          border: "none",
          color: "#8E8E93",
          fontSize: "18px",
          lineHeight: 1,
          cursor: "pointer",
          padding: "2px 4px",
        }}
      >
        ×
      </button>
    </div>
  );
}
