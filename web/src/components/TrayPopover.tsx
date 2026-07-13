/**
 * TrayPopover — compact 320×400 panel rendered when the URL hash includes "popover".
 *
 * Opaque LIGHT background — NOT transparent.
 * Transparency was removed from the main window to fix blank WebKitGTK rendering in VMs;
 * the same reasoning applies here.
 */
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getPosture, getPending, getBootStart, setBootStart } from "../lib/api";
import { setProtection } from "../lib/ipc";
import type { PostureSummary } from "../lib/api";

// Derive a human-readable status label from the posture.
function statusLabel(posture: PostureSummary | null): string {
  if (!posture) return "Loading…";
  const score = posture.score ?? 100;
  const deny = posture.deny ?? 0;
  const ask = posture.ask ?? 0;
  if (deny > 0 || score < 60) return "Action needed";
  if (ask > 0) return "Monitoring";
  return "Protected";
}

// Belay brand accent (falls back if the CSS var is absent in the popover window).
const ACCENT = "var(--accent, #0A66D6)";

export default function TrayPopover() {
  const [posture, setPosture] = useState<PostureSummary | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [paused, setPaused] = useState(false);
  const [toggling, setToggling] = useState(false);
  // Boot-start (autostart): null until loaded; `supported` is false in the web build.
  const [bootOn, setBootOn] = useState<boolean | null>(null);
  const [bootSupported, setBootSupported] = useState(true);
  const [bootBusy, setBootBusy] = useState(false);

  // Load posture + pending + boot-start on mount.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const p = await getPosture();
        if (!cancelled) setPosture(p);
      } catch {
        // non-fatal; keep null / "Loading…"
      }
      try {
        const pending = await getPending();
        if (!cancelled)
          setPendingCount(Array.isArray(pending) ? pending.length : 0);
      } catch {
        // non-fatal; keep 0
      }
      try {
        const b = await getBootStart();
        if (!cancelled) {
          setBootOn(b.enabled);
          setBootSupported(b.supported);
        }
      } catch {
        if (!cancelled) setBootSupported(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  async function handlePauseResume() {
    if (toggling) return;
    setToggling(true);
    try {
      await setProtection(paused); // paused=true → turn back on (pass true); paused=false → turn off (pass false)
      setPaused((p) => !p);
    } catch {
      // keep current state on error
    } finally {
      setToggling(false);
    }
  }

  // Flip boot-start. The OS shows an elevation prompt (UAC / pkexec / osascript);
  // optimistically reflect the target, then reconcile with the real state after
  // the user accepts or cancels the prompt.
  async function handleToggleBoot() {
    if (bootBusy || bootOn === null || !bootSupported) return;
    const target = !bootOn;
    setBootBusy(true);
    setBootOn(target);
    try {
      await setBootStart(target);
    } catch {
      setBootOn(!target); // immediate failure (e.g. no elevation helper) → revert
      setBootBusy(false);
      return;
    }
    const recheck = async () => {
      try {
        const b = await getBootStart();
        setBootOn(b.enabled);
      } catch { /* keep optimistic */ }
    };
    setTimeout(recheck, 3000);
    setTimeout(() => { recheck(); setBootBusy(false); }, 8000);
  }

  async function handleOpenDashboard() {
    await invoke("focus_main");
  }

  const status = statusLabel(posture);

  return (
    <div
      style={{
        width: "320px",
        height: "400px",
        background: "#FFFFFF",
        color: "#1C1C1E",
        fontFamily: "system-ui, sans-serif",
        display: "flex",
        flexDirection: "column",
        padding: "20px",
        boxSizing: "border-box",
        userSelect: "none",
        boxShadow: "var(--shadow-popover)",
      }}
    >
      {/* Header - branded (accent shield + accent wordmark) */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "20px" }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill={ACCENT} aria-hidden="true">
          <path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3z" />
        </svg>
        <span style={{ fontWeight: 700, fontSize: "16px", letterSpacing: "0.02em", color: ACCENT }}>
          Belay
        </span>
      </div>

      {/* Status */}
      <div
        style={{
          background: "#F5F5F7",
          borderRadius: "8px",
          padding: "14px 16px",
          marginBottom: "12px",
          border: "1px solid rgba(0,0,0,0.08)",
        }}
      >
        <div style={{ fontSize: "11px", color: "#8E8E93", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>
          Status
        </div>
        <div
          data-testid="popover-status"
          style={{
            fontSize: "18px",
            fontWeight: 600,
            color: paused ? "var(--semantic-ask, #B27B00)" : status === "Action needed" ? "var(--semantic-deny, #C8312A)" : "var(--semantic-allow, #1B8C3A)",
          }}
        >
          {paused ? "Paused" : status}
        </div>
      </div>

      {/* Pending approvals */}
      <div
        style={{
          background: "#F5F5F7",
          borderRadius: "8px",
          padding: "14px 16px",
          marginBottom: "auto",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          border: "1px solid rgba(0,0,0,0.08)",
        }}
      >
        <div>
          <div style={{ fontSize: "11px", color: "#8E8E93", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>
            Actions waiting for you
          </div>
          <div
            data-testid="popover-pending"
            style={{ fontSize: "18px", fontWeight: 600, color: pendingCount > 0 ? "var(--semantic-ask, #B27B00)" : "#8E8E93" }}
          >
            {pendingCount}
          </div>
        </div>
        {pendingCount > 0 && (
          <span
            style={{
              background: "var(--semantic-ask, #B27B00)",
              color: "#FFFFFF",
              borderRadius: "9999px",
              padding: "2px 8px",
              fontSize: "12px",
              fontWeight: 700,
            }}
          >
            {pendingCount}
          </span>
        )}
      </div>

      {/* Actions */}
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "20px" }}>
        {/* Start-on-boot toggle (desktop only; hidden when the OS reports it unsupported) */}
        {bootSupported && bootOn !== null && (
          <button
            data-testid="btn-bootstart"
            onClick={handleToggleBoot}
            disabled={bootBusy}
            aria-pressed={bootOn}
            title="Run Belay automatically when this computer starts (needs Administrator once)"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "rgba(0,0,0,0.04)",
              color: "#1C1C1E",
              border: "1px solid rgba(0,0,0,0.08)",
              borderRadius: "6px",
              padding: "10px",
              fontSize: "14px",
              fontWeight: 500,
              cursor: bootBusy ? "not-allowed" : "pointer",
              opacity: bootBusy ? 0.7 : 1,
            }}
          >
            <span>Start on boot</span>
            <span
              aria-hidden="true"
              style={{
                width: "36px",
                height: "20px",
                borderRadius: "9999px",
                background: bootOn ? ACCENT : "rgba(0,0,0,0.25)",
                position: "relative",
                transition: "background 0.15s",
                flexShrink: 0,
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: "2px",
                  left: bootOn ? "18px" : "2px",
                  width: "16px",
                  height: "16px",
                  borderRadius: "50%",
                  background: "#FFFFFF",
                  transition: "left 0.15s",
                }}
              />
            </span>
          </button>
        )}

        <button
          data-testid="btn-pause"
          onClick={handlePauseResume}
          disabled={toggling}
          style={{
            background: "rgba(0,0,0,0.06)",
            color: "#1C1C1E",
            border: "1px solid rgba(0,0,0,0.08)",
            borderRadius: "6px",
            padding: "10px",
            fontSize: "14px",
            fontWeight: 500,
            cursor: toggling ? "not-allowed" : "pointer",
            opacity: toggling ? 0.7 : 1,
            transition: "background 0.15s",
          }}
        >
          {paused ? "Resume protection" : "Pause protection"}
        </button>

        <button
          data-testid="btn-open-dashboard"
          onClick={handleOpenDashboard}
          style={{
            background: ACCENT,
            color: "#FFFFFF",
            border: "none",
            borderRadius: "6px",
            padding: "10px",
            fontSize: "14px",
            fontWeight: 500,
            cursor: "pointer",
            transition: "background 0.15s",
          }}
        >
          Open dashboard
        </button>
      </div>

      {/* Reduced-motion support: disable transitions when requested */}
      <style>{`
        @media (prefers-reduced-motion: reduce) {
          button, button * { transition: none !important; }
        }
      `}</style>
    </div>
  );
}
