/**
 * TrayPopover — compact 320×400 panel rendered when the URL hash includes "popover".
 *
 * Opaque LIGHT background — NOT transparent.
 * Transparency was removed from the main window to fix blank WebKitGTK rendering in VMs;
 * the same reasoning applies here.
 */
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getPosture, getPending } from "../lib/api";
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

export default function TrayPopover() {
  const [posture, setPosture] = useState<PostureSummary | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [paused, setPaused] = useState(false);
  const [toggling, setToggling] = useState(false);

  // Load posture + pending on mount.
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
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "20px" }}>
        <span style={{ fontSize: "20px" }}>🛡</span>
        <span style={{ fontWeight: 700, fontSize: "16px", letterSpacing: "0.02em" }}>
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
            background: "var(--accent, #0A66D6)",
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
          button { transition: none !important; }
        }
      `}</style>
    </div>
  );
}
