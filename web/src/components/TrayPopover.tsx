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
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// Derive the posture's STATE - deliberately not its label.
//
// This used to return the display string, and the colour was chosen by
// comparing it: `status === "Action needed" ? red : green`. That works only
// while the string is English. Translate it and the comparison silently never
// matches, so a tray that needs action renders GREEN - the failure mode is a
// security surface saying "fine" when it means "look at me". The state is now
// the thing that is branched on, and the label is derived from it.
type PostureState = "loading" | "action" | "monitoring" | "protected";

function postureState(posture: PostureSummary | null): PostureState {
  if (!posture) return "loading";
  const score = posture.score ?? 100;
  const deny = posture.deny ?? 0;
  const ask = posture.ask ?? 0;
  if (deny > 0 || score < 60) return "action";
  if (ask > 0) return "monitoring";
  return "protected";
}

const STATUS_LABEL: Record<PostureState, MessageDescriptor> = {
  loading: msg`Loading…`,
  action: msg`Action needed`,
  monitoring: msg`Monitoring`,
  protected: msg`Protected`,
};

const STATUS_COLOR: Record<PostureState, string> = {
  loading: "var(--semantic-allow, #187D34)",
  action: "var(--semantic-deny, #C8312A)",
  monitoring: "var(--semantic-allow, #187D34)",
  protected: "var(--semantic-allow, #187D34)",
};

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

  const { t } = useLingui();
  const state = postureState(posture);

  return (
    <div
      style={{
        width: "320px",
        height: "400px",
        // OPAQUE ambient (never transparent - see header note: transparency blanks
        // WebKitGTK in VMs, and see-through chrome makes small text unreadable).
        // The glass look comes from the frosted panels inside, not the window.
        background: "var(--lg-ambient)",
        color: "#1C1C1E",
        fontFamily: "var(--font-sans, system-ui, sans-serif)",
        display: "flex",
        flexDirection: "column",
        padding: "18px",
        boxSizing: "border-box",
        userSelect: "none",
        boxShadow: "var(--shadow-popover)",
      }}
    >
      {/* Header - branded (guard-dog mascot + accent wordmark) */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "18px" }}>
        <img src="/mascot/happy.png" alt="" width={26} height={26}
          style={{ display: "block", filter: "drop-shadow(0 2px 3px rgba(17,24,39,0.2))" }} />
        <span style={{ fontWeight: 700, fontSize: "16px", letterSpacing: "0.02em", color: ACCENT }}>
          Belay
        </span>
      </div>

      {/* Status */}
      <div
        style={{
          background: "rgba(255,255,255,0.72)",
          backdropFilter: "blur(14px) saturate(160%)",
          WebkitBackdropFilter: "blur(14px) saturate(160%)",
          boxShadow: "var(--lg-shadow-card)",
          borderRadius: "14px",
          padding: "14px 16px",
          marginBottom: "12px",
          border: "1px solid rgba(0,0,0,0.08)",
        }}
      >
        <div style={{ fontSize: "11px", color: "var(--text-tertiary, #6C6C71)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>
          <Trans>Status</Trans>
        </div>
        <div
          data-testid="popover-status"
          style={{
            fontSize: "18px",
            fontWeight: 600,
            color: paused ? "var(--semantic-ask, #916400)" : STATUS_COLOR[state],
          }}
        >
          {paused ? t`Paused` : t(STATUS_LABEL[state])}
        </div>
      </div>

      {/* Pending approvals */}
      <div
        style={{
          background: "rgba(255,255,255,0.72)",
          backdropFilter: "blur(14px) saturate(160%)",
          WebkitBackdropFilter: "blur(14px) saturate(160%)",
          boxShadow: "var(--lg-shadow-card)",
          borderRadius: "14px",
          padding: "14px 16px",
          marginBottom: "auto",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          border: "1px solid rgba(0,0,0,0.08)",
        }}
      >
        <div>
          <div style={{ fontSize: "11px", color: "var(--text-tertiary, #6C6C71)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>
            <Trans>Actions waiting for you</Trans>
          </div>
          <div
            data-testid="popover-pending"
            style={{ fontSize: "18px", fontWeight: 600, color: pendingCount > 0 ? "var(--semantic-ask, #916400)" : "var(--text-tertiary, #6C6C71)" }}
          >
            {pendingCount}
          </div>
        </div>
        {pendingCount > 0 && (
          <span
            style={{
              background: "var(--semantic-ask, #916400)",
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
            title={t`Run Belay automatically when this computer starts (needs Administrator once)`}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "rgba(255,255,255,0.66)",
              color: "#1C1C1E",
              border: "1px solid rgba(0,0,0,0.08)",
              borderRadius: "12px",
              padding: "10px",
              fontSize: "14px",
              fontWeight: 500,
              cursor: bootBusy ? "not-allowed" : "pointer",
              opacity: bootBusy ? 0.7 : 1,
            }}
          >
            <span><Trans>Start on boot</Trans></span>
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
            background: "rgba(255,255,255,0.66)",
            color: "#1C1C1E",
            border: "1px solid rgba(0,0,0,0.08)",
            borderRadius: "12px",
            padding: "10px",
            fontSize: "14px",
            fontWeight: 500,
            cursor: toggling ? "not-allowed" : "pointer",
            opacity: toggling ? 0.7 : 1,
            transition: "background 0.15s",
          }}
        >
          {paused ? t`Resume protection` : t`Pause protection`}
        </button>

        <button
          data-testid="btn-open-dashboard"
          onClick={handleOpenDashboard}
          style={{
            background: ACCENT,
            color: "#FFFFFF",
            border: "none",
            borderRadius: "12px",
            padding: "10px",
            fontSize: "14px",
            fontWeight: 500,
            cursor: "pointer",
            transition: "background 0.15s",
          }}
        >
          <Trans>Open dashboard</Trans>
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
