// DeadMansSwitchPanel — safety-critical countdown overlay for firewall rollback.
//
// SAFETY CONTRACT:
//   • Countdown is driven by the SERVER-provided `deadlineMs` (epoch ms).
//     `setInterval` only triggers re-renders; the remaining time is always
//     computed as `deadlineMs - Date.now()` so a frozen/suspended tab cannot lie.
//   • When the deadline passes, `onRevert` fires automatically — exactly ONCE,
//     guarded by a `firedRef` so double-fire is impossible.
//   • If the component unmounts before the deadline (e.g. navigate-away),
//     `settledRef` is false → cleanup fires `doRevert` to guarantee rollback.
//   • "Keep these rules" calls `onKeep`, NOT `onRevert`; it also sets
//     `settledRef` so the unmount-cleanup does NOT re-fire.
//   • The panel is NOT click-away dismissible; focus is trapped inside.
//   • role="alertdialog" + aria-labelledby on the root; the live countdown
//     is announced via a child <p aria-live="assertive"> so that
//     aria-label/aria-labelledby do not conflict.
//   • Color is NEVER the only signal: the countdown is rendered as text + the
//     border/label text conveys urgency.

import { useEffect, useRef, useState, useCallback } from "react";

export interface DeadMansSwitchPanelProps {
  /** Server-provided absolute deadline (epoch ms). Source of truth. */
  deadlineMs: number;
  /** Opaque handle returned by applyFirewall. */
  handle: string;
  /** Called when the user clicks "Keep these rules" → triggers confirmFirewall. */
  onKeep: (handle: string) => void;
  /** Called on timeout OR when the user clicks "Revert now" → triggers revertFirewall. */
  onRevert: (handle: string) => void;
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "0:00";
  const totalSecs = Math.ceil(ms / 1000);
  const m = Math.floor(totalSecs / 60);
  const s = totalSecs % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export default function DeadMansSwitchPanel({
  deadlineMs,
  handle,
  onKeep,
  onRevert,
}: DeadMansSwitchPanelProps) {
  const [remainingMs, setRemainingMs] = useState(() =>
    Math.max(0, deadlineMs - Date.now()),
  );
  // Guard: ensure onRevert fires exactly once (immune to double-setInterval ticks).
  const firedRef = useRef(false);
  // Guard: tracks whether the action has been settled (Keep or Revert).
  // If the component unmounts before settled, cleanup fires doRevert.
  const settledRef = useRef(false);
  // Ref to the panel element for focus-trapping.
  const panelRef = useRef<HTMLDivElement>(null);
  // Ref to "Keep" button for initial focus.
  const keepBtnRef = useRef<HTMLButtonElement>(null);

  // Hold callbacks in refs so interval / cleanup never captures a stale closure.
  // Updating these refs is an intentional "always-current" pattern — not a dep.
  const onRevertRef = useRef(onRevert);
  useEffect(() => { onRevertRef.current = onRevert; });

  const onKeepRef = useRef(onKeep);
  useEffect(() => { onKeepRef.current = onKeep; });

  // Stable revert callback — deps are only [handle] (not onRevert itself).
  const doRevert = useCallback(() => {
    if (firedRef.current) return;
    firedRef.current = true;
    settledRef.current = true;
    onRevertRef.current(handle);
  }, [handle]);

  // Stable keep callback — deps are only [handle].
  const doKeep = useCallback(() => {
    if (firedRef.current) return;
    firedRef.current = true;
    settledRef.current = true;
    onKeepRef.current(handle);
  }, [handle]);

  // Tick-only interval — source of truth is deadlineMs, not a counter.
  // Deps: [deadlineMs, doRevert] — both stable unless the server changes the deadline.
  useEffect(() => {
    const id = setInterval(() => {
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) {
        setRemainingMs(0);
        clearInterval(id);
        doRevert();
      } else {
        setRemainingMs(remaining);
      }
    }, 250);
    return () => {
      clearInterval(id);
      // Unmount without settling → revert (safe default: navigate-away reverts).
      if (!settledRef.current) doRevert();
    };
  }, [deadlineMs, doRevert]);

  // Initial focus trap: focus the "Keep" button on mount.
  useEffect(() => {
    keepBtnRef.current?.focus();
  }, []);

  // Focus trap: intercept Tab/Shift+Tab and cycle within the panel.
  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab") return;
    const panel = panelRef.current;
    if (!panel) return;
    const focusable = Array.from(
      panel.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => !el.hasAttribute("disabled"));
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const isUrgent = remainingMs <= 15_000;
  const timeStr = formatRemaining(remainingMs);
  const urgencyLabel = isUrgent ? "URGENT — " : "";

  // Amber → red visual escalation (text + border; NOT color-only).
  const accentColor = isUrgent ? "#C8312A" : "#B27B00";
  const accentBg = isUrgent ? "rgba(200,49,42,0.08)" : "rgba(178,123,0,0.08)";
  const accentBorder = isUrgent ? "rgba(200,49,42,0.35)" : "rgba(178,123,0,0.35)";

  return (
    /* Sticky overlay — covers top of viewport; NOT a full modal so the user
       can still see the rule table beneath it. The backdrop prevents clicks
       reaching the rule table, enforcing intentional interaction. */
    <div
      className="fixed inset-0 z-50 flex flex-col items-stretch pointer-events-none"
      aria-hidden={false}
    >
      {/* Click-away shield — absorbs pointer events but does NOT dismiss. */}
      <div className="absolute inset-0 bg-black/30 pointer-events-auto" onClick={() => {}} />

      {/* The panel itself — sticky top */}
      <div
        ref={panelRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="dms-title"
        aria-describedby="dms-desc"
        onKeyDown={handleKeyDown}
        className="relative pointer-events-auto mx-auto mt-6 w-full max-w-xl rounded-2xl p-6 space-y-5 shadow-2xl"
        style={{
          background: "#FFFFFF",
          border: `2px solid ${accentBorder}`,
        }}
      >
        {/* Accent top stripe */}
        <div
          className="absolute top-0 left-0 right-0 h-1 rounded-t-2xl"
          style={{ background: accentColor }}
          aria-hidden
        />

        {/* Header */}
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span
              className="text-[11px] font-bold uppercase tracking-widest"
              style={{ color: accentColor }}
              aria-hidden
            >
              {isUrgent ? "Urgent" : "Action required"}
            </span>
          </div>
          <h2
            id="dms-title"
            className="text-[#1C1C1E] font-semibold text-lg leading-snug"
          >
            Confirm or revert firewall rules
          </h2>
        </div>

        {/* Countdown */}
        <div
          className="rounded-xl px-5 py-4 flex items-center justify-between"
          style={{ background: accentBg, border: `1px solid ${accentBorder}` }}
        >
          <div className="space-y-0.5">
            <p
              className="text-xs font-medium uppercase tracking-widest"
              style={{ color: accentColor }}
            >
              {isUrgent ? "Reverting in" : "Auto-reverts in"}
            </p>
            {/* Live region: announces countdown changes to screen readers. */}
            <p
              aria-live="assertive"
              aria-atomic="true"
              className="text-4xl font-mono font-bold tabular-nums"
              style={{ color: accentColor }}
            >
              {`${urgencyLabel}${timeStr} remaining`}
            </p>
          </div>
          <div className="text-right text-xs text-[#636366] max-w-[160px]">
            {isUrgent
              ? "Doing nothing reverts to safe defaults."
              : "No action needed to revert — doing nothing is safe."}
          </div>
        </div>

        {/* Description */}
        <p id="dms-desc" className="text-sm text-[#636366]">
          Firewall rules have been applied. If you cannot reach your host or
          SSH is blocked, do nothing — rules will revert automatically when
          the timer expires. Click <strong>Keep these rules</strong> only if
          you have verified the rules are correct.
        </p>

        {/* Actions */}
        <div className="flex flex-col gap-3 sm:flex-row sm:gap-3">
          {/* "Keep" — initial focus, but timeout = revert */}
          <button
            ref={keepBtnRef}
            onClick={doKeep}
            className="flex-1 py-3 rounded-xl font-semibold text-white text-sm transition-opacity"
            style={{ background: "#0A66D6" }}
            aria-label="Keep these rules — confirm firewall ruleset"
          >
            Keep these rules
          </button>

          {/* "Revert now" — visually de-emphasized because it's the SAFE default */}
          <button
            onClick={doRevert}
            className="flex-1 py-3 rounded-xl font-semibold text-sm transition-opacity border"
            style={{
              background: accentBg,
              color: accentColor,
              borderColor: accentBorder,
            }}
            aria-label="Revert now — restore previous firewall rules immediately"
          >
            Revert now
          </button>
        </div>

        {/* Safety note */}
        <p className="text-[11px] text-[#8E8E93] text-center">
          Default on timeout: <strong>Revert</strong> (safe). SSH exemption is
          always preserved.
        </p>
      </div>
    </div>
  );
}
