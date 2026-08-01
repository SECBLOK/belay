// Overview visibility for rule-scoped deny mutes ("Deny & mute this rule" in
// ApprovalCard/ApprovalSurface). A mute is powerful (it silently auto-denies
// future matches without prompting) so it must never be invisible or hard to
// undo — this panel is the "N rules muted" indicator + one-click revoke that
// makes the feature safe to ship. Renders nothing when no mute is active, so
// it never clutters the Overview during normal (unmuted) operation.

import { useCallback, useEffect, useState } from "react";
import { Plural, Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import { getDenyMutes, revokeDenyMute, revokeAllDenyMutes, type DenyMuteRow } from "../lib/api";

const POLL_MS = 5000;

const originLabel = (origin: DenyMuteRow["origin"]) =>
  origin === "auto" ? msg`Auto — flood detected` : msg`Manual`;

const minutesLeft = (expiresMs: number, nowMs: number): number =>
  Math.max(0, Math.ceil((expiresMs - nowMs) / 60000));

// Tauri usually rejects with a plain string (the Rust command's Err
// payload); stay defensive about Error-shaped values too.
function errorMessage(e: unknown): string {
  return String((e as { message?: string } | undefined)?.message ?? e);
}

function MuteRow({
  mute, nowMs, onRevoke,
}: {
  mute: DenyMuteRow;
  nowMs: number;
  onRevoke: (rule: string) => Promise<void>;
}) {
  const { t } = useLingui();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  // Set only when the in-flight revoke actually failed; cleared on retry.
  // The old `void x().then(refresh)` swallowed a rejection entirely: no
  // busy state, no error, the row just sat there looking unrevoked.
  const [error, setError] = useState<string | null>(null);

  const handleClick = async () => {
    if (!confirming) { setConfirming(true); return; }
    setConfirming(false);
    setBusy(true);
    setError(null);
    try {
      await onRevoke(mute.rule);
      setBusy(false);
    } catch (err) {
      setBusy(false);
      setError(errorMessage(err));
    }
  };

  return (
    <div
      className="flex items-center justify-between gap-2 rounded-lg px-2 py-1.5 flex-wrap"
      style={{ background: "rgba(0,0,0,0.02)" }}
    >
      <div className="min-w-0">
        <div className="text-sm font-mono text-[#1C1C1E] truncate" title={mute.rule}>
          {mute.rule}
        </div>
        <div className="text-[11px] text-[var(--text-tertiary)] flex items-center gap-1">
          <span>{t(originLabel(mute.origin))}</span>
          <span aria-hidden="true">·</span>
          <Trans>{minutesLeft(mute.expires_ms, nowMs)}m left</Trans>
          <span aria-hidden="true">·</span>
          <Plural value={mute.hits} one="# hit" other="# hits" />
        </div>
        {error && (
          <p role="alert" data-testid="mute-revoke-error" className="text-[11px] mt-0.5" style={{ color: "#C8312A" }}>
            <Trans>Could not revoke: {error}</Trans>
          </p>
        )}
      </div>
      <button
        onClick={handleClick}
        onBlur={() => setConfirming(false)}
        disabled={busy}
        className={`shrink-0 text-xs px-2 py-1 rounded transition-colors disabled:opacity-60 ${
          confirming ? "bg-red-600 text-white" : "bg-[#E5E5EA] text-[#636366] hover:bg-[#D1D1D6]"
        }`}
      >
        {busy ? <Trans>Revoking…</Trans> : confirming ? <Trans>Confirm revoke?</Trans> : <Trans>Revoke</Trans>}
      </button>
    </div>
  );
}

export default function MutedRulesPanel() {
  const [mutes, setMutes] = useState<DenyMuteRow[]>([]);
  const [nowMs, setNowMs] = useState(0);
  const [confirmingAll, setConfirmingAll] = useState(false);
  const [revokingAll, setRevokingAll] = useState(false);
  // Same shape as MuteRow's `error` above, for the "Revoke all" action.
  const [revokeAllError, setRevokeAllError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const rows = await getDenyMutes();
      setMutes(rows);
    } catch {
      setMutes([]);
    }
    setNowMs(Date.now());
  }, []);

  useEffect(() => {
    let alive = true;
    const tick = () => { if (alive) void refresh(); };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, [refresh]);

  // Returned (not fired-and-forgotten) so MuteRow's own try/catch can react
  // to a failure instead of it vanishing into an unhandled rejection.
  const revokeOne = (rule: string) => revokeDenyMute(rule).then(() => refresh());

  const revokeAll = async () => {
    if (!confirmingAll) { setConfirmingAll(true); return; }
    setConfirmingAll(false);
    setRevokingAll(true);
    setRevokeAllError(null);
    try {
      await revokeAllDenyMutes();
      await refresh();
      setRevokingAll(false);
    } catch (err) {
      setRevokingAll(false);
      setRevokeAllError(errorMessage(err));
    }
  };

  if (mutes.length === 0) return null;

  return (
    <div className="lg-glass px-4 py-3 flex flex-col" data-testid="muted-rules-panel">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]">
          <Plural value={mutes.length} one="# rule muted" other="# rules muted" />
        </span>
        {mutes.length > 1 && (
          <button
            onClick={revokeAll}
            onBlur={() => setConfirmingAll(false)}
            disabled={revokingAll}
            className={`text-xs px-2 py-1 rounded transition-colors disabled:opacity-60 ${
              confirmingAll ? "bg-red-600 text-white" : "text-[var(--text-tertiary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {revokingAll ? <Trans>Revoking…</Trans> : confirmingAll ? <Trans>Confirm revoke all?</Trans> : <Trans>Revoke all</Trans>}
          </button>
        )}
      </div>
      {revokeAllError && (
        <p role="alert" data-testid="mute-revoke-all-error" className="text-[11px] mb-1.5" style={{ color: "#C8312A" }}>
          <Trans>Could not revoke all: {revokeAllError}</Trans>
        </p>
      )}
      <div className="flex flex-col gap-1.5">
        {mutes.map((m) => (
          <MuteRow key={m.rule} mute={m} nowMs={nowMs} onRevoke={revokeOne} />
        ))}
      </div>
    </div>
  );
}
