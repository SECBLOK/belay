// BanList — shows banned IPs/users with expires-in and Unban inline-confirm.

import { useState } from "react";
import type { Ban } from "../../lib/hostTypes";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

function expiresIn(t: (descriptor: MessageDescriptor) => string, expiresAt: string | null): string {
  if (!expiresAt) return t(msg`Permanent`);
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return t(msg`Expired`);
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

interface BanRowProps {
  ban: Ban;
  onUnban: (id: string) => Promise<void>;
}

function BanRow({ ban, onUnban }: BanRowProps) {
  const { t } = useLingui();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const doUnban = async () => {
    setBusy(true);
    setConfirming(false);
    try {
      await onUnban(ban.id);
    } finally {
      setBusy(false);
    }
  };

  const kindLabel = ban.kind === "ip" ? t`IP` : t`User`;

  return (
    <div
      className="py-3 px-4 border-b last:border-0 space-y-1.5"
      style={{ borderColor: "rgba(0,0,0,0.08)" }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
          style={{ background: "rgba(200,49,42,0.06)", color: "#C8312A" }}
          aria-label={t`Ban type: ${kindLabel}`}
        >
          {kindLabel}
        </span>
        <span className="text-sm font-mono text-[#1C1C1E] font-medium">{ban.target}</span>
        <span className="text-xs text-[var(--text-tertiary)]">
          <Trans>expires in <span className="font-mono">{expiresIn(t, ban.expires_at)}</span></Trans>
        </span>
      </div>

      <p className="text-xs text-[var(--text-tertiary)]">{ban.reason}</p>

      <div className="flex items-center gap-2 flex-wrap pt-0.5">
        {confirming ? (
          <>
            <span className="text-xs text-[#636366]"><Trans>Unban this IP/user?</Trans></span>
            <button
              onClick={doUnban}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-semibold disabled:opacity-40"
              style={{ background: "rgba(10,102,214,0.10)", color: "#0A66D6" }}
            >
              <Trans>Yes, unban</Trans>
            </button>
            <button
              onClick={() => setConfirming(false)}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-medium disabled:opacity-40"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              <Trans>Cancel</Trans>
            </button>
          </>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            disabled={busy}
            className="px-3 py-1 rounded text-[12px] font-medium disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
          >
            <Trans>Unban</Trans>
          </button>
        )}
      </div>
    </div>
  );
}

interface BanListProps {
  bans: Ban[];
  onUnban: (id: string) => Promise<void>;
}

export default function BanList({ bans, onUnban }: BanListProps) {
  if (bans.length === 0) {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>No active bans.</Trans>
      </div>
    );
  }

  return (
    <div className="lg-glass overflow-hidden">
      <div
        className="px-4 py-2.5 border-b text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"
        style={{ borderColor: "rgba(0,0,0,0.08)" }}
      >
        <Trans>Active bans</Trans>{" "}
        <span className="font-mono tabular-nums text-[#636366] normal-case tracking-normal">
          {bans.length}
        </span>
      </div>
      {bans.map((ban) => (
        <BanRow key={ban.id} ban={ban} onUnban={onUnban} />
      ))}
    </div>
  );
}
