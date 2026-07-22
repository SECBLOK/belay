// Host → SSH sub-view: hardening posture + SSH guard config + ban list.

import { useEffect, useState } from "react";
import {
  getHardeningPosture,
  getSshGuard,
  setSshGuard,
  listBans,
  unban,
} from "../../lib/api";
import type { HardeningPosture, SshGuardConfig, Ban } from "../../lib/hostTypes";
import FindingFixRow from "../../components/host/FindingFixRow";
import BanList from "../../components/host/BanList";
import { Trans } from "@lingui/react/macro";

// ── SSH Guard config panel ────────────────────────────────────────────────────

interface SshGuardPanelProps {
  config: SshGuardConfig;
  onSave: (c: Partial<SshGuardConfig>) => Promise<void>;
}

function SshGuardPanel({ config, onSave }: SshGuardPanelProps) {
  const [enabled, setEnabled] = useState(config.enabled);
  const [banThreshold, setBanThreshold] = useState(String(config.ban_threshold));
  const [banDuration, setBanDuration] = useState(String(config.ban_duration_secs));
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const isDirty =
    enabled !== config.enabled ||
    banThreshold !== String(config.ban_threshold) ||
    banDuration !== String(config.ban_duration_secs);

  const handleSave = async () => {
    setSaving(true);
    setSaved(false);
    try {
      await onSave({
        enabled,
        ban_threshold: parseInt(banThreshold, 10) || config.ban_threshold,
        ban_duration_secs: parseInt(banDuration, 10) || config.ban_duration_secs,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="lg-glass p-5 space-y-4" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"><Trans>SSH guard</Trans></h3>

      {/* Enabled toggle */}
      <div className="flex items-center gap-3">
        <button
          role="switch"
          aria-checked={enabled}
          onClick={() => setEnabled((v) => !v)}
          className="w-10 h-6 rounded-full relative transition-colors"
          style={{ background: enabled ? "#187D34" : "#D1D1D6" }}
        >
          <span
            className="absolute top-1 w-4 h-4 rounded-full bg-white transition-transform"
            style={{ left: enabled ? "22px" : "2px" }}
            aria-hidden
          />
        </button>
        <span className="text-sm text-[#1C1C1E]">
          {enabled ? <Trans>Guard enabled</Trans> : <Trans>Guard disabled</Trans>}
        </span>
      </div>

      {enabled && (
        <div className="grid grid-cols-2 gap-4">
          <label className="space-y-1">
            <span className="text-xs text-[var(--text-tertiary)]"><Trans>Ban after N failures</Trans></span>
            <input
              type="number"
              min={1}
              max={20}
              value={banThreshold}
              onChange={(e) => setBanThreshold(e.target.value)}
              className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
              style={{ border: "1px solid rgba(0,0,0,0.14)" }}
            />
          </label>
          <label className="space-y-1">
            <span className="text-xs text-[var(--text-tertiary)]"><Trans>Ban duration (seconds)</Trans></span>
            <input
              type="number"
              min={60}
              value={banDuration}
              onChange={(e) => setBanDuration(e.target.value)}
              className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
              style={{ border: "1px solid rgba(0,0,0,0.14)" }}
            />
          </label>
        </div>
      )}

      {isDirty && (
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-1.5 rounded-lg text-sm font-semibold disabled:opacity-40"
          style={{ background: "#0A66D6", color: "#fff" }}
        >
          {saving ? <Trans>Saving…</Trans> : <Trans>Save</Trans>}
        </button>
      )}
      {saved && (
        <p className="text-xs" style={{ color: "#187D34" }}>
          <Trans>Settings saved.</Trans>
        </p>
      )}
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; posture: HardeningPosture; guard: SshGuardConfig; bans: Ban[] }
  | { kind: "error"; message: string };

export default function SshHardening() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  const load = async () => {
    setState({ kind: "loading" });
    try {
      const [posture, guard, bans] = await Promise.all([
        getHardeningPosture(),
        getSshGuard(),
        listBans(),
      ]);
      setState({ kind: "ready", posture, guard, bans });
    } catch (err: unknown) {
      setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  };

  useEffect(() => { load(); }, []);

  const handleSaveSshGuard = async (cfg: Partial<SshGuardConfig>) => {
    await setSshGuard(cfg);
    if (state.kind === "ready") {
      setState((s) =>
        s.kind === "ready"
          ? { ...s, guard: { ...s.guard, ...cfg } }
          : s
      );
    }
  };

  const handleUnban = async (id: string) => {
    await unban(id);
    if (state.kind === "ready") {
      setState((s) =>
        s.kind === "ready"
          ? { ...s, bans: s.bans.filter((b) => b.id !== id) }
          : s
      );
    }
  };

  if (state.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading SSH guard…</Trans>
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium"><Trans>Something went wrong</Trans></p>
        <p className="font-mono text-xs text-[var(--text-tertiary)]">{state.message}</p>
        <button
          onClick={load}
          className="text-xs hover:underline mt-1"
          style={{ color: "#0856B3" }}
        >
          <Trans>Try again</Trans>
        </button>
      </div>
    );
  }

  const { posture, guard, bans } = state;
  const failChecks = posture.checks.filter((c) => c.status === "fail" || c.status === "warn");
  const passCount = posture.checks.filter((c) => c.status === "pass").length;

  return (
    <div className="space-y-4">
      {/* Score header */}
      <div className="flex items-center gap-3">
        <div
          className="text-3xl font-mono tabular-nums font-bold"
          style={{ color: posture.score >= 70 ? "#187D34" : posture.score >= 40 ? "#916400" : "#C8312A" }}
        >
          {posture.score}
        </div>
        <div className="text-xs text-[var(--text-tertiary)]">
          <div><Trans>Hardening score</Trans></div>
          <div><Trans>{passCount} of {posture.checks.length} checks pass</Trans></div>
        </div>
      </div>

      {/* SSH guard config */}
      <SshGuardPanel config={guard} onSave={handleSaveSshGuard} />

      {/* Hardening findings */}
      {failChecks.length > 0 && (
        <div className="lg-glass overflow-hidden">
          <div
            className="px-4 py-2.5 border-b text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"
            style={{ borderColor: "rgba(0,0,0,0.08)" }}
          >
            <Trans>Issues to fix</Trans>{" "}
            <span className="font-mono tabular-nums text-[#636366] normal-case tracking-normal">
              {failChecks.length}
            </span>
          </div>
          {failChecks.map((check) => (
            <FindingFixRow key={check.id} check={check} />
          ))}
        </div>
      )}

      {failChecks.length === 0 && (
        <div
          className="rounded-xl px-5 py-6 text-sm text-[#636366]"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
        >
          <Trans>All hardening checks pass.</Trans>
        </div>
      )}

      {/* Ban list */}
      <div>
        <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] mb-2">
          <Trans>Active bans</Trans>
        </h3>
        <BanList bans={bans} onUnban={handleUnban} />
      </div>
    </div>
  );
}
