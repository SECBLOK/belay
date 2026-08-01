import { useCallback, useEffect, useState } from "react";
import type { EgressMode, EgressRule } from "../../lib/hostTypes";
import {
  getEgressAllowlist,
  addEgressRule,
  removeEgressRule,
  setEgressMode,
  setInlineEgress,
  getNetEnrich,
  setNetEnrich,
} from "../../lib/api";
import AllowlistManager from "../../components/host/AllowlistManager";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// Tauri usually rejects with a plain string (the Rust command's Err
// payload); stay defensive about Error-shaped values too.
function errorMessage(e: unknown): string {
  return String((e as { message?: string } | undefined)?.message ?? e);
}

// ── Mode selector ─────────────────────────────────────────────────────────────

type UiMode = { label: MessageDescriptor; value: EgressMode };
const MODES: UiMode[] = [
  { label: msg`Off`, value: "off" },
  { label: msg`Alert (detect only)`, value: "monitor" },
  { label: msg`Block`, value: "enforce" },
];

function ModeSelector({
  current,
  onChange,
  busy,
  error,
}: {
  current: EgressMode;
  onChange: (m: EgressMode) => void;
  busy: boolean;
  error: string | null;
}) {
  const { t } = useLingui();
  return (
    <div className="space-y-2">
      <p className="text-sm font-semibold text-[#1C1C1E]"><Trans>Egress mode</Trans></p>
      <div className="flex gap-2 flex-wrap">
        {MODES.map(({ label, value }) => (
          <button
            key={value}
            onClick={() => onChange(value)}
            disabled={busy}
            aria-pressed={current === value}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors border disabled:opacity-60 ${
              current === value
                ? "bg-[#1C1C1E] text-white border-[#1C1C1E]"
                : "bg-white text-[#636366] border-black/10 hover:border-black/20"
            }`}
          >
            {t(label)}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" data-testid="egress-mode-error" className="text-xs" style={{ color: "#C8312A" }}>
          <Trans>Could not change egress mode: {error}</Trans>
        </p>
      )}
    </div>
  );
}

// ── Enrich destinations toggle (display-only; unobtrusive, always visible) ────

function EnrichToggle({
  enabled,
  onToggle,
  busy,
  error,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
  busy: boolean;
  error: string | null;
}) {
  const { t } = useLingui();
  return (
    <div>
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-[#1C1C1E]"><Trans>Enrich destinations</Trans></p>
          <p className="text-xs text-[#636366] mt-0.5">
            <Trans>Show owner/ASN/country next to egress hosts. Display-only, and never affects allow/deny.</Trans>
          </p>
        </div>
        <button
          role="switch"
          aria-checked={enabled}
          aria-label={t`Enrich destinations (show owner/ASN/country)`}
          onClick={() => onToggle(!enabled)}
          disabled={busy}
          className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60 ${
            enabled
              ? "bg-[#34C759] border-[#34C759]"
              : "bg-[#E5E5EA] border-[#E5E5EA]"
          }`}
        >
          <span
            className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
              enabled ? "translate-x-5" : "translate-x-0"
            }`}
          />
        </button>
      </div>
      {error && (
        <p role="alert" data-testid="enrich-toggle-error" className="text-xs mt-1" style={{ color: "#C8312A" }}>
          <Trans>Could not save your enrich-destinations setting: {error}</Trans>
        </p>
      )}
    </div>
  );
}

// ── Inline NFQUEUE toggle (Advanced, collapsed by default) ────────────────────

function InlineToggle({
  enabled,
  onToggle,
  busy,
  error,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
  busy: boolean;
  error: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const handleToggle = () => {
    if (!enabled) {
      // Enable path: show confirm dialog
      setConfirming(true);
    } else {
      onToggle(false);
    }
  };

  const handleConfirm = () => {
    setConfirming(false);
    onToggle(true);
  };

  const handleCancel = () => {
    setConfirming(false);
  };

  return (
    <div className="space-y-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 text-sm font-semibold text-[#636366] hover:text-[#1C1C1E] transition-colors"
        aria-expanded={open}
        aria-controls="inline-toggle-region"
      >
        <span className={`transition-transform text-xs ${open ? "rotate-90" : ""}`}>▶</span>
        <Trans>Advanced</Trans>
      </button>

      {open && (
        <div id="inline-toggle-region" className="pl-4 space-y-3">
          {/* Amber warning strip — always visible when section is open */}
          <div className="rounded-lg px-3 py-2 bg-amber-50 border border-amber-200 text-xs text-amber-800">
            <Trans>Can affect networking · fail-open if unattributable</Trans>
          </div>

          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-[#1C1C1E]"><Trans>Inline enforcement (NFQUEUE)</Trans></p>
              <p className="text-xs text-[#636366] mt-0.5">
                <Trans>Installs a kernel hook that intercepts connections before they leave the host.</Trans>
              </p>
            </div>
            <button
              role="switch"
              aria-checked={enabled}
              onClick={handleToggle}
              disabled={busy}
              className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60 ${
                enabled
                  ? "bg-[#34C759] border-[#34C759]"
                  : "bg-[#E5E5EA] border-[#E5E5EA]"
              }`}
            >
              <span
                className={`inline-block h-5 w-5 rounded-full bg-white shadow transition-transform ${
                  enabled ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
          </div>

          {error && (
            <p role="alert" data-testid="inline-toggle-error" className="text-xs" style={{ color: "#C8312A" }}>
              <Trans>Could not change inline enforcement: {error}</Trans>
            </p>
          )}

          {/* Inline confirm dialog */}
          {confirming && (
            <div className="lg-glass p-4 space-y-3">
              <p className="text-sm font-semibold text-[#1C1C1E]"><Trans>Enable inline egress?</Trans></p>
              <p className="text-xs text-[#636366]">
                <Trans>
                  This installs an NFQUEUE hook that can affect system networking. If a connection
                  cannot be attributed to a process, it is allowed through (fail-open).
                </Trans>
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleConfirm}
                  disabled={busy}
                  className="px-4 py-1.5 rounded-lg bg-[#1C1C1E] text-white text-sm font-medium hover:bg-black/80 transition-colors disabled:opacity-60"
                >
                  <Trans>Enable</Trans>
                </button>
                <button
                  onClick={handleCancel}
                  disabled={busy}
                  className="px-4 py-1.5 rounded-lg bg-[#E5E5EA] text-[#636366] text-sm font-medium hover:bg-[#D1D1D6] transition-colors disabled:opacity-60"
                >
                  <Trans>Cancel</Trans>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main EgressControl view ───────────────────────────────────────────────────

export default function EgressControl() {
  const { t } = useLingui();
  const [rules, setRules] = useState<EgressRule[]>([]);
  const [mode, setMode] = useState<EgressMode>("monitor");
  const [inlineEnabled, setInlineEnabled] = useState(false);
  const [enrichEnabled, setEnrichEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // These three used to flip the visible state BEFORE the daemon confirmed
  // the change, then silently swallow a rejection - the control would show
  // the new setting while the daemon never actually changed. Each is now
  // await-first: the daemon's real answer decides what gets rendered, and a
  // failure surfaces instead of being papered over.
  const [modeBusy, setModeBusy] = useState(false);
  const [modeError, setModeError] = useState<string | null>(null);
  const [enrichBusy, setEnrichBusy] = useState(false);
  const [enrichError, setEnrichError] = useState<string | null>(null);
  const [inlineBusy, setInlineBusy] = useState(false);
  const [inlineError, setInlineError] = useState<string | null>(null);

  // Fetch allowlist on mount
  const fetchRules = useCallback(async () => {
    try {
      const data = await getEgressAllowlist();
      setRules(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t`Failed to load egress rules`);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void fetchRules();
    getNetEnrich().then(setEnrichEnabled);
  }, [fetchRules]);

  // setNetEnrich never rejects (it fail-softs internally to {ok:false}), so
  // the failure signal here is `result.ok`, not a thrown exception - the old
  // `catch` was genuinely dead code, meaning this toggle always "succeeded"
  // from the UI's point of view regardless of what the daemon actually did.
  const handleEnrichToggle = async (v: boolean) => {
    if (enrichBusy) return;
    setEnrichBusy(true);
    setEnrichError(null);
    const result = await setNetEnrich(v);
    setEnrichBusy(false);
    if (result.ok) {
      setEnrichEnabled(v);
    } else {
      setEnrichError(result.error || t`Could not reach the daemon.`);
    }
  };

  const handleModeChange = async (m: EgressMode) => {
    if (modeBusy) return;
    setModeBusy(true);
    setModeError(null);
    try {
      await setEgressMode(m);
      setMode(m);
    } catch (err) {
      setModeError(errorMessage(err));
    } finally {
      setModeBusy(false);
    }
  };

  const handleAdd = async (rule: Omit<EgressRule, "id">) => {
    // No local try/catch: the rejection propagates to AllowlistManager's own
    // add-rule form, which is what actually shows the failure and keeps the
    // user's typed values instead of clearing them.
    const added = await addEgressRule(rule);
    setRules((prev) => [...prev, added]);
  };

  const handleRemove = async (id: string) => {
    // No local try/catch: the rejection propagates to AllowlistManager's own
    // row handling, which is what actually shows the failure and keeps the
    // rule on screen instead of the click silently doing nothing.
    await removeEgressRule(id);
    setRules((prev) => prev.filter((r) => r.id !== id));
  };

  const handleInlineToggle = async (v: boolean) => {
    if (inlineBusy) return;
    setInlineBusy(true);
    setInlineError(null);
    try {
      await setInlineEgress(v);
      setInlineEnabled(v);
    } catch (err) {
      setInlineError(errorMessage(err));
    } finally {
      setInlineBusy(false);
    }
  };

  const cardStyle: React.CSSProperties = {
    background: "#F5F5F7",
    border: "1px solid rgba(0,0,0,0.08)",
  };

  if (loading) {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm text-[#636366]"
        style={cardStyle}
      >
        <Trans>Loading egress configuration…</Trans>
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-1"
        style={cardStyle}
      >
        <p className="text-[#1C1C1E] font-medium"><Trans>Unable to load egress configuration</Trans></p>
        <p className="text-[#636366]">{error}</p>
        <button
          onClick={() => { setLoading(true); void fetchRules(); }}
          className="mt-2 text-xs text-blue-600 hover:underline"
        >
          <Trans>Retry</Trans>
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-3xl mx-auto">
      {/* Enrich destinations toggle */}
      <div className="rounded-xl px-5 py-3" style={cardStyle}>
        <EnrichToggle enabled={enrichEnabled} onToggle={handleEnrichToggle} busy={enrichBusy} error={enrichError} />
      </div>

      {/* Mode selector */}
      <div className="rounded-xl px-5 py-5 space-y-4" style={cardStyle}>
        <ModeSelector current={mode} onChange={handleModeChange} busy={modeBusy} error={modeError} />
      </div>

      {/* Allowlist */}
      <div className="rounded-xl px-5 py-5 space-y-3" style={cardStyle}>
        <p className="text-sm font-semibold text-[#1C1C1E]"><Trans>Egress allowlist</Trans></p>
        <AllowlistManager rules={rules} onRemove={handleRemove} onAdd={handleAdd} />
      </div>

      {/* Advanced (inline NFQUEUE) */}
      <div className="rounded-xl px-5 py-5" style={cardStyle}>
        <InlineToggle enabled={inlineEnabled} onToggle={handleInlineToggle} busy={inlineBusy} error={inlineError} />
      </div>
    </div>
  );
}
