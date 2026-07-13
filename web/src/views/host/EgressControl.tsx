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

// ── Mode selector ─────────────────────────────────────────────────────────────

type UiMode = { label: string; value: EgressMode };
const MODES: UiMode[] = [
  { label: "Off", value: "off" },
  { label: "Alert (detect only)", value: "monitor" },
  { label: "Block", value: "enforce" },
];

function ModeSelector({
  current,
  onChange,
}: {
  current: EgressMode;
  onChange: (m: EgressMode) => void;
}) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-semibold text-[#1C1C1E]">Egress mode</p>
      <div className="flex gap-2 flex-wrap">
        {MODES.map(({ label, value }) => (
          <button
            key={value}
            onClick={() => onChange(value)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors border ${
              current === value
                ? "bg-[#1C1C1E] text-white border-[#1C1C1E]"
                : "bg-white text-[#636366] border-black/10 hover:border-black/20"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Enrich destinations toggle (display-only; unobtrusive, always visible) ────

function EnrichToggle({
  enabled,
  onToggle,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <p className="text-sm font-medium text-[#1C1C1E]">Enrich destinations</p>
        <p className="text-xs text-[#636366] mt-0.5">
          Show owner/ASN/country next to egress hosts. Display-only — never affects allow/deny.
        </p>
      </div>
      <button
        role="switch"
        aria-checked={enabled}
        aria-label="Enrich destinations (show owner/ASN/country)"
        onClick={() => onToggle(!enabled)}
        className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
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
  );
}

// ── Inline NFQUEUE toggle (Advanced, collapsed by default) ────────────────────

function InlineToggle({
  enabled,
  onToggle,
}: {
  enabled: boolean;
  onToggle: (v: boolean) => void;
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
        Advanced
      </button>

      {open && (
        <div id="inline-toggle-region" className="pl-4 space-y-3">
          {/* Amber warning strip — always visible when section is open */}
          <div className="rounded-lg px-3 py-2 bg-amber-50 border border-amber-200 text-xs text-amber-800">
            Can affect networking · fail-open if unattributable
          </div>

          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-[#1C1C1E]">Inline enforcement (NFQUEUE)</p>
              <p className="text-xs text-[#636366] mt-0.5">
                Installs a kernel hook that intercepts connections before they leave the host.
              </p>
            </div>
            <button
              role="switch"
              aria-checked={enabled}
              onClick={handleToggle}
              className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
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

          {/* Inline confirm dialog */}
          {confirming && (
            <div className="rounded-xl border border-black/10 bg-white p-4 space-y-3 shadow-sm">
              <p className="text-sm font-semibold text-[#1C1C1E]">Enable inline egress?</p>
              <p className="text-xs text-[#636366]">
                This installs an NFQUEUE hook that can affect system networking. If a connection
                cannot be attributed to a process, it is allowed through (fail-open).
              </p>
              <div className="flex gap-2">
                <button
                  onClick={handleConfirm}
                  className="px-4 py-1.5 rounded-lg bg-[#1C1C1E] text-white text-sm font-medium hover:bg-black/80 transition-colors"
                >
                  Enable
                </button>
                <button
                  onClick={handleCancel}
                  className="px-4 py-1.5 rounded-lg bg-[#E5E5EA] text-[#636366] text-sm font-medium hover:bg-[#D1D1D6] transition-colors"
                >
                  Cancel
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
  const [rules, setRules] = useState<EgressRule[]>([]);
  const [mode, setMode] = useState<EgressMode>("monitor");
  const [inlineEnabled, setInlineEnabled] = useState(false);
  const [enrichEnabled, setEnrichEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch allowlist on mount
  const fetchRules = useCallback(async () => {
    try {
      const data = await getEgressAllowlist();
      setRules(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load egress rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchRules();
    getNetEnrich().then(setEnrichEnabled);
  }, [fetchRules]);

  const handleEnrichToggle = async (v: boolean) => {
    setEnrichEnabled(v);
    try {
      await setNetEnrich(v);
    } catch {
      // desktop-only / daemon unreachable — silently ignore, matches the
      // other toggles' fail-soft handling in this view.
    }
  };

  const handleModeChange = async (m: EgressMode) => {
    setMode(m);
    try {
      await setEgressMode(m);
    } catch {
      // desktop-only — silently ignore in browser dashboard
    }
  };

  const handleAdd = async (rule: Omit<EgressRule, "id">) => {
    try {
      const added = await addEgressRule(rule);
      setRules((prev) => [...prev, added]);
    } catch {
      // desktop-only
    }
  };

  const handleRemove = async (id: string) => {
    try {
      await removeEgressRule(id);
      setRules((prev) => prev.filter((r) => r.id !== id));
    } catch {
      // desktop-only
    }
  };

  const handleInlineToggle = async (v: boolean) => {
    setInlineEnabled(v);
    try {
      await setInlineEgress(v);
    } catch {
      // desktop-only
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
        Loading egress configuration…
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-1"
        style={cardStyle}
      >
        <p className="text-[#1C1C1E] font-medium">Unable to load egress configuration</p>
        <p className="text-[#636366]">{error}</p>
        <button
          onClick={() => { setLoading(true); void fetchRules(); }}
          className="mt-2 text-xs text-blue-600 hover:underline"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-3xl mx-auto">
      {/* Enrich destinations toggle */}
      <div className="rounded-xl px-5 py-3" style={cardStyle}>
        <EnrichToggle enabled={enrichEnabled} onToggle={handleEnrichToggle} />
      </div>

      {/* Mode selector */}
      <div className="rounded-xl px-5 py-5 space-y-4" style={cardStyle}>
        <ModeSelector current={mode} onChange={handleModeChange} />
      </div>

      {/* Allowlist */}
      <div className="rounded-xl px-5 py-5 space-y-3" style={cardStyle}>
        <p className="text-sm font-semibold text-[#1C1C1E]">Egress allowlist</p>
        <AllowlistManager rules={rules} onRemove={handleRemove} onAdd={handleAdd} />
      </div>

      {/* Advanced (inline NFQUEUE) */}
      <div className="rounded-xl px-5 py-5" style={cardStyle}>
        <InlineToggle enabled={inlineEnabled} onToggle={handleInlineToggle} />
      </div>
    </div>
  );
}
