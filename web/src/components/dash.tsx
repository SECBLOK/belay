import { useEffect, type ReactNode } from "react";
import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// Tab views mount into an already-laid-out page, where Recharts'
// ResponsiveContainer can measure 0 on its first ResizeObserver pass and render
// blank until the next window resize. Nudging a resize event right after mount
// forces every container to re-measure. Call once near the top of a chart view.
export function useChartReflow() {
  useEffect(() => {
    const t = setTimeout(() => window.dispatchEvent(new Event("resize")), 60);
    return () => clearTimeout(t);
  }, []);
}

// Shared dashboard tokens + primitives used by the Posture and Fleet views.
// Semantic color == meaning: green allow / amber ask / red deny, LIGHT theme.
export const C = {
  allow: "#187D34", ask: "#916400", deny: "#C8312A",
  muted: "#6C6C71", grid: "#E5E5EA",
  tipBg: "#1C1C1E",   // tooltip stays DARK (intentional inversion)
  tipTx: "#F5F5F7",
  // Muted text for that dark tooltip only. `muted` is tuned for LIGHT surfaces
  // (4.60:1 there) and would fall to 3.26:1 on tipBg; this lighter grey gives
  // 5.22:1. Mirrors --text-tertiary-on-dark in tokens.css.
  tipMuted: "#8E8E93",
  online: "#187D34", offline: "#6C6C71",
};

export const tip = {
  contentStyle: { background: C.tipBg, border: "1px solid rgba(255,255,255,0.10)", borderRadius: 6, color: C.tipTx, fontSize: 12 },
  itemStyle: { color: C.tipTx }, labelStyle: { color: C.tipMuted },
};

export const Card = ({ title, hint, span, children }: { title: string; hint?: string; span: string; children: ReactNode }) => (
  <section className={`${span} lg-glass p-4 flex flex-col`}>
    <div className="flex items-baseline justify-between mb-3">
      <h2 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]">{title}</h2>
      {hint && <span className="text-[11px] text-[var(--text-tertiary)]">{hint}</span>}
    </div>
    {children}
  </section>
);

export function StatTile({ label, value, accent, dominant }: { label: string; value: number; accent: string; dominant?: boolean }) {
  const displayColor = accent === "var(--text-primary)" ? "var(--text-primary)" : accent;
  return (
    <div className="lg-glass px-4 py-3">
      <div className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]">{label}</div>
      <div className={`font-mono tabular-nums leading-tight ${dominant ? "text-4xl" : "text-3xl"}`} style={{ color: displayColor }}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

export const Empty = ({ children }: { children: ReactNode }) => (
  <div className="flex-1 min-h-[150px] flex items-center justify-center text-xs text-[var(--text-tertiary)]">{children}</div>
);

// verdict → semantic color, and category → severity-tier mapping (shared by
// the Findings and Timeline event views).
// `detected` = a canary/honeytoken trip: something READ a decoy secret. It is
// NOT a block (Belay only saw it, post-hoc), so it gets its own violet accent —
// deliberately not the red `deny` — and is never styled as "Blocked" or counted
// as a deny. Honesty bar: never imply a detection-only signal prevented anything.
export const C_DETECTED = "#7A3FBF";
export const VERDICT_C: Record<string, string> = {
  deny: C.deny, ask: C.ask, allow: C.allow, detected: C_DETECTED,
};
const SEV_RANK: Record<string, number> = { Critical: 3, High: 2, Medium: 1, Info: 0 };
const CAT_SEV: Record<string, { label: string; color: string }> = {
  rce: { label: "Critical", color: C.deny }, destructive: { label: "Critical", color: C.deny },
  honeypot: { label: "Critical", color: C_DETECTED },
  persistence: { label: "High", color: "#AB550F" }, persist: { label: "High", color: "#AB550F" },
  secrets: { label: "High", color: "#AB550F" },
  egress: { label: "Medium", color: C.ask }, tamper: { label: "Medium", color: C.ask },
  recon: { label: "Info", color: "#1A6BC5" },
};
export const categoryOf = (rules?: string[]) => rules?.[0]?.split(".")[0] ?? "";
// Worst-severity tier across a finding's rules; falls back to verdict (deny→Medium).
export function severityOf(verdict: string, rules: string[] = []): { label: string; color: string } | null {
  let best: { label: string; color: string } | null = null;
  for (const r of rules) {
    const s = CAT_SEV[r.split(".")[0]];
    if (s && (!best || SEV_RANK[s.label] > SEV_RANK[best.label])) best = s;
  }
  if (!best) return verdict === "deny" ? { label: "Medium", color: C.ask } : null;
  if (best.label === "Info" && verdict === "deny") return CAT_SEV.egress;
  return best;
}

// The severity tier's DISPLAY label, keyed by the stable English rank name
// that `severityOf` returns. severityOf keeps returning the English string
// because it is also the key into SEV_RANK; translating that would break the
// ranking. Callers render `t(SEV_LABEL[sev.label])`.
export const SEV_LABEL: Record<string, MessageDescriptor> = {
  Critical: msg`Critical`,
  High: msg`High`,
  Medium: msg`Medium`,
  Info: msg`Info`,
};

// relative "time ago" from an ISO-8601 timestamp; em-dash for missing/invalid.
// A plain function with no hook access, so it reaches the active locale through
// the global `i18n` instance directly. The `{n}` unit strings are catalogued.
export function ago(iso: string) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = (Date.now() - t) / 1000;
  if (s < 60) return i18n._(msg`${Math.floor(s)}s ago`);
  if (s < 3600) return i18n._(msg`${Math.floor(s / 60)}m ago`);
  if (s < 86400) return i18n._(msg`${Math.floor(s / 3600)}h ago`);
  return i18n._(msg`${Math.floor(s / 86400)}d ago`);
}
