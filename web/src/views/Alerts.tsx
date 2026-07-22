// Alerts feed — the observability stream for the alert-only detectors. These
// events (MCP-response injection markers, secret redactions, injection→action
// correlation) are INFORMATIONAL: nothing was blocked. They are styled softly
// and apart from the Live Feed's Deny/Ask decisions — "worth knowing," not
// "acted on." Shares the same audit source (seed + live stream) as the feed.

import { useEffect, useMemo, useRef, useState } from "react";
import { getRecentAudit, getRecentApprovals, openAuditStream } from "../lib/api";
import { classifyAlert, type AlertItem, type AlertKind } from "../lib/alerts";
import MascotEmpty from "../components/MascotEmpty";
import { Trans, useLingui } from "@lingui/react/macro";
import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

const CAP = 500;

function relTime(ts: string, now: number): string {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, (now - t) / 1000);
  if (s < 5) return i18n._(msg`just now`);
  if (s < 60) return i18n._(msg`${Math.floor(s)}s ago`);
  if (s < 3600) return i18n._(msg`${Math.floor(s / 60)}m ago`);
  if (s < 86400) return i18n._(msg`${Math.floor(s / 3600)}h ago`);
  return i18n._(msg`${Math.floor(s / 86400)}d ago`);
}

// label is a descriptor; color/icon are keyed by the AlertKind, never by the
// label, so translating cannot change a chip's colour.
const KIND_META: Record<AlertKind, { label: MessageDescriptor; color: string; icon: string }> = {
  injection:     { label: msg`Injection`,     color: "#916400", icon: "⚑" },
  secret:        { label: msg`Secret`,        color: "#1A6BC5", icon: "🔑" },
  correlation:   { label: msg`Correlation`,   color: "#7A3FBF", icon: "🔗" },
  self_approval: { label: msg`Self-approval`, color: "#C8312A", icon: "🛡" },
  resolution:    { label: msg`Resolution`,    color: "#6C6C71", icon: "✓" },
};

function KindChip({ kind }: { kind: AlertKind }) {
  const { t } = useLingui();
  const m = KIND_META[kind];
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold shrink-0"
      style={{ background: `${m.color}0f`, color: m.color }}
    >
      <span aria-hidden>{m.icon}</span>
      {t(m.label)}
    </span>
  );
}

function AlertCard({ item, now, index = 0 }: { item: AlertItem; now: number; index?: number }) {
  const m = KIND_META[item.kind];
  // Rows use .lg-glass-lite, not .lg-glass: this feed renders up to CAP (500)
  // rows, and a per-row backdrop-filter wrecks scroll performance. Timeline's
  // rows were moved off .lg-glass for the same reason - see the note above
  // .lg-glass-lite in liquid-glass.css. Translucent fill, no per-row blur.
  return (
    <div
      className="flex items-start gap-3 px-4 py-3 lg-glass-lite lg-stagger border-l-4"
      style={{ border: "1px solid rgba(0,0,0,0.08)", borderLeftColor: m.color, borderLeftWidth: 4, ["--lg-i" as string]: Math.min(index, 8) } as React.CSSProperties}
    >
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <KindChip kind={item.kind} />
          <span className="text-sm font-medium text-[#1C1C1E]">{item.title}</span>
        </div>
        {item.detail && (
          <p className="text-xs text-[#636366] font-mono truncate" title={item.detail}>
            {item.detail}
          </p>
        )}
        <div className="flex items-center gap-2 text-[11px] text-[var(--text-tertiary)]">
          {item.session && <span className="font-mono truncate">{item.session}</span>}
          {item.session && <span aria-hidden>·</span>}
          <span>{relTime(item.ts, now)}</span>
        </div>
      </div>
    </div>
  );
}

type Filter = "all" | AlertKind;

export default function Alerts() {
  const { t } = useLingui();
  const [items, setItems] = useState<AlertItem[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [now, setNow] = useState(() => Date.now());
  const esRef = useRef<EventSource | null>(null);
  const seenRef = useRef<Set<string>>(new Set());

  const add = (raws: unknown[]) => {
    const fresh: AlertItem[] = [];
    for (const raw of raws) {
      const a = classifyAlert(raw);
      if (!a || seenRef.current.has(a.id)) continue;
      seenRef.current.add(a.id);
      fresh.push(a);
    }
    if (fresh.length === 0) return;
    // Newest-first: sort the combined set by timestamp so seed + live interleave
    // correctly regardless of arrival order.
    setItems((prev) =>
      [...fresh, ...prev].sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)).slice(0, CAP),
    );
  };

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    let cancelled = false;
    // Seed from recent history: the gate audit log (mcp/* + correlation) plus
    // the separate approvals store (self-approval-blocked + channel resolution).
    getRecentAudit(CAP).then((rows) => {
      if (!cancelled) add(rows);
    });
    getRecentApprovals(CAP).then((rows) => {
      if (!cancelled) add(rows);
    });
    // The live audit-event stream carries gate/mcp rows; approval-provenance
    // rows are not streamed, so they refresh on view open (seed only).
    esRef.current = openAuditStream({
      onOpen: () => {},
      onError: () => {},
      onRow: (row: unknown) => add([row]),
    });
    return () => {
      cancelled = true;
      esRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const counts = useMemo(() => {
    const c: Record<AlertKind, number> = { injection: 0, secret: 0, correlation: 0, self_approval: 0, resolution: 0 };
    for (const it of items) c[it.kind]++;
    return c;
  }, [items]);

  const shown = filter === "all" ? items : items.filter((it) => it.kind === filter);

  const FILTERS: { key: Filter; label: string; count: number }[] = [
    { key: "all", label: t`All`, count: items.length },
    { key: "injection", label: t(KIND_META.injection.label), count: counts.injection },
    { key: "secret", label: t(KIND_META.secret.label), count: counts.secret },
    { key: "correlation", label: t(KIND_META.correlation.label), count: counts.correlation },
    { key: "self_approval", label: t(KIND_META.self_approval.label), count: counts.self_approval },
    { key: "resolution", label: t(KIND_META.resolution.label), count: counts.resolution },
  ];

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div className="mb-1">
        <h1 className="text-sm font-semibold text-[var(--text-tertiary)] uppercase tracking-widest"><Trans>Alerts</Trans></h1>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          <Trans>
            Security events recorded for awareness — injection markers, secret redactions,
            risky-action correlations, and how approvals resolved.
          </Trans>
        </p>
      </div>

      {/* Filter chips */}
      <div className="flex gap-2 flex-wrap">
        {FILTERS.map((f) => {
          const active = filter === f.key;
          return (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className="px-3 py-1 rounded-lg text-xs font-medium transition-colors"
              style={{
                background: active ? "white" : "rgba(0,0,0,0.05)",
                color: active ? "var(--accent, #6B3DE8)" : "#636366",
                border: active ? "1px solid rgba(0,0,0,0.08)" : "1px solid transparent",
                boxShadow: active ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
              }}
              aria-pressed={active}
            >
              {f.label}{" "}
              <span className="font-mono tabular-nums text-[var(--text-tertiary)]">{f.count}</span>
            </button>
          );
        })}
      </div>

      {/* Feed */}
      {shown.length === 0 ? (
        <div className="lg-glass">
          {items.length === 0
            ? <MascotEmpty pose="nap" title={t`Nothing to report`}><Trans>No alerts recorded yet — the pup's keeping an eye out.</Trans></MascotEmpty>
            : <div className="px-5 py-8 text-center text-sm text-[#636366]"><Trans>No alerts match this filter.</Trans></div>}
        </div>
      ) : (
        <div className="space-y-2">
          {shown.map((item, i) => (
            <AlertCard key={item.id} item={item} now={now} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}
