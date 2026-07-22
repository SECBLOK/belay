import { useEffect, useMemo, useRef, useState } from "react";
import { AreaChart, Area } from "recharts";
import { openAuditStream, getRecentAudit } from "../lib/api";
import { isAlertEvent } from "../lib/alerts";
import { C, VERDICT_C, severityOf, categoryOf, SEV_LABEL } from "../components/dash";
import { humanizeRule, verdictWord, describeAction } from "../lib/humanize";
import { Plural, Trans, useLingui } from "@lingui/react/macro";
import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

interface TLEvent {
  id: number; ts: string; tool: string; verdict: string;
  reason: string; rules: string[]; session: string; device?: string;
  input?: Record<string, unknown>;
}
type Status = "live" | "paused" | "reconnecting";
const CAP = 500;

// Module-scope helpers (no hook access) reach the active locale through the
// global `i18n` instance. The unit strings are catalogued via msg.
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
function groupLabel(ts: string, now: number): string {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return i18n._(msg`earlier`);
  const s = (now - t) / 1000;
  if (s < 60) return i18n._(msg`just now`);
  if (s < 900) return i18n._(msg`${Math.max(1, Math.round(s / 60))} min ago`);
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
const absTime = (ts: string) => {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
};

function VerdictBadge({ v }: { v: string }) {
  const col = VERDICT_C[v] ?? C.muted;
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide shrink-0"
      style={v === "allow"
        ? { background: `${col}0f`, color: col, border: `1px solid ${col}55` }
        : { background: col, color: "#1C1C1E" }}>
      {verdictWord(v)}
    </span>
  );
}

function EventNode({ e, now }: { e: TLEvent; now: number }) {
  const { t } = useLingui();
  const col = VERDICT_C[e.verdict] ?? C.muted;
  const sev = severityOf(e.verdict, e.rules);
  const cat = categoryOf(e.rules);
  const isDeny = e.verdict === "deny";
  return (
    <div className="tl-enter relative pl-7 py-1">
      {/* node dot on the rail */}
      <span className="absolute left-[6px] top-3 w-2.5 h-2.5 rounded-full"
        style={{ background: col, border: "2px solid #F5F5F7", boxShadow: isDeny ? `0 0 0 3px ${col}40` : undefined }} />
      <div className="rounded-lg border px-3 py-2 transition-colors lg-glass-lite"
        style={{
          borderColor: isDeny ? `${C.deny}55` : "rgba(0,0,0,0.08)",
          boxShadow: isDeny ? `inset 3px 0 0 ${C.deny}` : "var(--shadow-card)",
        }}>
        <div className="flex items-center gap-2 flex-wrap">
          <VerdictBadge v={e.verdict} />
          {sev && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
              style={{ background: `${sev.color}0f`, color: sev.color }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: sev.color }} />{SEV_LABEL[sev.label] ? t(SEV_LABEL[sev.label]) : sev.label}
            </span>
          )}
          <span className="font-mono text-[13px] text-[#1C1C1E]">{e.tool || "—"}</span>
          {cat && <span className="text-[11px] px-1.5 py-0.5 rounded text-[#636366]" style={{ border: "1px solid rgba(0,0,0,0.08)" }} title={cat}>{humanizeRule(cat)}</span>}
          <span className="ml-auto font-mono text-[11px] text-[var(--text-tertiary)] whitespace-nowrap" title={e.ts}>
            {relTime(e.ts, now)} · {absTime(e.ts)}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap mt-1.5">
          {e.rules.map((r) => (
            <span key={r} className="text-[11px] px-1.5 py-0.5 rounded text-[#1C1C1E]" style={{ background: "rgba(0,0,0,0.06)" }} title={r}>{humanizeRule(r)}</span>
          ))}
          <span className="text-[12px] text-[#636366] truncate" title={describeAction(e)}>{describeAction(e)}</span>
          {e.session && <span className="ml-auto font-mono text-[10px] text-[var(--text-tertiary)]">sess·{e.session.slice(-6)}</span>}
          {e.device && <span className="font-mono text-[10px] text-[var(--text-tertiary)]">{e.device}</span>}
        </div>
      </div>
    </div>
  );
}

export default function Timeline() {
  const { t } = useLingui();
  const [events, setEvents] = useState<TLEvent[]>([]);
  const [pending, setPending] = useState<TLEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [denies, setDenies] = useState(0);
  const [status, setStatus] = useState<Status>("reconnecting");
  const [pinned, setPinned] = useState(true);
  const [now, setNow] = useState(() => Date.now());

  const esRef = useRef<EventSource | null>(null);
  const pinnedRef = useRef(true);
  const seqRef = useRef(0);
  const arrivalsRef = useRef<number[]>([]);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  // De-dupe rows across the on-open snapshot and the live stream: the tail loop
  // re-emits its historical backlog, which overlaps the snapshot. Keyed by the
  // hash-chain hash when present, else a content composite.
  const seenRef = useRef<Set<string>>(new Set());

  const rowKey = (row: any): string =>
    row.hash ?? `${row.ts ?? ""}|${row.tool ?? ""}|${row.session ?? ""}|${row.verdict ?? ""}|${row.reason ?? ""}`;

  const toEvent = (row: any): TLEvent => ({
    id: seqRef.current++, ts: row.ts ?? "", tool: row.tool ?? "",
    verdict: row.verdict ?? "", reason: row.reason ?? "",
    rules: row.rules ?? [], session: row.session ?? "", device: row.device,
    input: row.input ?? {},
  });

  // keep relative times fresh
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(t);
  }, []);

  const connect = () => {
    esRef.current?.close();
    esRef.current = openAuditStream({
      onOpen: () => setStatus("live"),
      onError: () => setStatus("reconnecting"),
      onRow: (row: any) => {
        // Alert-only observability rows (no gate verdict) belong on the Alerts
        // feed, not this decision-oriented one.
        if (isAlertEvent(row)) return;
        const key = rowKey(row);
        if (seenRef.current.has(key)) return; // already shown via snapshot/backlog
        seenRef.current.add(key);
        const e = toEvent(row);
        arrivalsRef.current.push(Date.now());
        if (arrivalsRef.current.length > CAP) arrivalsRef.current.shift();
        setTotal((n) => n + 1);
        if (e.verdict === "deny") setDenies((n) => n + 1);
        if (pinnedRef.current) setEvents((prev) => [e, ...prev].slice(0, CAP));
        else setPending((prev) => [e, ...prev].slice(0, CAP));
      },
    });
  };

  useEffect(() => {
    connect();
    return () => esRef.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // On open, seed the feed with the most recent audit rows so it isn't blank
  // until the next event lands. The snapshot is newest-first; live events are
  // newer and already prepended, so history appends after them. rowKey de-dupes
  // against anything the live backlog already delivered.
  useEffect(() => {
    let cancelled = false;
    getRecentAudit(CAP).then((rows) => {
      if (cancelled || rows.length === 0) return;
      const fresh = rows.filter((r) => !isAlertEvent(r) && !seenRef.current.has(rowKey(r)));
      if (fresh.length === 0) return;
      fresh.forEach((r) => seenRef.current.add(rowKey(r)));
      const evs = fresh.map(toEvent);
      setEvents((prev) => [...prev, ...evs].slice(0, CAP));
      setTotal((n) => n + fresh.length);
      setDenies((n) => n + fresh.filter((r) => (r.verdict ?? "") === "deny").length);
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const atTop = el.scrollTop <= 8;
    pinnedRef.current = atTop;
    setPinned(atTop);
  };

  const flushPending = () => {
    setEvents((prev) => [...pending, ...prev].slice(0, CAP));
    setPending([]);
    pinnedRef.current = true; setPinned(true);
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };

  const togglePause = () => {
    if (status === "paused") { connect(); }
    else { esRef.current?.close(); esRef.current = null; setPending([]); setStatus("paused"); }
  };

  const clearAll = () => { setEvents([]); setPending([]); setTotal(0); setDenies(0); arrivalsRef.current = []; };

  const spark = useMemo(() => {
    const N = 30, W = 15000;
    const b = new Array(N).fill(0);
    for (const t of arrivalsRef.current) {
      const idx = Math.floor((now - t) / W);
      if (idx >= 0 && idx < N) b[N - 1 - idx]++;
    }
    return b.map((c, i) => ({ i, c }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [total, now]);

  const statusMeta: Record<Status, { color: string; label: MessageDescriptor; ping: boolean }> = {
    live: { color: C.allow, label: msg`LIVE`, ping: true },
    paused: { color: C.ask, label: msg`PAUSED`, ping: false },
    reconnecting: { color: C.deny, label: msg`RECONNECTING…`, ping: false },
  };
  const sm = statusMeta[status];

  // group headers computed at render
  let lastLabel = "";

  return (
    <div className="flex flex-col h-full">
      {/* live header — sticky, light frosted glass */}
      <div className="sticky top-0 z-10 flex items-center gap-5 px-6 py-3 backdrop-blur-xl"
        style={{ background: "rgba(245,245,247,0.88)", borderBottom: "1px solid rgba(0,0,0,0.08)" }}>
        <span className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            {sm.ping && <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-60" style={{ background: sm.color }} />}
            <span className="relative inline-flex rounded-full h-2.5 w-2.5" style={{ background: sm.color }} />
          </span>
          <span className="text-xs font-semibold tracking-widest" style={{ color: sm.color }}>{t(sm.label)}</span>
        </span>
        <span className="text-xs text-[var(--text-tertiary)]"><Trans>Events</Trans> <span className="font-mono tabular-nums text-[#1C1C1E]">{total}</span></span>
        <span className="text-xs text-[var(--text-tertiary)]"><Trans>Denies</Trans> <span className="font-mono tabular-nums" style={{ color: denies > 0 ? C.deny : C.muted }}>{denies}</span></span>
        <div className="w-[96px] h-[28px]">
          <AreaChart width={96} height={28} data={spark} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
            <Area type="monotone" dataKey="c" stroke="#1A6BC5" fill="rgba(26,107,197,0.15)" strokeWidth={1} isAnimationActive={false} dot={false} />
          </AreaChart>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <button onClick={togglePause}
            className="text-xs px-3 py-1 rounded-md text-[#1C1C1E] hover:text-[#1C1C1E] transition-colors"
            style={{ border: "1px solid rgba(0,0,0,0.14)" }}>
            {status === "paused" ? t`▶ Resume` : t`⏸ Pause`}
          </button>
          {total > 0 && (
            <button onClick={clearAll} className="text-xs text-[var(--text-tertiary)] hover:text-[#1C1C1E]"><Trans>clear</Trans></button>
          )}
        </div>
      </div>

      {/* stream */}
      <div ref={scrollRef} onScroll={onScroll} className="relative flex-1 overflow-y-auto px-6 py-4">
        {!pinned && pending.length > 0 && (
          <button onClick={flushPending}
            className="sticky top-2 z-20 mx-auto flex items-center gap-2 px-3 py-1.5 rounded-full text-xs shadow-md bg-white"
            style={{ border: "1px solid rgba(0,0,0,0.14)", color: pending.some((p) => p.verdict === "deny") ? C.deny : "#1A6BC5" }}>
            ↑ <Plural value={pending.length} one="# new event — jump to top" other="# new events — jump to top" />
          </button>
        )}

        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-center gap-2 py-20">
            <img src="/mascot/alert.png" alt="" width={104} height={104} className="mascot-img"
              style={{ display: "block", filter: "drop-shadow(0 6px 10px rgba(17,24,39,0.14))" }} />
            <p className="text-[#1C1C1E] font-medium mt-1"><Trans>On watch…</Trans></p>
            <p className="text-[#636366] text-sm max-w-xs">
              <Trans>Your AI agents' actions will appear here in real time.</Trans>
            </p>
          </div>
        ) : (
          <div className="relative">
            {/* connector rail */}
            <div className="absolute left-[10px] top-0 bottom-0 w-px" style={{ background: "#E5E5EA" }} />
            {events.map((e) => {
              const label = groupLabel(e.ts, now);
              const showHeader = label !== lastLabel;
              lastLabel = label;
              return (
                <div key={e.id}>
                  {showHeader && (
                    <div className="flex items-center gap-3 py-2 pl-7">
                      <span className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)] whitespace-nowrap">{label}</span>
                      <span className="flex-1 h-px" style={{ background: "#E5E5EA" }} />
                    </div>
                  )}
                  <EventNode e={e} now={now} />
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
