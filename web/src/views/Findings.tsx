import { Fragment, useEffect, useMemo, useState } from "react";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import { getFindings, streamAudit, type Finding } from "../lib/api";
import { C, useChartReflow, ago, VERDICT_C, severityOf, categoryOf } from "../components/dash";
import { humanizeRule, describeAction, verdictWord } from "../lib/humanize";

function bucketKey(ts: string): string | null {
  const t = Date.parse(ts);
  if (Number.isNaN(t)) return null;
  const d = new Date(t);
  const m = Math.floor(d.getMinutes() / 5) * 5;
  return `${String(d.getHours()).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}


function SevTag({ f }: { f: Finding }) {
  const s = severityOf(f.verdict, f.rules);
  if (!s) return <span className="text-[11px] text-[#8E8E93]">—</span>;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: `${s.color}1f`, color: s.color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.color }} />{s.label}
    </span>
  );
}

const FilterChip = ({ label, count, active, color, onClick }:
  { label: string; count: number; active: boolean; color: string; onClick: () => void }) => (
  <button onClick={onClick}
    className="px-2.5 py-1 rounded-md text-xs flex items-center gap-1.5 border transition-colors"
    style={{
      background: active ? `${color}22` : "transparent",
      borderColor: active ? `${color}88` : C.grid,
      color: active ? color : C.muted,
    }}>
    <span className="w-1.5 h-1.5 rounded-full" style={{ background: color, opacity: active ? 1 : 0.5 }} />
    <span className="capitalize">{label}</span>
    <span className="font-mono tabular-nums">{count}</span>
  </button>
);

// Verdict → plain-English outcome word
function outcomeWord(v: string): string {
  if (v === "deny") return "Blocked";
  if (v === "ask") return "Waiting";
  return "Allowed";
}

export default function Findings() {
  const [rows, setRows] = useState<Finding[]>([]);
  const [verdicts, setVerdicts] = useState<Set<string>>(new Set());
  const [tool, setTool] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  useChartReflow();

  useEffect(() => {
    let live = true;
    const load = () => getFindings().then((d) => { if (live) setRows(Array.isArray(d) ? d : []); });
    load();
    const stop = streamAudit(() => load());
    return () => { live = false; stop(); };
  }, []);

  const counts = useMemo(() => {
    const c = { allow: 0, ask: 0, deny: 0 } as Record<string, number>;
    for (const r of rows) c[r.verdict] = (c[r.verdict] ?? 0) + 1;
    return c;
  }, [rows]);

  const tools = useMemo(() => Array.from(new Set(rows.map((r) => r.tool).filter(Boolean))).sort(), [rows]);

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (verdicts.size && !verdicts.has(r.verdict)) return false;
      if (tool && r.tool !== tool) return false;
      if (ql) {
        const hay = `${r.tool} ${r.reason} ${(r.rules || []).join(" ")} ${r.session}`.toLowerCase();
        if (!hay.includes(ql)) return false;
      }
      return true;
    });
  }, [rows, verdicts, tool, q]);

  const spark = useMemo(() => {
    const m = new Map<string, { bucket: string; allow: number; ask: number; deny: number }>();
    for (const r of rows) {
      const k = bucketKey(r.ts); if (!k) continue;
      const b = m.get(k) ?? { bucket: k, allow: 0, ask: 0, deny: 0 };
      if (r.verdict in b) (b as any)[r.verdict]++;
      m.set(k, b);
    }
    return [...m.values()].sort((a, b) => a.bucket.localeCompare(b.bucket));
  }, [rows]);

  const toggleVerdict = (v: string) => setVerdicts((prev) => {
    const n = new Set(prev); n.has(v) ? n.delete(v) : n.add(v); return n;
  });
  const hasFilters = verdicts.size > 0 || tool !== "" || q.trim() !== "";
  const clearAll = () => { setVerdicts(new Set()); setTool(""); setQ(""); };
  const RENDER_CAP = 300;
  const shown = filtered.slice(0, RENDER_CAP);

  return (
    <div className="p-6 space-y-3">
      {/* filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-2">
          {(["deny", "ask", "allow"] as const).map((v) => {
            const DISPLAY: Record<string, string> = { deny: "Blocked", ask: "Needs review", allow: "Allowed" };
            return (
              <FilterChip key={v} label={DISPLAY[v]} count={counts[v] ?? 0} color={VERDICT_C[v]}
                active={verdicts.has(v)} onClick={() => toggleVerdict(v)} />
            );
          })}
        </div>
        <select value={tool} onChange={(e) => setTool(e.target.value)}
          className="bg-white rounded-md text-xs text-[#1C1C1E] px-2 py-1.5 outline-none"
          style={{ border: "1px solid rgba(0,0,0,0.14)" }}>
          <option value="">All tools</option>
          {tools.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search tool, rule, reason…"
          className="flex-1 min-w-[200px] max-w-[320px] bg-white rounded-md text-xs text-[#1C1C1E] px-3 py-1.5 outline-none font-mono"
          style={{ border: "1px solid rgba(0,0,0,0.14)" }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "#0A66D6")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,0,0,0.14)")} />
        {hasFilters && (
          <button onClick={clearAll} className="text-xs text-[#8E8E93] hover:text-[#1C1C1E]">clear</button>
        )}
        <div className="ml-auto flex items-center gap-4">
          <span className="text-xs text-[#8E8E93]">
            <span className="font-mono tabular-nums text-[#1C1C1E]">{filtered.length}</span> of{" "}
            <span className="font-mono tabular-nums">{rows.length}</span>
          </span>
          {spark.length > 1 && (
            <div className="w-[140px] h-[34px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={spark} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
                  <Area type="monotone" dataKey="allow" stackId="1" stroke={C.allow} fill={`${C.allow}22`} strokeWidth={1} isAnimationActive={false} />
                  <Area type="monotone" dataKey="ask" stackId="1" stroke={C.ask} fill={`${C.ask}22`} strokeWidth={1} isAnimationActive={false} />
                  <Area type="monotone" dataKey="deny" stackId="1" stroke={C.deny} fill={`${C.deny}44`} strokeWidth={1.2} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* advanced columns toggle */}
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-2 text-xs text-[#8E8E93] cursor-pointer select-none">
          <input
            type="checkbox"
            checked={advanced}
            onChange={(e) => setAdvanced(e.target.checked)}
            className="w-3.5 h-3.5 accent-[#0A66D6]"
            aria-label="Show advanced columns"
          />
          Show advanced columns
        </label>
      </div>

      {/* table */}
      <div className="rounded-xl overflow-hidden bg-white" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[600px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-widest text-[#8E8E93]" style={{ borderBottom: "1px solid rgba(0,0,0,0.08)" }}>
                <th className="py-2.5 px-3 font-normal w-20">Time</th>
                <th className="py-2.5 px-2 font-normal">What happened</th>
                <th className="py-2.5 px-2 font-normal w-24">Outcome</th>
                {advanced && <>
                  <th className="py-2.5 px-2 font-normal w-24">Severity</th>
                  <th className="py-2.5 px-2 font-normal w-24">Category</th>
                  <th className="py-2.5 px-2 font-normal w-32">Tool</th>
                  <th className="py-2.5 px-2 font-normal w-40">Rule</th>
                  <th className="py-2.5 px-3 font-normal w-20 text-right">Session</th>
                </>}
              </tr>
            </thead>
            <tbody>
              {shown.map((r, i) => {
                const id = `${r.ts}-${i}`;
                const cat = categoryOf(r.rules);
                const border = r.verdict === "deny" ? C.deny : r.verdict === "ask" ? C.ask : "transparent";
                const isOpen = open === id;
                const outcomeCol = VERDICT_C[r.verdict] ?? C.muted;
                const colSpanCount = advanced ? 8 : 3;
                return (
                  <Fragment key={id}>
                    <tr onClick={() => setOpen(isOpen ? null : id)}
                      className="transition-colors cursor-pointer hover:bg-[rgba(0,0,0,0.03)]"
                      style={{ borderBottom: "1px solid rgba(0,0,0,0.06)", boxShadow: `inset 3px 0 0 ${border}` }}>
                      <td className="py-2 px-3 font-mono text-[11px] text-[#8E8E93] whitespace-nowrap" title={r.ts}>{ago(r.ts)}</td>
                      <td className="py-2 px-2 max-w-0 w-full">
                        <div className="text-[13px] truncate" title={`${verdictWord(r.verdict)} — ${describeAction(r)}`}>
                          <span className="font-semibold" style={{ color: outcomeCol }}>{verdictWord(r.verdict)}</span>
                          <span className="text-text-secondary"> — {describeAction(r)}</span>
                        </div>
                      </td>
                      <td className="py-2 px-2 whitespace-nowrap">
                        <span className="text-[12px] font-semibold" style={{ color: outcomeCol }}>
                          {outcomeWord(r.verdict)}
                        </span>
                      </td>
                      {advanced && <>
                        <td className="py-2 px-2"><SevTag f={r} /></td>
                        <td className="py-2 px-2">
                          {cat ? (
                            <button onClick={(e) => { e.stopPropagation(); setQ(cat); }}
                              className="text-[11px] px-1.5 py-0.5 rounded text-[#1C1C1E] hover:opacity-70"
                              style={{ background: "rgba(0,0,0,0.06)", border: "1px solid rgba(0,0,0,0.08)" }}
                              title={cat}>
                              {humanizeRule(cat)}
                            </button>
                          ) : <span className="text-[#8E8E93] text-[11px]">—</span>}
                        </td>
                        <td className="py-2 px-2">
                          <button onClick={(e) => { e.stopPropagation(); setTool(r.tool); }}
                            className="font-mono text-[12px] text-[#1C1C1E] hover:text-[#0856B3] truncate max-w-[120px] inline-block align-bottom">
                            {r.tool || "—"}
                          </button>
                        </td>
                        <td className="py-2 px-2">
                          {(r.rules || []).length ? (
                            <span className="flex items-center gap-1">
                              <button onClick={(e) => { e.stopPropagation(); setQ(r.rules[0]); }}
                                className="text-[11px] px-1.5 py-0.5 rounded text-[#1C1C1E] hover:opacity-70 truncate max-w-[130px]"
                                style={{ background: "rgba(0,0,0,0.06)" }}
                                title={r.rules[0]}>
                                {humanizeRule(r.rules[0])}
                              </button>
                              {r.rules.length > 1 && <span className="text-[10px] text-[#8E8E93]">+{r.rules.length - 1}</span>}
                            </span>
                          ) : <span className="text-[#8E8E93] text-[11px]">—</span>}
                        </td>
                        <td className="py-2 px-3 font-mono text-[11px] text-[#8E8E93] text-right">{r.session ? r.session.slice(-6) : "—"}</td>
                      </>}
                    </tr>
                    {isOpen && (
                      <tr style={{ background: "#F5F5F7", borderBottom: "1px solid rgba(0,0,0,0.06)" }}>
                        <td colSpan={colSpanCount} className="px-4 py-3">
                          <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-1.5 text-[12px] font-mono">
                            <div><span className="text-[#8E8E93]">ts </span><span className="text-[#1C1C1E]">{r.ts}</span></div>
                            <div><span className="text-[#8E8E93]">event </span><span className="text-[#1C1C1E]">{r.event || "—"}</span></div>
                            <div><span className="text-[#8E8E93]">tool </span><span className="text-[#1C1C1E]">{r.tool || "—"}</span></div>
                            <div><span className="text-[#8E8E93]">session </span><span className="text-[#1C1C1E]">{r.session || "—"}</span></div>
                            <div className="col-span-2 lg:col-span-4"><span className="text-[#8E8E93]">reason </span><span className="text-[#1C1C1E]">{r.reason || "—"}</span></div>
                            {(r.rules || []).length > 0 && (
                              <div className="col-span-2 lg:col-span-4 flex flex-wrap gap-1.5 pt-1">
                                {r.rules.map((rule) => (
                                  <button key={rule} onClick={() => setQ(rule)}
                                    className="text-[11px] px-1.5 py-0.5 rounded text-[#1C1C1E] hover:opacity-70"
                                    style={{ background: "rgba(0,0,0,0.06)" }}>{rule}</button>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="py-16 text-center text-sm text-[#8E8E93]">
            {rows.length === 0
              ? "No findings recorded yet — the engine will populate this feed as agents run."
              : <>No findings match the current filters. <button onClick={clearAll} className="hover:underline" style={{ color: "#0856B3" }}>Clear filters</button></>}
          </div>
        )}
        {filtered.length > RENDER_CAP && (
          <div className="py-2 text-center text-[11px] text-[#8E8E93]" style={{ borderTop: "1px solid rgba(0,0,0,0.06)" }}>
            Showing newest {RENDER_CAP} of {filtered.length} matches — narrow the filter to see more
          </div>
        )}
      </div>
    </div>
  );
}
