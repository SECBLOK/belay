import { useEffect, useState } from "react";
import {
  RadialBarChart, RadialBar, PolarAngleAxis,
  PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area, Tooltip, ResponsiveContainer,
} from "recharts";
import { getPosture, streamAudit, type PostureSummary } from "../lib/api";
import { C, tip, Card, StatTile, Empty, useChartReflow } from "../components/dash";
import StatusRing, { type RingState } from "../components/StatusRing";
import TrustPanel from "../components/TrustPanel";
import { PawLoader } from "../components/Paw";
import MascotEmpty from "../components/MascotEmpty";
import ActivityFeed from "../components/ActivityFeed";
import BootStartToggle from "../components/BootStartToggle";
import UpdateControl from "../components/UpdateControl";
import { humanizeRule } from "../lib/humanize";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// Derive the native desktop hero ring state from posture (calm by default):
// any recent deny -> blocked (red); any ask -> action (amber); healthy score
// -> protected (green); otherwise monitoring (cyan). One meaning per color.
function ringState(p: PostureSummary, recent: any[]): RingState {
  if (recent.some((r) => r.verdict === "deny") || p.deny > 0) return "blocked";
  if (recent.some((r) => r.verdict === "ask") || p.ask > 0) return "action";
  if (p.score >= 80) return "protected";
  return "monitoring";
}

// category → severity-tier hue (light semantic tokens)
const CAT: Record<string, string> = {
  rce: "#C8312A", destructive: "#C8312A",
  persistence: "#AB550F", secrets: "#AB550F",
  egress: "#916400", tamper: "#916400",
  recon: "#1A6BC5",
};
const catColor = (c: string) => CAT[c] ?? C.muted;

function scoreColor(s: number) {
  return s >= 80 ? C.allow : s >= 60 ? "#916400" : s >= 40 ? "#AB550F" : C.deny;
}
function scoreLabel(s: number): MessageDescriptor {
  return s >= 80 ? msg`Healthy` : s >= 60 ? msg`Monitor` : s >= 40 ? msg`Investigate` : msg`Critical`;
}

function ScoreGauge({ score }: { score: number }) {
  const { t } = useLingui();
  const data = [{ value: score, fill: scoreColor(score) }];
  return (
    <div className="relative h-[200px]">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart data={data} startAngle={220} endAngle={-40} innerRadius="62%" outerRadius="100%" barSize={16}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} axisLine={false} />
          <RadialBar dataKey="value" background={{ fill: "#E5E5EA" }} cornerRadius={8} isAnimationActive={false} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-5xl font-bold tabular-nums" style={{ color: scoreColor(score) }}>{score}</span>
        <span className="text-[11px] uppercase tracking-widest mt-1" style={{ color: scoreColor(score) }}>{t(scoreLabel(score))}</span>
      </div>
    </div>
  );
}

function VerdictDonut({ p }: { p: PostureSummary }) {
  const data = [
    { name: "allow", value: p.allow, color: C.allow },
    { name: "ask", value: p.ask, color: C.ask },
    { name: "deny", value: p.deny, color: C.deny },
  ].filter((d) => d.value > 0);
  const denyRate = p.total ? Math.round((p.deny / p.total) * 100) : 0;
  return (
    <div className="flex flex-col">
      <div className="relative h-[170px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius="58%" outerRadius="82%" paddingAngle={3} strokeWidth={0} isAnimationActive={false}>
              {data.map((d) => <Cell key={d.name} fill={d.color} />)}
            </Pie>
            <Tooltip {...tip} />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-bold tabular-nums" style={{ color: denyRate > 20 ? C.deny : "#1C1C1E" }}>{denyRate}%</span>
          <span className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)]"><Trans>deny rate</Trans></span>
        </div>
      </div>
      <div className="flex justify-center gap-4 mt-2 text-[11px]">
        {([["allow", C.allow], ["ask", C.ask], ["deny", C.deny]] as const).map(([k, col]) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full" style={{ background: col }} />
            <span className="text-[#636366] capitalize">{k}</span>
            <span className="font-mono tabular-nums text-[#1C1C1E]">{(p as any)[k]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function CategoryBar({ by }: { by: Record<string, number> }) {
  const data = Object.entries(by).map(([cat, count]) => ({ cat, count })).sort((a, b) => b.count - a.count);
  if (!data.length) return <Empty><Trans>No category activity</Trans></Empty>;
  return (
    <div className="h-[200px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }}>
          <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke={C.grid} />
          <XAxis type="number" tick={{ fill: C.muted, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="cat" width={84} interval={0} tick={{ fill: C.muted, fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip {...tip} cursor={{ fill: "rgba(0,0,0,0.03)" }} />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14} isAnimationActive={false}>
            {data.map((d) => <Cell key={d.cat} fill={catColor(d.cat)} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TrendArea({ p }: { p: PostureSummary }) {
  if (!p.trend.length) return <Empty><Trans>No timeline activity yet</Trans></Empty>;
  return (
    <div className="h-[220px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={p.trend} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
          <defs>
            {(["allow", "ask", "deny"] as const).map((k) => (
              <linearGradient key={k} id={`pg-${k}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={C[k]} stopOpacity={k === "deny" ? 0.30 : 0.15} />
                <stop offset="95%" stopColor={C[k]} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={C.grid} vertical={false} />
          <XAxis dataKey="bucket" tick={{ fill: C.muted, fontSize: 10 }} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis tick={{ fill: C.muted, fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
          <Tooltip {...tip} />
          <Area type="monotone" dataKey="allow" stackId="1" stroke={C.allow} fill="url(#pg-allow)" strokeWidth={1.5} isAnimationActive={false} />
          <Area type="monotone" dataKey="ask" stackId="1" stroke={C.ask} fill="url(#pg-ask)" strokeWidth={1.5} isAnimationActive={false} />
          <Area type="monotone" dataKey="deny" stackId="1" stroke={C.deny} fill="url(#pg-deny)" strokeWidth={1.8} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopRules({ rules }: { rules: PostureSummary["top_rules"] }) {
  if (!rules.length) return <Empty><Trans>No rules triggered</Trans></Empty>;
  const max = rules[0]?.count ?? 1;
  return (
    <ul className="space-y-2.5 flex-1">
      {rules.map((r) => (
        <li key={r.rule_id} className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-[#1C1C1E] w-44 truncate shrink-0" title={r.rule_id}>{humanizeRule(r.rule_id)}</span>
          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "#E5E5EA" }}>
            <div className="h-full rounded-full" style={{ width: `${(r.count / max) * 100}%`, background: catColor(r.category) }} />
          </div>
          <span className="font-mono tabular-nums text-xs text-[#636366] w-6 text-right shrink-0">{r.count}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Posture() {
  const { t } = useLingui();
  const [p, setP] = useState<PostureSummary | null>(null);
  const [recent, setRecent] = useState<any[]>([]);
  const [showDetails, setShowDetails] = useState(false);
  useChartReflow();
  useEffect(() => {
    let live = true;
    const load = () => getPosture().then((d) => { if (live) setP(d); });
    load();
    // refresh on each new audit event so counters stay live, and keep the
    // last ~50 rows for the native desktop activity feed (newest first).
    const stop = streamAudit((row) => {
      load();
      if (live) setRecent((rs) => [row, ...rs].slice(0, 50));
    });
    return () => { live = false; stop(); };
  }, []);

  if (!p) return (
    <div className="p-6 flex items-center gap-3 text-[var(--text-tertiary)] text-sm">
      <PawLoader /> <Trans>Fetching your protection status…</Trans>
    </div>
  );

  const rs = ringState(p, recent);

  return (
    <div className="p-6 space-y-4">
      {/* Native desktop hero: 160px status ring (one meaning per color) */}
      <div className="flex flex-col items-center gap-2 pb-2">
        <StatusRing state={rs} />
        <p data-testid="posture-reassurance" className="text-sm text-[#636366] text-center max-w-sm">
          {rs === "protected" && <Trans>All AI agent activity looks normal. Nothing needs your attention.</Trans>}
          {rs === "monitoring" && <Trans>Belay is watching. Some activity needs review — no action required.</Trans>}
          {rs === "action" && <Trans>An AI agent is waiting for your decision. See below.</Trans>}
          {rs === "blocked" && <Trans>Belay stopped a risky action. Your data was not affected — review it in Activity.</Trans>}
        </p>
      </div>

      {/* KPI row — deny is the dominant alarm signal */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatTile label={t`Actions monitored`} value={p.total} accent="var(--text-primary)" />
        <StatTile label={t`Approved`} value={p.allow} accent={C.allow} />
        <StatTile label={t`Waiting for you`} value={p.ask} accent={C.ask} />
        <StatTile label={t`Blocked`} value={p.deny} accent={C.deny} dominant />
      </div>

      {/* Security signals: per-session trust grades + GateGuard self-approval
          attempts (spec §1). Both degrade to empty/zero off-daemon. */}
      <TrustPanel />

      {/* Start-on-boot + update check (desktop only; render nothing in the web build) */}
      <BootStartToggle />
      <UpdateControl />

      {/* Native desktop live feed — verdict-accent rows, newest first */}
      <div className="grid grid-cols-1 gap-4">
        <Card title={t`Live Activity`} hint={t`recent events`} span="min-h-[120px]">
          {recent.length ? <ActivityFeed rows={recent} /> : <MascotEmpty pose="nap" title={t`All quiet`}><Trans>Nothing to guard right now — Belay will show what your AI agents do here.</Trans></MascotEmpty>}
        </Card>
      </div>

      {/* "Show details" disclosure — heavier analytics collapsed by default */}
      <div>
        <button
          onClick={() => setShowDetails((s) => !s)}
          aria-expanded={showDetails}
          className="flex items-center gap-2 text-xs text-[var(--text-tertiary)] hover:text-[#1C1C1E] transition-colors py-1"
        >
          <span className="inline-block w-3 text-center">{showDetails ? "▾" : "▸"}</span>
          {showDetails ? <Trans>Hide details</Trans> : <Trans>Show details</Trans>}
        </button>
        {showDetails && (
          <div className="mt-3 space-y-4">
            {/* score + verdict + category */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <Card title={t`Posture Score`} hint="0–100" span="lg:col-span-3 min-h-[260px]"><ScoreGauge score={p.score} /></Card>
              <Card title={t`Verdict Distribution`} span="lg:col-span-3 min-h-[260px]"><VerdictDonut p={p} /></Card>
              <Card title={t`Threat Categories`} hint={t`rule hits`} span="lg:col-span-6 min-h-[260px]"><CategoryBar by={p.by_category} /></Card>
            </div>

            {/* trend + top rules */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <Card title={t`Activity Over Time`} hint={t`5-min buckets`} span="lg:col-span-7 min-h-[260px]"><TrendArea p={p} /></Card>
              <Card title={t`Top Triggered Rules`} hint={t`deny + ask`} span="lg:col-span-5 min-h-[260px]"><TopRules rules={p.top_rules} /></Card>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
