// Overview §1 security signals: per-session trust grades (get_trust) and the
// GateGuard self-approval-attempts stat (from the approvals store). Both degrade
// to empty/zero when the daemon is unreachable or the browser build has no socket.

import { useEffect, useState } from "react";
import { getTrust, getRecentApprovals, type TrustSession } from "../lib/api";
import { Trans, useLingui } from "@lingui/react/macro";

// Grade → color: A+/A green through F red (spec §1).
const GRADE_COLOR: Record<string, string> = {
  "A+": "#187D34",
  "A": "#187D34",
  "B": "#5E9E2E",
  "C": "#916400",
  "D": "#D2691E",
  "F": "#C8312A",
};
const gradeColor = (g: string): string => GRADE_COLOR[g] ?? "#6C6C71";

function GradeBadge({ grade, big }: { grade: string; big?: boolean }) {
  const { t } = useLingui();
  const c = gradeColor(grade);
  return (
    <span
      className={`inline-flex items-center justify-center rounded-md font-bold tabular-nums ${big ? "px-2.5 py-1 text-base" : "px-2 py-0.5 text-xs"}`}
      style={{ background: `${c}0f`, color: c }}
      aria-label={t`Trust grade ${grade}`}
    >
      {grade}
    </span>
  );
}

// A session id like "claude-code:1234" / "codex/9f2a" → a readable name.
function friendlyAgent(session: string): string {
  const base = session.split(":")[0].split("/").pop() ?? session;
  return (
    base
      .split(/[-_\s]+/)
      .filter(Boolean)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ") || session
  );
}

interface GuardStat {
  attempts: number;
  blocked: number;
}

export default function TrustPanel() {
  const { t } = useLingui();
  const [sessions, setSessions] = useState<TrustSession[] | null>(null);
  const [guard, setGuard] = useState<GuardStat | null>(null);

  useEffect(() => {
    let live = true;
    getTrust()
      .then((t) => { if (live) setSessions(t.sessions ?? []); })
      .catch(() => { if (live) setSessions([]); });
    getRecentApprovals(500)
      .then((rows) => {
        if (!live) return;
        // A self-approval ATTEMPT = a resolution whose resolver ancestry tied
        // back to the gated agent; BLOCKED = the guard overrode it to deny.
        const resolved = rows.filter((r) => r?.event === "approval.resolved");
        setGuard({
          attempts: resolved.filter((r) => r.resolver_agent_lineage === true).length,
          blocked: resolved.filter((r) => r.self_approval_blocked === true).length,
        });
      })
      .catch(() => { if (live) setGuard({ attempts: 0, blocked: 0 }); });
    return () => { live = false; };
  }, []);

  // Worst session is first (get_trust sorts by demerits desc).
  const worst = sessions && sessions.length > 0 ? sessions[0] : null;
  const attempts = guard?.attempts ?? 0;
  const blocked = guard?.blocked ?? 0;
  // Any attempt is worth an amber; a blocked one is a red (a guard fired).
  const guardColor = blocked > 0 ? "#C8312A" : attempts > 0 ? "#916400" : "#187D34";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Session trust */}
      <div
        className="lg-glass px-4 py-3 flex flex-col"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"><Trans>Session trust</Trans></span>
          {worst && (
            <span className="flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)]">
              <Trans>lowest <GradeBadge grade={worst.grade} /></Trans>
            </span>
          )}
        </div>
        {sessions === null ? (
          <p className="text-sm text-[var(--text-tertiary)]"><Trans>Loading…</Trans></p>
        ) : sessions.length === 0 ? (
          <p className="text-sm text-[#636366]"><Trans>No agent sessions yet.</Trans></p>
        ) : (
          <div className="flex flex-col gap-1.5">
            {sessions.slice(0, 6).map((s, i) => (
              <div
                key={s.session}
                className="flex items-center justify-between gap-2 rounded-lg px-2 py-1"
                // Highlight the worst-graded session (first row).
                style={i === 0 ? { background: `${gradeColor(s.grade)}0f` } : undefined}
              >
                <span className="text-sm text-[#1C1C1E] truncate" title={s.session}>
                  {friendlyAgent(s.session)}
                </span>
                <span className="flex items-center gap-2 shrink-0">
                  <span className="text-[11px] font-mono tabular-nums text-[var(--text-tertiary)]" title={t`demerits`}>
                    {s.demerits.toFixed(1)}
                  </span>
                  <GradeBadge grade={s.grade} />
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Self-approval attempts (GateGuard) */}
      <div
        className="lg-glass px-4 py-3 flex flex-col"
      >
        <span className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"><Trans>Self-approval attempts</Trans></span>
        <div className="text-4xl font-mono tabular-nums leading-tight mt-1" style={{ color: guardColor }}>
          {attempts.toLocaleString()}
        </div>
        <p className="text-xs text-[#636366] mt-1">
          {guard === null
            ? t`Loading…`
            : attempts === 0
              ? t`No agent tried to approve its own request.`
              : t`${blocked} blocked by GateGuard.`}
        </p>
      </div>
    </div>
  );
}
