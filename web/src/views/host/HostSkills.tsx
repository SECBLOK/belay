// Host → Skills sub-view: the skill-scanner surface. One row per installed
// agent skill (agent · name · recommendation chip · drift chip · finding
// count) with an Approve / Re-approve action that snapshots the current
// manifest as the trusted baseline. Quarantined skills (whole directories,
// `kind: "dir"`) live here too — restore/delete via the shared QuarantineList.

import { useEffect, useState } from "react";
import { listSkills, approveSkill, listQuarantine, restoreQuarantine, deleteQuarantine } from "../../lib/api";
import type { SkillSummary, QuarantineEntry } from "../../lib/hostTypes";
import QuarantineList from "../../components/host/QuarantineList";
import { Trans, Plural, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// ── Chips ─────────────────────────────────────────────────────────────────────

const RECO_STYLE: Record<SkillSummary["recommendation"], { bg: string; color: string; label: MessageDescriptor }> = {
  safe:         { bg: "rgba(24,125,52,0.06)", color: "#187D34", label: msg`Safe` },
  caution:      { bg: "rgba(145,100,0,0.06)", color: "#916400", label: msg`Caution` },
  donotinstall: { bg: "rgba(200,49,42,0.06)", color: "#C8312A", label: msg`Do not install` },
};

function RecoChip({ recommendation }: { recommendation: SkillSummary["recommendation"] }) {
  const { t } = useLingui();
  const s = RECO_STYLE[recommendation];
  const label = t(s.label);
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold"
      style={{ background: s.bg, color: s.color }}
      aria-label={t`Recommendation: ${label}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: s.color }} aria-hidden />
      {label}
    </span>
  );
}

const DRIFT_STYLE: Record<SkillSummary["drift"], { bg: string; color: string; label: MessageDescriptor }> = {
  clean:       { bg: "rgba(24,125,52,0.06)", color: "#187D34", label: msg`Clean` },
  drifted:     { bg: "rgba(145,100,0,0.06)", color: "#916400", label: msg`Drifted` },
  unbaselined: { bg: "rgba(0,0,0,0.06)",     color: "#636366", label: msg`Unbaselined` },
};

function DriftChip({ drift }: { drift: SkillSummary["drift"] }) {
  const { t } = useLingui();
  const s = DRIFT_STYLE[drift];
  const label = t(s.label);
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium"
      style={{ background: s.bg, color: s.color }}
      aria-label={t`Baseline: ${label}`}
    >
      {label}
    </span>
  );
}

// ── Skill row ─────────────────────────────────────────────────────────────────

interface SkillRowProps {
  skill: SkillSummary;
  onApprove: (path: string) => Promise<void>;
}

function SkillRow({ skill, onApprove }: SkillRowProps) {
  const { t } = useLingui();
  const [busy, setBusy] = useState(false);

  // Clean skills are already at their trusted baseline — no action needed.
  // Unbaselined = never approved (establish the baseline); drifted = content
  // changed since approval (accept the update on purpose).
  const action =
    skill.drift === "unbaselined" ? t`Approve` : skill.drift === "drifted" ? t`Re-approve` : null;

  const doApprove = async () => {
    setBusy(true);
    try {
      await onApprove(skill.path);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="py-3 px-4 border-b last:border-0 flex items-center gap-3 flex-wrap"
      style={{ borderColor: "rgba(0,0,0,0.08)" }}
    >
      <div className="flex flex-col min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-[#1C1C1E] truncate" title={skill.path}>
            {skill.name}
          </span>
          <span className="text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">{skill.agent}</span>
        </div>
        <span className="text-xs text-[var(--text-tertiary)] truncate" title={skill.path}>
          <Plural
            value={skill.finding_count}
            _0="No findings"
            one="# finding"
            other="# findings"
          />
        </span>
      </div>

      <RecoChip recommendation={skill.recommendation} />
      <DriftChip drift={skill.drift} />

      {action && (
        <button
          onClick={doApprove}
          disabled={busy}
          className="px-3 py-1 rounded text-[12px] font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
          style={
            skill.drift === "drifted"
              ? { background: "rgba(145,100,0,0.12)", color: "#916400" }
              : { background: "rgba(10,102,214,0.10)", color: "#0A66D6" }
          }
          aria-label={`${action} ${skill.name}`}
        >
          {action}
        </button>
      )}
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

interface SkillsData {
  skills: SkillSummary[];
  quarantined: QuarantineEntry[];
}

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; data: SkillsData }
  | { kind: "error"; message: string };

export default function HostSkills() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    Promise.all([listSkills().catch(() => []), listQuarantine().catch(() => [])])
      .then(([skills, quarantine]) => {
        if (cancelled) return;
        // Only whole-directory quarantine entries are skills; files stay on the
        // Files tab (the honesty split from the Overview tiles).
        const quarantined = quarantine.filter((q) => q.kind === "dir");
        setState({ kind: "ready", data: { skills, quarantined } });
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
        }
      });
    return () => { cancelled = true; };
  }, []);

  const handleApprove = async (path: string) => {
    await approveSkill(path);
    // The manifest is now the trusted baseline → the row is clean.
    setState((prev) =>
      prev.kind === "ready"
        ? {
            kind: "ready",
            data: {
              ...prev.data,
              skills: prev.data.skills.map((s) =>
                s.path === path ? { ...s, drift: "clean" } : s,
              ),
            },
          }
        : prev,
    );
  };

  const handleRestore = async (id: string) => {
    await restoreQuarantine(id);
    setState((prev) =>
      prev.kind === "ready"
        ? { kind: "ready", data: { ...prev.data, quarantined: prev.data.quarantined.filter((e) => e.id !== id) } }
        : prev,
    );
  };

  const handleDelete = async (id: string) => {
    await deleteQuarantine(id);
    setState((prev) =>
      prev.kind === "ready"
        ? { kind: "ready", data: { ...prev.data, quarantined: prev.data.quarantined.filter((e) => e.id !== id) } }
        : prev,
    );
  };

  if (state.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading skills…</Trans>
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
      </div>
    );
  }

  const { skills, quarantined } = state.data;

  return (
    <div className="space-y-4">
      {/* Installed skills */}
      <div>
        <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] mb-2">
          <Trans>Installed skills</Trans>{" "}
          {skills.length > 0 && (
            <span className="font-mono tabular-nums text-[#636366] normal-case tracking-normal">
              {skills.length}
            </span>
          )}
        </h3>
        {skills.length === 0 ? (
          <div
            className="rounded-xl px-5 py-6 text-sm text-[#636366]"
            style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
          >
            <Trans>No agent skills installed.</Trans>
          </div>
        ) : (
          <div className="lg-glass overflow-hidden">
            {skills.map((skill) => (
              <SkillRow key={`${skill.agent}/${skill.path}`} skill={skill} onApprove={handleApprove} />
            ))}
          </div>
        )}
      </div>

      {/* Quarantined skills (whole directories) */}
      <div>
        <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] mb-2">
          <Trans>Quarantine</Trans>
        </h3>
        <QuarantineList
          entries={quarantined}
          noun="skill"
          onRestore={handleRestore}
          onDelete={handleDelete}
        />
      </div>
    </div>
  );
}
