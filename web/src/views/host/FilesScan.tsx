// Host → Files sub-view: scan-now + scope selector + ScheduleCard + results table
// + QuarantineList. Restore = primary inline-confirm; Delete = second red confirm.

import { useEffect, useState } from "react";
import {
  runHostScan,
  getSchedule,
  setSchedule,
  listQuarantine,
  restoreQuarantine,
  deleteQuarantine,
} from "../../lib/api";
import type { HostFinding, ScanSchedule, QuarantineEntry } from "../../lib/hostTypes";
import SeverityDot from "../../components/host/SeverityDot";
import QuarantineList from "../../components/host/QuarantineList";
import { Plural, Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// ── Verdict badge ─────────────────────────────────────────────────────────────

const VERDICT_STYLE: Record<string, { bg: string; color: string; label: MessageDescriptor }> = {
  malicious: { bg: "rgba(200,49,42,0.06)", color: "#C8312A", label: msg`Malicious` },
  suspicious: { bg: "rgba(145,100,0,0.06)", color: "#916400", label: msg`Suspicious` },
  clean:      { bg: "rgba(24,125,52,0.06)",  color: "#187D34", label: msg`Clean` },
};

function VerdictBadge({ verdict }: { verdict: HostFinding["verdict"] }) {
  const { t } = useLingui();
  const s = VERDICT_STYLE[verdict];
  const bg = s?.bg ?? "rgba(0,0,0,0.06)";
  const color = s?.color ?? "#636366";
  const label = s ? t(s.label) : verdict;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold"
      style={{ background: bg, color }}
      aria-label={t`Verdict: ${label}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} aria-hidden />
      {label}
    </span>
  );
}

// ── Schedule card ─────────────────────────────────────────────────────────────

type ScheduleOption = "off" | "daily" | "weekly";

function cronToOption(schedule: ScanSchedule): ScheduleOption {
  if (!schedule.enabled) return "off";
  if (schedule.cron.startsWith("0 3 * * *")) return "daily";
  return "weekly";
}

function optionToCron(opt: ScheduleOption): Pick<ScanSchedule, "enabled" | "cron"> {
  if (opt === "off") return { enabled: false, cron: "0 3 * * *" };
  if (opt === "daily") return { enabled: true, cron: "0 3 * * *" };
  return { enabled: true, cron: "0 3 * * 0" }; // weekly Sunday
}

interface ScheduleCardProps {
  schedule: ScanSchedule;
  onSave: (s: ScanSchedule) => Promise<void>;
}

function ScheduleCard({ schedule, onSave }: ScheduleCardProps) {
  const { t } = useLingui();
  const [selected, setSelected] = useState<ScheduleOption>(cronToOption(schedule));
  const [scope, setScope] = useState<ScanSchedule["scope"]>(schedule.scope);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const isDirty =
    selected !== cronToOption(schedule) || scope !== schedule.scope;

  const handleSave = async () => {
    setSaving(true);
    setSaved(false);
    try {
      await onSave({ ...optionToCron(selected), scope });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } finally {
      setSaving(false);
    }
  };

  const OPTIONS: { value: ScheduleOption; label: string }[] = [
    { value: "off", label: t`Off` },
    { value: "daily", label: t`Daily` },
    { value: "weekly", label: t`Weekly` },
  ];

  return (
    <div className="lg-glass p-5 space-y-4" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"><Trans>Scheduled scan</Trans></h3>

      {/* Frequency */}
      <div className="flex gap-2 flex-wrap">
        {OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => setSelected(opt.value)}
            className="px-4 py-1.5 rounded-lg text-sm font-medium transition-colors"
            style={
              selected === opt.value
                ? { background: "#0A66D6", color: "#fff" }
                : { background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }
            }
            aria-pressed={selected === opt.value}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {/* Scope */}
      {selected !== "off" && (
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#636366]"><Trans>Scan scope</Trans></span>
          <button
            onClick={() => setScope(scope === "full" ? "quick" : "full")}
            role="switch"
            aria-checked={scope === "full"}
            className="px-3 py-1 rounded text-[12px] font-medium"
            style={
              scope === "full"
                ? { background: "rgba(10,102,214,0.10)", color: "#0A66D6" }
                : { background: "rgba(0,0,0,0.06)", color: "var(--text-tertiary)" }
            }
          >
            {scope === "full" ? t`Full scan` : t`Quick scan`}
          </button>
        </div>
      )}

      {isDirty && (
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-1.5 rounded-lg text-sm font-semibold disabled:opacity-40"
          style={{ background: "#0A66D6", color: "#fff" }}
        >
          {saving ? t`Saving…` : t`Save schedule`}
        </button>
      )}
      {saved && (
        <p className="text-xs" style={{ color: "#187D34" }}>
          <Trans>Schedule saved.</Trans>
        </p>
      )}
    </div>
  );
}

// ── Results table ─────────────────────────────────────────────────────────────

function ResultsTable({ findings, scanned }: { findings: HostFinding[]; scanned: number }) {
  const { t } = useLingui();
  if (findings.length === 0) {
    // A clean scan is NOT a no-op: report what was covered so the operator can
    // see it actually ran (the count + green check), rather than an ambiguous
    // "no findings" that looks identical to nothing having happened.
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm flex items-center gap-2.5"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <span aria-hidden style={{ color: "var(--semantic-allow, #187D34)", fontSize: "16px" }}>✓</span>
        <span className="text-[#1C1C1E]">
          <Plural
            value={scanned}
            _0="Scan complete — no files to scan."
            one="Scan complete — scanned # file, no threats found."
            other="Scan complete — scanned # files, no threats found."
          />
        </span>
      </div>
    );
  }

  return (
    <div className="lg-glass overflow-hidden">
      <table className="w-full text-sm" aria-label={t`Scan findings`}>
        <thead>
          <tr
            className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] border-b"
            style={{ borderColor: "rgba(0,0,0,0.08)" }}
          >
            <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>File</Trans></th>
            <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Verdict</Trans></th>
            <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Severity</Trans></th>
            <th className="text-left px-4 py-2.5 font-medium"><Trans>Reason</Trans></th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.id}
              className="border-b last:border-0"
              style={{ borderColor: "rgba(0,0,0,0.06)" }}
            >
              <td className="px-4 py-3 font-mono text-xs text-[#1C1C1E] max-w-[200px] truncate" title={f.path}>
                {f.path.split("/").pop() ?? f.path}
              </td>
              <td className="px-4 py-3">
                <VerdictBadge verdict={f.verdict} />
              </td>
              <td className="px-4 py-3">
                <SeverityDot severity={f.severity} />
              </td>
              <td className="px-4 py-3 text-xs text-[#636366] max-w-[240px] truncate" title={f.reason}>
                {f.reason}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

type ScanState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "done"; findings: HostFinding[]; scanned: number }
  | { kind: "error"; message: string }
  | { kind: "desktop-only" };

const DESKTOP_ONLY_MSG = "Available in the Belay desktop app";

export default function FilesScan() {
  const { t } = useLingui();
  const [scanState, setScanState] = useState<ScanState>({ kind: "idle" });
  const [scope, setScope] = useState<"full" | "quick">("full");
  const [schedule, setScheduleState] = useState<ScanSchedule | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
  const [initLoading, setInitLoading] = useState(true);
  const [initError, setInitError] = useState<string | null>(null);

  // Load schedule + quarantine on mount
  useEffect(() => {
    let cancelled = false;
    setInitLoading(true);
    setInitError(null);

    Promise.all([getSchedule(), listQuarantine()])
      .then(([sched, qEntries]) => {
        if (cancelled) return;
        setScheduleState(sched);
        // Honesty split: only actual files belong on the Files surface.
        // Quarantined agent skills (`kind: "dir"`) are shown on the Skills tab.
        setQuarantine(qEntries.filter((e) => e.kind !== "dir"));
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setInitError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setInitLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  const doScan = async () => {
    setScanState({ kind: "loading" });
    try {
      const { findings, scanned } = await runHostScan({ quick: scope === "quick" });
      setScanState({ kind: "done", findings, scanned });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
        setScanState({ kind: "desktop-only" });
      } else {
        setScanState({ kind: "error", message: msg });
      }
    }
  };

  const handleSaveSchedule = async (newSchedule: ScanSchedule) => {
    await setSchedule(newSchedule);
    setScheduleState(newSchedule);
  };

  const handleRestore = async (id: string) => {
    await restoreQuarantine(id);
    setQuarantine((prev) => prev.filter((e) => e.id !== id));
  };

  const handleDelete = async (id: string) => {
    await deleteQuarantine(id);
    setQuarantine((prev) => prev.filter((e) => e.id !== id));
  };

  if (initLoading) {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading…</Trans>
      </div>
    );
  }

  if (initError) {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium"><Trans>Something went wrong</Trans></p>
        <p className="font-mono text-xs text-[var(--text-tertiary)]">{initError}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Scan controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={doScan}
          disabled={scanState.kind === "loading"}
          className="px-5 py-2.5 rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          style={{
            background: scanState.kind === "loading" ? "rgba(0,0,0,0.06)" : "#0A66D6",
            color: scanState.kind === "loading" ? "var(--text-tertiary)" : "#fff",
          }}
        >
          {scanState.kind === "loading" ? t`Scanning…` : t`Scan now`}
        </button>

        {/* Scope selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--text-tertiary)]"><Trans>Scope:</Trans></span>
          {(["full", "quick"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setScope(s)}
              className="px-3 py-1.5 rounded text-xs font-medium transition-colors"
              style={
                scope === s
                  ? { background: "#0A66D6", color: "#fff" }
                  : { background: "rgba(0,0,0,0.06)", color: "#636366" }
              }
              aria-pressed={scope === s}
            >
              {s === "full" ? t`Full` : t`Quick`}
            </button>
          ))}
        </div>
      </div>

      {/* Scan result states */}
      {scanState.kind === "desktop-only" && (
        <div
          className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
        >
          <p className="text-[#1C1C1E] font-medium"><Trans>Desktop app required</Trans></p>
          <p>
            <Trans>
              Host scanning runs in the Belay desktop app, where it can inspect
              files directly on your computer.
            </Trans>
          </p>
        </div>
      )}

      {scanState.kind === "error" && (
        <div
          className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
        >
          <p className="text-[#1C1C1E] font-medium"><Trans>Scan failed</Trans></p>
          <p className="font-mono text-xs text-[var(--text-tertiary)]">{scanState.message}</p>
          <button
            onClick={() => setScanState({ kind: "idle" })}
            className="text-xs hover:underline mt-1"
            style={{ color: "#0856B3" }}
          >
            <Trans>Dismiss</Trans>
          </button>
        </div>
      )}

      {scanState.kind === "done" && (
        <ResultsTable findings={scanState.findings} scanned={scanState.scanned} />
      )}

      {/* Schedule card */}
      {schedule && (
        <ScheduleCard schedule={schedule} onSave={handleSaveSchedule} />
      )}

      {/* Quarantine list */}
      <div>
        <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] mb-2">
          <Trans>Quarantine</Trans>
        </h3>
        <QuarantineList
          entries={quarantine}
          onRestore={handleRestore}
          onDelete={handleDelete}
        />
      </div>
    </div>
  );
}
