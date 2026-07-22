import { useState, useRef } from "react";
import { runScan } from "../lib/api";
import { humanizeRule } from "../lib/humanize";
import { C, Empty } from "../components/dash";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";

interface ScanFinding {
  rule_id: string;
  severity: string;
  reason: string;
}

interface ScanResult {
  score: number;
  severity: string;
  recommendation: string;
  findings: ScanFinding[];
}

type State =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "result"; data: ScanResult }
  | { kind: "error"; message: string }
  | { kind: "desktop-only" };

const RECOMMENDATION = {
  SAFE: { label: msg`Looks safe`, bg: "rgba(24,125,52,0.06)", border: "rgba(24,125,52,0.22)", text: "#187D34" },
  CAUTION: { label: msg`Be careful`, bg: "rgba(145,100,0,0.06)", border: "rgba(145,100,0,0.22)", text: "#916400" },
  DO_NOT_INSTALL: { label: msg`Do not install / run`, bg: "rgba(200,49,42,0.06)", border: "rgba(200,49,42,0.22)", text: "#C8312A" },
} as const;

// Keyed by the backend's UPPERCASE severity strings (scan emits "CRITICAL",
// "HIGH", "MEDIUM", "LOW", "INFO"). The lookup normalizes to uppercase so any
// casing resolves to the right color instead of silently falling back to gray.
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#C8312A",
  HIGH: "#AB550F",
  MEDIUM: "#916400",
  LOW: "#1A6BC5",
  INFO: "#1A6BC5",
};

function SeverityDot({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity.toUpperCase()] ?? C.muted;
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: `${color}0f`, color }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {severity}
    </span>
  );
}

function FindingRow({ f }: { f: ScanFinding }) {
  const humanLabel = humanizeRule(f.rule_id);
  return (
    <div className="py-3 px-4 border-b last:border-0" style={{ borderColor: "rgba(0,0,0,0.08)" }}>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm text-[#1C1C1E] font-medium" title={f.rule_id}>{humanLabel}</span>
        <SeverityDot severity={f.severity} />
      </div>
      <p className="text-xs text-[var(--text-tertiary)] font-mono leading-relaxed">{f.reason}</p>
    </div>
  );
}

function RecommendationBanner({ data }: { data: ScanResult }) {
  const { t } = useLingui();
  const rec = RECOMMENDATION[data.recommendation as keyof typeof RECOMMENDATION];
  const label = rec ? t(rec.label) : data.recommendation;
  const bg = rec?.bg ?? "rgba(0,0,0,0.04)";
  const border = rec?.border ?? "rgba(0,0,0,0.14)";
  const textColor = rec?.text ?? C.muted;

  return (
    <div
      className="rounded-xl border p-5 mb-4"
      style={{ background: bg, borderColor: border }}
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <div className="text-xl font-bold mb-0.5" style={{ color: textColor }}>
            {label}
          </div>
          <div className="text-xs text-[var(--text-tertiary)]">
            <Trans>Risk score:</Trans>{" "}
            <span className="font-mono tabular-nums text-[#1C1C1E]">
              {data.score} / 100
            </span>
            {" · "}
            <span className="text-[#636366]">{data.severity}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

const DESKTOP_ONLY_MSG = "Available in the Belay desktop app";

export default function Scan() {
  const { t } = useLingui();
  const [target, setTarget] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });
  const inputRef = useRef<HTMLInputElement>(null);

  const canScan = target.trim().length > 0 && state.kind !== "loading";

  const doScan = async () => {
    const tgt = target.trim();
    if (!tgt) return;
    setState({ kind: "loading" });
    try {
      const result = await runScan(tgt) as ScanResult;
      setState({ kind: "result", data: result });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
        setState({ kind: "desktop-only" });
      } else {
        setState({ kind: "error", message: msg });
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && canScan) doScan();
  };

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      {/* Input row */}
      <div className="flex gap-2">
        <input
          ref={inputRef}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={t`~/Downloads/some-repo  or  https://github.com/org/repo`}
          disabled={state.kind === "loading"}
          className="flex-1 bg-white rounded-lg text-sm text-[#1C1C1E] px-4 py-2.5 outline-none disabled:opacity-50 font-mono"
          style={{ border: "1px solid rgba(0,0,0,0.14)" }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "#0A66D6")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "rgba(0,0,0,0.14)")}
        />
        <button
          onClick={doScan}
          disabled={!canScan}
          className="px-5 py-2.5 rounded-lg text-sm font-semibold transition-colors disabled:cursor-not-allowed"
          style={{
            background: canScan ? "#0A66D6" : "rgba(0,0,0,0.06)",
            color: canScan ? "#fff" : "var(--text-tertiary)",
          }}
        >
          {state.kind === "loading" ? <Trans>Scanning…</Trans> : <Trans>Scan</Trans>}
        </button>
      </div>

      {/* States */}
      {state.kind === "idle" && (
        <div className="space-y-4">
          <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1.5" style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}>
            <p className="text-[#1C1C1E] font-medium"><Trans>What does scanning do?</Trans></p>
            <p>
              <Trans>
                Check a folder, file, or repository for risky code before you run it.
                Belay looks for things like credential theft, destructive commands,
                and hidden network calls.
              </Trans>
            </p>
            <p className="text-[var(--text-tertiary)] text-xs pt-1">
              <Trans>Enter a local path or GitHub URL above to get started.</Trans>
            </p>
          </div>

          <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1.5" style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}>
            <p className="text-[#1C1C1E] font-medium"><Trans>Malware scan (on-demand)</Trans></p>
            <p>
              <Trans>
                Every scan also runs an on-demand byte-level malware pass over
                the target (a bundled YARA rule set). This check runs only when
                you start a scan — it is not a continuously-running antivirus
                service watching your files in the background.
              </Trans>
            </p>
          </div>
        </div>
      )}

      {state.kind === "loading" && (
        <div className="rounded-xl px-5 py-8 text-center text-sm text-[#636366]" style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}>
          <Trans>Scanning… this can take a few seconds</Trans>
        </div>
      )}

      {state.kind === "desktop-only" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}>
          <p className="text-[#1C1C1E] font-medium"><Trans>Desktop app required</Trans></p>
          <p>
            <Trans>
              Scanning runs in the Belay desktop app, where it can inspect
              files directly on your computer. This feature is not available in the
              browser.
            </Trans>
          </p>
        </div>
      )}

      {state.kind === "error" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}>
          <p className="text-[#1C1C1E] font-medium"><Trans>Something went wrong</Trans></p>
          <p className="font-mono text-xs text-[var(--text-tertiary)]">{state.message}</p>
          <button
            onClick={() => setState({ kind: "idle" })}
            className="text-xs hover:underline mt-1"
            style={{ color: "#0856B3" }}
          >
            <Trans>Try again</Trans>
          </button>
        </div>
      )}

      {state.kind === "result" && (
        <div>
          <RecommendationBanner data={state.data} />

          {/* Findings list */}
          <div className="lg-glass overflow-hidden">
            <div className="px-4 py-2.5 border-b text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]" style={{ borderColor: "rgba(0,0,0,0.08)" }}>
              <Trans>Findings</Trans>{" "}
              <span className="font-mono tabular-nums text-[#636366] normal-case tracking-normal">
                {state.data.findings.length}
              </span>
            </div>

            {state.data.findings.length === 0 ? (
              <Empty><Trans>No risky patterns found.</Trans></Empty>
            ) : (
              state.data.findings.map((f, i) => (
                <FindingRow key={`${f.rule_id}-${i}`} f={f} />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
