// Host → Vulnerabilities sub-view: KEV-first CVE table + scan button + NVD API key.

import { useEffect, useState } from "react";
import { getVulnPosture, scanHostVuln } from "../../lib/api";
import type { VulnPosture as VulnPostureType } from "../../lib/hostTypes";
import CveTable from "../../components/host/CveTable";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; posture: VulnPostureType }
  | { kind: "error"; message: string };

type ScanState = "idle" | "scanning" | { error: string };

export default function VulnPosture() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [scanState, setScanState] = useState<ScanState>("idle");

  const load = async () => {
    setState({ kind: "loading" });
    try {
      const posture = await getVulnPosture();
      setState({ kind: "ready", posture });
    } catch (err: unknown) {
      setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  };

  useEffect(() => { load(); }, []);

  const doScan = async () => {
    setScanState("scanning");
    try {
      await scanHostVuln();
      setScanState("idle");
      await load();
    } catch (err: unknown) {
      setScanState({ error: err instanceof Error ? err.message : String(err) });
    }
  };

  if (state.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        Loading vulnerability posture…
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium">Something went wrong</p>
        <p className="font-mono text-xs text-[#8E8E93]">{state.message}</p>
        <button onClick={load} className="text-xs hover:underline mt-1" style={{ color: "#0856B3" }}>
          Try again
        </button>
      </div>
    );
  }

  const { posture } = state;

  // Unsupported OS / bundle mismatch: show a calm, honest "not available" card
  // instead of a misleading score. Gated by the daemon (supported === false).
  if (!posture.supported) {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm space-y-1.5"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium">Not available on this operating system</p>
        <p className="text-[#636366] leading-relaxed">
          {posture.reason ??
            "Vulnerability posture is not available for this operating system."}
        </p>
      </div>
    );
  }

  const kevCount = posture.findings.filter((f) => f.kev).length;

  return (
    <div className="space-y-4">
      {/* Approximate-match caveat (supported, but best-effort — e.g. Kali /
          Debian rolling matched against Debian sid). */}
      {posture.reason && (
        <div
          className="rounded-lg px-4 py-2.5 text-xs leading-relaxed flex items-start gap-2"
          style={{ background: "#FFF6E5", border: "1px solid rgba(178,123,0,0.25)", color: "#7A5300" }}
        >
          <span aria-hidden>ⓘ</span>
          <span>{posture.reason}</span>
        </div>
      )}

      {/* Summary row */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex gap-4">
          {[
            { label: "Critical", value: posture.critical, color: "#C8312A" },
            { label: "High",     value: posture.high,     color: "#B55A10" },
            { label: "Medium",   value: posture.medium,   color: "#B27B00" },
            { label: "Low",      value: posture.low,      color: "#1A6DC8" },
          ].map(({ label, value, color }) => (
            <div key={label} className="text-center">
              <div className="text-2xl font-mono tabular-nums font-bold" style={{ color }}>{value}</div>
              <div className="text-[10px] uppercase tracking-widest text-[#8E8E93]">{label}</div>
            </div>
          ))}
          {kevCount > 0 && (
            <div className="text-center">
              <div className="text-2xl font-mono tabular-nums font-bold" style={{ color: "#C8312A" }}>{kevCount}</div>
              <div className="text-[10px] uppercase tracking-widest text-[#8E8E93]">KEV</div>
            </div>
          )}
        </div>

        <button
          onClick={doScan}
          disabled={scanState === "scanning"}
          className="ml-auto px-4 py-2 rounded-lg text-sm font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
          style={{ background: "#0A66D6", color: "#fff" }}
        >
          {scanState === "scanning" ? "Scanning…" : "Scan now"}
        </button>
      </div>

      {/* Scan state banner */}
      {typeof scanState === "object" && "error" in scanState && (
        <div
          className="rounded-xl px-5 py-4 text-sm text-[#636366] space-y-1"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
        >
          <p className="text-[#1C1C1E] font-medium">Scan failed</p>
          <p className="font-mono text-xs text-[#8E8E93]">{scanState.error}</p>
        </div>
      )}

      {/* CVE table — KEV-first */}
      <div>
        <h3 className="text-[11px] uppercase tracking-widest text-[#8E8E93] mb-2">
          Findings{posture.scanned_at && (
            <span className="ml-2 normal-case tracking-normal text-[#636366]">
              — scanned {new Date(posture.scanned_at).toLocaleDateString()}
            </span>
          )}
        </h3>
        <CveTable findings={posture.findings} />
      </div>
    </div>
  );
}
