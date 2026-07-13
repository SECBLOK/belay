// Host → Overview sub-view: 4 StatTiles + needs-attention rows that deep-link
// into the right sub-section via the Host shell's section setter.

import { useEffect, useState } from "react";
import { listQuarantine, listBans, getVulnPosture, getFirewallStatus } from "../../lib/api";
import type { HostSection } from "../Host";

// ── StatTile ─────────────────────────────────────────────────────────────────

interface StatTileProps {
  label: string;
  value: number;
  color?: string;
}

function StatTile({ label, value, color = "#1C1C1E" }: StatTileProps) {
  return (
    <div
      className="rounded-xl bg-white px-4 py-4 flex flex-col gap-1"
      style={{ border: "1px solid rgba(0,0,0,0.08)", boxShadow: "var(--shadow-card)" }}
    >
      <div className="text-[11px] uppercase tracking-widest text-[#8E8E93]">{label}</div>
      <div className="text-3xl font-mono tabular-nums font-bold leading-tight" style={{ color }}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

// ── AttentionRow ──────────────────────────────────────────────────────────────

interface AttentionRowProps {
  icon: string;
  message: string;
  actionLabel: string;
  section: HostSection;
  onNavigate: (s: HostSection) => void;
}

function AttentionRow({ icon, message, actionLabel, section, onNavigate }: AttentionRowProps) {
  return (
    <div
      className="flex items-center gap-3 px-4 py-3 rounded-xl bg-white border-l-4"
      style={{ border: "1px solid rgba(0,0,0,0.08)", borderLeftColor: "#B27B00", borderLeftWidth: 4 }}
    >
      <span className="text-lg" aria-hidden>{icon}</span>
      <span className="text-sm text-[#1C1C1E] flex-1">{message}</span>
      <button
        onClick={() => onNavigate(section)}
        className="text-xs font-semibold px-3 py-1.5 rounded-lg"
        style={{ background: "rgba(10,102,214,0.10)", color: "#0A66D6" }}
        aria-label={actionLabel}
      >
        {actionLabel}
      </button>
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

interface OverviewData {
  quarantineCount: number;
  bannedIpCount: number;
  kevCount: number;
  enforcingSurfaces: number;
}

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; data: OverviewData }
  | { kind: "error"; message: string };

interface HostOverviewProps {
  setSection: (s: HostSection) => void;
}

export default function HostOverview({ setSection }: HostOverviewProps) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      listQuarantine().catch(() => []),
      listBans().catch(() => []),
      getVulnPosture().catch(() => null),
      getFirewallStatus().catch(() => null),
    ]).then(([quarantine, bans, vuln, firewall]) => {
      if (cancelled) return;
      const kevCount = vuln?.findings.filter((f) => f.kev).length ?? 0;
      const enforcingSurfaces =
        (firewall?.active && firewall.mode === "enforce" ? 1 : 0);

      setState({
        kind: "ready",
        data: {
          quarantineCount: quarantine.length,
          bannedIpCount: bans.length,
          kevCount,
          enforcingSurfaces,
        },
      });
    }).catch((err: unknown) => {
      if (!cancelled) {
        setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
      }
    });
    return () => { cancelled = true; };
  }, []);

  if (state.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        Loading overview…
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
      </div>
    );
  }

  const { data } = state;

  // Build attention items
  const attention: AttentionRowProps[] = [];

  if (data.quarantineCount > 0) {
    attention.push({
      icon: "🔒",
      message: `${data.quarantineCount} file${data.quarantineCount !== 1 ? "s" : ""} in quarantine`,
      actionLabel: "View files",
      section: "files",
      onNavigate: setSection,
    });
  }
  if (data.bannedIpCount > 0) {
    attention.push({
      icon: "🚫",
      message: `${data.bannedIpCount} IP${data.bannedIpCount !== 1 ? "s" : ""} currently banned`,
      actionLabel: "View SSH",
      section: "ssh",
      onNavigate: setSection,
    });
  }
  if (data.kevCount > 0) {
    attention.push({
      icon: "⚠️",
      message: `${data.kevCount} Known Exploited Vulnerabilit${data.kevCount !== 1 ? "ies" : "y"} detected`,
      actionLabel: "View vulnerabilities",
      section: "vulnerabilities",
      onNavigate: setSection,
    });
  }

  return (
    <div className="space-y-4">
      {/* 4 stat tiles in a 2×2 grid */}
      <div className="grid grid-cols-2 gap-3">
        <StatTile
          label="Quarantined files"
          value={data.quarantineCount}
          color={data.quarantineCount > 0 ? "#B27B00" : "#1B8C3A"}
        />
        <StatTile
          label="Banned IPs"
          value={data.bannedIpCount}
          color={data.bannedIpCount > 0 ? "#B27B00" : "#1B8C3A"}
        />
        <StatTile
          label="KEV findings"
          value={data.kevCount}
          color={data.kevCount > 0 ? "#C8312A" : "#1B8C3A"}
        />
        <StatTile
          label="Enforcing surfaces"
          value={data.enforcingSurfaces}
          color={data.enforcingSurfaces > 0 ? "#1B8C3A" : "#8E8E93"}
        />
      </div>

      {/* Needs-attention section */}
      {attention.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-[11px] uppercase tracking-widest text-[#8E8E93]">
            Needs attention
          </h3>
          {attention.map((item) => (
            <AttentionRow key={item.section} {...item} />
          ))}
        </div>
      )}

      {attention.length === 0 && (
        <div
          className="rounded-xl px-5 py-6 text-sm text-[#636366]"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
        >
          All surfaces look healthy. No immediate action needed.
        </div>
      )}
    </div>
  );
}
