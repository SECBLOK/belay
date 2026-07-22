// Host → Overview sub-view: 4 StatTiles + needs-attention rows that deep-link
// into the right sub-section via the Host shell's section setter.

import { useEffect, useState, type ReactNode } from "react";
import { listQuarantine, listBans, getVulnPosture, getFirewallStatus } from "../../lib/api";
import type { HostSection } from "../Host";
import { Plural, Trans, useLingui } from "@lingui/react/macro";

// ── StatTile ─────────────────────────────────────────────────────────────────

interface StatTileProps {
  label: string;
  value: number;
  color?: string;
}

function StatTile({ label, value, color = "#1C1C1E" }: StatTileProps) {
  return (
    <div
      className="lg-glass px-4 py-4 flex flex-col gap-1"
     
    >
      <div className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]">{label}</div>
      <div className="text-3xl font-mono tabular-nums font-bold leading-tight" style={{ color }}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}

// ── AttentionRow ──────────────────────────────────────────────────────────────

interface AttentionRowProps {
  icon: string;
  message: ReactNode;
  actionLabel: string;
  section: HostSection;
  onNavigate: (s: HostSection) => void;
}

function AttentionRow({ icon, message, actionLabel, section, onNavigate }: AttentionRowProps) {
  return (
    <div
      className="flex items-center gap-3 px-4 py-3 lg-glass border-l-4"
      style={{ border: "1px solid rgba(0,0,0,0.08)", borderLeftColor: "#916400", borderLeftWidth: 4 }}
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
  skillQuarantineCount: number;
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
  const { t } = useLingui();
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

      // Honesty: the "Quarantined files" tile must count only actual files.
      // Quarantined agent SKILLS are whole directories (`kind: "dir"`) and belong
      // on the Skills surface — counting them here mislabeled them as files.
      const quarantinedFiles = quarantine.filter((q) => q.kind !== "dir");
      const quarantinedSkills = quarantine.filter((q) => q.kind === "dir");
      setState({
        kind: "ready",
        data: {
          quarantineCount: quarantinedFiles.length,
          skillQuarantineCount: quarantinedSkills.length,
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
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading overview…</Trans>
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

  const { data } = state;

  // Build attention items
  const attention: AttentionRowProps[] = [];

  if (data.quarantineCount > 0) {
    attention.push({
      icon: "🔒",
      message: (
        <Plural
          value={data.quarantineCount}
          one="# file in quarantine"
          other="# files in quarantine"
        />
      ),
      actionLabel: t`View files`,
      section: "files",
      onNavigate: setSection,
    });
  }
  if (data.skillQuarantineCount > 0) {
    attention.push({
      icon: "🧩",
      message: (
        <Plural
          value={data.skillQuarantineCount}
          one="# skill in quarantine"
          other="# skills in quarantine"
        />
      ),
      actionLabel: t`View skills`,
      section: "skills",
      onNavigate: setSection,
    });
  }
  if (data.bannedIpCount > 0) {
    attention.push({
      icon: "🚫",
      message: (
        <Plural
          value={data.bannedIpCount}
          one="# IP currently banned"
          other="# IPs currently banned"
        />
      ),
      actionLabel: t`View SSH`,
      section: "ssh",
      onNavigate: setSection,
    });
  }
  if (data.kevCount > 0) {
    attention.push({
      icon: "⚠️",
      message: (
        <Plural
          value={data.kevCount}
          one="# Known Exploited Vulnerability detected"
          other="# Known Exploited Vulnerabilities detected"
        />
      ),
      actionLabel: t`View vulnerabilities`,
      section: "vulnerabilities",
      onNavigate: setSection,
    });
  }

  return (
    <div className="space-y-4">
      {/* Quarantine pair — the two things Belay has physically pulled aside. */}
      <div className="grid grid-cols-2 gap-3">
        <StatTile
          label={t`Quarantined files`}
          value={data.quarantineCount}
          color={data.quarantineCount > 0 ? "#916400" : "#187D34"}
        />
        <StatTile
          label={t`Quarantined skills`}
          value={data.skillQuarantineCount}
          color={data.skillQuarantineCount > 0 ? "#916400" : "#187D34"}
        />
      </div>
      {/* Posture triad — the live host-control signals. */}
      <div className="grid grid-cols-3 gap-3">
        <StatTile
          label={t`Banned IPs`}
          value={data.bannedIpCount}
          color={data.bannedIpCount > 0 ? "#916400" : "#187D34"}
        />
        <StatTile
          label={t`KEV findings`}
          value={data.kevCount}
          color={data.kevCount > 0 ? "#C8312A" : "#187D34"}
        />
        <StatTile
          label={t`Enforcing surfaces`}
          value={data.enforcingSurfaces}
          color={data.enforcingSurfaces > 0 ? "#187D34" : "var(--text-tertiary)"}
        />
      </div>

      {/* Needs-attention section */}
      {attention.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]">
            <Trans>Needs attention</Trans>
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
          <Trans>All surfaces look healthy. No immediate action needed.</Trans>
        </div>
      )}
    </div>
  );
}
