import { useState } from "react";
import SegmentedNav from "../components/host/SegmentedNav";
import ErrorBoundary from "../components/ErrorBoundary";
import HostOverview from "./host/HostOverview";
import FilesScan from "./host/FilesScan";
import HostSkills from "./host/HostSkills";
import FirewallSetup from "./host/FirewallSetup";
import EgressControl from "./host/EgressControl";
import SshHardening from "./host/SshHardening";
import VulnPosture from "./host/VulnPosture";

export type HostSection =
  | "overview"
  | "files"
  | "skills"
  | "firewall"
  | "network"
  | "ssh"
  | "vulnerabilities";

const SECTIONS: readonly HostSection[] = [
  "overview",
  "files",
  "skills",
  "firewall",
  "network",
  "ssh",
  "vulnerabilities",
] as const;


function SectionPanel({
  section,
  setSection,
}: {
  section: HostSection;
  setSection: (s: HostSection) => void;
}) {
  switch (section) {
    case "overview":
      return <HostOverview setSection={setSection} />;
    case "files":
      return <FilesScan />;
    case "skills":
      return <HostSkills />;
    case "firewall":
      return <FirewallSetup />;
    case "network":
      return <EgressControl />;
    case "ssh":
      return <SshHardening />;
    case "vulnerabilities":
      return <VulnPosture />;
  }
}

// ── Main view ─────────────────────────────────────────────────────────────────

export default function Host() {
  const [section, setSection] = useState<HostSection>("overview");

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div className="mb-2">
        <h1 className="text-sm font-semibold text-[var(--text-tertiary)] uppercase tracking-widest">
          Host Protection
        </h1>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          Malware scanning, firewall, egress control, SSH hardening, and vulnerability management.
        </p>
      </div>

      <SegmentedNav
        sections={SECTIONS}
        active={section}
        onChange={(s) => setSection(s as HostSection)}
      />

      {/* A crash in any single section must not blank the whole app — keep the
          header + nav alive and show a localized, recoverable error instead.
          resetKey={section} clears a stale error when the user switches tabs. */}
      <ErrorBoundary label="This section" resetKey={section}>
        <SectionPanel section={section} setSection={setSection} />
      </ErrorBoundary>
    </div>
  );
}
