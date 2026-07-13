// Promoted from Scan.tsx — shared severity badge used across Host sub-views.
// Accepts a lowercase severity prop matching the HostFinding type, but
// normalises to uppercase for lookup so callers never need to worry about case.

import type { HostFinding } from "../../lib/hostTypes";

type Severity = HostFinding["severity"];

// Mirrors SEV_COLOR in Scan.tsx — one source of truth here for Host views.
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#C8312A",
  HIGH:     "#B55A10",
  MEDIUM:   "#B27B00",
  LOW:      "#1A6DC8",
  INFO:     "#1A6DC8",
};

interface SeverityDotProps {
  severity: Severity;
}

export default function SeverityDot({ severity }: SeverityDotProps) {
  const key = severity.toUpperCase();
  const color = SEV_COLOR[key] ?? "#8E8E93";
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: `${color}1f`, color }}
      aria-label={`Severity: ${severity}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} aria-hidden />
      {severity}
    </span>
  );
}
