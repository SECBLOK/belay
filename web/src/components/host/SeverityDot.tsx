// Promoted from Scan.tsx — shared severity badge used across Host sub-views.
// Accepts a lowercase severity prop matching the HostFinding type, but
// normalises to uppercase for lookup so callers never need to worry about case.

import type { HostFinding } from "../../lib/hostTypes";
import { useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

type Severity = HostFinding["severity"];

// Mirrors SEV_COLOR in Scan.tsx — one source of truth here for Host views.
// Both maps are keyed by the NORMALISED uppercase enum, never by the display
// label, so translating the label cannot change which colour a severity gets.
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#C8312A",
  HIGH:     "#AB550F",
  MEDIUM:   "#916400",
  LOW:      "#1A6BC5",
  INFO:     "#1A6BC5",
};

const SEV_DISPLAY: Record<string, MessageDescriptor> = {
  CRITICAL: msg`CRITICAL`,
  HIGH:     msg`HIGH`,
  MEDIUM:   msg`MEDIUM`,
  LOW:      msg`LOW`,
  INFO:     msg`INFO`,
};

interface SeverityDotProps {
  severity: Severity;
}

export default function SeverityDot({ severity }: SeverityDotProps) {
  const { t } = useLingui();
  const key = severity.toUpperCase();
  const color = SEV_COLOR[key] ?? "#6C6C71";
  const label = SEV_DISPLAY[key] ? t(SEV_DISPLAY[key]) : severity;
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: `${color}0f`, color }}
      aria-label={t`Severity: ${label}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} aria-hidden />
      {label}
    </span>
  );
}
