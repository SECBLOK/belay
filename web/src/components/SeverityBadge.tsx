import type { Severity } from "../lib/api";

/**
 * Per-tier presentation tokens. `label` + `color` stay the stable contract for
 * existing callers (badge, accent border); the extra fields drive tier-scaled
 * behaviour on the approval card:
 *   - cardPulse:          run the single-shot Critical ring pulse
 *   - confirmAlwaysAllow: require a second click before "Always allow"
 *   - topAccent:          card top-edge accent thickness (null = none)
 * Color is NEVER the only signal: the badge always renders an icon + a text
 * label, and the accessible name carries the label text too.
 */
export interface SeverityMeta {
  label: string;
  color: string;
  cardPulse: boolean;
  confirmAlwaysAllow: boolean;
  topAccent: string | null;
}

const META: Record<string, SeverityMeta> = {
  critical: { label: "Critical", color: "var(--semantic-deny)", cardPulse: true, confirmAlwaysAllow: true, topAccent: "2px" },
  high: { label: "High", color: "#B55A10", cardPulse: false, confirmAlwaysAllow: true, topAccent: "2px" },
  medium: { label: "Medium", color: "var(--semantic-ask)", cardPulse: false, confirmAlwaysAllow: false, topAccent: "1px" },
  low: { label: "Low", color: "var(--semantic-info)", cardPulse: false, confirmAlwaysAllow: false, topAccent: null },
  info: { label: "Info", color: "var(--semantic-info)", cardPulse: false, confirmAlwaysAllow: false, topAccent: null },
};

/** Resolve severity metadata (label + color + tier tokens); unknown → medium. */
export function severityMeta(severity: string | undefined): SeverityMeta {
  return META[(severity ?? "").toLowerCase()] ?? META.medium;
}

/**
 * A compact severity chip: warning-triangle icon + text label, tinted by tier.
 * Color + icon + text (never color-only); `aria-label` repeats the text.
 */
export default function SeverityBadge({ severity }: { severity: Severity | string }) {
  const m = severityMeta(String(severity));
  return (
    <span
      role="img"
      aria-label={`Severity: ${m.label}`}
      className="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-xs font-medium"
      style={{ color: m.color, border: `1px solid ${m.color}` }}
    >
      <svg
        width="11" height="11" viewBox="0 0 12 12" aria-hidden="true" className="shrink-0"
        fill="none" stroke={m.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
      >
        <path d="M6 1L11 10.5H1L6 1Z" />
        <path d="M6 5v2.5" />
        <circle cx="6" cy="9" r="0.4" fill={m.color} stroke="none" />
      </svg>
      <span>{m.label}</span>
    </span>
  );
}
