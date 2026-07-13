import type { ReactNode } from "react";
import type { Explanation } from "../lib/explain";
import { severityMeta } from "./SeverityBadge";

// A single labelled field: the label is a real <h3> (fixes heading semantics —
// these were <span>s before) and the value a plain paragraph.
function Field({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <h3 className="text-text-secondary text-xs uppercase tracking-wide font-normal">{label}</h3>
      <p className="text-text-primary">{children}</p>
    </div>
  );
}

/**
 * The plain-English explanation body of the approval card: what / why-risky /
 * is-this-normal / suggested-action. Reads as a top-down risk story —
 * neutral facts first, the risk called out with a tier-tinted accent, a
 * reassurance cue on "is this normal?", and the recommended action landing
 * last in a recessed panel so the eye ends on what to do.
 */
export default function ExplanationPanel({ ex }: { ex: Explanation }) {
  const riskColor = severityMeta(ex.severity).color;
  return (
    <>
      {/* What this is — neutral framing */}
      {ex.what && <Field label="What this is">{ex.what}</Field>}

      {/* What could go wrong — tier-tinted accent block + warning glyph */}
      {ex.why_risky && (
        <div className="flex gap-2 pl-3" style={{ borderLeft: `2px solid ${riskColor}` }}>
          <svg
            width="12" height="12" viewBox="0 0 12 12" className="mt-1 shrink-0" aria-hidden="true"
            fill="none" stroke={riskColor} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
          >
            <path d="M6 1L11 10.5H1L6 1Z" />
            <path d="M6 5v2.5" />
            <circle cx="6" cy="9" r="0.4" fill={riskColor} stroke="none" />
          </svg>
          <div className="space-y-0.5">
            <h3 className="text-text-secondary text-xs uppercase tracking-wide font-normal">What could go wrong</h3>
            <p className="text-text-primary">{ex.why_risky}</p>
          </div>
        </div>
      )}

      {/* Is this normal? — a small reassurance check-circle marks it as calming */}
      {ex.normal_use && (
        <Field
          label={
            <span className="inline-flex items-center gap-1">
              <svg
                width="12" height="12" viewBox="0 0 24 24" className="shrink-0" aria-hidden="true"
                fill="none" stroke="var(--semantic-info)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
              >
                <circle cx="12" cy="12" r="10" />
                <path d="M8 12l3 3 5-6" />
              </svg>
              Is this normal?
            </span>
          }
        >
          {ex.normal_use}
        </Field>
      )}

      {/* Suggested action — recessed neutral panel, placed last so it reads as the takeaway */}
      {ex.suggested_action && (
        <div className="rounded-card bg-window px-3 py-2.5 space-y-0.5">
          <h3 className="text-text-secondary text-xs uppercase tracking-wide font-normal">Suggested action</h3>
          <p className="font-medium text-text-primary">{ex.suggested_action}</p>
        </div>
      )}
    </>
  );
}
