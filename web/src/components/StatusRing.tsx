export const STATES = {
  protected:  { label: "Protected",     color: "var(--status-protected)",  glyph: "shield.fill" },
  monitoring: { label: "Monitoring",    color: "var(--status-monitoring)", glyph: "eye.fill" },
  action:     { label: "Action needed", color: "var(--status-action)",     glyph: "exclamationmark.triangle.fill" },
  blocked:    { label: "Threat blocked",color: "var(--status-blocked)",    glyph: "xmark.shield.fill" },
} as const;
export type RingState = keyof typeof STATES;

export default function StatusRing({ state }: { state: RingState }) {
  const s = STATES[state];
  const R = 76, C = 2 * Math.PI * R; // 160px box, 8px stroke -> r=76
  return (
    <div className="flex flex-col items-center gap-3">
      <svg width={160} height={160} viewBox="0 0 160 160" role="img" aria-label={s.label}>
        <circle cx={80} cy={80} r={R} fill="none" stroke="var(--separator)" strokeWidth={8} />
        <circle data-testid="ring-arc" cx={80} cy={80} r={R} fill="none" stroke={s.color}
          strokeWidth={8} strokeLinecap="round" strokeDasharray={C}
          transform="rotate(-90 80 80)"
          style={{ transition: "stroke var(--d-base) var(--ease)" }} />
        <text x={80} y={86} textAnchor="middle" fontSize={28} fill={s.color} aria-hidden>
          {state === "protected" ? "✓" : state === "blocked" ? "✕" : "●"}
        </text>
      </svg>
      <div className="text-title1" style={{ color: s.color }}>{s.label}</div>
    </div>
  );
}
