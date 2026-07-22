import { useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// `label` is a MessageDescriptor (resolved with `t()` at render), not a raw
// string, so the status text re-translates on locale change. The COLOUR/GLYPH
// are keyed by state, never by the label, so branching stays locale-proof.
export const STATES = {
  protected:  { label: msg`Protected`,      color: "var(--status-protected)",  glyph: "shield.fill" },
  monitoring: { label: msg`Monitoring`,     color: "var(--status-monitoring)", glyph: "eye.fill" },
  action:     { label: msg`Action needed`,  color: "var(--status-action)",     glyph: "exclamationmark.triangle.fill" },
  blocked:    { label: msg`Threat blocked`, color: "var(--status-blocked)",    glyph: "xmark.shield.fill" },
} as const satisfies Record<string, { label: MessageDescriptor; color: string; glyph: string }>;
export type RingState = keyof typeof STATES;

// The Belay guard-dog mascot — a loyal black Lab watching over your agents.
// Pose per state; a soft state-colored glow carries the green/amber/red signal
// without a hard ring. (Component name kept as StatusRing so callers are unchanged.)
const POSE: Record<RingState, string> = {
  protected: "happy",
  monitoring: "alert",
  action: "alert",
  blocked: "guard",
};

export default function StatusRing({ state }: { state: RingState }) {
  const { t } = useLingui();
  const s = STATES[state];
  const label = t(s.label);
  const pose = POSE[state];
  return (
    // key={state} replays the pop/wiggle whenever the status changes
    <div key={state} className="flex flex-col items-center gap-1" data-testid="mascot-status">
      <div style={{ position: "relative", width: 190, height: 176, display: "grid", placeItems: "center" }}>
        {/* soft state-colored glow — the guarding aura */}
        <div className="mascot-glow" aria-hidden style={{
          position: "absolute", width: 150, height: 150, borderRadius: "50%",
          background: `radial-gradient(circle, ${s.color} 0%, transparent 68%)`,
          filter: "blur(20px)", bottom: 8,
        }} />
        {/* the dog */}
        <img
          className={`mascot-img${state === "blocked" ? " mascot-alert" : ""}`}
          src={`/mascot/${pose}.png`}
          alt={label}
          width={168}
          height={168}
          style={{ position: "relative", display: "block", objectFit: "contain",
            filter: "drop-shadow(0 6px 10px rgba(17,24,39,0.18))" }}
        />
      </div>
      <div className="sr-label text-title1" style={{ color: s.color }}>{label}</div>
    </div>
  );
}
