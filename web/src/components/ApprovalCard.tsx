import { useEffect, useMemo, useRef, useState } from "react";
import { explainFor, type Explanation } from "../lib/explain";
import SeverityBadge, { severityMeta } from "./SeverityBadge";
import ExplanationPanel from "./ExplanationPanel";
import type { Explain, Severity } from "../lib/api";
import { aiStatus, explainAction } from "../lib/ipc";

type Decision = "allow" | "deny";
type Scope = "once" | "always";
export type Risk = "low" | "medium" | "high";

/** Original tool-approval variant (kind absent or "tool") */
export interface Pending {
  id: string; agent: string; tool: string; input: Record<string, unknown>;
  // risk is `string` (not the narrow union) so verbatim payloads with an inline
  // `risk: "high"` literal type-check; only `=== "high"` is ever read.
  reason: string; rule: string; risk?: Risk | string;
  // Explain & Advise: curated severity/category/explanation from the daemon
  // verdict snapshot. All optional (absent on older rows / open build).
  severity?: Severity | string;
  category?: string;
  explain?: Explain;
}

/** Egress (outbound connection) approval variant */
export interface EgressPending {
  kind: "egress";
  id: string;
  agent: string;
  dest: string;
  binary: string;
  risk?: Risk | string;
}

/** Discriminated union — egress has kind:"egress"; tool variant has no kind (or kind:"tool") */
export type AnyPending = Pending | EgressPending;

export const isEgress = (p: AnyPending): p is EgressPending =>
  (p as EgressPending).kind === "egress";

const targetOf = (p: Pending) =>
  p.input.command ?? p.input.path ?? p.input.url ?? JSON.stringify(p.input);

const targetLabel = (p: Pending): string => {
  if (p.input.command != null) return "Command it wants to run:";
  if (p.input.path != null) return "File it wants to read:";
  if (p.input.url != null) return "URL it wants to reach:";
  return "Details:";
};

// ── Shared countdown ring ─────────────────────────────────────────────────────
// A calm circular progress ring with the remaining seconds in the centre.
// Time-aware tint: info/muted → amber under ~15s → red under ~5s. No flashing.

function Countdown({ left, total }: { left: number; total: number }) {
  const R = 16;                       // ring radius (≈40px box with stroke)
  const C = 2 * Math.PI * R;
  const frac = total > 0 ? Math.max(0, Math.min(1, left / total)) : 0;
  const offset = C * (1 - frac);
  const color =
    left <= 5 ? "var(--semantic-deny)" :
    left <= 15 ? "var(--semantic-ask)" :
    "var(--semantic-info)";
  return (
    <div className="flex items-center gap-3">
      <svg width="40" height="40" viewBox="0 0 40 40" className="shrink-0" aria-hidden="true">
        <circle cx="20" cy="20" r={R} fill="none" stroke="var(--separator)" strokeWidth="2.5" />
        <circle
          cx="20" cy="20" r={R} fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round"
          strokeDasharray={C} strokeDashoffset={offset}
          transform="rotate(-90 20 20)"
          className="transition-[stroke-dashoffset] duration-1000 ease-linear"
        />
        <text x="20" y="20" textAnchor="middle" dominantBaseline="central"
          className="tabular-nums text-sm" fill="var(--text-primary)" fontSize="13">
          {left}
        </text>
      </svg>
      <div className="space-y-0.5">
        <p className="text-text-primary text-sm">Auto-blocks in {left}s</p>
        <p className="text-text-secondary text-xs">No response &rarr; blocked automatically.</p>
      </div>
    </div>
  );
}

// ── Egress card body ─────────────────────────────────────────────────────────

function EgressBody({
  pending, armed, left, total, act,
}: {
  pending: EgressPending;
  armed: boolean;
  left: number;
  total: number;
  act: (d: Decision, s: Scope) => void;
}) {
  // High-risk egress → Deny leads: Allow once recedes to a ghost button while
  // Deny keeps the filled emphasis (same button order/positions either way).
  const denyLeads = pending.risk === "high";
  return (
    <>
      {/* Header */}
      <div className="space-y-1">
        <span className="text-text-secondary text-sm">{pending.agent}</span>
        <h2 className="text-text-primary font-semibold text-lg leading-snug">
          Outbound connection blocked
        </h2>
      </div>

      {/* Binary */}
      <div className="space-y-1">
        <span className="text-text-secondary text-xs uppercase tracking-wide">Process:</span>
        <div data-testid="egress-binary" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary break-all">
          {pending.binary}
        </div>
      </div>

      {/* Destination */}
      <div className="space-y-1">
        <span className="text-text-secondary text-xs uppercase tracking-wide">Destination:</span>
        <div data-testid="egress-dest" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary break-all">
          {pending.dest}
        </div>
      </div>

      {/* Countdown */}
      <Countdown left={left} total={total} />

      {/* Little-Snitch triad */}
      <div className="space-y-2">
        <button
          disabled={!armed}
          className={denyLeads
            ? "w-full py-2 rounded-pill border border-[var(--separator)] text-text-primary"
            : "w-full py-2 rounded-pill font-medium text-white"}
          style={denyLeads ? undefined : { background: "var(--semantic-allow)" }}
          onClick={() => act("allow", "once")}
        >
          Allow once
        </button>
        <button
          disabled={!armed}
          className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
          onClick={() => act("allow", "always")}
        >
          Always
        </button>
        <button
          disabled={!armed}
          className="w-full py-2 rounded-pill text-white font-medium"
          style={{ background: "var(--semantic-deny)" }}
          onClick={() => act("deny", "once")}
        >
          Deny
        </button>
      </div>
    </>
  );
}

// ── Tool card body ────────────────────────────────────────────────────────────

function ToolBody({
  pending, armed, left, total, act, ex,
}: {
  pending: Pending;
  armed: boolean;
  left: number;
  total: number;
  act: (d: Decision, s: Scope) => void;
  // Curated explanation resolved once by the parent (daemon `explain` → per-rule
  // KB → category fallback → generic). Passed in so it isn't recomputed here.
  ex: Explanation;
}) {
  const [alwaysConfirm, setAlwaysConfirm] = useState(false);
  const [showCommand, setShowCommand] = useState(false);

  // On-demand "Explain with AI": hidden entirely unless the daemon reports the
  // (optional, off-by-default) `ai` feature is enabled. `aiState` tracks the
  // fetch lifecycle; the curated `ex` above is ALWAYS rendered regardless —
  // this is purely additive.
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiState, setAiState] = useState<"idle" | "loading" | "shown" | "unavailable">("idle");
  const [aiExplanation, setAiExplanation] = useState<Explanation | null>(null);
  // Collapse toggle for the AI opinion once shown — purely a display switch,
  // the fetched aiExplanation stays cached so re-expanding never refetches.
  const [aiCollapsed, setAiCollapsed] = useState(false);

  // Shared unmount guard for the two async sites below (mount probe + on-demand
  // click fetch). The card unmounts as soon as the approval resolves (user acts,
  // or the 45s auto-deny fires) — an in-flight promise must not `setState` after
  // that point.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    aiStatus().then((enabled) => {
      if (mountedRef.current) setAiEnabled(enabled);
    });
  }, []);

  const handleExplainWithAi = async () => {
    if (aiState === "loading") return; // guard against double-fetch
    setAiState("loading");
    const result = await explainAction(pending.tool, pending.input, pending.rule);
    if (!mountedRef.current) return;
    if (result) {
      setAiExplanation(
        explainFor({
          rules: pending.rule ? [pending.rule] : [],
          explain: result,
          reason: pending.reason,
          severity: pending.severity,
          category: pending.category,
        }),
      );
      setAiState("shown");
    } else {
      setAiState("unavailable");
    }
  };

  // Tier-scaled behaviour keyed off the RESOLVED severity (not the raw daemon
  // `risk`): whether "Always allow" needs a confirm, and whether Deny leads.
  const confirmAlwaysAllow = severityMeta(ex.severity).confirmAlwaysAllow;
  const denyLeads = ex.severity === "critical" || ex.severity === "high";

  // Strip a leading `${rule}:` prefix so the reason line shows only the human
  // clause (the raw rule id already lives in the footnote below).
  const humanReason =
    pending.rule && pending.reason.startsWith(pending.rule + ":")
      ? pending.reason.slice(pending.rule.length + 1).trim()
      : pending.reason;

  const handleAlwaysAllow = () => {
    if (!armed) return;
    if (confirmAlwaysAllow && !alwaysConfirm) {
      setAlwaysConfirm(true);
      return;
    }
    act("allow", "always");
  };

  return (
    <>
      {/* ── Reading zone: what happened + why it matters ────────────────── */}
      <div className="space-y-3">
        {/* Header: agent name + severity badge + curated summary headline */}
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <span className="text-text-secondary text-sm min-w-0 truncate">{pending.agent}</span>
            <span className="shrink-0">
              <SeverityBadge severity={ex.severity} />
            </span>
          </div>
          <h2 className="text-text-primary font-semibold text-lg leading-snug">
            {ex.summary}
          </h2>
        </div>

        {/* Original reason (raw daemon detail — demoted below the summary) */}
        <p className="text-text-secondary text-sm">{humanReason}</p>

        {/* Plain-English explanation body — the curated copy ALWAYS renders,
            whether or not the AI affordance below is available/used. */}
        <ExplanationPanel ex={ex} />

        {/* On-demand "Explain with AI" — hidden entirely when the daemon's
            optional `ai` feature is off. Additive: never replaces the
            curated explanation above. */}
        {aiEnabled && (
          <div className="space-y-2">
            {aiState === "idle" && (
              <button
                type="button"
                onClick={handleExplainWithAi}
                className="text-text-secondary text-xs hover:text-text-primary underline"
              >
                Explain with AI
              </button>
            )}
            {aiState === "loading" && (
              <button
                type="button"
                disabled
                aria-live="polite"
                className="text-text-secondary text-xs"
              >
                Thinking…
              </button>
            )}
            {aiState === "shown" && aiExplanation && (
              aiCollapsed ? (
                <button
                  type="button"
                  onClick={() => setAiCollapsed(false)}
                  aria-expanded={false}
                  className="text-text-secondary text-xs hover:text-text-primary"
                >
                  <span aria-hidden="true">▸</span> Show AI opinion
                </button>
              ) : (
                // Recessed secondary panel — visually distinct from the curated
                // block above so it reads as a supplementary "second opinion",
                // not a redundant clone. Tighter internal rhythm (space-y-1.5).
                <div
                  role="group"
                  aria-label="AI-generated explanation"
                  className="rounded-card bg-window px-3 py-3 space-y-1.5"
                >
                  <span
                    role="img"
                    aria-label="AI-generated — may be imperfect"
                    className="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-xs font-medium"
                    style={{ color: "var(--semantic-ask)", border: "1px solid var(--semantic-ask)" }}
                  >
                    <svg
                      width="11" height="11" viewBox="0 0 12 12" aria-hidden="true" className="shrink-0"
                      fill="none" stroke="var(--semantic-ask)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
                    >
                      <path d="M6 1v2.2M6 8.8V11M1 6h2.2M8.8 6H11M2.76 2.76l1.56 1.56M7.68 7.68l1.56 1.56M2.76 9.24l1.56-1.56M7.68 4.32l1.56-1.56" />
                    </svg>
                    <span>AI · may be imperfect</span>
                  </span>
                  <ExplanationPanel ex={aiExplanation} />
                  <button
                    type="button"
                    onClick={() => setAiCollapsed(true)}
                    aria-expanded={true}
                    className="text-text-secondary text-xs hover:text-text-primary"
                  >
                    <span aria-hidden="true">▾</span> Hide AI opinion
                  </button>
                </div>
              )
            )}
            {aiState === "unavailable" && (
              <p className="text-text-secondary text-xs italic">AI explanation unavailable</p>
            )}
          </div>
        )}
      </div>

      {/* ── Divider: reading zone above, action zone below ──────────────── */}
      <hr className="border-0 border-t border-[var(--border-hairline)]" />

      {/* Progressive disclosure: the raw command/path, collapsed by default.
          Reading is always allowed — not gated by the keystroke `armed` guard. */}
      <div className="space-y-1">
        <button
          type="button"
          onClick={() => setShowCommand((v) => !v)}
          aria-expanded={showCommand}
          aria-controls="approval-command"
          className="text-text-secondary text-xs hover:text-text-primary"
        >
          <span aria-hidden="true">{showCommand ? "▾" : "▸"}</span> {showCommand ? "Hide command" : "Show command"}
        </button>
        <div id="approval-command" className={showCommand ? "space-y-1" : "hidden"}>
          <span className="text-text-secondary text-xs uppercase tracking-wide">{targetLabel(pending)}</span>
          <div data-testid="target" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary overflow-x-auto whitespace-pre">
            {String(targetOf(pending))}
          </div>
        </div>
      </div>

      {/* Calm countdown ring */}
      <Countdown left={left} total={total} />

      {/* Action buttons — Deny leads on high/critical; Allow once recedes to a
          ghost. Button order/positions stay constant across tiers. */}
      <div className="space-y-2">
        {/* Allow once: filled when calm, ghost when Deny leads */}
        <button
          disabled={!armed}
          className={denyLeads
            ? "w-full py-2 rounded-pill border border-[var(--separator)] text-text-primary"
            : "w-full py-2 rounded-pill font-medium text-white"}
          style={denyLeads ? undefined : { background: "var(--semantic-allow)" }}
          onClick={() => act("allow", "once")}
        >
          Allow once
        </button>

        {/* Always allow (outline/ghost, de-emphasized; high-risk needs confirm) */}
        {alwaysConfirm && confirmAlwaysAllow ? (
          <button
            disabled={!armed}
            className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={handleAlwaysAllow}
          >
            Confirm — always allow (even when risk is high)
          </button>
        ) : (
          <button
            disabled={!armed}
            className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={handleAlwaysAllow}
          >
            Always allow
          </button>
        )}

        {/* Deny — always the filled/primary emphasis */}
        <div className="grid grid-cols-2 gap-2 pt-1">
          <button
            disabled={!armed}
            className="py-2 rounded-pill text-white font-medium"
            style={{ background: "var(--semantic-deny)" }}
            onClick={() => act("deny", "once")}
          >
            Deny
          </button>
          <button
            disabled={!armed}
            className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={() => act("deny", "always")}
          >
            Deny &amp; stop agent
          </button>
        </div>
      </div>

      {/* Rule-id footnote (demoted, for the curious / support) */}
      <p className="text-[10px] text-text-secondary font-mono">rule · {pending.rule}</p>
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ApprovalCard({
  pending, onResolve, timeoutMs = 45000,
}: { pending: AnyPending; onResolve: (id: string, d: Decision, s: Scope) => void; timeoutMs?: number }) {
  const [armed, setArmed] = useState(false);          // ~1s keystroke guard
  const [left, setLeft] = useState(Math.ceil(timeoutMs / 1000));
  const done = useRef(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const total = Math.ceil(timeoutMs / 1000);

  useEffect(() => {
    const g = setTimeout(() => setArmed(true), 1000);
    const tick = setInterval(() => setLeft((n) => Math.max(0, n - 1)), 1000);
    const to = setTimeout(() => { if (!done.current) { done.current = true; onResolve(pending.id, "deny", "once"); } }, timeoutMs);
    return () => { clearTimeout(g); clearInterval(tick); clearTimeout(to); };
  }, [pending.id, timeoutMs, onResolve]);

  // Focus the dialog on mount so keyboard/screen-reader users land inside it;
  // restore focus to the previously-focused element when it unmounts.
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    return () => { prev?.focus?.(); };
  }, [pending.id]);

  const act = (d: Decision, s: Scope) => { if (!armed || done.current) return; done.current = true; onResolve(pending.id, d, s); };

  // Resolve the curated explanation ONCE for tool cards (memoized on the pending
  // identity), then reuse it for both the accent gate and the ToolBody render.
  const toolEx = useMemo(
    () =>
      isEgress(pending)
        ? null
        : explainFor({
            rules: pending.rule ? [pending.rule] : [],
            explain: pending.explain,
            reason: pending.reason,
            severity: pending.severity,
            category: pending.category,
          }),
    [pending],
  );

  // Resolved severity drives the restrained, single-shot Critical accent + the
  // top-edge accent. Egress has no daemon severity — map its `risk` tier; tool
  // cards use the shared renderer. All motion is CSS-gated behind reduced-motion.
  const severity = isEgress(pending)
    ? String(pending.risk ?? "medium")
    : toolEx!.severity;
  const meta = severityMeta(severity);
  const cardClass =
    "bg-white rounded-modal p-6 max-w-md w-full space-y-4 alert-enter max-h-[calc(100vh-2rem)] overflow-y-auto" +
    (meta.cardPulse ? " alert-critical-pulse" : "");

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black/40 backdrop-blur-sm p-4">
      <div
        ref={dialogRef}
        tabIndex={-1}
        className={cardClass}
        style={{
          boxShadow: "var(--shadow-modal)",
          borderTop: meta.topAccent ? `${meta.topAccent} solid ${meta.color}` : undefined,
        }}
        role="alertdialog"
        aria-modal="true"
        aria-label="Approval required"
      >
        {isEgress(pending) ? (
          <EgressBody pending={pending} armed={armed} left={left} total={total} act={act} />
        ) : (
          <ToolBody pending={pending} armed={armed} left={left} total={total} act={act} ex={toolEx!} />
        )}
      </div>
    </div>
  );
}
