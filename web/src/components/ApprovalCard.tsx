import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { explainFor, type Explanation } from "../lib/explain";
import SeverityBadge, { severityMeta } from "./SeverityBadge";
import ExplanationPanel from "./ExplanationPanel";
import type { Explain, Severity } from "../lib/api";
import { aiStatus, explainAction } from "../lib/ipc";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

type Decision = "allow" | "deny";
// "rule": deny this call AND temporarily mute the rule that fired it — every
// future Ask on the same rule id auto-denies until the mute expires or is
// revoked (see MutedRulesPanel). Deny-only; the daemon refuses it outright if
// sent with an "allow" decision.
type Scope = "once" | "always" | "rule";
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

// A gate on an MCP-server config change routes through the same approval path
// as any tool call, tagged with an `mcp.install.*` rule. The card specializes
// its copy so the user reads it as "a new MCP server is being added," not "a
// command wants to run."
const isMcpInstall = (p: Pending): boolean => (p.rule ?? "").startsWith("mcp.install");

const targetLabel = (p: Pending): MessageDescriptor => {
  if (isMcpInstall(p)) return msg`MCP server configuration:`;
  if (p.input.command != null) return msg`Command it wants to run:`;
  if (p.input.path != null) return msg`File it wants to read:`;
  if (p.input.url != null) return msg`URL it wants to reach:`;
  return msg`Details:`;
};

// Extract a short human string from an IPC rejection. Tauri usually rejects
// with a plain string (the Rust command's Err payload), but stay defensive
// about Error-shaped values too (e.g. a transport-level failure).
function errorMessage(e: unknown): string {
  return String((e as { message?: string } | undefined)?.message ?? e);
}

// Shared in-flight / failure indicator for the action-button zone. A silent
// failure on this control is the defect this exists to close: the operator
// must see that a click is being sent, and if it fails, see why and that the
// buttons are usable again (the parent leaves `armed`/`done` alone on
// failure - see ApprovalCard's `act`).
function ApprovalStatus({ busy, error }: { busy: boolean; error: string | null }) {
  if (error) {
    return (
      <p role="alert" data-testid="approval-error" className="text-xs" style={{ color: "var(--semantic-deny)" }}>
        <Trans>Could not send your response: {error}</Trans>{" "}
        <Trans>Tap a button below to try again.</Trans>
      </p>
    );
  }
  if (busy) {
    return (
      <p role="status" data-testid="approval-busy" className="text-text-secondary text-xs">
        <Trans>Sending your response…</Trans>
      </p>
    );
  }
  return null;
}

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
        <p className="text-text-primary text-sm"><Trans>Auto-blocks in {left}s</Trans></p>
        <p className="text-text-secondary text-xs"><Trans>No response &rarr; blocked automatically.</Trans></p>
      </div>
    </div>
  );
}

// ── Egress card body ─────────────────────────────────────────────────────────

function EgressBody({
  pending, armed, left, total, act, busy, error,
}: {
  pending: EgressPending;
  armed: boolean;
  left: number;
  total: number;
  act: (d: Decision, s: Scope) => void;
  busy: boolean;
  error: string | null;
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
          <Trans>Outbound connection blocked</Trans>
        </h2>
      </div>

      {/* Binary */}
      <div className="space-y-1">
        <span className="text-text-secondary text-xs uppercase tracking-wide"><Trans>Process:</Trans></span>
        <div data-testid="egress-binary" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary break-all">
          {pending.binary}
        </div>
      </div>

      {/* Destination */}
      <div className="space-y-1">
        <span className="text-text-secondary text-xs uppercase tracking-wide"><Trans>Destination:</Trans></span>
        <div data-testid="egress-dest" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary break-all">
          {pending.dest}
        </div>
      </div>

      {/* Countdown */}
      <Countdown left={left} total={total} />

      {/* In-flight / failure indicator - see ApprovalStatus */}
      <ApprovalStatus busy={busy} error={error} />

      {/* Little-Snitch triad */}
      <div className="space-y-2">
        <button
          disabled={!armed || busy}
          className={denyLeads
            ? "w-full py-2 rounded-pill border border-[var(--separator)] text-text-primary"
            : "w-full py-2 rounded-pill font-medium text-white"}
          style={denyLeads ? undefined : { background: "var(--semantic-allow)" }}
          onClick={() => act("allow", "once")}
        >
          <Trans>Allow once</Trans>
        </button>
        <button
          disabled={!armed || busy}
          className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
          onClick={() => act("allow", "always")}
        >
          <Trans>Always</Trans>
        </button>
        <button
          disabled={!armed || busy}
          className="w-full py-2 rounded-pill text-white font-medium"
          style={{ background: "var(--semantic-deny)" }}
          onClick={() => act("deny", "once")}
        >
          <Trans>Deny</Trans>
        </button>
      </div>
    </>
  );
}

// ── Tool card body ────────────────────────────────────────────────────────────

function ToolBody({
  pending, armed, left, total, act, ex, busy, error,
}: {
  pending: Pending;
  armed: boolean;
  left: number;
  total: number;
  act: (d: Decision, s: Scope) => void;
  // Curated explanation resolved once by the parent (daemon `explain` → per-rule
  // KB → category fallback → generic). Passed in so it isn't recomputed here.
  ex: Explanation;
  busy: boolean;
  error: string | null;
}) {
  const { t } = useLingui();
  const [alwaysConfirm, setAlwaysConfirm] = useState(false);
  const [showCommand, setShowCommand] = useState(false);
  const mcpInstall = isMcpInstall(pending);
  // The collapsed detail is an MCP config change, not a shell command.

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
          {mcpInstall && (
            <span
              className="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-xs font-medium"
              style={{ color: "var(--semantic-ask)", border: "1px solid var(--semantic-ask)" }}
            >
              <span aria-hidden>🔌</span> <Trans>MCP server change</Trans>
            </span>
          )}
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
                <Trans>Explain with AI</Trans>
              </button>
            )}
            {aiState === "loading" && (
              <button
                type="button"
                disabled
                aria-live="polite"
                className="text-text-secondary text-xs"
              >
                <Trans>Thinking…</Trans>
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
                  <span aria-hidden="true">▸</span> <Trans>Show AI opinion</Trans>
                </button>
              ) : (
                // Recessed secondary panel — visually distinct from the curated
                // block above so it reads as a supplementary "second opinion",
                // not a redundant clone. Tighter internal rhythm (space-y-1.5).
                <div
                  role="group"
                  aria-label={t`AI-generated explanation`}
                  className="rounded-card bg-window px-3 py-3 space-y-1.5"
                >
                  <span
                    role="img"
                    aria-label={t`AI-generated — may be imperfect`}
                    className="inline-flex items-center gap-1 rounded-pill px-2 py-0.5 text-xs font-medium"
                    style={{ color: "var(--semantic-ask)", border: "1px solid var(--semantic-ask)" }}
                  >
                    <svg
                      width="11" height="11" viewBox="0 0 12 12" aria-hidden="true" className="shrink-0"
                      fill="none" stroke="var(--semantic-ask)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
                    >
                      <path d="M6 1v2.2M6 8.8V11M1 6h2.2M8.8 6H11M2.76 2.76l1.56 1.56M7.68 7.68l1.56 1.56M2.76 9.24l1.56-1.56M7.68 4.32l1.56-1.56" />
                    </svg>
                    <span><Trans>AI · may be imperfect</Trans></span>
                  </span>
                  <ExplanationPanel ex={aiExplanation} />
                  <button
                    type="button"
                    onClick={() => setAiCollapsed(true)}
                    aria-expanded={true}
                    className="text-text-secondary text-xs hover:text-text-primary"
                  >
                    <span aria-hidden="true">▾</span> <Trans>Hide AI opinion</Trans>
                  </button>
                </div>
              )
            )}
            {aiState === "unavailable" && (
              <p className="text-text-secondary text-xs italic"><Trans>AI explanation unavailable</Trans></p>
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
          <span aria-hidden="true">{showCommand ? "▾" : "▸"}</span>{" "}
          {showCommand
            ? (mcpInstall ? t`Hide config` : t`Hide command`)
            : (mcpInstall ? t`Show config` : t`Show command`)}
        </button>
        <div id="approval-command" className={showCommand ? "space-y-1" : "hidden"}>
          <span className="text-text-secondary text-xs uppercase tracking-wide">{t(targetLabel(pending))}</span>
          <div data-testid="target" className="bg-window rounded-card px-3 py-2 font-mono text-mono text-text-secondary overflow-x-auto whitespace-pre">
            {String(targetOf(pending))}
          </div>
        </div>
      </div>

      {/* Calm countdown ring */}
      <Countdown left={left} total={total} />

      {/* In-flight / failure indicator - see ApprovalStatus */}
      <ApprovalStatus busy={busy} error={error} />

      {/* Action buttons — Deny leads on high/critical; Allow once recedes to a
          ghost. Button order/positions stay constant across tiers. */}
      <div className="space-y-2">
        {/* Allow once: filled when calm, ghost when Deny leads */}
        <button
          disabled={!armed || busy}
          className={denyLeads
            ? "w-full py-2 rounded-pill border border-[var(--separator)] text-text-primary"
            : "w-full py-2 rounded-pill font-medium text-white"}
          style={denyLeads ? undefined : { background: "var(--semantic-allow)" }}
          onClick={() => act("allow", "once")}
        >
          <Trans>Allow once</Trans>
        </button>

        {/* Always allow (outline/ghost, de-emphasized; high-risk needs confirm) */}
        {alwaysConfirm && confirmAlwaysAllow ? (
          <button
            disabled={!armed || busy}
            className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={handleAlwaysAllow}
          >
            <Trans>Confirm — always allow (even when risk is high)</Trans>
          </button>
        ) : (
          <button
            disabled={!armed || busy}
            className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={handleAlwaysAllow}
          >
            <Trans>Always allow</Trans>
          </button>
        )}

        {/* Deny — always the filled/primary emphasis */}
        <div className="grid grid-cols-2 gap-2 pt-1">
          <button
            disabled={!armed || busy}
            className="py-2 rounded-pill text-white font-medium"
            style={{ background: "var(--semantic-deny)" }}
            onClick={() => act("deny", "once")}
          >
            <Trans>Deny</Trans>
          </button>
          <button
            disabled={!armed || busy}
            className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
            onClick={() => act("deny", "always")}
          >
            <Trans>Deny &amp; stop agent</Trans>
          </button>
        </div>

        {/* Rule-scoped deny mute: a flood of near-identical Asks for the same
            rule (e.g. an agent probing which credential paths are gated) is
            itself an attack shape — this lets the operator deny once and stop
            being asked about that rule for a while, instead of clicking Deny
            one at a time. Strictly more restrictive than doing nothing, never
            less; the daemon may still refuse (critical severity, an
            unmutable rule, a detected self-approval, or the 8-mute cap) —
            see ApprovalSurface's mute notice for why. No confirm step: a
            second click would defeat the reason this button exists. */}
        <button
          disabled={!armed || busy}
          className="w-full py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-xs"
          onClick={() => act("deny", "rule")}
        >
          <Trans>Deny &amp; mute this rule</Trans>
        </button>
      </div>

      {/* Rule-id footnote (demoted, for the curious / support) */}
      <p className="text-[10px] text-text-secondary font-mono"><Trans>rule · {pending.rule}</Trans></p>
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ApprovalCard({
  pending, onResolve, timeoutMs = 45000,
}: { pending: AnyPending; onResolve: (id: string, d: Decision, s: Scope) => Promise<void>; timeoutMs?: number }) {
  const { t } = useLingui();
  const [armed, setArmed] = useState(false);          // ~1s keystroke guard
  // `armed` (state, for rendering) is mirrored into a ref so the guard inside
  // `act` always reads the CURRENT value, even when `act` is invoked from the
  // long-lived auto-deny timeout closure below (a plain state-closured read
  // there would be stuck at the value captured when the effect first ran,
  // i.e. permanently `false` - the timeout would silently never fire).
  const armedRef = useRef(false);
  const [left, setLeft] = useState(Math.ceil(timeoutMs / 1000));
  // `busy`: a request is in flight - guards against a second submit WHILE
  // one is outstanding. Deliberately separate from `done`: a failed request
  // must clear `busy` (buttons work again) without ever having set `done`.
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  // Set only when the in-flight request actually failed; cleared on retry.
  const [error, setError] = useState<string | null>(null);
  // `done`: the request has actually SUCCEEDED. Only this - never the start
  // of a request - may permanently retire the card. This is the crux of the
  // fix: the old code set `done.current = true` before the result was known,
  // so a rejected respond_approval left the card clickable-looking but
  // permanently inert, and the same flag disarmed the auto-deny timeout below.
  const done = useRef(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const total = Math.ceil(timeoutMs / 1000);

  // Stable identity (memoized on the things it actually reads from props/refs)
  // so it can be safely captured once by the timeout effect below without a
  // stale-closure risk, and so a rerender doesn't tear down/recreate that timer.
  const act = useCallback((d: Decision, s: Scope) => {
    if (!armedRef.current || done.current || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    Promise.resolve(onResolve(pending.id, d, s)).then(
      () => {
        done.current = true;
      },
      (err: unknown) => {
        // Failure: leave `done` false. Buttons re-enable (busy -> false) and
        // the auto-deny timeout below - untouched by this path - is still
        // armed to fire at its original deadline.
        busyRef.current = false;
        setBusy(false);
        setError(errorMessage(err));
      },
    );
  }, [onResolve, pending.id]);

  useEffect(() => {
    const g = setTimeout(() => { armedRef.current = true; setArmed(true); }, 1000);
    const tick = setInterval(() => setLeft((n) => Math.max(0, n - 1)), 1000);
    const to = setTimeout(() => act("deny", "once"), timeoutMs);
    return () => { clearTimeout(g); clearInterval(tick); clearTimeout(to); };
  }, [pending.id, timeoutMs, act]);

  // Focus the dialog on mount so keyboard/screen-reader users land inside it;
  // restore focus to the previously-focused element when it unmounts.
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    return () => { prev?.focus?.(); };
  }, [pending.id]);

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
    "lg-modal p-6 max-w-md w-full space-y-4 alert-enter max-h-[calc(100vh-2rem)] overflow-y-auto" +
    (meta.cardPulse ? " alert-critical-pulse" : "");

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4"
      style={{ background: "rgba(18,20,31,0.46)", backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)" }}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        className={cardClass}
        style={{
          boxShadow: "var(--lg-shadow-modal)",
          borderTop: meta.topAccent ? `${meta.topAccent} solid ${meta.color}` : undefined,
        }}
        role="alertdialog"
        aria-modal="true"
        aria-label={t`Approval required`}
      >
        {isEgress(pending) ? (
          <EgressBody pending={pending} armed={armed} left={left} total={total} act={act} busy={busy} error={error} />
        ) : (
          <ToolBody pending={pending} armed={armed} left={left} total={total} act={act} ex={toolEx!} busy={busy} error={error} />
        )}
      </div>
    </div>
  );
}
