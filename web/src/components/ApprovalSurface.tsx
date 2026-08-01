import { useCallback, useEffect, useState } from "react";
import { Plural, Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";
import { getPending, resolve } from "../lib/api";
import ApprovalCard, { isEgress } from "./ApprovalCard";
import type { AnyPending, Pending } from "./ApprovalCard";
import type { Explain } from "../lib/api";
import BatchDigest from "./BatchDigest";

// Why the daemon refused a rule-scoped deny mute (ResolveResult.mute_refused).
// `scope_rule_requires_deny` can't actually surface from this UI (the mute
// button always sends decision:"deny"); it and any future/unrecognised code
// fall back to the generic message rather than expose a raw wire string.
function muteRefusalMessage(reason: string): MessageDescriptor {
  switch (reason) {
    case "rule_not_mutable":
      return msg`This type of finding always requires review and can't be muted.`;
    case "severity_critical":
      return msg`Critical-severity findings can't be muted.`;
    case "cap_reached":
      return msg`Too many rules are already muted — revoke one from Overview first.`;
    case "self_approval_detected":
      return msg`Refused: this looks like the agent tried to approve its own request.`;
    default:
      return msg`Could not mute this rule right now.`;
  }
}

// Are we running inside the native Tauri desktop window? Polling is gated on
// this so the plain browser dashboard (and its tests) are unaffected.
const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const POLL_MS = 1000;

// The daemon's parked-approval payload is
//   { id, session, tool, input, reason, rule, created_ms }
// ApprovalCard/BatchDigest want a Pending:
//   { id, agent, tool, input, reason, rule, risk? }
// Mapping rules:
//   - target path is derived inside the card from input.command|path|url.
//   - agent <- a friendly name derived from `session` (falls back to "Agent").
//   - risk  <- from the payload if present, else default "medium"
//     (the daemon doesn't currently carry a risk field; medium keeps the card
//      calm-by-default and still applies the keystroke guard + countdown).
const toPending = (raw: Record<string, unknown>): AnyPending => {
  if (raw.kind === "egress") {
    return {
      kind: "egress",
      id: String(raw.id),
      agent: friendlyAgent(raw.session),
      dest: typeof raw.dest === "string" ? raw.dest : "",
      binary: typeof raw.binary === "string" ? raw.binary : "",
      risk: (raw.risk as Pending["risk"]) ?? "medium",
    };
  }
  return {
    id: String(raw.id),
    agent: friendlyAgent(raw.session),
    tool: typeof raw.tool === "string" ? raw.tool : "",
    input: (raw.input as Record<string, unknown>) ?? {},
    reason: typeof raw.reason === "string" ? raw.reason : "An agent action needs your review",
    rule: typeof raw.rule === "string" ? raw.rule : "",
    risk: (raw.risk as Pending["risk"]) ?? "medium",
    // Explain & Advise: carry the daemon's curated severity/category/explain
    // through to the card (undefined when the snapshot omits them).
    severity: typeof raw.severity === "string" ? raw.severity : undefined,
    category: typeof raw.category === "string" ? raw.category : undefined,
    explain: typeof raw.explain === "object" && raw.explain !== null ? (raw.explain as Explain) : undefined,
  };
};

function friendlyAgent(session: unknown): string {
  if (typeof session !== "string" || session.length === 0) return "Agent";
  // session ids like "claude-code" / "claude-code:1234" -> "Claude Code"
  const base = session.split(":")[0].split("/").pop() ?? session;
  return base
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ") || "Agent";
}

export default function ApprovalSurface() {
  const { t } = useLingui();
  const [pendings, setPendings] = useState<AnyPending[]>([]);
  const [expanded, setExpanded] = useState(false); // "Review individually"
  // Set when the daemon reports that an Allow we sent was overridden to Deny by
  // the GateGuard self-approval guard. Without this the row simply disappears
  // and the operator is left believing they allowed the action.
  const [blockedCount, setBlockedCount] = useState(0);
  // Set after a "Deny & mute this rule" click resolves — either the rule that
  // got muted, or why the daemon refused. Like blockedCount, this must outlive
  // the queue draining (resolving the card that triggered it removes it from
  // `pendings` immediately).
  const [muteNotice, setMuteNotice] = useState<{ rule: string; refused: string | null } | null>(null);

  const refresh = useCallback(async () => {
    if (!isTauri()) return;
    try {
      const raw = await getPending();
      setPendings(Array.isArray(raw) ? (raw as Record<string, unknown>[]).map(toPending) : []);
    } catch {
      // daemon unreachable / command not ready -> show nothing, retry next poll
      setPendings([]);
    }
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    let alive = true;
    const tick = () => { if (alive) void refresh(); };
    tick(); // immediate first poll
    const id = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, [refresh]);

  // collapse the individual-review view once the queue drains
  useEffect(() => {
    if (pendings.length === 0 && expanded) setExpanded(false);
  }, [pendings.length, expanded]);

  // Stable across renders (only depends on `refresh`, itself stable) — otherwise
  // ApprovalCard's timer effect, keyed on `onResolve`, would tear down and
  // recreate its 45s auto-deny setTimeout on every 1s poll and never fire.
  // Declared before the early return below to satisfy the Rules of Hooks.
  // `ok:true` does NOT mean the requested decision was honored - the guard can
  // override an allow to deny. Count those so the banner below can say so.
  const noteBlocked = useCallback((r: { self_approval_blocked?: boolean } | undefined) => {
    if (r?.self_approval_blocked) setBlockedCount((n) => n + 1);
  }, []);

  // `mute`/`mute_refused` are only ever set when the request carried
  // scope:"rule" (see respond_local) — a no-op for every other click.
  const noteMute = useCallback(
    (r: { mute?: string | null; mute_refused?: string | null } | undefined) => {
      if (r?.mute) setMuteNotice({ rule: r.mute, refused: null });
      else if (r?.mute_refused) setMuteNotice({ rule: "", refused: r.mute_refused });
    },
    [],
  );

  // Returns the underlying promise (rather than firing-and-forgetting it with
  // `void`) so ApprovalCard's `act` can await the outcome: a rejection here -
  // e.g. respond_approval failing because the daemon is mid-restart - must
  // reach the card so it can show the failure and stay usable, instead of
  // being swallowed here while the card believes the click "worked" and
  // locks itself. See ApprovalCard.tsx's `act` for the consumer side.
  const resolveOne = useCallback(
    (id: string, d: "allow" | "deny", s: "once" | "always" | "rule") =>
      resolve(id, d, s).then((r) => {
        noteBlocked(r);
        noteMute(r);
        return refresh();
      }),
    [refresh, noteBlocked, noteMute],
  );

  const blockedBanner = blockedCount > 0 && (
    <div
      role="alert"
      data-testid="self-approval-blocked"
      className="lg-glass-lite px-4 py-3 mb-2 text-sm"
      style={{ border: "1px solid rgba(0,0,0,0.08)", borderLeft: "4px solid var(--semantic-deny)" }}
    >
      <div className="font-semibold" style={{ color: "var(--semantic-deny)" }}>
        <Plural value={blockedCount} one="Approval blocked" other="# approvals blocked" />
      </div>
      <p className="mt-0.5" style={{ color: "var(--text-secondary)" }}>
        <Trans>
          That request was answered from the agent&apos;s own process, so Belay denied it
          instead of allowing it. An agent cannot approve its own action.
        </Trans>
      </p>
      <button
        onClick={() => setBlockedCount(0)}
        className="mt-1.5 text-xs font-medium"
        style={{ color: "var(--accent)" }}
      >
        <Trans>Dismiss</Trans>
      </button>
    </div>
  );

  const muteBanner = muteNotice && (
    <div
      role="status"
      data-testid="deny-mute-notice"
      className="lg-glass-lite px-4 py-3 mb-2 text-sm"
      style={{
        border: "1px solid rgba(0,0,0,0.08)",
        borderLeft: `4px solid var(${muteNotice.refused ? "--semantic-ask" : "--semantic-deny"})`,
      }}
    >
      {muteNotice.refused ? (
        <>
          <div className="font-semibold" style={{ color: "var(--semantic-ask)" }}>
            <Trans>Rule not muted</Trans>
          </div>
          <p className="mt-0.5" style={{ color: "var(--text-secondary)" }}>
            {t(muteRefusalMessage(muteNotice.refused))}
          </p>
        </>
      ) : (
        <>
          <div className="font-semibold" style={{ color: "var(--semantic-deny)" }}>
            <Trans>Rule muted</Trans>
          </div>
          <p className="mt-0.5 font-mono text-xs break-all" style={{ color: "var(--text-secondary)" }}>
            {muteNotice.rule}
          </p>
          <p className="mt-0.5" style={{ color: "var(--text-secondary)" }}>
            <Trans>Further matches will auto-deny for a while. Manage active mutes from Overview.</Trans>
          </p>
        </>
      )}
      <button
        onClick={() => setMuteNotice(null)}
        className="mt-1.5 text-xs font-medium"
        style={{ color: "var(--accent)" }}
      >
        <Trans>Dismiss</Trans>
      </button>
    </div>
  );

  // NOTE: both banners must outlive the queue. Resolving the last item drains
  // `pendings`, so returning null on an empty queue would blank the notice the
  // instant it became relevant.
  if (pendings.length === 0) {
    if (!blockedBanner && !muteBanner) return null;
    return (
      <>
        {blockedBanner}
        {muteBanner}
      </>
    );
  }

  // Always show the first item as an individual card if there's only one,
  // or if the user expanded, or if the first item is an egress pending (no batch view for egress).
  if (pendings.length === 1 || expanded || isEgress(pendings[0])) {
    const p = pendings[0];
    return (
      <>
        {blockedBanner}
        {muteBanner}
        <ApprovalCard key={p.id} pending={p} onResolve={resolveOne} />
      </>
    );
  }

  // ≥2 tool pendings -> one digest card (egress items are not batched).
  const toolPendings = pendings.filter((p): p is Pending => !isEgress(p));
  if (toolPendings.length < 2) {
    const p = pendings[0];
    return (
      <>
        {blockedBanner}
        {muteBanner}
        <ApprovalCard key={p.id} pending={p} onResolve={resolveOne} />
      </>
    );
  }

  return (
    <>
      {blockedBanner}
      {muteBanner}
      <BatchDigest
        pendings={toolPendings}
        // Returns the underlying promise (rather than firing-and-forgetting
        // it with `void`) so BatchDigest's own resolveAll can await the
        // outcome: a rejection - e.g. the daemon restarting mid-batch - must
        // reach the dialog so it can show the failure and stay usable,
        // instead of being swallowed here. Same pattern as resolveOne above.
        onResolveAll={(d) =>
          Promise.all(toolPendings.map((p) => resolve(p.id, d, "once")))
            .then((rs) => {
              // Batch path: any blocked item in the batch must still surface.
              rs.forEach(noteBlocked);
              return refresh();
            })
        }
        onExpand={() => setExpanded(true)}
      />
    </>
  );
}
