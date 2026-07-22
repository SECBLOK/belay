// Host → Firewall sub-view: assistant flow for proposing, applying, and
// confirming or reverting firewall rules. Includes the dead-man's-switch panel.

import { useEffect, useState } from "react";
import {
  getProposedRuleset,
  getAutoProposedRuleset,
  applyFirewall,
  confirmFirewall,
  revertFirewall,
  getFirewallStatus,
} from "../../lib/api";
import type { ProposedRuleset, FirewallStatus } from "../../lib/hostTypes";
import ProposedRuleTable from "../../components/host/ProposedRuleTable";
import DeadMansSwitchPanel from "../../components/host/DeadMansSwitchPanel";
import { Plural, Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: FirewallStatus }) {
  const { t } = useLingui();
  const color = status.active ? "#187D34" : "var(--text-tertiary)";
  const bg = status.active ? "rgba(24,125,52,0.06)" : "rgba(0,0,0,0.06)";
  const stateWord = status.active ? t`active` : t`inactive`;
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] font-semibold"
      style={{ background: bg, color }}
      aria-label={t`Firewall ${stateWord}, mode: ${status.mode}, ${status.rule_count} rules`}
    >
      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} aria-hidden />
      {status.active ? <Trans>Active</Trans> : <Trans>Inactive</Trans>}
      <span className="font-normal text-[11px] uppercase ml-1">{status.mode}</span>
      <span className="font-normal text-[11px] ml-1">
        <Plural value={status.rule_count} one="# rule" other="# rules" />
      </span>
    </span>
  );
}

// ── Flow state machine ────────────────────────────────────────────────────────

type FlowState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "idle"; ruleset: ProposedRuleset; status: FirewallStatus | null; auto?: boolean }
  | { kind: "applying" }
  | { kind: "pending-confirm"; deadlineMs: number; handle: string; status: FirewallStatus | null }
  | { kind: "confirmed" }
  | { kind: "reverted" }
  | { kind: "desktop-only" };

const DESKTOP_ONLY_MSG = "Available in the Belay desktop app";

// An outdated/half-initialised daemon can return a response without a `rules`
// array; rendering it would throw (`ruleset.rules.filter`). Validate the shape so
// we show a clean error instead of crashing the view.
function isValidRuleset(r: unknown): r is ProposedRuleset {
  return (
    !!r &&
    typeof r === "object" &&
    Array.isArray((r as { rules?: unknown }).rules)
  );
}

const BAD_RULESET_MSG = msg`The daemon returned an unexpected firewall response — it may be an outdated build. Restart the Belay daemon and try again.`;

export default function FirewallSetup() {
  const { t } = useLingui();
  const [flow, setFlow] = useState<FlowState>({ kind: "loading" });
  const [autoBusy, setAutoBusy] = useState(false);

  // Load proposed ruleset + current status on mount.
  useEffect(() => {
    let cancelled = false;
    Promise.all([getProposedRuleset(), getFirewallStatus()])
      .then(([ruleset, status]) => {
        if (cancelled) return;
        if (!isValidRuleset(ruleset)) {
          setFlow({ kind: "error", message: t(BAD_RULESET_MSG) });
          return;
        }
        // If the server already has an active rollback window, re-mount the panel.
        if (status.revert_deadline != null && status.handle != null) {
          setFlow({
            kind: "pending-confirm",
            // The daemon reports revert_deadline in epoch SECONDS
            // (now_secs() + window); DeadMansSwitchPanel's deadlineMs is epoch
            // MS (compared against Date.now()). Without ×1000 the countdown is
            // ~1.7e12 ms in the past, so it "expires" instantly and the confirm
            // dialog flashes and auto-reverts before the user can click.
            deadlineMs: status.revert_deadline * 1000,
            handle: status.handle,
            status,
          });
        } else {
          setFlow({ kind: "idle", ruleset, status });
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
          setFlow({ kind: "desktop-only" });
        } else {
          setFlow({ kind: "error", message: msg });
        }
      });
    return () => { cancelled = true; };
    // `t` so a locale change re-renders the error/ruleset copy in the new language.
  }, [t]);

  const handleApply = async () => {
    if (flow.kind !== "idle") return;
    const { ruleset, status } = flow;
    setFlow({ kind: "applying" });
    try {
      const { revertDeadline, handle } = await applyFirewall(ruleset);
      // revertDeadline is epoch SECONDS from the daemon; deadlineMs is epoch MS.
      setFlow({ kind: "pending-confirm", deadlineMs: revertDeadline * 1000, handle, status });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
        setFlow({ kind: "desktop-only" });
      } else {
        setFlow({ kind: "error", message: msg });
      }
    }
  };

  // One-click auto setup: auto-detect the system and pre-fill the proposal, then
  // the operator reviews and clicks "Apply ruleset" (same dead-man's-switch path).
  const handleAutoSetup = async () => {
    if (flow.kind !== "idle" || autoBusy) return;
    const { status } = flow;
    setAutoBusy(true);
    try {
      const ruleset = await getAutoProposedRuleset();
      if (!isValidRuleset(ruleset)) {
        setFlow({ kind: "error", message: t(BAD_RULESET_MSG) });
        return;
      }
      setFlow({ kind: "idle", ruleset, status, auto: true });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
        setFlow({ kind: "desktop-only" });
      } else {
        setFlow({ kind: "error", message: msg });
      }
    } finally {
      setAutoBusy(false);
    }
  };

  const handleKeep = async (handle: string) => {
    try {
      await confirmFirewall(handle);
      setFlow({ kind: "confirmed" });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setFlow({ kind: "error", message: msg });
    }
  };

  const handleRevert = async (handle: string) => {
    try {
      await revertFirewall(handle);
      setFlow({ kind: "reverted" });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setFlow({ kind: "error", message: msg });
    }
  };

  const handleReset = () => {
    setFlow({ kind: "loading" });
    Promise.all([getProposedRuleset(), getFirewallStatus()])
      .then(([ruleset, status]) => {
        if (!isValidRuleset(ruleset)) {
          setFlow({ kind: "error", message: t(BAD_RULESET_MSG) });
          return;
        }
        setFlow({ kind: "idle", ruleset, status });
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setFlow({ kind: "error", message: msg });
      });
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  if (flow.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading firewall setup…</Trans>
      </div>
    );
  }

  if (flow.kind === "desktop-only") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium"><Trans>Firewall setup</Trans></p>
        <p>
          <Trans>
            Firewall control runs in the Belay desktop app, where it can
            apply rules directly to your host.
          </Trans>
        </p>
      </div>
    );
  }

  if (flow.kind === "error") {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-2"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium"><Trans>Firewall setup — error</Trans></p>
        <p className="font-mono text-xs text-[var(--text-tertiary)]">{flow.message}</p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          <Trans>Retry</Trans>
        </button>
      </div>
    );
  }

  if (flow.kind === "confirmed") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-2"
        style={{ background: "rgba(24,125,52,0.06)", border: "1px solid rgba(24,125,52,0.25)" }}
      >
        <p className="text-[#187D34] font-semibold"><Trans>Firewall setup — rules confirmed</Trans></p>
        <p className="text-[#636366]">
          <Trans>The proposed ruleset is now active. SSH access is preserved.</Trans>
        </p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          <Trans>View updated status</Trans>
        </button>
      </div>
    );
  }

  if (flow.kind === "reverted") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-2"
        style={{ background: "rgba(145,100,0,0.06)", border: "1px solid rgba(145,100,0,0.25)" }}
      >
        <p className="text-[#916400] font-semibold"><Trans>Firewall setup — rules reverted</Trans></p>
        <p className="text-[#636366]">
          <Trans>
            The previous firewall rules have been restored. Your host is back to
            its pre-change state.
          </Trans>
        </p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          <Trans>Start over</Trans>
        </button>
      </div>
    );
  }

  // "pending-confirm" — the DMS panel is mounted on top.
  if (flow.kind === "pending-confirm") {
    const { deadlineMs, handle, status } = flow;
    return (
      <div className="space-y-4">
        {/* DMS panel is a fixed overlay — rendered alongside the rule table. */}
        <DeadMansSwitchPanel
          deadlineMs={deadlineMs}
          handle={handle}
          onKeep={handleKeep}
          onRevert={handleRevert}
        />

        {/* Status */}
        {status && (
          <div className="flex items-center gap-3">
            <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-widest"><Trans>Firewall status</Trans></span>
            <StatusBadge status={status} />
          </div>
        )}

        {/* Dimmed hint */}
        <div
          className="rounded-xl px-5 py-4 text-sm text-[var(--text-tertiary)]"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.06)", opacity: 0.7 }}
          aria-hidden
        >
          <p className="font-medium text-[#1C1C1E]"><Trans>Firewall setup</Trans></p>
          <p><Trans>Rules applied — confirm or revert using the panel above.</Trans></p>
        </div>
      </div>
    );
  }

  // "applying"
  if (flow.kind === "applying") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Applying rules…</Trans>
      </div>
    );
  }

  // "idle" — show proposed ruleset + auto-setup + apply buttons.
  const { ruleset, status, auto } = flow;
  return (
    <div className="space-y-4">
      {/* Section title — keeps "Firewall setup" text visible for C1 assertion */}
      <div>
        <h2 className="text-sm font-semibold text-[#1C1C1E]"><Trans>Firewall setup</Trans></h2>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          <Trans>
            Use <strong>Auto setup</strong> to auto-detect this system and pre-fill
            a least-privilege ruleset, or review the proposal below. Applying starts
            a <strong>dead-man&apos;s-switch countdown</strong>: rules revert
            automatically unless you confirm within the window.
          </Trans>
        </p>
      </div>

      {/* Current status */}
      {status && (
        <div className="flex items-center gap-3">
          <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-widest"><Trans>Status</Trans></span>
          <StatusBadge status={status} />
        </div>
      )}

      {/* Auto-detected badge */}
      {auto && (
        <div
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-[12px] font-medium"
          style={{ background: "rgba(10,102,214,0.08)", color: "#0856B3" }}
        >
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: "#0A66D6" }} aria-hidden />
          <Trans>Auto-detected proposal — review the rules, then Apply</Trans>
        </div>
      )}

      {/* Proposed rule table */}
      <ProposedRuleTable ruleset={ruleset} />

      {/* Auto setup + Apply buttons */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={handleAutoSetup}
          disabled={autoBusy}
          className="px-5 py-3 rounded-xl text-sm font-semibold transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          style={{ background: "rgba(10,102,214,0.10)", color: "#0856B3" }}
          aria-label={t`Auto setup — detect this system and pre-fill a least-privilege ruleset`}
        >
          {autoBusy ? <Trans>Detecting…</Trans> : <Trans>⚡ Auto setup</Trans>}
        </button>
        <button
          onClick={handleApply}
          className="px-6 py-3 rounded-xl text-sm font-semibold text-white transition-opacity"
          style={{ background: "#0A66D6" }}
          aria-label={t`Apply proposed firewall ruleset — starts rollback countdown`}
        >
          <Trans>Apply ruleset</Trans>
        </button>
        <p className="text-xs text-[var(--text-tertiary)]">
          <Trans>A rollback window opens immediately. SSH is always preserved.</Trans>
        </p>
      </div>
    </div>
  );
}
