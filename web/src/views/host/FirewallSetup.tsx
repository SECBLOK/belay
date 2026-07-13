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

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: FirewallStatus }) {
  const color = status.active ? "#1B8C3A" : "#8E8E93";
  const bg = status.active ? "rgba(27,140,58,0.10)" : "rgba(0,0,0,0.06)";
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] font-semibold"
      style={{ background: bg, color }}
      aria-label={`Firewall ${status.active ? "active" : "inactive"}, mode: ${status.mode}, ${status.rule_count} rules`}
    >
      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} aria-hidden />
      {status.active ? "Active" : "Inactive"}
      <span className="font-normal text-[11px] uppercase ml-1">{status.mode}</span>
      <span className="font-normal text-[11px] ml-1">{status.rule_count} rules</span>
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

const BAD_RULESET_MSG =
  "The daemon returned an unexpected firewall response — it may be an outdated " +
  "build. Restart the Belay daemon and try again.";

export default function FirewallSetup() {
  const [flow, setFlow] = useState<FlowState>({ kind: "loading" });
  const [autoBusy, setAutoBusy] = useState(false);

  // Load proposed ruleset + current status on mount.
  useEffect(() => {
    let cancelled = false;
    Promise.all([getProposedRuleset(), getFirewallStatus()])
      .then(([ruleset, status]) => {
        if (cancelled) return;
        if (!isValidRuleset(ruleset)) {
          setFlow({ kind: "error", message: BAD_RULESET_MSG });
          return;
        }
        // If the server already has an active rollback window, re-mount the panel.
        if (status.revert_deadline != null && status.handle != null) {
          setFlow({
            kind: "pending-confirm",
            deadlineMs: status.revert_deadline,
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
  }, []);

  const handleApply = async () => {
    if (flow.kind !== "idle") return;
    const { ruleset, status } = flow;
    setFlow({ kind: "applying" });
    try {
      const { revertDeadline, handle } = await applyFirewall(ruleset);
      setFlow({ kind: "pending-confirm", deadlineMs: revertDeadline, handle, status });
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
        setFlow({ kind: "error", message: BAD_RULESET_MSG });
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
          setFlow({ kind: "error", message: BAD_RULESET_MSG });
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
        className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        Loading firewall setup…
      </div>
    );
  }

  if (flow.kind === "desktop-only") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium">Firewall setup</p>
        <p>
          Firewall control runs in the Belay desktop app, where it can
          apply rules directly to your host.
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
        <p className="text-[#1C1C1E] font-medium">Firewall setup — error</p>
        <p className="font-mono text-xs text-[#8E8E93]">{flow.message}</p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (flow.kind === "confirmed") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-2"
        style={{ background: "rgba(27,140,58,0.06)", border: "1px solid rgba(27,140,58,0.25)" }}
      >
        <p className="text-[#1B8C3A] font-semibold">Firewall setup — rules confirmed</p>
        <p className="text-[#636366]">
          The proposed ruleset is now active. SSH access is preserved.
        </p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          View updated status
        </button>
      </div>
    );
  }

  if (flow.kind === "reverted") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-sm space-y-2"
        style={{ background: "rgba(178,123,0,0.06)", border: "1px solid rgba(178,123,0,0.25)" }}
      >
        <p className="text-[#B27B00] font-semibold">Firewall setup — rules reverted</p>
        <p className="text-[#636366]">
          The previous firewall rules have been restored. Your host is back to
          its pre-change state.
        </p>
        <button
          onClick={handleReset}
          className="text-xs hover:underline"
          style={{ color: "#0856B3" }}
        >
          Start over
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
            <span className="text-xs text-[#8E8E93] uppercase tracking-widest">Firewall status</span>
            <StatusBadge status={status} />
          </div>
        )}

        {/* Dimmed hint */}
        <div
          className="rounded-xl px-5 py-4 text-sm text-[#8E8E93]"
          style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.06)", opacity: 0.7 }}
          aria-hidden
        >
          <p className="font-medium text-[#1C1C1E]">Firewall setup</p>
          <p>Rules applied — confirm or revert using the panel above.</p>
        </div>
      </div>
    );
  }

  // "applying"
  if (flow.kind === "applying") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        Applying rules…
      </div>
    );
  }

  // "idle" — show proposed ruleset + auto-setup + apply buttons.
  const { ruleset, status, auto } = flow;
  return (
    <div className="space-y-4">
      {/* Section title — keeps "Firewall setup" text visible for C1 assertion */}
      <div>
        <h2 className="text-sm font-semibold text-[#1C1C1E]">Firewall setup</h2>
        <p className="text-xs text-[#8E8E93] mt-0.5">
          Use <strong>Auto setup</strong> to auto-detect this system and pre-fill
          a least-privilege ruleset, or review the proposal below. Applying starts
          a <strong>dead-man&apos;s-switch countdown</strong>: rules revert
          automatically unless you confirm within the window.
        </p>
      </div>

      {/* Current status */}
      {status && (
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#8E8E93] uppercase tracking-widest">Status</span>
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
          Auto-detected proposal — review the rules, then Apply
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
          aria-label="Auto setup — detect this system and pre-fill a least-privilege ruleset"
        >
          {autoBusy ? "Detecting…" : "⚡ Auto setup"}
        </button>
        <button
          onClick={handleApply}
          className="px-6 py-3 rounded-xl text-sm font-semibold text-white transition-opacity"
          style={{ background: "#0A66D6" }}
          aria-label="Apply proposed firewall ruleset — starts rollback countdown"
        >
          Apply ruleset
        </button>
        <p className="text-xs text-[#8E8E93]">
          A rollback window opens immediately. SSH is always preserved.
        </p>
      </div>
    </div>
  );
}
