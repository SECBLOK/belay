import { useEffect, useState } from "react";
import { listAgents, protectAgent, unprotectAgent } from "../lib/api";
import { C, Empty } from "../components/dash";

export interface DetectedAgentDto {
  name: string;
  settings: string[];
  risky: string[];
  interception: string;
  mcp_config: string[];
  mcp_servers?: string[];
  skills?: string[];
  protected?: boolean;
}

// ── Plain-English maps ──────────────────────────────────────────────────────

const INTERCEPTION_LABEL: Record<string, string> = {
  hook: "Guarded via hook",
  "mcp-proxy": "Guarded via MCP proxy",
  "config-policy": "Guarded via config policy",
};

const RISKY_LABEL: Record<string, string> = {
  bypassPermissions: "Permission prompts are off",
  enableAllProjectMcpServers: "All MCP servers auto-enabled",
  "danger-full-access": "Full system access enabled",
  "approval_policy=never": "Never asks for approval",
  "full-host": "Full host access enabled",
};

const DESKTOP_ONLY_MSG = "Available in the Belay desktop app";

// Per-agent clarifier: which desktop chat app (if any) shares this CLI's
// config/hook file but does NOT actually route its tool calls through it.
// Confirmed by live Windows reproduction, not assumption - see
// docs/superpowers/plans/2026-07-15-windows-desktop-app-coverage-gap.md.
// Only CLIs with a known, verified desktop-app namesake get an entry here;
// do not add one speculatively.
const DESKTOP_UNENFORCEABLE: Record<string, string> = {
  "claude-code":
    "Enforces the Claude Code CLI. The Claude Desktop app is a separate surface that runs its own tools in a sandbox Belay can't hook - it is not covered, even though it shares no config with this entry.",
  codex:
    "Enforces the Codex CLI (once trusted, see below). The ChatGPT desktop app shares this hooks.json file but its agentic mode never invokes it - it is not covered.",
};

// ── Sub-components ──────────────────────────────────────────────────────────

function RiskyChip({ flag }: { flag: string }) {
  const label = RISKY_LABEL[flag] ?? flag;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium"
      style={{
        background: `${C.ask}22`,
        color: C.ask,
        border: `1px solid ${C.ask}55`,
      }}
      title={flag}
    >
      <span
        className="w-1.5 h-1.5 rounded-full shrink-0"
        style={{ background: C.ask }}
      />
      {label}
    </span>
  );
}

// Compact list of named tools (MCP servers / skills). Shows up to `max` chips,
// then a "+N more" pill so an agent with 100+ skills stays scannable.
function ToolList({ label, items, max = 8 }: { label: string; items: string[]; max?: number }) {
  if (items.length === 0) return null;
  const shown = items.slice(0, max);
  const extra = items.length - shown.length;
  return (
    <div className="space-y-1">
      <p className="text-[10px] uppercase tracking-widest text-[#8E8E93]">
        {label} <span className="font-mono text-[#636366]">{items.length}</span>
      </p>
      <div className="flex flex-wrap gap-1.5">
        {shown.map((name) => (
          <span
            key={name}
            className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono"
            style={{ background: "rgba(0,0,0,0.05)", color: "#1C1C1E" }}
            title={name}
          >
            {name}
          </span>
        ))}
        {extra > 0 && (
          <span
            className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium"
            style={{ background: "rgba(0,0,0,0.04)", color: "#8E8E93" }}
            title={items.slice(max).join(", ")}
          >
            +{extra} more
          </span>
        )}
      </div>
    </div>
  );
}

// Inline confirm state for a single agent
type ConfirmState = "idle" | "confirming";

interface AgentCardProps {
  agent: DetectedAgentDto;
  onRefresh: () => void;
}

function AgentCard({ agent, onRefresh }: AgentCardProps) {
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmState>("idle");
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const interceptionLabel =
    INTERCEPTION_LABEL[agent.interception] ?? agent.interception;

  // Codex only ENFORCES an installed hook after the user reviews + trusts it
  // (new hooks start as "needs review"), and its hook coverage has documented
  // gaps. So an installed codex hook is NOT proof of active protection - we must
  // not show a confident green "Protected" for it.
  //
  // NOTE (corrected 2026-07-15, see docs/superpowers/plans/2026-07-15-windows-
  // desktop-app-coverage-gap.md): this "codex" entry does NOT cover the ChatGPT
  // desktop app, even though ChatGPT desktop's agentic mode shares ~/.codex's
  // hooks.json file. A live Windows investigation confirmed ChatGPT desktop
  // (package OpenAI.Codex, binary ChatGPT.exe) reads and writes that same
  // hooks.json but its sandboxed tool-execution runtime never invokes it -
  // zero audit events when it read a test secret file. Do not let this
  // "codex" card's protected/needsTrust state be read as covering ChatGPT
  // desktop; see the DESKTOP_UNENFORCEABLE clarifier below.
  const needsTrust = agent.name === "codex";
  const protectedActive = !!agent.protected && !needsTrust;

  const doProtect = async () => {
    setBusy(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      await protectAgent(agent.name);
      setSuccessMsg(`Protection updated for ${agent.name}`);
      onRefresh();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Something went wrong"
      );
    } finally {
      setBusy(false);
    }
  };

  const doUnprotect = async () => {
    setBusy(true);
    setConfirm("idle");
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      await unprotectAgent(agent.name);
      setSuccessMsg(`Protection updated for ${agent.name}`);
      onRefresh();
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Something went wrong"
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl bg-white p-5 space-y-4" style={{ border: "1px solid rgba(0,0,0,0.08)", boxShadow: "var(--shadow-card)" }}>
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-base font-semibold text-[#1C1C1E] font-mono">
            {agent.name}
          </h3>
          {DESKTOP_UNENFORCEABLE[agent.name] && (
            <p className="text-[11px] text-[#8E8E93] mt-0.5 max-w-md leading-snug">
              {DESKTOP_UNENFORCEABLE[agent.name]}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {protectedActive ? (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-semibold"
              style={{ background: "rgba(27,140,58,0.10)", color: C.allow }}
            >
              ✓ Protected
            </span>
          ) : agent.protected && needsTrust ? (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-semibold"
              style={{ background: `${C.ask}1A`, color: C.ask }}
              title="Hook installed, but Codex won't enforce it until you trust it"
            >
              ⚠ Finish in Codex
            </span>
          ) : (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-medium"
              style={{ background: "rgba(0,0,0,0.05)", color: "#8E8E93" }}
            >
              Not protected
            </span>
          )}
          <span
            className="text-[11px] px-2 py-0.5 rounded font-medium"
            style={{ background: "rgba(26,109,200,0.10)", color: "#1A6DC8" }}
          >
            {interceptionLabel}
          </span>
        </div>
      </div>

      {/* Codex trust caveat: an installed hook is dormant until trusted, and
          Codex hook coverage has gaps - never imply blanket protection. */}
      {needsTrust && agent.protected && (
        <div
          className="rounded-lg px-3 py-2 text-[11px] leading-relaxed"
          style={{ background: `${C.ask}12`, border: `1px solid ${C.ask}40`, color: "#7A5200" }}
        >
          <b>Action needed to activate.</b> Codex leaves a new hook dormant until you
          trust it: open the Codex CLI, run <code>/hooks</code>, and trust the Belay
          hook. Until then this agent is <b>not actively protected</b>. Even once
          trusted, Codex hooks fire on <b>shell commands, edits, and MCP calls - not
          plain file reads</b>, and apply only to <b>local tasks, not Codex Cloud</b>
          runs. Treat this as a strong guardrail, not a guarantee.
        </div>
      )}

      {/* Settings paths */}
      {agent.settings.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-widest text-[#8E8E93]">
            Where it lives
          </p>
          <div className="space-y-0.5">
            {agent.settings.map((path) => (
              <p
                key={path}
                className="text-[11px] font-mono text-[#8E8E93] truncate max-w-full"
                title={path}
              >
                {path}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Connected tools — MCP servers + skills detected for this agent */}
      <ToolList label="MCP servers" items={agent.mcp_servers ?? []} />
      <ToolList label="Skills" items={agent.skills ?? []} />

      {/* Risky settings */}
      <div className="space-y-1.5">
        <p className="text-[10px] uppercase tracking-widest text-[#8E8E93]">
          Settings check
        </p>
        {agent.risky.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {agent.risky.map((flag) => (
              <RiskyChip key={flag} flag={flag} />
            ))}
          </div>
        ) : (
          <p className="text-[11px]" style={{ color: C.allow }}>
            No risky settings
          </p>
        )}
      </div>

      {/* Success / error feedback */}
      {successMsg && (
        <p className="text-[11px]" style={{ color: C.allow }}>
          {successMsg}
        </p>
      )}
      {errorMsg && (
        <p className="text-[11px]" style={{ color: C.deny }}>
          {errorMsg}
        </p>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 flex-wrap pt-1">
        {confirm === "confirming" ? (
          // Inline confirm for Unprotect (testable — no window.confirm)
          <>
            <span className="text-[11px] text-[#636366]">
              Remove Belay protection from this agent?
            </span>
            <button
              onClick={doUnprotect}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-semibold transition-colors disabled:opacity-40"
              style={{ background: "rgba(200,49,42,0.10)", color: "#C8312A" }}
            >
              Yes, unprotect
            </button>
            <button
              onClick={() => setConfirm("idle")}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-medium transition-colors disabled:opacity-40"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            <button
              onClick={doProtect}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                background: busy ? "rgba(0,0,0,0.04)" : "rgba(27,140,58,0.10)",
                color: busy ? "#8E8E93" : C.allow,
              }}
            >
              Protect
            </button>
            <button
              onClick={() => setConfirm("confirming")}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              Unprotect
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// ── Main view ───────────────────────────────────────────────────────────────

type ViewState =
  | { kind: "loading" }
  | { kind: "list"; agents: DetectedAgentDto[] }
  | { kind: "empty" }
  | { kind: "error"; message: string }
  | { kind: "desktop-only" };

export default function Agents() {
  const [state, setState] = useState<ViewState>({ kind: "loading" });

  const load = async () => {
    setState({ kind: "loading" });
    try {
      const agents = (await listAgents()) as DetectedAgentDto[];
      if (agents.length === 0) {
        setState({ kind: "empty" });
      } else {
        setState({ kind: "list", agents });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes(DESKTOP_ONLY_MSG) || msg.includes("desktop app")) {
        setState({ kind: "desktop-only" });
      } else {
        setState({ kind: "error", message: msg });
      }
    }
  };

  useEffect(() => {
    load();
  }, []);

  const refresh = async () => {
    try {
      const agents = (await listAgents()) as DetectedAgentDto[];
      if (agents.length === 0) {
        setState({ kind: "empty" });
      } else {
        setState({ kind: "list", agents });
      }
    } catch {
      // Silently keep current state on refresh error
    }
  };

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-4">
      <div className="mb-2">
        <h1 className="text-sm font-semibold text-[#8E8E93] uppercase tracking-widest">
          Detected Agents
        </h1>
        <p className="text-xs text-[#8E8E93] mt-0.5">
          AI agents found on this computer — their settings and Belay
          protection status.
        </p>
      </div>

      {/* Persistent, evergreen coverage disclosure - shown regardless of load
          state since it's not about any one agent's data. Verified by live
          Windows reproduction, not assumption; see
          docs/superpowers/plans/2026-07-15-windows-desktop-app-coverage-gap.md. */}
      <div
        className="rounded-lg px-3 py-2.5 text-[11px] leading-relaxed"
        style={{ background: `${C.ask}12`, border: `1px solid ${C.ask}40`, color: "#7A5200" }}
      >
        <b>What Belay can and can't enforce.</b> Belay blocks agents that run
        through a cooperative hook — the <b>Claude Code CLI</b>,{" "}
        <b>Cursor</b>, and the <b>Codex CLI</b> (once trusted). The{" "}
        <b>Claude Desktop</b> and <b>ChatGPT desktop</b> apps are detected
        here, but they run their tools in a separate sandbox that bypasses
        these hooks, so Belay can't block them yet. Deeper coverage for
        desktop apps needs OS-level interception (an optional, admin-enabled
        tier).
      </div>

      {state.kind === "loading" && (
        <div className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          Loading agents…
        </div>
      )}

      {state.kind === "desktop-only" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <p className="text-[#1C1C1E] font-medium">Desktop app required</p>
          <p>
            Agent management runs in the Belay desktop app, where it can
            inspect tools installed on your computer. This feature is not
            available in the browser.
          </p>
        </div>
      )}

      {state.kind === "error" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <p className="text-[#1C1C1E] font-medium">Something went wrong</p>
          <p className="font-mono text-xs text-[#8E8E93]">{state.message}</p>
          <button
            onClick={load}
            className="text-xs hover:underline mt-1"
            style={{ color: "#0856B3" }}
          >
            Try again
          </button>
        </div>
      )}

      {state.kind === "empty" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366]" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <Empty>
            No AI agents detected yet. Belay watches for tools like Claude
            Code, Cursor, and others — none are installed yet.
          </Empty>
        </div>
      )}

      {state.kind === "list" && (
        <div className="space-y-3">
          {state.agents.map((agent) => (
            <AgentCard key={agent.name} agent={agent} onRefresh={refresh} />
          ))}
        </div>
      )}
    </div>
  );
}
