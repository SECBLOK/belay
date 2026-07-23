import { useEffect, useState } from "react";
import { listAgents, protectAgent, unprotectAgent } from "../lib/api";
import { C, Empty } from "../components/dash";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

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

const INTERCEPTION_LABEL: Record<string, MessageDescriptor> = {
  hook: msg`Guarded via hook`,
  "mcp-proxy": msg`Guarded via MCP proxy`,
  "config-policy": msg`Guarded via config policy`,
};

const RISKY_LABEL: Record<string, MessageDescriptor> = {
  bypassPermissions: msg`Permission prompts are off`,
  enableAllProjectMcpServers: msg`All MCP servers auto-enabled`,
  "danger-full-access": msg`Full system access enabled`,
  "approval_policy=never": msg`Never asks for approval`,
  "full-host": msg`Full host access enabled`,
};

// Logic sentinel matched against error messages, never rendered — do NOT translate.
const DESKTOP_ONLY_MSG = "Available in the Belay desktop app";

// Per-agent clarifier: which desktop chat app (if any) shares this CLI's
// config/hook file but does NOT actually route its tool calls through it.
// Confirmed by live Windows reproduction, not assumption - see
// docs/superpowers/plans/2026-07-15-windows-desktop-app-coverage-gap.md.
// Only CLIs with a known, verified desktop-app namesake get an entry here;
// do not add one speculatively.
const DESKTOP_UNENFORCEABLE: Record<string, MessageDescriptor> = {
  "claude-code":
    msg`Enforces the Claude Code CLI. The Claude Desktop app is a separate surface that runs its own tools in a sandbox Belay can't hook - it is not covered, even though it shares no config with this entry.`,
  codex:
    msg`Enforces the Codex CLI (once trusted, see below). The ChatGPT desktop app shares this hooks.json file but its agentic mode never invokes it - it is not covered.`,
};

// ── Sub-components ──────────────────────────────────────────────────────────

function RiskyChip({ flag }: { flag: string }) {
  const { t } = useLingui();
  const desc = RISKY_LABEL[flag];
  const label = desc ? t(desc) : flag;
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium"
      style={{
        background: `${C.ask}0f`,
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
      <p className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)]">
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
            style={{ background: "rgba(0,0,0,0.04)", color: "var(--text-tertiary)" }}
            title={items.slice(max).join(", ")}
          >
            <Trans>+{extra} more</Trans>
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
  const { t } = useLingui();
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmState>("idle");
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const interceptionDesc = INTERCEPTION_LABEL[agent.interception];
  const interceptionLabel = interceptionDesc ? t(interceptionDesc) : agent.interception;
  const desktopNote = DESKTOP_UNENFORCEABLE[agent.name];

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
      setSuccessMsg(t`Protection updated for ${agent.name}`);
      onRefresh();
    } catch (err: unknown) {
      // Tauri commands returning `Result<T, String>` reject with the raw
      // string itself, not a wrapped Error — `String(err)` passes that
      // through unchanged (matches every other view's error handling); the
      // old `t\`Something went wrong\`` fallback silently discarded it.
      setErrorMsg(err instanceof Error ? err.message : String(err));
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
      setSuccessMsg(t`Protection updated for ${agent.name}`);
      onRefresh();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="lg-glass p-5 space-y-4">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-base font-semibold text-[#1C1C1E] font-mono">
            {agent.name}
          </h3>
          {desktopNote && (
            <p className="text-[11px] text-[var(--text-tertiary)] mt-0.5 max-w-md leading-snug">
              {t(desktopNote)}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {protectedActive ? (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-semibold"
              style={{ background: "rgba(24,125,52,0.06)", color: C.allow }}
            >
              <Trans>✓ Protected</Trans>
            </span>
          ) : agent.protected && needsTrust ? (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-semibold"
              style={{ background: `${C.ask}0f`, color: C.ask }}
              title={t`Hook installed, but Codex won't enforce it until you trust it`}
            >
              <Trans>⚠ Finish in Codex</Trans>
            </span>
          ) : (
            <span
              className="text-[11px] px-2 py-0.5 rounded font-medium"
              style={{ background: "rgba(0,0,0,0.05)", color: "var(--text-tertiary)" }}
            >
              <Trans>Not protected</Trans>
            </span>
          )}
          <span
            className="text-[11px] px-2 py-0.5 rounded font-medium"
            style={{ background: "rgba(26,107,197,0.06)", color: "#1A6BC5" }}
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
          <Trans>
            <b>Action needed to activate.</b> Codex leaves a new hook dormant until you
            trust it: open the Codex CLI, run <code>/hooks</code>, and trust the Belay
            hook. Until then this agent is <b>not actively protected</b>. Even once
            trusted, Codex hooks fire on <b>shell commands, edits, and MCP calls - not
            plain file reads</b>, and apply only to <b>local tasks, not Codex Cloud</b>
            runs. Treat this as a strong guardrail, not a guarantee.
          </Trans>
        </div>
      )}

      {/* Settings paths */}
      {agent.settings.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)]">
            <Trans>Where it lives</Trans>
          </p>
          <div className="space-y-0.5">
            {agent.settings.map((path) => (
              <p
                key={path}
                className="text-[11px] font-mono text-[var(--text-tertiary)] truncate max-w-full"
                title={path}
              >
                {path}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Connected tools — MCP servers + skills detected for this agent */}
      <ToolList label={t`MCP servers`} items={agent.mcp_servers ?? []} />
      <ToolList label={t`Skills`} items={agent.skills ?? []} />

      {/* Risky settings */}
      <div className="space-y-1.5">
        <p className="text-[10px] uppercase tracking-widest text-[var(--text-tertiary)]">
          <Trans>Settings check</Trans>
        </p>
        {agent.risky.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {agent.risky.map((flag) => (
              <RiskyChip key={flag} flag={flag} />
            ))}
          </div>
        ) : (
          <p className="text-[11px]" style={{ color: C.allow }}>
            <Trans>No risky settings</Trans>
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
              <Trans>Remove Belay protection from this agent?</Trans>
            </span>
            <button
              onClick={doUnprotect}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-semibold transition-colors disabled:opacity-40"
              style={{ background: "rgba(200,49,42,0.06)", color: "#C8312A" }}
            >
              <Trans>Yes, unprotect</Trans>
            </button>
            <button
              onClick={() => setConfirm("idle")}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-medium transition-colors disabled:opacity-40"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              <Trans>Cancel</Trans>
            </button>
          </>
        ) : (
          <>
            <button
              onClick={doProtect}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                background: busy ? "rgba(0,0,0,0.04)" : "rgba(24,125,52,0.06)",
                color: busy ? "var(--text-tertiary)" : C.allow,
              }}
            >
              <Trans>Protect</Trans>
            </button>
            <button
              onClick={() => setConfirm("confirming")}
              disabled={busy}
              className="px-3 py-1 rounded text-[12px] font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              <Trans>Unprotect</Trans>
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
      const errMsg = err instanceof Error ? err.message : String(err);
      if (errMsg.includes(DESKTOP_ONLY_MSG) || errMsg.includes("desktop app")) {
        setState({ kind: "desktop-only" });
      } else {
        setState({ kind: "error", message: errMsg });
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
        <h1 className="text-sm font-semibold text-[var(--text-tertiary)] uppercase tracking-widest">
          <Trans>Detected Agents</Trans>
        </h1>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          <Trans>
            AI agents found on this computer — their settings and Belay
            protection status.
          </Trans>
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
        <Trans>
          <b>What Belay can and can't enforce.</b> Belay blocks agents that run
          through a cooperative hook — the <b>Claude Code CLI</b>, <b>Cursor</b>,
          and the <b>Codex CLI</b> (once trusted). The <b>Claude Desktop</b> and
          <b>ChatGPT desktop</b> apps are detected here, but they run their tools
          in a separate sandbox that bypasses these hooks, so Belay can't block
          them yet. Deeper coverage for desktop apps needs OS-level interception
          (an optional, admin-enabled tier).
        </Trans>
      </div>

      {state.kind === "loading" && (
        <div className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <Trans>Loading agents…</Trans>
        </div>
      )}

      {state.kind === "desktop-only" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <p className="text-[#1C1C1E] font-medium"><Trans>Desktop app required</Trans></p>
          <p>
            <Trans>
              Agent management runs in the Belay desktop app, where it can
              inspect tools installed on your computer. This feature is not
              available in the browser.
            </Trans>
          </p>
        </div>
      )}

      {state.kind === "error" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <p className="text-[#1C1C1E] font-medium"><Trans>Something went wrong</Trans></p>
          <p className="font-mono text-xs text-[var(--text-tertiary)]">{state.message}</p>
          <button
            onClick={load}
            className="text-xs hover:underline mt-1"
            style={{ color: "#0856B3" }}
          >
            <Trans>Try again</Trans>
          </button>
        </div>
      )}

      {state.kind === "empty" && (
        <div className="rounded-xl px-5 py-6 text-sm text-[#636366]" style={{ border: "1px solid rgba(0,0,0,0.08)", background: "#F5F5F7" }}>
          <Empty>
            <Trans>
              No AI agents detected yet. Belay watches for tools like Claude
              Code, Cursor, and others — none are installed yet.
            </Trans>
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
