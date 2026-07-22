import { useEffect, useState } from "react";
import { listAgents, getAiConfig } from "../lib/api";
import { C } from "./dash";
import { Trans, useLingui } from "@lingui/react/macro";

const FLAG = "belay.welcomed";

export default function Welcome() {
  const { t } = useLingui();
  const [visible, setVisible] = useState(false);
  const [agentNames, setAgentNames] = useState<string[]>([]);
  const [aiAvailable, setAiAvailable] = useState(false);

  useEffect(() => {
    if (localStorage.getItem(FLAG)) return;
    setVisible(true);
    // Try to list installed agents (desktop only); fall back silently on rejection.
    listAgents()
      .then((agents: unknown) => {
        if (Array.isArray(agents) && agents.length > 0) {
          const names = agents
            .map((a: any) => a?.name ?? a?.id ?? String(a))
            .filter(Boolean)
            .slice(0, 5);
          setAgentNames(names);
        }
      })
      .catch(() => {
        // Browser / non-desktop environment — generic copy is shown, no error thrown.
      });
    // Desktop-only: probe whether the AI config surface exists so we can show
    // the optional step. Browser build (or ai feature off) → null → hidden.
    getAiConfig()
      .then((cfg) => setAiAvailable(cfg !== null))
      .catch(() => setAiAvailable(false));
  }, []);

  if (!visible) return null;

  const dismiss = () => {
    localStorage.setItem(FLAG, "1");
    setVisible(false);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={t`Welcome to Belay`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
    >
      <div className="relative w-full max-w-md mx-4 lg-modal alert-enter p-8">
        {/* Header */}
        <div className="mb-6 text-center">
          <img src="/mascot/happy.png" alt="" width={92} height={92}
            className="mascot-img mx-auto mb-2"
            style={{ display: "block", filter: "drop-shadow(0 6px 10px rgba(17,24,39,0.18))" }} />
          <h1 className="text-xl font-bold text-[#1C1C1E] mb-1"><Trans>Welcome to Belay</Trans></h1>
          <p className="text-sm text-[#636366]"><Trans>You're protected. Here's what to know:</Trans></p>
        </div>

        {/* Points */}
        <ul className="space-y-4 mb-7">
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.allow}0f`, color: C.allow, border: `1px solid ${C.allow}55` }}>1</span>
            <p className="text-sm text-[#1C1C1E] leading-relaxed">
              {agentNames.length > 0
                ? <Trans>Belay is active and watching the AI agents on your computer. <span className="text-[#636366]">Watching: {agentNames.join(", ")}.</span></Trans>
                : <Trans>Belay is active and watching the AI agents on your computer.</Trans>}
            </p>
          </li>
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.ask}0f`, color: C.ask, border: `1px solid ${C.ask}55` }}>2</span>
            <p className="text-sm text-[#1C1C1E] leading-relaxed">
              <Trans>If an agent tries something risky, we'll ask you before it happens.</Trans>
            </p>
          </li>
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.muted}0f`, color: C.muted, border: `1px solid ${C.muted}55` }}>3</span>
            <div>
              <p className="text-sm text-[#1C1C1E] leading-relaxed mb-2"><Trans>Colors mean the same thing everywhere:</Trans></p>
              <div className="flex flex-wrap gap-3">
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.allow }} />
                  <span style={{ color: C.allow }}><Trans>Green</Trans></span>
                  <span className="text-[#636366]"><Trans>= safe / allowed</Trans></span>
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.ask }} />
                  <span style={{ color: C.ask }}><Trans>Amber</Trans></span>
                  <span className="text-[#636366]"><Trans>= needs your review</Trans></span>
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.deny }} />
                  <span style={{ color: C.deny }}><Trans>Red</Trans></span>
                  <span className="text-[#636366]"><Trans>= blocked</Trans></span>
                </span>
              </div>
            </div>
          </li>
          {aiAvailable && (
            <li className="flex gap-3">
              <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
                style={{ background: `${C.muted}0f`, color: C.muted, border: `1px solid ${C.muted}55` }}>4</span>
              <p className="text-sm text-[#1C1C1E] leading-relaxed">
                <Trans>
                  Optional: turn on AI explanations & the <strong>Skill Judge</strong> (off by default,
                  bring your own key) any time in <span className="text-[#636366]">Settings → AI</span>.
                </Trans>
              </p>
            </li>
          )}
        </ul>

        {/* Dismiss */}
        <button
          onClick={dismiss}
          className="w-full py-2.5 rounded-lg font-semibold text-sm text-white transition-colors"
          style={{ background: C.allow }}
        >
          <Trans>Got it</Trans>
        </button>
      </div>
    </div>
  );
}
