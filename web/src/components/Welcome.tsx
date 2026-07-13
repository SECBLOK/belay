import { useEffect, useState } from "react";
import { listAgents } from "../lib/api";
import { C } from "./dash";

const FLAG = "belay.welcomed";

export default function Welcome() {
  const [visible, setVisible] = useState(false);
  const [agentNames, setAgentNames] = useState<string[]>([]);

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
      aria-label="Welcome to Belay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm"
    >
      <div className="relative w-full max-w-md mx-4 rounded-2xl border border-[rgba(0,0,0,0.08)] bg-white p-8" style={{ boxShadow: "var(--shadow-modal)" }}>
        {/* Header */}
        <div className="mb-6 text-center">
          <span className="inline-block text-3xl mb-3">🛡️</span>
          <h1 className="text-xl font-bold text-[#1C1C1E] mb-1">Welcome to Belay</h1>
          <p className="text-sm text-[#636366]">You're protected. Here's what to know:</p>
        </div>

        {/* Points */}
        <ul className="space-y-4 mb-7">
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.allow}22`, color: C.allow, border: `1px solid ${C.allow}55` }}>1</span>
            <p className="text-sm text-[#1C1C1E] leading-relaxed">
              {agentNames.length > 0
                ? <>Belay is active and watching the AI agents on your computer. <span className="text-[#636366]">Watching: {agentNames.join(", ")}.</span></>
                : "Belay is active and watching the AI agents on your computer."}
            </p>
          </li>
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.ask}22`, color: C.ask, border: `1px solid ${C.ask}55` }}>2</span>
            <p className="text-sm text-[#1C1C1E] leading-relaxed">
              If an agent tries something risky, we'll ask you before it happens.
            </p>
          </li>
          <li className="flex gap-3">
            <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold"
              style={{ background: `${C.muted}22`, color: C.muted, border: `1px solid ${C.muted}55` }}>3</span>
            <div>
              <p className="text-sm text-[#1C1C1E] leading-relaxed mb-2">Colors mean the same thing everywhere:</p>
              <div className="flex flex-wrap gap-3">
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.allow }} />
                  <span style={{ color: C.allow }}>Green</span>
                  <span className="text-[#636366]">= safe / allowed</span>
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.ask }} />
                  <span style={{ color: C.ask }}>Amber</span>
                  <span className="text-[#636366]">= needs your review</span>
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: C.deny }} />
                  <span style={{ color: C.deny }}>Red</span>
                  <span className="text-[#636366]">= blocked</span>
                </span>
              </div>
            </div>
          </li>
        </ul>

        {/* Dismiss */}
        <button
          onClick={dismiss}
          className="w-full py-2.5 rounded-lg font-semibold text-sm text-white transition-colors"
          style={{ background: C.allow }}
        >
          Got it
        </button>
      </div>
    </div>
  );
}
