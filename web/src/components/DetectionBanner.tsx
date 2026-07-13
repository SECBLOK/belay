import { useEffect, useState } from "react";
import { listAgents } from "../lib/api";

// First-run discoverability: when Belay detects AI agents on the machine,
// surface a friendly, dismissible prompt on the Overview so non-technical users
// don't have to hunt for the Agents tab. Detection is desktop-only; in the
// browser `listAgents()` rejects and the banner renders nothing.

const DISMISS_KEY = "belay.detectionBanner.dismissed";

/** "claude-code" → "Claude Code", "openclaw" → "Openclaw". */
function prettyName(name: string): string {
  return name
    .split(/[-_]/)
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ");
}

export default function DetectionBanner({
  onNavigate,
}: {
  onNavigate: (tab: "agents") => void;
}) {
  const [names, setNames] = useState<string[] | null>(null);
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(DISMISS_KEY) === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    let alive = true;
    listAgents()
      .then((list) => {
        // Only prompt for agents that are NOT already protected — otherwise the
        // banner keeps nagging after the user has turned protection on.
        const arr = (Array.isArray(list) ? list : []) as Array<{
          name: string;
          protected?: boolean;
        }>;
        const unprotected = arr.filter((a) => !a.protected).map((a) => a.name);
        if (alive) setNames(unprotected);
      })
      .catch(() => {
        // Desktop-only / unreachable → stay hidden.
        if (alive) setNames([]);
      });
    return () => {
      alive = false;
    };
  }, []);

  if (dismissed || !names || names.length === 0) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* ignore */
    }
    setDismissed(true);
  };

  const labels = names.map(prettyName);
  const list =
    labels.length === 1
      ? labels[0]
      : labels.length === 2
        ? `${labels[0]} and ${labels[1]}`
        : `${labels.slice(0, -1).join(", ")}, and ${labels[labels.length - 1]}`;

  return (
    <div
      className="mx-6 mt-6 rounded-xl p-4 flex items-start gap-3"
      style={{
        background: "rgba(10,102,214,0.06)",
        border: "1px solid rgba(10,102,214,0.20)",
      }}
      role="status"
    >
      <div
        className="w-8 h-8 rounded-full shrink-0 flex items-center justify-center text-sm"
        style={{ background: "rgba(10,102,214,0.12)", color: "#0A66D6" }}
        aria-hidden
      >
        🛡️
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-[#1C1C1E]">
          We found {names.length} AI {names.length === 1 ? "tool" : "tools"} on this computer
        </p>
        <p className="text-xs text-[#636366] mt-0.5">
          {list} {names.length === 1 ? "is" : "are"} installed. Review{" "}
          {names.length === 1 ? "it" : "them"} to turn on protection.
        </p>
        <div className="flex items-center gap-2 mt-2.5">
          <button
            onClick={() => onNavigate("agents")}
            className="px-3 py-1 rounded text-[12px] font-semibold transition-colors"
            style={{ background: "#0A66D6", color: "#fff" }}
          >
            Review &amp; protect
          </button>
          <button
            onClick={dismiss}
            className="px-3 py-1 rounded text-[12px] font-medium transition-colors"
            style={{ background: "rgba(0,0,0,0.05)", color: "#636366" }}
          >
            Not now
          </button>
        </div>
      </div>
    </div>
  );
}
