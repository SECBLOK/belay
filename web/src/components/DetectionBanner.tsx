import { useEffect, useState } from "react";
import { listAgents } from "../lib/api";
import { Plural, Trans, useLingui } from "@lingui/react/macro";

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
  const { t } = useLingui();
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
  // The agent names are proper nouns kept as-is; only the joiner is localized
  // (English "A and B" → Chinese "A 和 B").
  const list =
    labels.length === 1
      ? labels[0]
      : labels.length === 2
        ? t`${labels[0]} and ${labels[1]}`
        : t`${labels.slice(0, -1).join(", ")}, and ${labels[labels.length - 1]}`;

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
          <Plural
            value={names.length}
            one="We found # AI tool on this computer"
            other="We found # AI tools on this computer"
          />
        </p>
        <p className="text-xs text-[#636366] mt-0.5">
          {names.length === 1 ? (
            <Trans>{list} is installed. Review it to turn on protection.</Trans>
          ) : (
            <Trans>{list} are installed. Review them to turn on protection.</Trans>
          )}
        </p>
        <div className="flex items-center gap-2 mt-2.5">
          <button
            onClick={() => onNavigate("agents")}
            className="px-3 py-1 rounded text-[12px] font-semibold transition-colors"
            style={{ background: "#0A66D6", color: "#fff" }}
          >
            <Trans>Review &amp; protect</Trans>
          </button>
          <button
            onClick={dismiss}
            className="px-3 py-1 rounded text-[12px] font-medium transition-colors"
            style={{ background: "rgba(0,0,0,0.05)", color: "#636366" }}
          >
            <Trans>Not now</Trans>
          </button>
        </div>
      </div>
    </div>
  );
}
