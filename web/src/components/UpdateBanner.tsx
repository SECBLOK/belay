import { useState } from "react";
import { useUpdater } from "../lib/updater";

/**
 * In-app "Update available" banner (desktop only). Reads the shared updater
 * context (which checks on launch and every few hours), so a release cut while
 * the app is running is surfaced without a restart. Offers one-click Install
 * (download -> verify -> relaunch). Renders nothing when no update is available.
 */
export default function UpdateBanner() {
  const { available, version, install } = useUpdater();
  const [installing, setInstalling] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!available || !version || dismissed) return null;

  async function doInstall() {
    setInstalling(true);
    setError(null);
    try {
      await install();
      // On success the app downloads, quits, and relaunches - we won't reach here.
    } catch (e) {
      setInstalling(false);
      setError(String((e as { message?: string } | undefined)?.message ?? e));
    }
  }

  return (
    <div className="flex items-center justify-between gap-3 border-b border-[rgba(0,0,0,0.08)] bg-[#EAF2FE] px-4 py-2 text-sm">
      <span className="text-[#1C1C1E]">
        Belay <b>{version}</b> is available.
        {error && <span className="ml-2 text-[#C8312A]">Update failed: {error}</span>}
      </span>
      <div className="flex shrink-0 items-center gap-2">
        <button
          onClick={doInstall}
          disabled={installing}
          className="rounded-md px-3 py-1 text-white transition-colors disabled:cursor-not-allowed disabled:opacity-60"
          style={{ background: "var(--accent, #0A66D6)" }}
        >
          {installing ? "Installing…" : "Install & restart"}
        </button>
        <button
          onClick={() => setDismissed(true)}
          disabled={installing}
          className="px-2 py-1 text-[var(--text-tertiary)] hover:text-[#1C1C1E] disabled:opacity-60"
        >
          Later
        </button>
      </div>
    </div>
  );
}
