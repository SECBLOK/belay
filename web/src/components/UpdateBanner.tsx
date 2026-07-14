import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type UpdateInfo = { available: boolean; version?: string; current?: string; notes?: string };

/**
 * In-app "Update available" banner (desktop only). On mount it asks the Rust
 * updater to check the configured endpoint; if a newer, signature-verified
 * release exists it offers one-click Install (download -> verify -> relaunch).
 * Renders nothing in the web build or when no update is available.
 */
export default function UpdateBanner() {
  const [upd, setUpd] = useState<{ version: string; notes?: string } | null>(null);
  const [installing, setInstalling] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    // Deferred so a synchronous throw (web build, no Tauri bridge) is caught.
    Promise.resolve()
      .then(() => invoke<UpdateInfo>("check_update"))
      .then((r) => {
        if (live && r && r.available && r.version) setUpd({ version: r.version, notes: r.notes });
      })
      .catch(() => { /* updater unavailable - stay hidden */ });
    return () => { live = false; };
  }, []);

  if (!upd || dismissed) return null;

  async function install() {
    setInstalling(true);
    setError(null);
    try {
      await invoke("install_update");
      // On success the app downloads, quits, and relaunches - we won't reach here.
    } catch (e) {
      setInstalling(false);
      setError(String((e as { message?: string } | undefined)?.message ?? e));
    }
  }

  return (
    <div className="flex items-center justify-between gap-3 border-b border-[rgba(0,0,0,0.08)] bg-[#EAF2FE] px-4 py-2 text-sm">
      <span className="text-[#1C1C1E]">
        Belay <b>{upd.version}</b> is available.
        {error && <span className="ml-2 text-[#C8312A]">Update failed: {error}</span>}
      </span>
      <div className="flex shrink-0 items-center gap-2">
        <button
          onClick={install}
          disabled={installing}
          className="rounded-md px-3 py-1 text-white transition-colors disabled:cursor-not-allowed disabled:opacity-60"
          style={{ background: "var(--accent, #0A66D6)" }}
        >
          {installing ? "Installing…" : "Install & restart"}
        </button>
        <button
          onClick={() => setDismissed(true)}
          disabled={installing}
          className="px-2 py-1 text-[#8E8E93] hover:text-[#1C1C1E] disabled:opacity-60"
        >
          Later
        </button>
      </div>
    </div>
  );
}
