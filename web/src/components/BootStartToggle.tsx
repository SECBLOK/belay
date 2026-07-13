import { useEffect, useState } from "react";
import { getBootStart, setBootStart } from "../lib/api";

/**
 * Start-on-boot (autostart) toggle for the dashboard.
 *
 * Desktop-only: renders nothing when the OS reports the feature unsupported
 * (e.g. the browser / web `serve` build). Flipping it triggers an OS elevation
 * prompt (UAC on Windows, pkexec on Linux, osascript on macOS); the displayed
 * state is optimistic and reconciles with the real service state once the user
 * accepts or cancels the prompt.
 */
export default function BootStartToggle({ className = "" }: { className?: string }) {
  const [on, setOn] = useState<boolean | null>(null);
  const [supported, setSupported] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    // Defer the call into the promise chain so even a synchronous throw (e.g. an
    // unavailable binding) becomes a caught rejection → "unsupported", never a crash.
    Promise.resolve()
      .then(() => getBootStart())
      .then((b) => { if (live) { setOn(b.enabled); setSupported(b.supported); } })
      .catch(() => { if (live) setSupported(false); });
    return () => { live = false; };
  }, []);

  async function toggle() {
    if (busy || on === null || !supported) return;
    const target = !on;
    setBusy(true);
    setOn(target);
    try {
      await setBootStart(target);
    } catch {
      setOn(!target); // immediate failure (e.g. no elevation helper) → revert
      setBusy(false);
      return;
    }
    const recheck = () => Promise.resolve().then(() => getBootStart()).then((b) => setOn(b.enabled)).catch(() => {});
    setTimeout(recheck, 3000);
    setTimeout(() => { recheck(); setBusy(false); }, 8000);
  }

  // Hidden until we know it's supported and have the current state.
  if (!supported || on === null) return null;

  return (
    <div
      className={`flex items-center justify-between rounded-lg border border-[rgba(0,0,0,0.08)] bg-[#F5F5F7] px-4 py-3 ${className}`}
    >
      <div className="pr-3">
        <div className="text-sm font-medium text-[#1C1C1E]">Start on boot</div>
        <div className="text-xs text-[#8E8E93]">
          Run Belay automatically when this computer starts (asks for Administrator once).
        </div>
      </div>
      <button
        role="switch"
        aria-checked={on}
        data-testid="bootstart-toggle"
        disabled={busy}
        onClick={toggle}
        title="Toggle running Belay at startup"
        className="relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-60"
        style={{ background: on ? "var(--accent, #0A66D6)" : "rgba(0,0,0,0.25)" }}
      >
        <span
          className="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all"
          style={{ left: on ? "22px" : "2px" }}
        />
      </button>
    </div>
  );
}
