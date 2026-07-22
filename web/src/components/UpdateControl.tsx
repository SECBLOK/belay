import { useState } from "react";
import { Trans, useLingui } from "@lingui/react/macro";
import { useUpdater } from "../lib/updater";

/**
 * Dashboard "Check for updates" control (desktop only; hidden in the web build).
 * Shows the current version and a manual check button, and - when a newer signed
 * release exists - an inline Install & restart. Shares state with the top
 * UpdateBanner via the updater context, so a manual check here also drives the
 * banner, and it benefits from the periodic re-check.
 */
export default function UpdateControl({ className = "" }: { className?: string }) {
  const { t } = useLingui();
  const u = useUpdater();
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Web build / no Tauri bridge: nothing to update here.
  if (u.supported === false) return null;

  async function doInstall() {
    setInstalling(true);
    setError(null);
    try {
      await u.install();
      // On success the app downloads, quits, and relaunches - we won't reach here.
    } catch (e) {
      setInstalling(false);
      setError(String((e as { message?: string } | undefined)?.message ?? e));
    }
  }

  const status =
    u.available && u.version
      ? t`Belay ${u.version} is available.`
      : u.checking
        ? t`Checking for updates…`
        : u.checkedAt
          ? u.current
            ? t`You're on the latest version (v${u.current}).`
            : t`You're on the latest version.`
          : u.current
            ? t`Version ${u.current}.`
            : "";

  return (
    <div
      className={`flex items-center justify-between lg-glass px-4 py-3 ${className}`}
    >
      <div className="pr-3">
        <div className="text-sm font-medium text-[#1C1C1E]"><Trans>Updates</Trans></div>
        <div className="text-xs text-[var(--text-tertiary)]">
          {status}
          {(error || u.error) && (
            <span className="ml-1 text-[#C8312A]"><Trans>Update failed: {error ?? u.error}</Trans></span>
          )}
        </div>
      </div>
      {u.available && u.version ? (
        <button
          data-testid="update-install"
          disabled={installing}
          onClick={doInstall}
          className="shrink-0 rounded-md px-3 py-1 text-sm text-white transition-colors disabled:cursor-not-allowed disabled:opacity-60"
          style={{ background: "var(--accent, #0A66D6)" }}
        >
          {installing ? t`Installing…` : t`Install & restart`}
        </button>
      ) : (
        <button
          data-testid="update-check"
          disabled={u.checking}
          onClick={() => u.checkNow()}
          title={t`Check dl.belay.secblok.io for a newer signed release`}
          className="shrink-0 rounded-md border border-[rgba(0,0,0,0.12)] bg-white px-3 py-1 text-sm text-[#1C1C1E] transition-colors hover:bg-[#EFEFF4] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {u.checking ? t`Checking…` : t`Check for updates`}
        </button>
      )}
    </div>
  );
}
