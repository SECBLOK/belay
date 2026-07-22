// Language switcher. Lets the operator change the UI language at runtime — the
// one control the whole i18n feature exists to provide. Persists the choice to
// the daemon (so the tray, toast, and next launch agree) AND activates it live
// so the current window re-renders immediately, no reload.
//
// Desktop installs never run the CLI setup wizard, so for many users this is
// the ONLY place the language is ever chosen — it must be discoverable, which
// is why it sits in the always-visible sidebar footer.

import { useEffect, useState } from "react";
import { Trans, useLingui } from "@lingui/react/macro";
import { getLocale, setLocale as persistLocale } from "../lib/api";
import { activateLocale, isSupported, LOCALE_NAMES, type SupportedLocale } from "../lib/i18n";

export default function LanguagePicker({ collapsed = false }: { collapsed?: boolean }) {
  // Subscribing to Lingui keeps this in step if some other surface switches the
  // locale, and gives us the active tag to show as selected.
  const { t, i18n } = useLingui();
  const [current, setCurrent] = useState<SupportedLocale>(
    isSupported(i18n.locale) ? i18n.locale : "en",
  );
  const [busy, setBusy] = useState(false);

  // Reconcile with the daemon's persisted locale on mount: the boot path in
  // main.tsx already does this, but re-reading here keeps the control honest if
  // it mounts after a change made elsewhere.
  useEffect(() => {
    let live = true;
    getLocale()
      .then(({ locale }) => {
        if (live && isSupported(locale)) setCurrent(locale);
      })
      .catch(() => {
        /* daemon unreachable — keep whatever is active */
      });
    return () => {
      live = false;
    };
  }, []);

  const change = async (next: string) => {
    if (!isSupported(next) || next === current || busy) return;
    setBusy(true);
    // Activate live first so the UI switches instantly; then persist. If the
    // persist fails (daemon down / web build), the language still changed for
    // this session — better than an unresponsive control.
    activateLocale(next);
    setCurrent(next);
    try {
      await persistLocale(next);
    } catch {
      /* non-fatal: the live switch already happened */
    } finally {
      setBusy(false);
    }
  };

  const options = Object.entries(LOCALE_NAMES) as [SupportedLocale, string][];

  // Collapsed sidebar: a bare globe that cycles to the next language, since
  // there is no room for a labelled control. Expanded: a real <select>.
  if (collapsed) {
    const idx = options.findIndex(([tag]) => tag === current);
    const next = options[(idx + 1) % options.length][0];
    return (
      <button
        onClick={() => void change(next)}
        disabled={busy}
        title={`${LOCALE_NAMES[current]} — ${current}`}
        aria-label={t`Language: ${LOCALE_NAMES[current]}`}
        className="mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:bg-[rgba(0,0,0,0.05)] hover:text-[#1C1C1E] transition-colors disabled:opacity-50"
      >
        <GlobeIcon />
      </button>
    );
  }

  return (
    <label className="mx-3 mb-2 flex items-center gap-2 text-[11px] text-[var(--text-tertiary)]">
      <GlobeIcon />
      <span className="sr-only"><Trans>Language</Trans></span>
      <select
        value={current}
        disabled={busy}
        onChange={(e) => void change(e.target.value)}
        aria-label={t`Language`}
        className="flex-1 rounded-md border border-[rgba(0,0,0,0.1)] bg-transparent px-1.5 py-1 text-[12px] text-[#1C1C1E] outline-none focus:border-[var(--accent)] disabled:opacity-50"
      >
        {options.map(([tag, name]) => (
          <option key={tag} value={tag}>
            {name}
          </option>
        ))}
      </select>
    </label>
  );
}

function GlobeIcon() {
  return (
    <svg
      width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden
      stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
      className="shrink-0"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18" />
    </svg>
  );
}
