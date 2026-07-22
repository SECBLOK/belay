// Locale bootstrap for every window (main, tray popover, toast).
//
// Catalogues are STATIC imports, so Vite inlines them into the bundle. Nothing
// is fetched at runtime and nothing is read from disk: a translation file that
// could be swapped after install would let someone rewrite the text of a
// security decision - making a "deny" read as an "allow" - without touching a
// signed binary. Two locales is a few KB; lazy-loading buys nothing and costs
// that guarantee.
//
// The daemon owns which locale is active (see host_config::locale). This module
// only applies it.

import { i18n } from "@lingui/core";
import { messages as en } from "../locales/en.po";
import { messages as zhHans } from "../locales/zh-Hans.po";
import { getLocale } from "./api";

/// Must stay in step with the daemon's SUPPORTED_LOCALES and the wizard's
/// LOCALE_OPTIONS. Guarded by a test rather than a comment.
export const CATALOGS = { en, "zh-Hans": zhHans } as const;

export type SupportedLocale = keyof typeof CATALOGS;

export const DEFAULT_LOCALE: SupportedLocale = "en";

/// Each locale's own endonym — a language is always named in itself, never
/// translated ("中文", not "Chinese"), so a speaker recognizes it whatever the
/// current UI language is. Keyed identically to CATALOGS.
export const LOCALE_NAMES: Record<SupportedLocale, string> = {
  en: "English",
  "zh-Hans": "中文（简体）",
};

export function isSupported(tag: string): tag is SupportedLocale {
  return Object.prototype.hasOwnProperty.call(CATALOGS, tag);
}

/// Activate a locale synchronously. An unknown tag falls back to English
/// rather than throwing or rendering blank: this runs during boot, and a
/// security UI that fails to paint is worse than one painting English.
export function activateLocale(tag: string): SupportedLocale {
  const locale: SupportedLocale = isSupported(tag) ? tag : DEFAULT_LOCALE;
  i18n.load(locale, CATALOGS[locale]);
  i18n.activate(locale);
  if (typeof document !== "undefined") {
    // Lets CSS target the locale (CJK line-breaking rules differ) and tells
    // the browser/AT which language it is reading.
    document.documentElement.lang = locale;
  }
  return locale;
}

/// Boot: English first so the very first paint is never blank, then switch to
/// the operator's choice once the daemon answers. Deliberately does NOT block
/// rendering on the IPC round-trip - if the daemon is down, the GUI still
/// comes up, in English.
export async function initLocale(): Promise<SupportedLocale> {
  activateLocale(DEFAULT_LOCALE);
  try {
    const { locale } = await getLocale();
    return activateLocale(locale);
  } catch {
    return DEFAULT_LOCALE;
  }
}
