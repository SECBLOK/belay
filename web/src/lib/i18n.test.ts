// The set of shipped locales is written down in three places that cannot
// import each other: the daemon (`host_config::SUPPORTED_LOCALES`), the setup
// wizard (`setup::LOCALE_OPTIONS`), and this bundle (`CATALOGS`). The Rust
// side already guards its own pair; this closes the third edge.
//
// Drift here is not cosmetic. If the daemon persists a locale the bundle has
// no catalogue for, `activateLocale` silently falls back to English and the
// operator's setting appears to do nothing.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { CATALOGS, DEFAULT_LOCALE, activateLocale, isSupported } from "./i18n";
import { i18n } from "@lingui/core";

function daemonSupportedLocales(): string[] {
  // Resolved from cwd, not import.meta.url: under the jsdom environment
  // import.meta.url is an http:// URL and readFileSync rejects it.
  const src = readFileSync(
    resolve(process.cwd(), "../daemon/src/host_config.rs"),
    "utf8",
  );
  const line = src.split("\n").find((l) => l.includes("SUPPORTED_LOCALES"));
  expect(line, "daemon lost SUPPORTED_LOCALES").toBeTruthy();
  return [...line!.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

describe("shipped locales", () => {
  it("has a bundled catalogue for every locale the daemon accepts", () => {
    const daemon = daemonSupportedLocales();
    expect(daemon.length).toBeGreaterThan(0);
    expect([...daemon].sort()).toEqual(Object.keys(CATALOGS).sort());
  });

  it("bundles English, the source locale every string is guaranteed to have", () => {
    expect(Object.keys(CATALOGS)).toContain(DEFAULT_LOCALE);
  });

  it("inlines catalogues rather than fetching them at runtime", () => {
    // A catalogue fetched at runtime could be swapped after install, letting
    // someone rewrite the text of a security decision without touching a
    // signed binary. Static imports mean the objects are already populated.
    for (const [tag, messages] of Object.entries(CATALOGS)) {
      expect(messages, `${tag} catalogue is not an object`).toBeTypeOf("object");
    }
  });
});

describe("activateLocale", () => {
  it("falls back to English on an unknown tag rather than throwing", () => {
    expect(activateLocale("klingon")).toBe(DEFAULT_LOCALE);
    expect(i18n.locale).toBe(DEFAULT_LOCALE);
  });

  it("activates a supported tag and marks it on <html> for CSS and AT", () => {
    expect(activateLocale("zh-Hans")).toBe("zh-Hans");
    expect(i18n.locale).toBe("zh-Hans");
    expect(document.documentElement.lang).toBe("zh-Hans");
    activateLocale(DEFAULT_LOCALE);
  });

  it("does not treat inherited Object properties as supported locales", () => {
    // `isSupported` uses hasOwnProperty for exactly this reason: a plain `in`
    // check would say "constructor" and "toString" are shipped locales.
    expect(isSupported("constructor")).toBe(false);
    expect(isSupported("toString")).toBe(false);
    expect(activateLocale("constructor")).toBe(DEFAULT_LOCALE);
  });
});
