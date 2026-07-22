import { defineConfig } from "@lingui/cli";
import { formatter } from "@lingui/format-po";

// Two real locales, deliberately (see docs/i18n-multi-language-plan.md).
// `pseudo` is not shipped: activating it renders every wrapped string in
// accented look-alikes, so any string still in plain English on screen is one
// nobody wrapped. It is the only practical way to audit ~665 call sites.
export default defineConfig({
  sourceLocale: "en",
  locales: ["en", "zh-Hans", "pseudo"],
  pseudoLocale: "pseudo",
  fallbackLocales: { default: "en" },
  catalogs: [
    {
      path: "<rootDir>/src/locales/{locale}",
      include: ["<rootDir>/src"],
      exclude: ["**/*.test.tsx", "**/*.test.ts", "**/node_modules/**"],
    },
  ],
  // lineNumbers: false keeps every .po from churning on unrelated refactors,
  // which would otherwise drown code review in noise.
  format: formatter({ origins: true, lineNumbers: false }),
});
