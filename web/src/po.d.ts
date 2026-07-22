// `@lingui/vite-plugin` turns a `.po` catalogue into an ES module at build
// time, but ships no ambient types for the import, so TypeScript needs to be
// told the shape.
//
// Typed as Lingui's own `Messages` rather than `any` or a hand-rolled
// `Record<string, ...>`: it is exactly what `i18n.load` accepts, so a
// catalogue that stops matching that shape fails at the import instead of
// somewhere downstream.
declare module "*.po" {
  import type { Messages } from "@lingui/core";
  export const messages: Messages;
}
