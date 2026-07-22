import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'
import { lingui, linguiTransformerBabelPreset } from '@lingui/vite-plugin'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Lets `.po` catalogs be imported as ES modules so they are INLINED into
    // the bundle. Nothing is fetched at runtime: a translation file that can be
    // edited on disk is a way to make a deny read as an allow.
    lingui(),
    // The macro transform. It is code-filtered - only files whose source
    // literally contains `from "@lingui/react/macro"` are handed to babel - so
    // re-exporting the macros through a barrel file silently disables it.
    babel({ presets: [linguiTransformerBabelPreset()] }),
  ],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
  },
})
