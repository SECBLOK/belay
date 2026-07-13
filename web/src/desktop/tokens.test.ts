import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { it, expect } from "vitest";
// Resolve relative to this file. (vitest 4 rebases bare `new URL(rel, import.meta.url)`
// onto its http dev-server base, so we go through fileURLToPath to stay on disk.)
const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "tokens.css"), "utf8");
it("declares the light status tokens with canonical hex", () => {
  expect(css).toContain("--status-protected:  #1B8C3A");
  expect(css).toContain("--status-monitoring: #1A6DC8");
  expect(css).toContain("--status-action:     #B27B00");
  expect(css).toContain("--status-blocked:    #C8312A");
});
it("declares surface-base + accent tokens", () => {
  expect(css).toContain("--surface-base:    #F5F5F7");
  expect(css).toContain("--accent:          #0A66D6");
});
it("declares the legacy bg-window alias pointing to light value", () => {
  expect(css).toContain("--bg-window:         #F5F5F7");
});
it("uses the reduced-motion guard", () => {
  expect(css).toContain("prefers-reduced-motion");
});
