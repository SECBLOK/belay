import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { it, expect } from "vitest";
// Resolve relative to this file. (vitest 4 rebases bare `new URL(rel, import.meta.url)`
// onto its http dev-server base, so we go through fileURLToPath to stay on disk.)
const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "tokens.css"), "utf8");
// The legacy --status-* names must ALIAS the semantic tokens rather than carry
// their own hex. They used to hold copies, and when the AA contrast pass
// darkened allow/ask the copies silently disagreed and the app rendered two
// different greens. Asserting the alias is what stops that recurring.
it("declares the legacy status tokens as aliases of the semantic tokens", () => {
  expect(css).toContain("--status-protected:  var(--semantic-allow)");
  expect(css).toContain("--status-monitoring: var(--semantic-info)");
  expect(css).toContain("--status-action:     var(--semantic-ask)");
  expect(css).toContain("--status-blocked:    var(--semantic-deny)");
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

// ── Palette drift + contrast guards ────────────────────────────────────────
// dash.tsx cannot use var() for its palette: those constants get concatenated
// into 8-digit hex (`${C.allow}22`) for chip fills and borders, where a var()
// would be invalid CSS. So it necessarily holds literals, and the only way to
// keep it honest is to assert here that they still match the tokens.
const dash = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../components/dash.tsx"),
  "utf8",
);
const tokenHex = (name: string): string => {
  const m = css.match(new RegExp(`--${name}:\\s*(#[0-9A-Fa-f]{6})`));
  if (!m) throw new Error(`token --${name} not found (or no longer a literal hex)`);
  return m[1].toUpperCase();
};
const dashHex = (key: string): string => {
  const m = dash.match(new RegExp(`\\b${key}:\\s*"(#[0-9A-Fa-f]{6})"`));
  if (!m) throw new Error(`dash.tsx palette key '${key}' not found`);
  return m[1].toUpperCase();
};

it("keeps dash.tsx's chart palette in step with the semantic tokens", () => {
  expect(dashHex("allow")).toBe(tokenHex("semantic-allow"));
  expect(dashHex("ask")).toBe(tokenHex("semantic-ask"));
  expect(dashHex("deny")).toBe(tokenHex("semantic-deny"));
  expect(dashHex("muted")).toBe(tokenHex("text-tertiary"));
  // `online` is the same "healthy" green; `offline` the same muted grey.
  expect(dashHex("online")).toBe(tokenHex("semantic-allow"));
  expect(dashHex("offline")).toBe(tokenHex("text-tertiary"));
});

// WCAG 2.1 relative luminance / contrast ratio.
const lum = (hex: string): number => {
  const ch = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
};
const contrast = (a: string, b: string): number => {
  const [x, y] = [lum(a), lum(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
};

const TEXT_TOKENS = [
  "text-primary", "text-secondary", "text-tertiary",
  "semantic-allow", "semantic-ask", "semantic-deny", "semantic-info", "semantic-high", "semantic-muted",
];

it("keeps body-text tokens at WCAG AA on the app's light surfaces", () => {
  // The frosted card (white @72% over --lg-ambient) composites to about
  // #F5F8FD at its darkest; white is the lightest surface. Both must pass.
  for (const surface of ["#FFFFFF", "#F5F8FD"]) {
    for (const token of TEXT_TOKENS) {
      expect(
        contrast(tokenHex(token), surface),
        `--${token} on ${surface} must be >= 4.5:1 for body text`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  }
});

// The chip pattern paints a colour's own tint behind text of that same colour
// (`background: ${c}0f; color: c`). The tint darkens the surface, so the text
// loses contrast against its own chip - the fill alpha is what decides whether
// the chip clears AA. At the previous 0x22 every chip failed (allow 4.17, ask
// 4.18, muted 4.22). CHIP_FILL_ALPHA below must stay in step with the `0f`
// suffix used at the call sites.
const CHIP_FILL_ALPHA = 0x0f / 255;
const composite = (fg: string, alpha: number, bg: string): string => {
  const mix = [1, 3, 5].map((i) => {
    const f = parseInt(fg.slice(i, i + 2), 16);
    const b = parseInt(bg.slice(i, i + 2), 16);
    return Math.round(alpha * f + (1 - alpha) * b);
  });
  return `#${mix.map((v) => v.toString(16).padStart(2, "0")).join("")}`.toUpperCase();
};

it("keeps tinted chips at WCAG AA (text on its own fill)", () => {
  for (const surface of ["#FFFFFF", "#F5F8FD"]) {
    for (const token of ["semantic-allow", "semantic-ask", "semantic-deny", "semantic-info", "semantic-high", "text-tertiary"]) {
      const c = tokenHex(token);
      expect(
        contrast(c, composite(c, CHIP_FILL_ALPHA, surface)),
        `--${token} chip on ${surface} must be >= 4.5:1`,
      ).toBeGreaterThanOrEqual(4.5);
    }
  }
});

it("keeps the inverted-surface grey readable on the dark toast/tooltip", () => {
  // Opposite polarity: --text-tertiary would FAIL here, which is exactly why
  // this separate token exists. Guard it so the two never get "unified".
  expect(contrast(tokenHex("text-tertiary-on-dark"), "#1C1C1E")).toBeGreaterThanOrEqual(4.5);
  expect(contrast(tokenHex("text-tertiary"), "#1C1C1E")).toBeLessThan(4.5);
});

// ── CJK fallbacks ──────────────────────────────────────────────────────────
// Without a CJK face in the stack, Chinese text falls through to whatever the
// browser picks last. On a Linux desktop with no CJK font installed that is
// tofu (□□□); where one exists the metrics differ enough to break the fixed
// toast and tray geometry. The faces are listed AFTER the Latin ones so Latin
// glyphs keep their current rendering and only CJK codepoints fall through.
//
// The stack is declared twice - tokens.css (--font-sans) and index.css
// (--sans/--heading) - so these also pin the two copies to each other.
const indexCss = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "..", "index.css"),
  "utf8",
);

const CJK_FACES = ["PingFang SC", "Microsoft YaHei", "Noto Sans SC"];

it("carries CJK fallbacks in every sans stack", () => {
  for (const face of CJK_FACES) {
    expect(css, `tokens.css --font-sans lost "${face}"`).toContain(`"${face}"`);
    expect(indexCss, `index.css --sans/--heading lost "${face}"`).toContain(`"${face}"`);
  }
});

it("carries a CJK fallback in the mono stack too", () => {
  // Session and rule ids render in mono and can sit beside Chinese prose. A
  // mono stack with no CJK face silently substitutes a proportional one and
  // the columns stop lining up.
  expect(css).toContain("Noto Sans Mono CJK SC");
  expect(indexCss).toContain("Noto Sans Mono CJK SC");
});

it("keeps the sans stack identical across tokens.css and index.css", () => {
  const stackOf = (src: string, name: string) =>
    src.match(new RegExp(`--${name}:\\s*([^;]+);`))?.[1].trim();
  const fromTokens = stackOf(css, "font-sans");
  const fromIndex = stackOf(indexCss, "sans");
  expect(fromTokens).toBeTruthy();
  expect(fromIndex).toBe(fromTokens);
});

it("keeps CJK faces after the Latin faces, not before", () => {
  // Order matters: a CJK face placed first would render Latin text in that
  // font's Latin glyphs, changing the look of the whole app.
  const stack = css.match(/--font-sans:\s*([^;]+);/)?.[1] ?? "";
  expect(stack.indexOf("system-ui")).toBeGreaterThan(-1);
  expect(stack.indexOf('"PingFang SC"')).toBeGreaterThan(stack.indexOf("system-ui"));
});

it("bundles the Noto Sans SC subset as a Linux-only multi-weight CJK face", () => {
  // The bundled variable font (private family name) exists on disk, is declared
  // via @font-face in index.css, and appears in every sans stack. It's what
  // gives Linux a real BOLD master instead of single-weight WenQuanYi.
  const fontPath = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "assets",
    "fonts",
    "NotoSansSC-subset.woff2",
  );
  expect(existsSync(fontPath)).toBe(true);
  expect(indexCss).toContain("@font-face");
  expect(indexCss).toContain('font-family: "Noto Sans SC Belay"');
  expect(indexCss).toContain("NotoSansSC-subset.woff2");
  // Variable weight axis declared, so font-weight actually works.
  expect(indexCss).toMatch(/font-weight:\s*100\s+900/);
  for (const src of [css, indexCss]) {
    expect(src).toContain('"Noto Sans SC Belay"');
  }
});

it("positions the bundled font AFTER system CJK and BEFORE WenQuanYi", () => {
  // System YaHei (Windows) / PingFang (macOS) must win first — the bundle is
  // never even reached there. It must come BEFORE WenQuanYi so Linux uses the
  // real multi-weight face rather than the thin single-weight fallback.
  const stack = css.match(/--font-sans:\s*([^;]+);/)?.[1] ?? "";
  const bundled = stack.indexOf('"Noto Sans SC Belay"');
  const yahei = stack.indexOf('"Microsoft YaHei"');
  const wqy = stack.indexOf('"WenQuanYi Zen Hei"');
  expect(bundled).toBeGreaterThan(yahei);
  expect(bundled).toBeLessThan(wqy);
});
