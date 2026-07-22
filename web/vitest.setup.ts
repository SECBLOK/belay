import "@testing-library/jest-dom";
import React from "react";
import { i18n } from "@lingui/core";
import { vi } from "vitest";

// Lingui's <Trans> requires an I18nProvider in the React tree, and 40+ test
// files call render() directly with no wrapper. Rather than touch every one,
// activate a source-locale catalogue and stub the React context requirement:
// under `en` the runtime returns the English SOURCE string, which is exactly
// what the existing assertions expect.
i18n.load("en", {});
i18n.activate("en");

// Faithful-enough rendering of a compiled Lingui message WITHOUT a provider or
// catalogue. The macro moves interpolated variables OUT of the JSX and into
// `values` (`<Trans>rule · {pending.rule}</Trans>` → message "rule · {rule}" +
// values {rule}), and <Plural> compiles to an ICU string
// (`{count, plural, one {# x} other {# x}}`). A stub that just pasted the raw
// message would show "{rule}" or the literal ICU, so any test asserting the
// interpolated value or the chosen plural form would fail even though the
// component is correct.
//
// Rather than re-implement ICU, delegate to Lingui's own formatter via
// `i18n._` (the `en` source catalogue is active, so it compiles the source
// message and substitutes/selects correctly). Component element tags <0>…</0>
// are then dropped to their inner text - the real <Trans> would render those
// via `components`, but for text assertions the inner text is what matters.
function formatMessage(
  src: string | undefined,
  values: Record<string, unknown> | undefined,
  id?: string,
): string {
  if (src == null && id == null) return "";
  // `msg`Bot token`` compiles to a descriptor carrying only `id` (the source
  // text) and no separate `message`. With an empty catalogue, i18n._ needs a
  // `message` to return/interpolate, so fall back to the id as the source -
  // otherwise a msg-descriptor label renders blank and getByLabelText misses.
  const message = src ?? id ?? "";
  return i18n._({ id: id ?? message, message, values });
}

// Plain-string form (for `t`, aria-label, placeholder, etc.): drop the numbered
// component tags to their inner text.
function renderMessage(
  src: string | undefined,
  values: Record<string, unknown> | undefined,
  id?: string,
): string {
  return formatMessage(src, values, id).replace(/<\/?\d+\s*\/?>/g, "");
}

// Rich form (for <Trans>): reconstruct the numbered <N>…</N> / <N/> component
// tags as REAL React elements from the macro's `components` map, so a value or
// text inside a wrapping element (e.g. `<code>{addr}</code>`) stays its own DOM
// node - which is what the real <Trans> produces and what getByText/getByRole
// assertions rely on. Single level of nesting, which covers every call site.
function renderRich(
  src: string,
  values: Record<string, unknown> | undefined,
  id: string | undefined,
  components: Record<string, React.ReactElement> | undefined,
): React.ReactNode {
  const text = formatMessage(src, values, id);
  if (!components || Object.keys(components).length === 0) {
    return text.replace(/<\/?\d+\s*\/?>/g, "");
  }
  const re = /<(\d+)>([\s\S]*?)<\/\1>|<(\d+)\s*\/>/g;
  const nodes: React.ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const idx = m[1] ?? m[3];
    const inner = m[2];
    const el = components[idx];
    if (el) nodes.push(React.cloneElement(el, { key: key++ }, inner ?? undefined));
    else if (inner != null) nodes.push(inner);
    last = re.lastIndex;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

type TransProps = {
  message?: string;
  id?: string;
  values?: Record<string, unknown>;
  components?: Record<string, React.ReactElement>;
  children?: React.ReactNode;
};

// One stable formatter + one stable useLingui return value, created once (not
// per render) - see the note on `useLingui` below for why identity matters.
// The `t` macro compiles `` t`Updated ${name}` `` to a call taking a descriptor
// { message, id, values }; interpolate it the same way. Falling back to `id`
// matters: a msg-built descriptor may carry only an id, and returning undefined
// would render blank - the failure mode a security UI must never have.
const stableT = (
  d: { message?: string; id?: string; values?: Record<string, unknown> } | string,
) => (typeof d === "string" ? d : renderMessage(d?.message, d?.values, d?.id));
// The macro rewrites `const { t } = useLingui()` into a destructure of `_`, NOT
// `t` - so the stub must expose `_` or every call site fails with "_t is not a
// function". `t` is kept for any non-macro caller.
const STABLE_LINGUI = { i18n, _: stableT, t: stableT };

vi.mock("@lingui/react", async (orig) => {
  const actual = await orig<typeof import("@lingui/react")>();
  return {
    ...actual,
    Trans: ({ message, id, values, components, children }: TransProps) => {
      const src = message ?? id;
      // Non-macro <Trans> (rare) may pass children instead of a message.
      if (src == null) return (children ?? null) as React.ReactElement;
      return renderRich(src, values, id, components) as unknown as React.ReactElement;
    },
    // Returns a STABLE object/function every call. The real useLingui memoizes
    // `t`, and components rely on that: `useCallback(fn, [t])` must keep its
    // identity across renders. A stub that returned a fresh `t` each render
    // would change every such callback's identity every render, re-firing the
    // effects that depend on them in a loop - which manifests as a view stuck
    // on "Loading…". Freezing the reference here mirrors real Lingui.
    useLingui: () => STABLE_LINGUI,
  };
});
