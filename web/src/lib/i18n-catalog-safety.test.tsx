// A translation catalogue is DATA that renders into the security UI. If a
// catalogue string could introduce markup, then shipping a locale would be
// shipping code, and a `.po` file - the one artefact a translator, a
// contributor, or a compromised localisation pipeline can most easily touch -
// would become an injection vector into the surface that tells the operator
// what was blocked.
//
// The plan for this task originally said to set `transSupportBasicHtmlNodes:
// false` and `transKeepBasicHtmlNodesFor: []`. Those options do not exist in
// Lingui - they are react-i18next's, and the string "BasicHtml" appears
// nowhere in @lingui 6.5.0. Lingui's design is different and stronger: the
// macro compiles JSX children to numbered placeholders (`<0>...</0>`) that are
// bound to elements from the SOURCE, so a catalogue can only rearrange
// elements the code already declared - it cannot name a new one.
//
// That is an argument, not evidence. These tests are the evidence, and they
// are written against the real runtime rather than the test-suite's <Trans>
// mock, which would otherwise render the attack strings itself and pass
// vacuously.

import { render, screen } from "@testing-library/react";
import { i18n } from "@lingui/core";
import { beforeAll, describe, expect, it, vi } from "vitest";

// vitest.setup.ts globally mocks @lingui/react so component tests need no
// provider. A security test of the real renderer must opt back out.
vi.mock("@lingui/react", async (orig) => await orig<typeof import("@lingui/react")>());

const { I18nProvider, Trans } = await vi.importActual<typeof import("@lingui/react")>(
  "@lingui/react",
);

// A REAL tag: Lingui hands the locale to Intl.PluralRules, which throws on a
// made-up one. The attack lives in the catalogue's content, not its name.
const LOCALE = "en";

const ATTACKS = {
  script: "<script>window.__pwned = true</script>",
  img: '<img src=x onerror="window.__pwned = true">',
  anchor: '<a href="javascript:window.__pwned=true">click</a>',
  iframe: '<iframe src="https://evil.example"></iframe>',
};

beforeAll(() => {
  i18n.load(LOCALE, ATTACKS);
  i18n.activate(LOCALE);
});

function renderWithI18n(ui: React.ReactNode) {
  return render(<I18nProvider i18n={i18n}>{ui}</I18nProvider>);
}

describe("a translation catalogue cannot inject markup", () => {
  // Lingui handles a tag-shaped payload in one of two ways, and it is worth
  // knowing which, because they fail differently:
  //
  //   `<script>x</script>`        - a BARE tag name parses as an element
  //                                 placeholder (the `<0>` syntax). It is not
  //                                 declared by the source, so Lingui warns on
  //                                 the console and DROPS the tags, keeping
  //                                 the inner text.
  //   `<img src=x onerror="...">` - attributes make it invalid as a
  //                                 placeholder, so it is escaped and rendered
  //                                 as literal text.
  //
  // Neither creates an element, which is the security property. But the first
  // means a tampered catalogue can make markup-shaped copy silently VANISH -
  // a UI-integrity bug, not an XSS one. Worth knowing before anyone writes a
  // string containing a literal `<tag>`.
  it.each(Object.entries(ATTACKS))(
    "never turns a %s payload into DOM",
    (id, payload) => {
      const { container } = renderWithI18n(<Trans id={id} />);

      // Whatever survives is text, and it is never the executable form.
      const bare = /^<([a-z]+)>/.test(payload);
      if (bare) {
        // Tags dropped, inner text kept - nothing escaped, nothing executed.
        expect(container.textContent).not.toContain("<");
      } else {
        // Escaped and fully visible, so the operator can see the tampering.
        expect(container.textContent).toContain(payload);
        expect(container.innerHTML).toContain("&lt;");
      }

      // In both cases: none of it became an element.
      expect(container.querySelector("script")).toBeNull();
      expect(container.querySelector("img")).toBeNull();
      expect(container.querySelector("iframe")).toBeNull();
      expect(container.querySelector("a")).toBeNull();
      // Note innerHTML legitimately still contains the substring "onerror"
      // when the payload was escaped - as inert text. The property that
      // matters is that no `<tag` survives unescaped.
      expect(container.innerHTML).not.toMatch(/<(script|img|iframe|a)[\s>]/i);
      expect(
        (window as unknown as { __pwned?: boolean }).__pwned,
      ).toBeUndefined();
    },
  );

  it("cannot conjure an element the source code never declared", () => {
    // The source declares exactly one element (index 0, a <b>). The catalogue
    // tries to reference a second one and to smuggle a tag name.
    i18n.load(LOCALE, {
      smuggle: "safe <0>bold</0> then <1><script>x</script></1> and <img src=x>",
    });

    const { container } = renderWithI18n(
      <Trans id="smuggle" components={{ 0: <b /> }} />,
    );

    // The declared element survives; the undeclared ones do not materialise.
    expect(container.querySelector("b")?.textContent).toBe("bold");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).not.toMatch(/<(script|img|iframe)/);
  });

  it("keeps a tampered plural/ICU payload inert too", () => {
    // ICU is evaluated by Lingui, so it is a second parser reachable from the
    // catalogue and worth pinning separately from the plain-string case.
    i18n.load(LOCALE, {
      counted: "{n, plural, one {<img src=x onerror=alert(1)>} other {# items}}",
    });

    const { container } = renderWithI18n(<Trans id="counted" values={{ n: 1 }} />);

    expect(container.querySelector("img")).toBeNull();
    // Escaped, same as the plain-string case above.
    expect(container.innerHTML).not.toMatch(/<(script|img|iframe|a)[\s>]/i);
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });
});

describe("a missing or malformed translation degrades safely", () => {
  it("falls back to the message id rather than rendering blank", () => {
    i18n.load(LOCALE, {});
    i18n.activate(LOCALE);
    renderWithI18n(<Trans id="Nothing to report" />);
    // Never blank: a security surface that silently renders nothing is worse
    // than one rendering untranslated English.
    expect(screen.getByText("Nothing to report")).toBeTruthy();
  });
});
