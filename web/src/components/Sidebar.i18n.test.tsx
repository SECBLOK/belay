// Renders the REAL Sidebar through the REAL Lingui runtime with zh-Hans, to
// prove nav labels, the status footer, and the pending PLURAL all translate.
// The plain Sidebar.test.tsx runs under the suite's <Trans>/useLingui stubs,
// which render English source - so it cannot catch a mistranslated plural or a
// label still keyed on an English string. This can.
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { I18nProvider } from "@lingui/react";
import { i18n } from "@lingui/core";
import { messages } from "../locales/zh-Hans.po";

vi.mock("@lingui/react", async (o) => await o<typeof import("@lingui/react")>());
vi.mock("../lib/api", () => ({
  getPosture: () => Promise.resolve({ score: 40, deny: 2, ask: 1 }),
  getPending: () => Promise.resolve([{ id: "a" }, { id: "b" }, { id: "c" }]),
  getLocale: () => Promise.resolve({ locale: "zh-Hans", supported: ["en", "zh-Hans"] }),
  setLocale: () => Promise.resolve({ ok: true }),
}));

const Sidebar = (await import("./Sidebar")).default;

describe("Sidebar renders in Simplified Chinese", () => {
  it("translates nav labels, the action-needed status, and the pending plural", async () => {
    i18n.load("zh-Hans", messages);
    i18n.activate("zh-Hans");
    render(
      <I18nProvider i18n={i18n}>
        <Sidebar tab="posture" onNavigate={() => {}} />
      </I18nProvider>,
    );

    // Nav labels (module-level msg descriptors, resolved at render).
    expect(screen.getByText("概览")).toBeTruthy();     // Overview
    expect(screen.getByText("实时动态")).toBeTruthy(); // Live Feed
    expect(screen.getByText("主机防护")).toBeTruthy(); // Host Protection

    // Status footer: deny>0 => action needed, in Chinese.
    await waitFor(() => expect(screen.getByText("需要处理")).toBeTruthy());

    // The pending plural: 3 actions, rendered through the ICU catalogue.
    expect(screen.getByText("3 项待处理操作")).toBeTruthy();
  });
});
