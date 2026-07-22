// Renders the REAL TrayPopover through the REAL Lingui runtime with the
// zh-Hans catalogue, to prove the translations actually reach the screen.
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { I18nProvider } from "@lingui/react";
import { i18n } from "@lingui/core";
import { messages } from "../locales/zh-Hans.po";

vi.mock("@lingui/react", async (o) => await o<typeof import("@lingui/react")>());
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../lib/api", () => ({
  getPosture: () => Promise.resolve({ score: 40, deny: 2, ask: 1 }),
  getPending: () => Promise.resolve([{}, {}]),
  getBootStart: () => Promise.resolve({ enabled: false, supported: true }),
  setBootStart: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ setProtection: vi.fn() }));

const TrayPopover = (await import("./TrayPopover")).default;

describe("tray renders in Simplified Chinese", () => {
  it("shows translated labels and the DENY colour for an action-needed posture", async () => {
    i18n.load("zh-Hans", messages);
    i18n.activate("zh-Hans");
    render(<I18nProvider i18n={i18n}><TrayPopover /></I18nProvider>);

    await waitFor(() => expect(screen.getByTestId("popover-status").textContent).toBe("需要处理"));
    expect(screen.getByText("待处理的操作")).toBeTruthy();
    expect(screen.getByText("状态")).toBeTruthy();
    expect(screen.getByText("暂停防护")).toBeTruthy();
    expect(screen.getByText("打开控制台")).toBeTruthy();
    expect(screen.getByText("开机自启")).toBeTruthy();

    // The regression this whole refactor was about: colour is chosen from the
    // STATE, so it must still be the deny red under a non-English locale.
    expect(screen.getByTestId("popover-status").style.color).toContain("semantic-deny");
  });
});
