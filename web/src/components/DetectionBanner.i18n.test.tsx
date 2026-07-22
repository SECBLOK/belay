import { render, screen, waitFor } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import { I18nProvider } from "@lingui/react";
import { i18n } from "@lingui/core";
import { messages } from "../locales/zh-Hans.po";
vi.mock("@lingui/react", async (o) => await o<typeof import("@lingui/react")>());
vi.mock("../lib/api", () => ({
  listAgents: () => Promise.resolve([
    { name: "claude-code", protected: false },
    { name: "hermes", protected: false },
  ]),
}));
const DetectionBanner = (await import("./DetectionBanner")).default;
it("renders the detection banner in Simplified Chinese", async () => {
  localStorage.clear();
  i18n.load("zh-Hans", messages); i18n.activate("zh-Hans");
  render(<I18nProvider i18n={i18n}><DetectionBanner onNavigate={() => {}} /></I18nProvider>);
  await waitFor(() => expect(screen.getByText(/我们在这台计算机上发现了 2 个 AI 工具/)).toBeTruthy());
  expect(screen.getByText(/已安装 Claude Code 和 Hermes/)).toBeTruthy();
  expect(screen.getByText("审查并开启防护")).toBeTruthy();
  expect(screen.getByText("暂不")).toBeTruthy();
});
