// Renders the REAL ApprovalCard through the REAL Lingui runtime in zh-Hans, to
// prove the CORE GATING BUTTONS translate. This is the surface where a
// mistranslation is worst: the operator decides allow-vs-deny from these
// words. The plain ApprovalCard.test.tsx runs under the suite's English stub
// and cannot catch a bad Chinese "Deny".
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { I18nProvider } from "@lingui/react";
import { i18n } from "@lingui/core";
import { messages } from "../locales/zh-Hans.po";

vi.mock("@lingui/react", async (o) => await o<typeof import("@lingui/react")>());
vi.mock("../lib/ipc", () => ({
  aiStatus: () => Promise.resolve(false),
  explainAction: () => Promise.resolve(null),
}));

const ApprovalCard = (await import("./ApprovalCard")).default;

const pending = {
  id: "z1", agent: "Claude Code", tool: "Bash",
  input: { command: "cat ~/.aws/credentials" },
  reason: "Reads cloud credentials", rule: "secrets.aws_credentials", risk: "high",
};

describe("ApprovalCard gating buttons render in Simplified Chinese", () => {
  it("translates Allow once / Deny / Deny & stop agent", () => {
    i18n.load("zh-Hans", messages);
    i18n.activate("zh-Hans");
    render(
      <I18nProvider i18n={i18n}>
        <ApprovalCard pending={pending} onResolve={() => {}} timeoutMs={20000} />
      </I18nProvider>,
    );
    expect(screen.getByText("允许一次")).toBeTruthy();       // Allow once
    expect(screen.getByText("拒绝并停止代理")).toBeTruthy(); // Deny & stop agent
    // Plain "Deny" also present (high-risk layout shows both).
    expect(screen.getByText("拒绝")).toBeTruthy();
  });
});
