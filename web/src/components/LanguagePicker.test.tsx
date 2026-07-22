import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";
import { I18nProvider } from "@lingui/react";
import { i18n } from "@lingui/core";

// Real Lingui runtime so activation actually flips i18n.locale.
vi.mock("@lingui/react", async (o) => await o<typeof import("@lingui/react")>());
const setLocaleMock = vi.fn().mockResolvedValue({ ok: true });
vi.mock("../lib/api", () => ({
  getLocale: () => Promise.resolve({ locale: "en", supported: ["en", "zh-Hans"] }),
  setLocale: (l: string) => setLocaleMock(l),
}));

const LanguagePicker = (await import("./LanguagePicker")).default;

beforeEach(() => {
  setLocaleMock.mockClear();
  i18n.load("en", {});
  i18n.load("zh-Hans", {});
  i18n.activate("en");
});

function renderPicker() {
  return render(
    <I18nProvider i18n={i18n}>
      <LanguagePicker />
    </I18nProvider>,
  );
}

it("offers each shipped language by its own endonym", () => {
  renderPicker();
  expect(screen.getByRole("option", { name: "English" })).toBeTruthy();
  expect(screen.getByRole("option", { name: "中文（简体）" })).toBeTruthy();
});

it("persists AND activates the chosen language", async () => {
  renderPicker();
  const select = screen.getByLabelText("Language") as HTMLSelectElement;
  await act(async () => {
    fireEvent.change(select, { target: { value: "zh-Hans" } });
  });
  // Live activation: the runtime switched immediately.
  expect(i18n.locale).toBe("zh-Hans");
  // And it was persisted to the daemon.
  await waitFor(() => expect(setLocaleMock).toHaveBeenCalledWith("zh-Hans"));
});

it("keeps the UI switched even if persistence fails", async () => {
  setLocaleMock.mockRejectedValueOnce(new Error("daemon down"));
  renderPicker();
  const select = screen.getByLabelText("Language") as HTMLSelectElement;
  await act(async () => {
    fireEvent.change(select, { target: { value: "zh-Hans" } });
  });
  // The live switch already happened; a failed persist must not revert it.
  expect(i18n.locale).toBe("zh-Hans");
});
