import { render, screen, fireEvent, act } from "@testing-library/react";
import { it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the Tauri IPC bridge (same pattern as ApprovalSurface.test.tsx).
const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: any[]) => invoke(...a) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));

// Mock lib/api so TrayPopover gets deterministic data.
const mockGetPosture = vi.fn();
const mockGetPending = vi.fn();
vi.mock("../lib/api", () => ({
  getPosture: (...a: any[]) => mockGetPosture(...a),
  getPending: (...a: any[]) => mockGetPending(...a),
}));

// Mock lib/ipc for setProtection + getProtectionStatus (not re-exported by api.ts).
const mockSetProtection = vi.fn();
const mockGetProtectionStatus = vi.fn();
vi.mock("../lib/ipc", () => ({
  setProtection: (...a: any[]) => mockSetProtection(...a),
  getProtectionStatus: (...a: any[]) => mockGetProtectionStatus(...a),
}));

import TrayPopover from "./TrayPopover";

const postureProtected = {
  total: 42,
  allow: 42,
  ask: 0,
  deny: 0,
  score: 100,
  by_category: {},
  trend: [],
  top_rules: [],
};

beforeEach(() => {
  vi.useFakeTimers();
  invoke.mockReset();
  invoke.mockResolvedValue({});
  mockGetPosture.mockResolvedValue(postureProtected);
  mockGetPending.mockResolvedValue([]);
  mockGetProtectionStatus.mockResolvedValue("on");
  mockSetProtection.mockResolvedValue({ ok: true, protection: false });
  // Simulate running inside Tauri desktop window.
  (window as any).__TAURI_INTERNALS__ = {};
});

afterEach(() => {
  delete (window as any).__TAURI_INTERNALS__;
  vi.useRealTimers();
});

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

// (a) Status text renders from mocked posture.
it("renders the status word from posture", async () => {
  render(<TrayPopover />);
  await flush();
  // The component must render the status derived from posture.
  expect(screen.getByTestId("popover-status")).toBeTruthy();
  expect(screen.getByTestId("popover-status").textContent).toMatch(/protected/i);
});

// (a) Pending-approval count is shown.
it("shows pending approval count", async () => {
  mockGetPending.mockResolvedValue([
    { id: "p1", session: "claude-code", tool: "Bash", input: {}, reason: "r", rule: "x" },
    { id: "p2", session: "claude-code", tool: "Read", input: {}, reason: "r", rule: "y" },
  ]);
  render(<TrayPopover />);
  await flush();
  expect(screen.getByTestId("popover-pending").textContent).toMatch(/2/);
});

// The tray must read the daemon's REAL protection state on open, not guess
// "on". Regression test for the bug this task fixes: `paused` used to be
// local-only state hardcoded to `false` on every popover open, so a tray
// opened after protection was paused elsewhere (a previous session, another
// surface) showed "Protected" / "Pause protection" as if nothing were wrong.
it("shows the real state on open when protection was already paused", async () => {
  mockGetProtectionStatus.mockResolvedValue("off");
  render(<TrayPopover />);
  await flush();
  expect(screen.getByTestId("popover-status").textContent).toMatch(/paused/i);
  expect(screen.getByTestId("btn-pause").textContent).toMatch(/resume/i);
});

// An unknown/failed read must render its OWN distinct state, never fall back
// to a confident "Protected"/"Pause protection" label - the same idiom
// `postureState`'s "loading" state uses for the score-derived posture.
it("an unknown protection read does not render a confident label, and disables the toggle", async () => {
  mockGetProtectionStatus.mockRejectedValue(new Error("daemon unreachable"));
  render(<TrayPopover />);
  await flush();
  const status = screen.getByTestId("popover-status").textContent ?? "";
  expect(status).not.toMatch(/protected/i);
  expect(status).not.toMatch(/paused/i);
  const btn = screen.getByTestId("btn-pause");
  expect(btn.textContent).not.toMatch(/pause protection/i);
  expect(btn.textContent).not.toMatch(/resume protection/i);
  expect(btn.hasAttribute("disabled")).toBe(true);
  // Clicking while unknown must not call setProtection with a guessed direction.
  fireEvent.click(btn);
  await flush();
  expect(mockSetProtection).not.toHaveBeenCalled();
});

// (b) Clicking "Pause protection" calls setProtection with false.
it("clicking Pause protection calls setProtection(false)", async () => {
  render(<TrayPopover />);
  await flush();
  const btn = screen.getByTestId("btn-pause");
  fireEvent.click(btn);
  await flush();
  expect(mockSetProtection).toHaveBeenCalledWith(false);
});

// The other toggle direction: starting from a real "off" read, clicking
// Resume must call setProtection(true) - not just flip a local boolean.
it("clicking Resume protection calls setProtection(true) when already paused", async () => {
  mockGetProtectionStatus.mockResolvedValue("off");
  mockSetProtection.mockResolvedValue({ ok: true, protection: true });
  render(<TrayPopover />);
  await flush();
  const btn = screen.getByTestId("btn-pause");
  expect(btn.textContent).toMatch(/resume/i);
  fireEvent.click(btn);
  await flush();
  expect(mockSetProtection).toHaveBeenCalledWith(true);
  expect(btn.textContent).toMatch(/pause protection/i);
});

// (b) Button label toggles after clicking pause.
it("button label reflects paused state after clicking", async () => {
  mockSetProtection.mockResolvedValue({ ok: true, protection: false });
  render(<TrayPopover />);
  await flush();
  const btn = screen.getByTestId("btn-pause");
  fireEvent.click(btn);
  await flush();
  // After pausing, button should offer to resume.
  expect(btn.textContent).toMatch(/resume|enable/i);
});

// handlePauseResume's `catch { /* keep current state */ }` used to swallow a
// failure with no visible message - the button silently reverted with no
// explanation, indistinguishable from the click doing nothing.
it("a failed pause/resume shows an error and leaves the label unchanged", async () => {
  mockSetProtection.mockRejectedValue(new Error("daemon unreachable"));
  render(<TrayPopover />);
  await flush();
  const btn = screen.getByTestId("btn-pause");
  expect(btn.textContent).toMatch(/pause/i);
  fireEvent.click(btn);
  await flush();

  expect(screen.getByTestId("pause-error").textContent).toMatch(/daemon unreachable/);
  // Never having flipped, the label is still "Pause protection", not
  // "Resume protection" - and the button is clickable again.
  expect(btn.textContent).toMatch(/pause protection/i);
  expect(btn.hasAttribute("disabled")).toBe(false);
});

// (c) Clicking "Open dashboard" invokes focus_main.
it("clicking Open dashboard invokes focus_main", async () => {
  render(<TrayPopover />);
  await flush();
  fireEvent.click(screen.getByTestId("btn-open-dashboard"));
  await flush();
  expect(invoke).toHaveBeenCalledWith("focus_main");
});
