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

// Mock lib/ipc for setProtection (not re-exported by api.ts).
const mockSetProtection = vi.fn();
vi.mock("../lib/ipc", () => ({
  setProtection: (...a: any[]) => mockSetProtection(...a),
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

// (b) Clicking "Pause protection" calls setProtection with false.
it("clicking Pause protection calls setProtection(false)", async () => {
  render(<TrayPopover />);
  await flush();
  const btn = screen.getByTestId("btn-pause");
  fireEvent.click(btn);
  await flush();
  expect(mockSetProtection).toHaveBeenCalledWith(false);
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

// (c) Clicking "Open dashboard" invokes focus_main.
it("clicking Open dashboard invokes focus_main", async () => {
  render(<TrayPopover />);
  await flush();
  fireEvent.click(screen.getByTestId("btn-open-dashboard"));
  await flush();
  expect(invoke).toHaveBeenCalledWith("focus_main");
});
