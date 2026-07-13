import { render, screen, act } from "@testing-library/react";
import { it, expect, vi, beforeEach, afterEach } from "vitest";

// Drive the surface through the REAL data path (component -> lib/api -> lib/ipc)
// by mocking only the Tauri IPC bridge. get_pending returns the daemon's true
// contract — an OBJECT { pending: [...] } — so the test exercises the unwrap in
// lib/ipc::getPending and can never again mask it by feeding a bare array.
const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: any[]) => invoke(...a) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));

import ApprovalSurface from "./ApprovalSurface";

// The daemon's real get_pending response shape.
const pendingResponse = (entries: any[]) => ({ pending: entries });

beforeEach(() => {
  vi.useFakeTimers();
  invoke.mockReset();
  // respond_approval (resolve) resolves to {}; get_pending is set per-test below.
  invoke.mockResolvedValue({});
  // Pretend we're inside the Tauri desktop window so polling is enabled and
  // lib/api routes through lib/ipc.
  (window as any).__TAURI_INTERNALS__ = {};
});
afterEach(() => {
  delete (window as any).__TAURI_INTERNALS__;
  vi.useRealTimers();
});

const flush = async () => {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
};

it("renders nothing when there are no pendings", async () => {
  invoke.mockResolvedValue(pendingResponse([]));
  const { container } = render(<ApprovalSurface />);
  await flush();
  expect(container.querySelector('[role="alertdialog"]')).toBeNull();
});

it("renders a single ApprovalCard for one pending, unwrapping the daemon { pending: [...] } shape", async () => {
  invoke.mockResolvedValue(
    pendingResponse([
      { id: "p1", session: "claude-code", tool: "Bash",
        input: { command: "cat ~/.aws/credentials" }, reason: "Reads cloud credentials",
        rule: "secrets.aws", created_ms: 1 },
    ]),
  );
  render(<ApprovalSurface />);
  await flush();
  // Proves the unwrap path: an OBJECT-shaped get_pending still renders the card.
  expect(screen.getByRole("alertdialog")).toBeTruthy();
  expect(screen.getByTestId("target").textContent).toContain("~/.aws/credentials");
});

it("renders a BatchDigest for two or more pendings", async () => {
  invoke.mockResolvedValue(
    pendingResponse([
      { id: "p1", session: "claude-code", tool: "Bash", input: { command: "npm i a" }, reason: "a", rule: "supply.install", created_ms: 1 },
      { id: "p2", session: "claude-code", tool: "Bash", input: { command: "npm i b" }, reason: "b", rule: "supply.install", created_ms: 2 },
    ]),
  );
  render(<ApprovalSurface />);
  await flush();
  expect(screen.getByText(/2 pending approvals/i)).toBeTruthy();
});

it("does NOT poll when not running under Tauri", async () => {
  delete (window as any).__TAURI_INTERNALS__;
  invoke.mockResolvedValue(pendingResponse([]));
  render(<ApprovalSurface />);
  await flush();
  expect(invoke).not.toHaveBeenCalledWith("get_pending");
});

it("polls get_pending on an interval", async () => {
  invoke.mockResolvedValue(pendingResponse([]));
  render(<ApprovalSurface />);
  await flush();
  const calls = () => invoke.mock.calls.filter((c) => c[0] === "get_pending").length;
  const firstCalls = calls();
  await act(async () => { vi.advanceTimersByTime(1000); });
  await flush();
  expect(calls()).toBeGreaterThan(firstCalls);
});
