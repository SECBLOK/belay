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

// The daemon's `ok:true` means "resolved", NOT "you got what you asked for":
// the GateGuard self-approval guard can override an Allow to Deny. If the
// surface ignores that, the row just disappears and the operator is left
// believing they allowed the action. Resolving also DRAINS the queue, so the
// notice has to outlive `pendings` becoming empty.
it("tells the operator when an Allow was overridden by the self-approval guard", async () => {
  const one = [{ id: "ap-1", session: "claude", tool: "Bash", input: { command: "cat .env" }, reason: "r", rule: "x", created_ms: 0 }];
  let drained = false;
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(drained ? [] : one));
    if (cmd === "respond_approval") {
      drained = true; // the request is gone from the queue after resolving
      return Promise.resolve({ ok: true, decision: "deny", requested: "allow", self_approval_blocked: true });
    }
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  expect(screen.queryByTestId("self-approval-blocked")).toBeNull();

  // Buttons arm after a ~1s keystroke guard.
  await act(async () => { vi.advanceTimersByTime(1100); });
  await act(async () => { screen.getByText("Allow once").click(); });
  await flush();

  const banner = screen.getByTestId("self-approval-blocked");
  expect(banner.textContent).toContain("Approval blocked");
  // Survives the now-empty queue rather than vanishing with the card.
  await act(async () => { vi.advanceTimersByTime(1100); });
  await flush();
  expect(screen.getByTestId("self-approval-blocked")).toBeTruthy();
});

it("stays silent when the Allow was honored", async () => {
  const one = [{ id: "ap-2", session: "claude", tool: "Bash", input: { command: "ls" }, reason: "r", rule: "x", created_ms: 0 }];
  let drained = false;
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(drained ? [] : one));
    if (cmd === "respond_approval") {
      drained = true;
      return Promise.resolve({ ok: true, decision: "allow", requested: "allow", self_approval_blocked: false });
    }
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  await act(async () => { vi.advanceTimersByTime(1100); });
  await act(async () => { screen.getByText("Allow once").click(); });
  await flush();
  expect(screen.queryByTestId("self-approval-blocked")).toBeNull();
});
