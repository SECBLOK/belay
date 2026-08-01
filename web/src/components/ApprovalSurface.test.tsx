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

// "Deny & mute this rule" — the daemon reports the outcome on the SAME
// respond_approval reply (mute / mute_refused), it doesn't need a separate
// round trip. The notice must survive the queue draining, same as the
// self-approval banner above.
it("tells the operator which rule got muted, and the notice survives the drained queue", async () => {
  const one = [{ id: "ap-3", session: "claude", tool: "Bash", input: { command: "cat ~/.aws/credentials" }, reason: "r", rule: "secrets.aws", created_ms: 0 }];
  let drained = false;
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(drained ? [] : one));
    if (cmd === "respond_approval") {
      drained = true;
      return Promise.resolve({ ok: true, decision: "deny", requested: "deny", mute: "secrets.aws", mute_refused: null });
    }
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  await act(async () => { vi.advanceTimersByTime(1100); });
  await act(async () => { screen.getByText("Deny & mute this rule").click(); });
  await flush();

  const notice = screen.getByTestId("deny-mute-notice");
  expect(notice.textContent).toContain("Rule muted");
  expect(notice.textContent).toContain("secrets.aws");

  // Survives the now-empty queue rather than vanishing with the card.
  await act(async () => { vi.advanceTimersByTime(1100); });
  await flush();
  expect(screen.getByTestId("deny-mute-notice")).toBeTruthy();
});

// resolveOne must propagate a respond_approval failure to the card instead of
// swallowing it (see ApprovalCard's `act`, which is the thing that actually
// shows the error and keeps the card usable). This exercises the REAL
// component -> lib/api -> lib/ipc -> respond_approval path, not a mock of
// ApprovalCard, so it proves the wiring end to end.
it("propagates a failed respond_approval to the card instead of swallowing it", async () => {
  const one = [{ id: "ap-5", session: "claude", tool: "Bash", input: { command: "cat ~/.aws/credentials" }, reason: "r", rule: "secrets.aws", created_ms: 0 }];
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(one));
    if (cmd === "respond_approval") return Promise.reject(new Error("daemon restarting"));
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  await act(async () => { vi.advanceTimersByTime(1100); });
  await act(async () => { screen.getByText("Allow once").click(); });
  await flush();

  // The card is still here (a swallowed rejection would leave it looking
  // "clicked" with no feedback, but the daemon never actually resolved it).
  expect(screen.getByRole("alertdialog")).toBeTruthy();
  expect(screen.getByTestId("approval-error").textContent).toMatch(/daemon restarting/);
});

// The BatchDigest onResolveAll path used to be
// `void Promise.all(...).then(...)` with no catch: a rejected
// respond_approval mid-batch vanished into an unhandled rejection and the
// dialog just sat there with no feedback, buttons still looking clickable
// but with nothing actually retried.
it("a failed batch resolve shows an error and keeps the dialog usable", async () => {
  const two = [
    { id: "b1", session: "claude", tool: "Bash", input: { command: "npm i a" }, reason: "a", rule: "supply.install", created_ms: 1 },
    { id: "b2", session: "claude", tool: "Bash", input: { command: "npm i b" }, reason: "b", rule: "supply.install", created_ms: 2 },
  ];
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(two));
    if (cmd === "respond_approval") return Promise.reject(new Error("daemon restarting"));
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  expect(screen.getByText(/2 pending approvals/i)).toBeTruthy();

  await act(async () => { screen.getByText("Deny all").click(); });
  await flush();

  const err = screen.getByTestId("batch-resolve-error");
  expect(err.textContent).toMatch(/daemon restarting/);
  // The dialog is still here (both items are still pending) and the batch
  // buttons are clickable again, not stuck disabled.
  expect(screen.getByText(/2 pending approvals/i)).toBeTruthy();
  expect((screen.getByText("Deny all") as HTMLButtonElement).disabled).toBe(false);
});

it("tells the operator why a mute was refused (e.g. critical severity)", async () => {
  const one = [{ id: "ap-4", session: "claude", tool: "Bash", input: { command: "rm -rf /" }, reason: "r", rule: "destructive.rm_rf", created_ms: 0, severity: "critical" }];
  let drained = false;
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "get_pending") return Promise.resolve(pendingResponse(drained ? [] : one));
    if (cmd === "respond_approval") {
      drained = true;
      return Promise.resolve({ ok: true, decision: "deny", requested: "deny", mute: null, mute_refused: "severity_critical" });
    }
    return Promise.resolve({});
  });

  render(<ApprovalSurface />);
  await flush();
  await act(async () => { vi.advanceTimersByTime(1100); });
  await act(async () => { screen.getByText("Deny & mute this rule").click(); });
  await flush();

  const notice = screen.getByTestId("deny-mute-notice");
  expect(notice.textContent).toContain("Rule not muted");
  expect(notice.textContent).toMatch(/critical/i);
});
