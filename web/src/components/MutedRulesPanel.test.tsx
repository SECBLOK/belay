import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../lib/api", () => ({
  getDenyMutes: vi.fn(),
  revokeDenyMute: vi.fn(),
  revokeAllDenyMutes: vi.fn(),
}));

import * as api from "../lib/api";
import MutedRulesPanel from "./MutedRulesPanel";

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  vi.mocked(api.revokeDenyMute).mockResolvedValue({ ok: true, removed: true });
  vi.mocked(api.revokeAllDenyMutes).mockResolvedValue({ ok: true, removed: 0 });
});
afterEach(() => vi.useRealTimers());

// Fake timers pause real setTimeout-based polling (testing-library's
// findBy/waitFor), so drain pending microtasks explicitly instead — same
// pattern as ApprovalSurface.test.tsx.
const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

describe("MutedRulesPanel", () => {
  it("renders nothing when there are no active mutes", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([]);
    const { container } = render(<MutedRulesPanel />);
    await flush();
    expect(container.firstChild).toBeNull();
  });

  it("shows an active mute with its rule id, origin, and hit count", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([
      { rule: "secrets.sensitive_path", installed_ms: 0, expires_ms: 30 * 60_000, origin: "local", hits: 3 },
    ]);
    render(<MutedRulesPanel />);
    await flush();
    expect(screen.getByText("secrets.sensitive_path")).toBeTruthy();
    expect(screen.getByText("Manual")).toBeTruthy();
    expect(screen.getByText(/3 hits/)).toBeTruthy();
    expect(screen.getByText(/1 rule muted/i)).toBeTruthy();
  });

  it("labels a flood-installed mute as automatic", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([
      { rule: "recon.basic", installed_ms: 0, expires_ms: 5 * 60_000, origin: "auto", hits: 12 },
    ]);
    render(<MutedRulesPanel />);
    await flush();
    expect(screen.getByText(/Auto — flood detected/)).toBeTruthy();
  });

  it("revokes a mute after a second confirm click, not the first", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([
      { rule: "secrets.sensitive_path", installed_ms: 0, expires_ms: 30 * 60_000, origin: "local", hits: 1 },
    ]);
    render(<MutedRulesPanel />);
    await flush();
    expect(screen.getByText("secrets.sensitive_path")).toBeTruthy();

    const btn = screen.getByText("Revoke");
    fireEvent.click(btn);
    expect(api.revokeDenyMute).not.toHaveBeenCalled();
    expect(screen.getByText("Confirm revoke?")).toBeTruthy();

    fireEvent.click(screen.getByText("Confirm revoke?"));
    expect(api.revokeDenyMute).toHaveBeenCalledWith("secrets.sensitive_path");
  });

  it("shows 'Revoke all' only when more than one rule is muted, gated the same way", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([
      { rule: "secrets.sensitive_path", installed_ms: 0, expires_ms: 30 * 60_000, origin: "local", hits: 1 },
      { rule: "recon.basic", installed_ms: 0, expires_ms: 30 * 60_000, origin: "local", hits: 2 },
    ]);
    render(<MutedRulesPanel />);
    await flush();
    expect(screen.getByText(/2 rules muted/i)).toBeTruthy();

    const btn = screen.getByText("Revoke all");
    fireEvent.click(btn);
    expect(api.revokeAllDenyMutes).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Confirm revoke all?"));
    expect(api.revokeAllDenyMutes).toHaveBeenCalled();
  });

  // revokeOne used to be `void x().then(refresh)` with no catch: a rejected
  // revokeDenyMute vanished into an unhandled rejection and the row just sat
  // there, unrevoked, with no feedback.
  it("a failed revoke shows an error and leaves the row usable", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([
      { rule: "secrets.sensitive_path", installed_ms: 0, expires_ms: 30 * 60_000, origin: "local", hits: 1 },
    ]);
    vi.mocked(api.revokeDenyMute).mockRejectedValue(new Error("daemon unreachable"));
    render(<MutedRulesPanel />);
    await flush();

    fireEvent.click(screen.getByText("Revoke"));
    fireEvent.click(screen.getByText("Confirm revoke?"));
    await flush();

    expect(screen.getByTestId("mute-revoke-error").textContent).toMatch(/daemon unreachable/);
    // The mute is still listed (no silent removal) and Revoke works again.
    expect(screen.getByText("secrets.sensitive_path")).toBeTruthy();
    expect(screen.getByText("Revoke")).toBeTruthy();
  });

  it("polls for fresh mutes on an interval", async () => {
    vi.mocked(api.getDenyMutes).mockResolvedValue([]);
    render(<MutedRulesPanel />);
    await flush();
    const firstCalls = vi.mocked(api.getDenyMutes).mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(5000); });
    await flush();
    expect(vi.mocked(api.getDenyMutes).mock.calls.length).toBeGreaterThan(firstCalls);
  });
});
