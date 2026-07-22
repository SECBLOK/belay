import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../lib/api", () => ({
  getTrust: vi.fn(),
  getRecentApprovals: vi.fn(),
}));

import * as api from "../lib/api";
import TrustPanel from "./TrustPanel";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getTrust).mockResolvedValue({
    sessions: [
      { session: "codex", grade: "F", demerits: 12.5 },
      { session: "claude-code:1234", grade: "A", demerits: 0.5 },
    ],
  });
  vi.mocked(api.getRecentApprovals).mockResolvedValue([
    { event: "approval.resolved", resolver_agent_lineage: true, self_approval_blocked: true },
    { event: "approval.resolved", resolver_agent_lineage: true, self_approval_blocked: false },
    { event: "approval.resolved", resolver_agent_lineage: false, self_approval_blocked: false },
  ]);
});

describe("TrustPanel", () => {
  it("shows per-session grades with the worst first, and the lowest-grade summary", async () => {
    render(<TrustPanel />);
    await waitFor(() => expect(screen.getByText("Codex")).toBeTruthy());
    expect(screen.getByText("Claude Code")).toBeTruthy();
    // Worst (F) present; the "lowest" summary badge + the row badge → 2 F badges.
    expect(screen.getAllByText("F").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/lowest/i)).toBeTruthy();
  });

  it("counts self-approval attempts and how many were blocked", async () => {
    render(<TrustPanel />);
    // 2 rows with resolver_agent_lineage:true → 2 attempts.
    await waitFor(() => expect(screen.getByText("2")).toBeTruthy());
    // 1 of them blocked.
    expect(screen.getByText(/1 blocked by GateGuard/i)).toBeTruthy();
  });

  it("degrades to empty state when there are no sessions", async () => {
    vi.mocked(api.getTrust).mockResolvedValue({ sessions: [] });
    vi.mocked(api.getRecentApprovals).mockResolvedValue([]);
    render(<TrustPanel />);
    await waitFor(() => expect(screen.getByText(/no agent sessions yet/i)).toBeTruthy());
    expect(screen.getByText(/no agent tried to approve/i)).toBeTruthy();
  });
});
