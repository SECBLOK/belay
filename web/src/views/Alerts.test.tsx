import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../lib/api", () => ({
  getRecentAudit: vi.fn(),
  getRecentApprovals: vi.fn(),
  openAuditStream: vi.fn(() => ({ close: vi.fn() })),
}));

import * as api from "../lib/api";
import Alerts from "./Alerts";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getRecentAudit).mockResolvedValue([
    { ts: "2026-07-18T10:00:00Z", session: "s1", event: "mcp/response_alert", tool: "github", reason: "injection marker" },
    { ts: "2026-07-18T10:01:00Z", session: "s2", event: "mcp/secret_redacted", reason: "aws_key ×1" },
    { ts: "2026-07-18T10:02:00Z", session: "s3", tool: "Bash", verdict: "allow", rules: ["correlate.injection_to_action"], reason: "curl after ingest" },
    // A plain gate decision — must be filtered OUT of the alerts feed.
    { ts: "2026-07-18T10:03:00Z", session: "s4", tool: "Bash", verdict: "deny", rules: ["cmd.rm_rf"], reason: "rm -rf /" },
  ]);
  vi.mocked(api.getRecentApprovals).mockResolvedValue([
    { ts_ms: 1_800_000_100_000, session: "s5", event: "approval.resolved", tool: "Bash", decision: "deny", source: "local", resolver_agent_lineage: true, self_approval_blocked: true },
    { ts_ms: 1_800_000_050_000, session: "s6", event: "approval.resolved", tool: "Write", decision: "allow", source: "channel", resolver_agent_lineage: false, self_approval_blocked: false },
  ]);
  vi.mocked(api.openAuditStream).mockReturnValue({ close: vi.fn() } as unknown as EventSource);
});

describe("Alerts", () => {
  it("renders only the three alert kinds, not plain gate decisions", async () => {
    render(<Alerts />);
    await waitFor(() => expect(screen.getByText(/injection marker in mcp response/i)).toBeTruthy());
    expect(screen.getByText(/secret redacted from mcp response/i)).toBeTruthy();
    expect(screen.getByText(/risky action after untrusted ingest/i)).toBeTruthy();
    // The rm -rf deny is a decision, not an alert.
    expect(screen.queryByText(/rm -rf/i)).toBeNull();
    // Approval provenance from the separate approvals store is merged in.
    expect(screen.getByText(/self-approval blocked/i)).toBeTruthy();
    expect(screen.getByText(/allowed via messaging channel/i)).toBeTruthy();
  });

  it("filters by kind", async () => {
    render(<Alerts />);
    await waitFor(() => expect(screen.getByText(/injection marker in mcp response/i)).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /^Secret/ }));
    expect(screen.getByText(/secret redacted from mcp response/i)).toBeTruthy();
    expect(screen.queryByText(/injection marker in mcp response/i)).toBeNull();
    expect(screen.queryByText(/risky action after untrusted ingest/i)).toBeNull();
  });
});
