import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  listQuarantine: vi.fn().mockResolvedValue([
    { id: "q-1", original_path: "/tmp/evil.sh", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "rce", severity: "critical" },
    { id: "q-2", original_path: "/tmp/bad.py", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "rce", severity: "high" },
  ]),
  listBans: vi.fn().mockResolvedValue([
    { id: "b-1", target: "10.0.0.1", kind: "ip", banned_at: "2026-06-01T00:00:00Z", expires_at: null, reason: "brute force" },
  ]),
  getVulnPosture: vi.fn().mockResolvedValue({
    scanned_at: "2026-06-01T00:00:00Z",
    job_id: null,
    total: 5,
    critical: 1,
    high: 2,
    medium: 2,
    low: 0,
    supported: true,
    findings: [
      { cve_id: "CVE-2024-1111", package: "openssl", installed_version: "3.0.0", fixed_version: "3.0.1", severity: "critical", description: "test", published_at: "2024-01-01T00:00:00Z", kev: true },
    ],
  }),
  getFirewallStatus: vi.fn().mockResolvedValue({
    active: true,
    mode: "enforce",
    handle: null,
    revert_deadline: null,
    rule_count: 5,
  }),
}));

import * as api from "../../lib/api";
import HostOverview from "./HostOverview";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.listQuarantine).mockResolvedValue([
    { id: "q-1", original_path: "/tmp/evil.sh", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "rce", severity: "critical" },
    { id: "q-2", original_path: "/tmp/bad.py", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "rce", severity: "high" },
  ]);
  vi.mocked(api.listBans).mockResolvedValue([
    { id: "b-1", target: "10.0.0.1", kind: "ip", banned_at: "2026-06-01T00:00:00Z", expires_at: null, reason: "brute force" },
  ]);
  vi.mocked(api.getVulnPosture).mockResolvedValue({
    scanned_at: "2026-06-01T00:00:00Z",
    job_id: null,
    total: 5,
    critical: 1,
    high: 2,
    medium: 2,
    low: 0,
    supported: true,
    findings: [
      { cve_id: "CVE-2024-1111", package: "openssl", installed_version: "3.0.0", fixed_version: "3.0.1", severity: "critical", description: "test", published_at: "2024-01-01T00:00:00Z", kev: true },
    ],
  });
  vi.mocked(api.getFirewallStatus).mockResolvedValue({
    active: true,
    mode: "enforce",
    handle: null,
    revert_deadline: null,
    rule_count: 5,
  });
});

describe("HostOverview", () => {
  it("renders four stat tiles", async () => {
    const setSection = vi.fn();
    render(<HostOverview setSection={setSection} />);

    // Wait for data to load
    await waitFor(() => expect(screen.getByText(/quarantined/i)).toBeTruthy());

    // All four stat tiles must be present
    expect(screen.getByText(/quarantined/i)).toBeTruthy();
    expect(screen.getByText(/banned ip/i)).toBeTruthy();
    expect(screen.getByText(/kev finding/i)).toBeTruthy();
    expect(screen.getByText(/enforcing/i)).toBeTruthy();
  });

  it("needs-attention row links to the right section", async () => {
    const setSection = vi.fn();
    render(<HostOverview setSection={setSection} />);

    // Wait for data to load — quarantine has 2 entries so should show attention row
    await waitFor(() => expect(screen.getByText(/quarantined/i)).toBeTruthy());

    // Find the "View quarantine" deep-link button and click it
    const viewBtn = screen.getByRole("button", { name: /view files/i });
    fireEvent.click(viewBtn);

    expect(setSection).toHaveBeenCalledWith("files");
  });
});
