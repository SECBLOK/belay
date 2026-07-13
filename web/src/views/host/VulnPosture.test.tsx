import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  getVulnPosture: vi.fn(),
  scanHostVuln: vi.fn(),
}));

import * as api from "../../lib/api";
import VulnPosture from "./VulnPosture";

const POSTURE = {
  scanned_at: "2026-06-01T00:00:00Z",
  job_id: null,
  total: 1,
  critical: 1,
  high: 0,
  medium: 0,
  low: 0,
  findings: [
    {
      cve_id: "CVE-2024-1111",
      package: "openssl",
      installed_version: "3.0.0",
      fixed_version: "3.0.1",
      severity: "critical",
      description: "test",
      published_at: "2024-01-01T00:00:00Z",
      kev: true,
    },
  ],
  supported: true,
  reason: null,
};

const UNSUPPORTED_POSTURE = {
  scanned_at: null,
  job_id: null,
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  findings: [],
  supported: false,
  reason: "Vulnerability posture currently supports Debian and Ubuntu; this OS is not covered.",
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getVulnPosture).mockResolvedValue(POSTURE as never);
  vi.mocked(api.scanHostVuln).mockResolvedValue({ jobId: "vuln-123" });
});

describe("VulnPosture scan button", () => {
  it("triggers scanHostVuln and refreshes the posture on click", async () => {
    render(<VulnPosture />);

    // Initial load fetches the posture once.
    await waitFor(() => expect(screen.getByRole("button", { name: /scan now/i })).toBeTruthy());
    expect(api.getVulnPosture).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /scan now/i }));

    // The button calls scanHostVuln, then re-fetches the posture.
    await waitFor(() => expect(api.scanHostVuln).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(api.getVulnPosture).toHaveBeenCalledTimes(2));
  });

  it("surfaces a scan failure without crashing", async () => {
    vi.mocked(api.scanHostVuln).mockRejectedValueOnce(new Error("POST /api/host/vuln/scan failed: 503"));
    render(<VulnPosture />);

    await waitFor(() => expect(screen.getByRole("button", { name: /scan now/i })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: /scan now/i }));

    await waitFor(() => expect(screen.getByText("Scan failed")).toBeTruthy());
    expect(screen.getByText(/vuln\/scan failed: 503/)).toBeTruthy();
  });
});

describe("VulnPosture approximate caveat", () => {
  it("shows the reason as a caveat note while still rendering the score", async () => {
    vi.mocked(api.getVulnPosture).mockResolvedValue({
      ...POSTURE,
      reason: "Rolling release (Kali / Debian testing): matched against Debian unstable (sid) — results are approximate.",
    } as never);
    render(<VulnPosture />);

    await waitFor(() => expect(screen.getByText(/results are approximate/i)).toBeTruthy());
    // Supported: the score and scan button still render alongside the caveat.
    expect(screen.getByText("Critical")).toBeTruthy();
    expect(screen.getByRole("button", { name: /scan now/i })).toBeTruthy();
  });
});

describe("VulnPosture unsupported OS", () => {
  it("renders the reason and a neutral card, not a score or findings table", async () => {
    vi.mocked(api.getVulnPosture).mockResolvedValue(UNSUPPORTED_POSTURE as never);
    render(<VulnPosture />);

    // The plain-English reason is shown.
    await waitFor(() =>
      expect(screen.getByText(/currently supports Debian and Ubuntu/i)).toBeTruthy(),
    );
    // A neutral "not available on this OS" heading, not a severity score.
    expect(screen.getByText(/not available on this/i)).toBeTruthy();
    // No severity counters and no scan button in the unsupported state.
    expect(screen.queryByText("Critical")).toBeNull();
    expect(screen.queryByRole("button", { name: /scan now/i })).toBeNull();
  });
});
