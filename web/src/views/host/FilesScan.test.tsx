import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the api module for all tests in this file
vi.mock("../../lib/api", () => ({
  runHostScan: vi.fn().mockResolvedValue({ findings: [], scanned: 0 }),
  getScanResults: vi.fn().mockResolvedValue([]),
  getSchedule: vi.fn().mockResolvedValue({ enabled: false, cron: "0 3 * * *", scope: "full" }),
  setSchedule: vi.fn().mockResolvedValue(undefined),
  listQuarantine: vi.fn().mockResolvedValue([
    {
      id: "q-1",
      original_path: "/home/user/evil.sh",
      quarantined_at: "2026-06-01T10:00:00Z",
      rule_id: "rce.shell",
      severity: "critical",
    },
  ]),
  restoreQuarantine: vi.fn().mockResolvedValue(undefined),
  deleteQuarantine: vi.fn().mockResolvedValue(undefined),
}));

import * as api from "../../lib/api";
import FilesScan from "./FilesScan";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.runHostScan).mockResolvedValue({ findings: [], scanned: 0 });
  vi.mocked(api.getScanResults).mockResolvedValue([]);
  vi.mocked(api.getSchedule).mockResolvedValue({ enabled: false, cron: "0 3 * * *", scope: "full" });
  vi.mocked(api.setSchedule).mockResolvedValue(undefined);
  vi.mocked(api.listQuarantine).mockResolvedValue([
    {
      id: "q-1",
      original_path: "/home/user/evil.sh",
      quarantined_at: "2026-06-01T10:00:00Z",
      rule_id: "rce.shell",
      severity: "critical",
    },
  ]);
  vi.mocked(api.restoreQuarantine).mockResolvedValue(undefined);
  vi.mocked(api.deleteQuarantine).mockResolvedValue(undefined);
});

describe("FilesScan", () => {
  it("restoring a quarantined file shows a confirm BEFORE calling restoreQuarantine", async () => {
    render(<FilesScan />);

    // Wait for quarantine list to load with the file entry
    await waitFor(() => expect(screen.getAllByText(/evil\.sh/i).length).toBeGreaterThan(0));

    // restoreQuarantine should NOT have been called yet
    expect(api.restoreQuarantine).not.toHaveBeenCalled();

    // Click the Restore button to trigger inline confirm
    const restoreBtn = screen.getByRole("button", { name: /^restore$/i });
    fireEvent.click(restoreBtn);

    // Confirm prompt should be visible
    expect(screen.getByText(/restore this file/i)).toBeTruthy();

    // restoreQuarantine still NOT called (only confirm shown)
    expect(api.restoreQuarantine).not.toHaveBeenCalled();

    // Click the confirm button
    const confirmBtn = screen.getByRole("button", { name: /yes, restore/i });
    fireEvent.click(confirmBtn);

    // NOW restoreQuarantine should have been called
    await waitFor(() => expect(api.restoreQuarantine).toHaveBeenCalledWith("q-1"));
  });

  // A clean scan must READ as a completed scan, not a no-op. Regression for the
  // "Scan now doesn't do anything" report: the empty result now reports how many
  // files were scanned instead of a bare "No scan findings."
  it("reports how many files were scanned after a clean run", async () => {
    vi.mocked(api.runHostScan).mockResolvedValue({ findings: [], scanned: 1247 });
    render(<FilesScan />);
    await waitFor(() => expect(screen.getByText("Scan now")).toBeTruthy());
    fireEvent.click(screen.getByText("Scan now"));
    await waitFor(() => expect(screen.getByText(/no threats found/i)).toBeTruthy());
    expect(screen.getByText(/1,?247/)).toBeTruthy();
  });

  // The Full/Quick selector used to be a no-op (the daemon discarded {quick}).
  // It must now actually drive the scan mode.
  it("Full vs Quick drive different scan modes", async () => {
    vi.mocked(api.runHostScan).mockResolvedValue({ findings: [], scanned: 3 });
    render(<FilesScan />);
    await waitFor(() => expect(screen.getByText("Scan now")).toBeTruthy());
    // Default scope is Full → quick:false.
    fireEvent.click(screen.getByText("Scan now"));
    await waitFor(() => expect(api.runHostScan).toHaveBeenCalledWith({ quick: false }));
    // Switch to Quick → quick:true.
    fireEvent.click(screen.getByText("Quick"));
    fireEvent.click(screen.getByText("Scan now"));
    await waitFor(() => expect(api.runHostScan).toHaveBeenCalledWith({ quick: true }));
  });
});
