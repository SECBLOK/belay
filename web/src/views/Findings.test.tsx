import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import Findings from "./Findings";
vi.mock("../lib/api", () => ({
  getFindings: vi.fn().mockResolvedValue([
    { ts: "2026-06-26T14:00:00Z", event: "PreToolUse", session: "abc123", tool: "Bash", verdict: "deny", reason: "rm -rf /", rules: ["destructive.rm_rf"] },
    { ts: "2026-06-26T14:01:00Z", event: "PreToolUse", session: "abc123", tool: "Read", verdict: "allow", reason: "ok", rules: [] },
  ]),
  streamAudit: vi.fn().mockReturnValue(() => {}),
}));
it("shows a finding row with outcome + plain-English description in What happened column", async () => {
  render(<Findings />);
  // "What happened" now reads the verdict word + describeAction (the daemon's
  // reason wins when present): "Blocked — rm -rf /".
  await waitFor(() => expect(screen.getByText(/Blocked/)).toBeTruthy());
  expect(screen.getByText(/rm -rf/)).toBeTruthy();
});
it("shows verdict filter chips with plain-English labels and counts", async () => {
  render(<Findings />);
  await waitFor(() => expect(screen.getByPlaceholderText(/Search tool/)).toBeTruthy());
  // Filter chips use plain-English display labels (not raw verdict keys).
  // getAllByText is used because "Blocked" and "Allowed" also appear in the table Outcome column.
  expect(screen.getAllByText(/Blocked/i).length).toBeGreaterThanOrEqual(1);
  expect(screen.getAllByText(/Needs review/i).length).toBeGreaterThanOrEqual(1);
  expect(screen.getAllByText(/Allowed/i).length).toBeGreaterThanOrEqual(1);
  // Confirm chip specifically: the filter button wrapper contains the label
  const chips = screen.getAllByRole("button").filter((b) =>
    /Blocked|Needs review|Allowed/.test(b.textContent ?? "")
  );
  expect(chips.length).toBe(3);
});
it("shows advanced columns (Severity, Category, Tool, Rule, Session) when toggle is on", async () => {
  render(<Findings />);
  await waitFor(() => expect(screen.getByText(/rm -rf/)).toBeTruthy());
  // Toggle on advanced columns
  const checkbox = screen.getByLabelText("Show advanced columns");
  fireEvent.click(checkbox);
  // Now Category and Rule columns also show the humanized rule
  await waitFor(() => expect(screen.getAllByText(/tried a destructive action/i).length).toBeGreaterThanOrEqual(2));
  // Severity column appears
  expect(screen.getByText("Critical")).toBeTruthy();
});
it("expanded row shows raw rule id and session for power users", async () => {
  render(<Findings />);
  await waitFor(() => expect(screen.getByText(/rm -rf/)).toBeTruthy());
  // Click the first row to expand it
  const rows = screen.getAllByRole("row");
  // first row is thead, second is the deny row
  fireEvent.click(rows[1]);
  await waitFor(() => expect(screen.getByText("destructive.rm_rf")).toBeTruthy());
});
