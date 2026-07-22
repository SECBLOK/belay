import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import Posture from "./Posture";
import { humanizeRule } from "../lib/humanize";
vi.mock("../lib/api", () => ({
  getPosture: vi.fn().mockResolvedValue({
    score: 85, total: 2, allow: 1, ask: 0, deny: 1,
    by_category: { destructive: 1 },
    trend: [{ bucket: "14:00", allow: 1, ask: 0, deny: 1 }],
    top_rules: [{ rule_id: "destructive.rm_rf", count: 1, category: "destructive" }],
  }),
  streamAudit: vi.fn().mockReturnValue(() => {}),
  getTrust: vi.fn().mockResolvedValue({ sessions: [] }),
  getRecentApprovals: vi.fn().mockResolvedValue([]),
}));
it("renders score via Show details disclosure", async () => {
  render(<Posture />);
  // Click "Show details" to reveal the Posture Score gauge
  const btn = await screen.findByText(/show details/i);
  fireEvent.click(btn);
  await waitFor(() => expect(screen.getByText("85")).toBeTruthy());
});
it("renders blocked KPI label (default visible) and top rule human label (behind Show details)", async () => {
  render(<Posture />);
  // "Blocked" KPI tile is always visible
  await waitFor(() => expect(screen.getByText("Blocked")).toBeTruthy());
  // Top rule human label is behind "Show details"
  const btn = screen.getByText(/show details/i);
  fireEvent.click(btn);
  await waitFor(() => expect(screen.getByText(humanizeRule("destructive.rm_rf"))).toBeTruthy());
});
it("renders KPI tiles and StatusRing reassurance sentence by default", async () => {
  render(<Posture />);
  // KPI tiles are default visible
  await waitFor(() => expect(screen.getByText("Actions monitored")).toBeTruthy());
  expect(screen.getByText("Approved")).toBeTruthy();
  // Reassurance sentence is default visible
  expect(screen.getByTestId("posture-reassurance")).toBeTruthy();
});
