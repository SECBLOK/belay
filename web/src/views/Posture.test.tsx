import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";
import Posture from "./Posture";
import { humanizeRule } from "../lib/humanize";

const POSTURE_OK = {
  score: 85, total: 2, allow: 1, ask: 0, deny: 1,
  by_category: { destructive: 1 },
  trend: [{ bucket: "14:00", allow: 1, ask: 0, deny: 1 }],
  top_rules: [{ rule_id: "destructive.rm_rf", count: 1, category: "destructive" }],
};

// Hoisted so individual tests can choose whether the posture load resolves or
// rejects, mirroring Fleet.test.tsx: the rejection path is the one that
// matters, since `getPosture()` had no `.catch()` and a rejected invoke used
// to strand this - the first screen the app opens - on its spinner forever.
const { getPosture, streamAudit } = vi.hoisted(() => ({
  getPosture: vi.fn(),
  streamAudit: vi.fn(),
}));

vi.mock("../lib/api", () => ({
  getPosture,
  streamAudit,
  getTrust: vi.fn().mockResolvedValue({ sessions: [] }),
  getRecentApprovals: vi.fn().mockResolvedValue([]),
  getDenyMutes: vi.fn().mockResolvedValue([]),
  revokeDenyMute: vi.fn().mockResolvedValue({ ok: true, removed: true }),
  revokeAllDenyMutes: vi.fn().mockResolvedValue({ ok: true, removed: 0 }),
}));

beforeEach(() => {
  getPosture.mockReset();
  streamAudit.mockReset();
  getPosture.mockResolvedValue(POSTURE_OK);
  streamAudit.mockReturnValue(() => {});
});
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

// getPosture() had no .catch(): a rejected invoke left `p` null and this -
// the first screen the app opens - stuck on "Fetching your protection
// status…" forever, with an unhandled rejection behind it. The failure must
// surface with its underlying reason instead.
it("surfaces a failed load instead of spinning forever, with its reason", async () => {
  getPosture.mockRejectedValue(new Error("Command get_posture not found"));
  render(<Posture />);

  await waitFor(() => expect(screen.getByText(/Could not load your protection status/i)).toBeTruthy());
  expect(screen.queryByText(/Fetching your protection status/i)).toBeNull();
  expect(screen.getByText(/Command get_posture not found/)).toBeTruthy();
});

// A recoverable blip must not strand the tab on the error state: the audit
// stream re-triggers a load, and a subsequent success has to clear it.
it("clears the error once a later load succeeds", async () => {
  let fire: (row: unknown) => void = () => {};
  streamAudit.mockImplementation((cb: (row: unknown) => void) => { fire = cb; return () => {}; });
  getPosture.mockRejectedValueOnce(new Error("transient"));
  render(<Posture />);

  await waitFor(() => expect(screen.getByText(/Could not load your protection status/i)).toBeTruthy());
  getPosture.mockResolvedValue(POSTURE_OK);
  // A real audit row always has a verdict; Posture.tsx pushes it straight
  // into the live-feed state, so an empty call here would crash ringState.
  fire({ ts: "2026-07-30T00:00:00Z", tool: "Bash", verdict: "allow" });
  await waitFor(() => expect(screen.getByText("Actions monitored")).toBeTruthy());
  expect(screen.queryByText(/Could not load your protection status/i)).toBeNull();
});
