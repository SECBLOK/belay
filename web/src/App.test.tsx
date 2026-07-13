import { render, screen, fireEvent } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";

// Suppress the Welcome overlay in App tests by pre-setting the flag.
// Without this the overlay mounts and the api mock for listAgents must be present.
beforeEach(() => {
  localStorage.setItem("belay.welcomed", "1");
});

// Minimal mocks for all views mounted by App (and Sidebar which calls getPosture/getPending)
vi.mock("./lib/api", () => ({
  getPending: vi.fn().mockResolvedValue([]),
  getPosture: vi.fn().mockResolvedValue({
    score: 85, total: 0, allow: 0, ask: 0, deny: 0,
    by_category: {}, trend: [], top_rules: [],
  }),
  getFindings: vi.fn().mockResolvedValue([]),
  openAuditStream: vi.fn().mockReturnValue({ close: () => {} }),
  streamAudit: vi.fn().mockReturnValue(() => {}),
  runScan: vi.fn().mockResolvedValue({}),
  listAgents: vi.fn().mockResolvedValue([]),
}));

import App from "./App";

it("renders the Belay brand in the sidebar", () => {
  render(<App />);
  expect(screen.getByText("Belay")).toBeTruthy();
});

it("renders the Overview nav item by default (sidebar)", () => {
  render(<App />);
  // Overview nav label is in the sidebar
  expect(screen.getByText("Overview")).toBeTruthy();
});

it("switches tabs on click (sidebar nav)", () => {
  render(<App />);
  // Activity nav item is in the sidebar
  const activityTab = screen.getByText("Activity");
  fireEvent.click(activityTab);
  // After clicking Activity tab, the Findings search input should appear
  expect(screen.getByPlaceholderText(/Search tool/i)).toBeTruthy();
});

it("does not show the Welcome overlay when flag is set", () => {
  render(<App />);
  expect(screen.queryByRole("dialog", { name: /Welcome/i })).toBeNull();
});
