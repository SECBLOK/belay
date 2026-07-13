import { render, screen, waitFor } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";

vi.mock("../lib/api", () => ({
  enrichDest: vi.fn(),
}));

import * as api from "../lib/api";
import ActivityFeed from "./ActivityFeed";

beforeEach(() => {
  vi.clearAllMocks();
});

const rows = [
  { ts: "2026-06-26T14:00:00Z", tool: "Bash", input: { command: "rm -rf /" }, verdict: "deny", rules: ["destructive.rm_rf"] },
  { ts: "2026-06-26T13:59:00Z", tool: "Read", input: { path: "/etc/hosts" }, verdict: "allow", rules: [] },
];
it("renders a row per event with a verdict-accent bar", () => {
  render(<ActivityFeed rows={rows} />);
  // The deny row's rule resolves to a plain-English description (raw command hidden)
  expect(screen.getByText("Tried a destructive action (delete/wipe)")).toBeTruthy();
  const bar = screen.getAllByTestId("verdict-bar")[0];
  expect(bar.style.background).toContain("status-blocked"); // deny -> red token
});
it("renders newest first", () => {
  render(<ActivityFeed rows={rows} />);
  const items = screen.getAllByTestId("feed-row");
  expect(items[0].textContent).toContain("Tried a destructive action");
});
it("gives an allow row a human description, not empty or 'no findings'", () => {
  const allowRows = [
    { ts: "2026-06-26T12:00:00Z", tool: "Read", input: { file_path: "/x/api.ts" }, verdict: "allow", reason: "no findings", rules: [] },
  ];
  render(<ActivityFeed rows={allowRows} />);
  expect(screen.getByText("Read api.ts")).toBeTruthy();
  expect(screen.queryByText("no findings")).toBeNull();
});

it("renders a DestOwner chip for an egress bypass row's extracted destination", async () => {
  vi.mocked(api.enrichDest).mockResolvedValue({
    hostname: "api.anthropic.com",
    asn: "13335",
    as_name: "CLOUDFLARENET",
    country: "US",
  });
  const egressRows = [
    {
      ts: "2026-06-26T15:00:00Z", tool: "raw", verdict: "deny",
      reason: "hook bypass: raw connect to new destination 203.0.113.9:443",
      rules: ["bypass.new_destination"],
    },
  ];
  render(<ActivityFeed rows={egressRows} />);
  await waitFor(() => expect(api.enrichDest).toHaveBeenCalledWith("203.0.113.9:443"));
  await waitFor(() => expect(screen.getByText(/CLOUDFLARENET/)).toBeTruthy());
});

it("renders no DestOwner chip for a non-egress row", () => {
  render(<ActivityFeed rows={rows} />);
  expect(api.enrichDest).not.toHaveBeenCalled();
});
