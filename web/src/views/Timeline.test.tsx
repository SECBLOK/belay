import { render, screen, act } from "@testing-library/react";
import { it, expect, vi } from "vitest";
let onRow: (r: any) => void = () => {};
let recent: any[] = [];
vi.mock("../lib/api", () => ({
  openAuditStream: (h: any) => { onRow = h.onRow; h.onOpen?.(); return { close: () => {} }; },
  getRecentAudit: () => Promise.resolve(recent),
}));
import Timeline from "./Timeline";

it("streams an event into the timeline", async () => {
  render(<Timeline />);
  act(() => onRow({
    ts: new Date().toISOString(), tool: "Read", verdict: "deny",
    reason: "reads .env", rules: ["secrets.env_read"], session: "abc123",
  }));
  await screen.findByText(/reads .env/);
  // Category chip + rule badge both show the human label; raw id is in the title attribute
  expect(screen.getAllByText(/tried to read your credentials/i).length).toBeGreaterThanOrEqual(2);
  // VerdictBadge now shows plain-English "Blocked" instead of raw "deny" token
  expect(screen.getByText("Blocked")).toBeTruthy();
});

it("shows LIVE status on connect", async () => {
  render(<Timeline />);
  await screen.findByText("LIVE");
});

it("renders a friendly action phrase for an allow row, not 'no findings'", async () => {
  render(<Timeline />);
  act(() => onRow({
    ts: new Date().toISOString(), tool: "Bash", verdict: "allow",
    reason: "no findings", rules: [], session: "ok1",
    input: { command: "cargo build --release" },
  }));
  await screen.findByText("Ran a build command");
  expect(screen.queryByText("no findings")).toBeNull();
});

it("seeds recent rows from the snapshot on open", async () => {
  recent = [{
    hash: "h1", ts: new Date().toISOString(), tool: "Bash", verdict: "ask",
    reason: "installs from a remote pipe", rules: ["rce.untrusted_install"], session: "snap01",
  }];
  render(<Timeline />);
  await screen.findByText(/installs from a remote pipe/);
  recent = [];
});

it("does not double-count a snapshot row also delivered by the live stream", async () => {
  const row = {
    hash: "dup1", ts: new Date().toISOString(), tool: "Read", verdict: "deny",
    reason: "reads your ssh key", rules: ["secrets.sensitive_path"], session: "dup01",
  };
  recent = [row];
  render(<Timeline />);
  await screen.findByText(/reads your ssh key/);
  // The live backlog re-delivers the same row; rowKey (hash) must drop it so
  // the row renders exactly once rather than twice.
  act(() => onRow(row));
  expect(screen.getAllByText(/reads your ssh key/).length).toBe(1);
  recent = [];
});
