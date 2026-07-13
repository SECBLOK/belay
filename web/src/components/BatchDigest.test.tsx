import { render, screen, fireEvent } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import BatchDigest from "./BatchDigest";

const many = [
  { id: "1", agent: "Claude Code", tool: "Bash", input: { command: "npm i a" }, reason: "Install a", rule: "supply.install" },
  { id: "2", agent: "Claude Code", tool: "Bash", input: { command: "npm i b" }, reason: "Install b", rule: "supply.install" },
  { id: "3", agent: "Claude Code", tool: "WebFetch", input: { url: "https://x" }, reason: "Fetch", rule: "egress.new" },
];

const knownRules = [
  { id: "1", agent: "Claude Code", tool: "Bash", input: { command: "rm -rf /" }, reason: "Delete everything", rule: "destructive.rm" },
  { id: "2", agent: "Claude Code", tool: "Bash", input: { command: "rm -rf /tmp" }, reason: "Delete tmp", rule: "destructive.rm" },
  { id: "3", agent: "Claude Code", tool: "Bash", input: { command: "cat ~/.aws/credentials" }, reason: "Read creds", rule: "secrets.aws" },
];

it("rolls multiple pendings into one digest grouped by human label", () => {
  render(<BatchDigest pendings={many} onResolveAll={vi.fn()} onExpand={vi.fn()} />);
  expect(screen.getByText(/3 pending approvals/i)).toBeTruthy();
  // supply.install has no known mapping -> fallback label
  expect(screen.getAllByText("An action that needs your review").length).toBeGreaterThanOrEqual(1);
  // egress group and supply group are separate -> two distinct groups
  // count for the supply.install group (2 items)
  expect(screen.getByText("2")).toBeTruthy();
});

it("groups by human label, not raw rule id — known rules show meaningful labels", () => {
  render(<BatchDigest pendings={knownRules} onResolveAll={vi.fn()} onExpand={vi.fn()} />);
  // Two distinct human labels
  expect(screen.getByText("Tried a destructive action (delete/wipe)")).toBeTruthy();
  expect(screen.getByText("Tried to read your credentials or passwords")).toBeTruthy();
  // destructive group has 2, secrets group has 1
  expect(screen.getByText("2")).toBeTruthy();
  expect(screen.getByText("1")).toBeTruthy();
});

it("shows a severity dot per group (rendered as a span with background)", () => {
  render(<BatchDigest pendings={knownRules} onResolveAll={vi.fn()} onExpand={vi.fn()} />);
  // Dots are aria-hidden spans inside list items
  const dots = document.querySelectorAll('li span[aria-hidden="true"]');
  expect(dots.length).toBeGreaterThanOrEqual(2); // one per group
});

it("Deny all is the prominent (first) action button", () => {
  render(<BatchDigest pendings={many} onResolveAll={vi.fn()} onExpand={vi.fn()} />);
  const buttons = screen.getAllByRole("button");
  const denyAllIdx = buttons.findIndex((b) => b.textContent === "Deny all");
  const allowAllIdx = buttons.findIndex((b) => b.textContent === "Allow all");
  expect(denyAllIdx).toBeLessThan(allowAllIdx);
});

it("Deny all resolves every pending as deny", () => {
  const onResolveAll = vi.fn();
  render(<BatchDigest pendings={many} onResolveAll={onResolveAll} onExpand={vi.fn()} />);
  fireEvent.click(screen.getByText("Deny all"));
  expect(onResolveAll).toHaveBeenCalledWith("deny");
});

it("Allow all resolves every pending as allow", () => {
  const onResolveAll = vi.fn();
  render(<BatchDigest pendings={many} onResolveAll={onResolveAll} onExpand={vi.fn()} />);
  fireEvent.click(screen.getByText("Allow all"));
  expect(onResolveAll).toHaveBeenCalledWith("allow");
});
