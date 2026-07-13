import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the api module before importing Welcome
vi.mock("../lib/api", () => ({
  listAgents: vi.fn(),
}));

import { listAgents } from "../lib/api";
import Welcome from "./Welcome";

const FLAG = "belay.welcomed";

beforeEach(() => {
  localStorage.removeItem(FLAG);
  vi.mocked(listAgents).mockReset();
});

afterEach(() => {
  localStorage.removeItem(FLAG);
});

it("shows welcome copy and color legend when flag is unset", async () => {
  vi.mocked(listAgents).mockRejectedValue(new Error("browser only"));
  render(<Welcome />);
  // Main heading visible
  expect(screen.getByRole("dialog")).toBeTruthy();
  expect(screen.getByText(/Welcome to Belay/i)).toBeTruthy();
  // All three copy points visible
  expect(screen.getByText(/watching the AI agents on your computer/i)).toBeTruthy();
  expect(screen.getByText(/ask you before it happens/i)).toBeTruthy();
  // Color legend
  expect(screen.getByText(/Green/i)).toBeTruthy();
  expect(screen.getByText(/Amber/i)).toBeTruthy();
  expect(screen.getByText(/Red/i)).toBeTruthy();
  // Dismiss button
  expect(screen.getByRole("button", { name: /Got it/i })).toBeTruthy();
});

it("renders nothing when flag is already set", () => {
  localStorage.setItem(FLAG, "1");
  vi.mocked(listAgents).mockResolvedValue([]);
  const { container } = render(<Welcome />);
  expect(container.firstChild).toBeNull();
});

it("clicking 'Got it' hides the overlay and persists the flag", async () => {
  vi.mocked(listAgents).mockRejectedValue(new Error("browser only"));
  render(<Welcome />);
  expect(screen.getByRole("dialog")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Got it/i }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(localStorage.getItem(FLAG)).toBe("1");
});

it("shows agent names when listAgents resolves with results", async () => {
  vi.mocked(listAgents).mockResolvedValue([
    { name: "claude-code" },
    { name: "cursor" },
  ]);
  render(<Welcome />);
  await waitFor(() => expect(screen.getByText(/claude-code/)).toBeTruthy());
  expect(screen.getByText(/cursor/)).toBeTruthy();
});

it("falls back to generic copy when listAgents returns empty", async () => {
  vi.mocked(listAgents).mockResolvedValue([]);
  render(<Welcome />);
  await waitFor(() =>
    expect(screen.getByText(/watching the AI agents on your computer/i)).toBeTruthy()
  );
  // Should not show "Watching:" prefix when no agents
  expect(screen.queryByText(/Watching:/i)).toBeNull();
});
