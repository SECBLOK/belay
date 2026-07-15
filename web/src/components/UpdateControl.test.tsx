import { render, screen, fireEvent } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";

// Drive UpdateControl through a mocked updater context so we can assert each
// state (unsupported / up-to-date / update-available) without a Tauri bridge.
const state: Record<string, unknown> = {};
vi.mock("../lib/updater", () => ({ useUpdater: () => state }));

import UpdateControl from "./UpdateControl";

function setState(s: Record<string, unknown>) {
  for (const k of Object.keys(state)) delete state[k];
  Object.assign(state, { checkNow: vi.fn(), install: vi.fn() }, s);
}

beforeEach(() => setState({ supported: true, available: false, checking: false }));

it("renders nothing in the web build (unsupported)", () => {
  setState({ supported: false, available: false, checking: false });
  const { container } = render(<UpdateControl />);
  expect(container.firstChild).toBeNull();
});

it("shows 'up to date' with the current version after a check", () => {
  setState({ supported: true, available: false, checking: false, checkedAt: 1, current: "0.1.11" });
  render(<UpdateControl />);
  expect(screen.getByText(/latest version \(v0\.1\.11\)/)).toBeTruthy();
  expect(screen.getByTestId("update-check")).toBeTruthy();
});

it("manual check button calls checkNow", () => {
  const checkNow = vi.fn();
  setState({ supported: true, available: false, checking: false, checkNow });
  render(<UpdateControl />);
  fireEvent.click(screen.getByTestId("update-check"));
  expect(checkNow).toHaveBeenCalled();
});

it("offers Install & restart when an update is available", () => {
  const install = vi.fn().mockResolvedValue(undefined);
  setState({ supported: true, available: true, version: "0.1.12", checking: false, install });
  render(<UpdateControl />);
  expect(screen.getByText(/Belay 0\.1\.12 is available/)).toBeTruthy();
  fireEvent.click(screen.getByTestId("update-install"));
  expect(install).toHaveBeenCalled();
});
