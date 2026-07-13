import { render, screen, fireEvent, act, waitFor } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";

// Mock the Tauri IPC bridge + event listener (same pattern as TrayPopover.test).
const invoke = vi.fn((..._a: any[]) => Promise.resolve());
let toastHandler: ((e: { payload: { title: string; body: string } }) => void) | null = null;
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: any[]) => invoke(...a) }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (_name: string, cb: any) => {
    toastHandler = cb;
    return Promise.resolve(() => {});
  },
}));

import Toast from "./Toast";

beforeEach(() => {
  invoke.mockClear();
  toastHandler = null;
});

it("renders nothing until a toast event arrives", () => {
  render(<Toast />);
  expect(screen.queryByRole("alert")).toBeNull();
});

it("shows the title/body from a toast event", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({
      payload: { title: "Belay", body: "Blocked an attempt to read credentials" },
    });
  });
  expect(screen.getByTestId("toast-title").textContent).toContain("Belay");
  expect(screen.getByTestId("toast-body").textContent).toContain("credentials");
});

it("dismiss button hides the toast window", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({ payload: { title: "Belay", body: "An agent action needs your review" } });
  });
  fireEvent.click(screen.getByTestId("toast-dismiss"));
  expect(invoke).toHaveBeenCalledWith("hide_toast");
  // Content cleared after dismiss.
  expect(screen.queryByRole("alert")).toBeNull();
});

it("clicking the toast opens the dashboard", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({ payload: { title: "Belay", body: "An agent action needs your review" } });
  });
  fireEvent.click(screen.getByRole("alert"));
  expect(invoke).toHaveBeenCalledWith("focus_main");
});
