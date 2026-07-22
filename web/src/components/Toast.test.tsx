import { render, screen, fireEvent, act, waitFor } from "@testing-library/react";
import { it, expect, vi, beforeEach } from "vitest";

// Mock the Tauri IPC bridge + event listener (same pattern as TrayPopover.test).
const invoke = vi.fn((..._a: any[]) => Promise.resolve());
let toastHandler:
  | ((e: { payload: { title: string; body: string; paw?: boolean } }) => void)
  | null = null;
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

// `paw: true` only arrives on a Windows build that actually clips the window
// (see shape.rs) - the shared component must render the trimmed, no-chrome
// layout there instead of the rounded card, since the card's border/radius
// would poke past the real silhouette and the window's own corners are
// clipped away entirely.
it("paw builds drop the rounded-card chrome and keep copy inside the pad", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({
      payload: { title: "Belay", body: "Blocked an attempt to read credentials", paw: true },
    });
  });
  const alertEl = screen.getByRole("alert") as HTMLElement;
  expect(alertEl.style.borderRadius).toBe("0px");
  // No chrome in paw mode. Assert the border LONGHAND, not the `border`
  // shorthand string: jsdom re-serializes `border: none` as `medium` and adds
  // spaces inside rgba(), so an exact shorthand compare is environment-fragile
  // (it only ever ran on the Windows box's jsdom). `borderStyle` is stable.
  expect(alertEl.style.borderStyle).toBe("none");
  expect(screen.getByTestId("toast-title").textContent).toContain("Belay");
  expect(screen.getByTestId("toast-body").textContent).toContain("credentials");
});

it("paw builds still dismiss and open the dashboard", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({
      payload: { title: "Belay", body: "An agent action needs your review", paw: true },
    });
  });
  fireEvent.click(screen.getByTestId("toast-dismiss"));
  expect(invoke).toHaveBeenCalledWith("hide_toast");
  expect(screen.queryByRole("alert")).toBeNull();
});

it("non-paw builds (Linux/macOS) keep the rounded-card chrome, unchanged", async () => {
  render(<Toast />);
  await waitFor(() => expect(toastHandler).not.toBeNull());
  act(() => {
    toastHandler!({ payload: { title: "Belay", body: "An agent action needs your review" } });
  });
  const alertEl = screen.getByRole("alert") as HTMLElement;
  expect(alertEl.style.borderRadius).toBe("22px");
  // Rounded-card chrome present. Longhands rather than the `border` shorthand
  // string — jsdom normalizes rgba() spacing, so an exact match on
  // "1px solid rgba(255,255,255,0.14)" fails on Linux jsdom though it passed
  // on the Windows box. borderStyle + borderWidth capture the same intent.
  expect(alertEl.style.borderStyle).toBe("solid");
  expect(alertEl.style.borderWidth).toBe("1px");
});
