// DeadMansSwitchPanel — TDD tests (spec lines 1683–1703).
// Tests were written to FAIL before the component existed, then made green.

import { render, screen, fireEvent, act } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import DeadMansSwitchPanel from "./DeadMansSwitchPanel";

describe("DeadMansSwitchPanel", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("counts down from the server deadline and auto-reverts on expiry", async () => {
    vi.useFakeTimers();
    const onRevert = vi.fn();
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-1"
        onKeep={vi.fn()}
        onRevert={onRevert}
      />,
    );
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    await act(async () => {
      vi.advanceTimersByTime(61_000);
    });
    expect(onRevert).toHaveBeenCalledWith("fw-1");
  });

  it("Keep calls confirm, not revert", async () => {
    const onKeep = vi.fn();
    const onRevert = vi.fn();
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-1"
        onKeep={onKeep}
        onRevert={onRevert}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /keep these rules/i }));
    expect(onKeep).toHaveBeenCalledWith("fw-1");
    expect(onRevert).not.toHaveBeenCalled();
  });

  it("does not fire onRevert twice (no double-fire on expiry)", async () => {
    const onRevert = vi.fn();
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 1_000}
        handle="fw-2"
        onKeep={vi.fn()}
        onRevert={onRevert}
      />,
    );
    await act(async () => {
      // Advance well past the deadline — multiple ticks should not double-fire.
      vi.advanceTimersByTime(5_000);
    });
    expect(onRevert).toHaveBeenCalledTimes(1);
    expect(onRevert).toHaveBeenCalledWith("fw-2");
  });

  it("does not call onRevert when Keep is clicked before expiry", async () => {
    const onKeep = vi.fn();
    const onRevert = vi.fn();
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-3"
        onKeep={onKeep}
        onRevert={onRevert}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /keep these rules/i }));
    // Advance past deadline — should NOT fire onRevert because already handled.
    await act(async () => {
      vi.advanceTimersByTime(65_000);
    });
    expect(onRevert).not.toHaveBeenCalled();
    expect(onKeep).toHaveBeenCalledTimes(1);
  });

  it("has a child live region with aria-live assertive (countdown p element)", () => {
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-4"
        onKeep={vi.fn()}
        onRevert={vi.fn()}
      />,
    );
    // The dialog root must NOT carry aria-live (aria-label/aria-labelledby conflict).
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.getAttribute("aria-live")).toBeNull();
    // The countdown <p> inside the dialog carries aria-live="assertive".
    const liveRegion = dialog.querySelector('[aria-live="assertive"]');
    expect(liveRegion).not.toBeNull();
    expect(liveRegion?.getAttribute("aria-atomic")).toBe("true");
  });

  it("shows visual escalation text when under 15 seconds remain", async () => {
    render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 14_000}
        handle="fw-5"
        onKeep={vi.fn()}
        onRevert={vi.fn()}
      />,
    );
    // At 14s remaining, urgency label should be visible (e.g. "Urgent" or "Reverting in").
    expect(screen.getByText(/reverting in/i)).toBeTruthy();
  });

  it("unmounting before deadline fires onRevert exactly once", async () => {
    const onRevert = vi.fn();
    const { unmount } = render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-6"
        onKeep={vi.fn()}
        onRevert={onRevert}
      />,
    );
    // Unmount before the deadline fires — cleanup must revert.
    unmount();
    expect(onRevert).toHaveBeenCalledTimes(1);
    expect(onRevert).toHaveBeenCalledWith("fw-6");
  });

  it("clicking Keep then unmounting does NOT call onRevert", async () => {
    const onKeep = vi.fn();
    const onRevert = vi.fn();
    const { unmount } = render(
      <DeadMansSwitchPanel
        deadlineMs={Date.now() + 60_000}
        handle="fw-7"
        onKeep={onKeep}
        onRevert={onRevert}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /keep these rules/i }));
    expect(onKeep).toHaveBeenCalledWith("fw-7");
    // Unmount after Keep — settled flag is true, revert must NOT fire.
    unmount();
    expect(onRevert).not.toHaveBeenCalled();
  });
});
