import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import AllowlistManager from "./AllowlistManager";
import type { EgressRule } from "../../lib/hostTypes";

const fillHost = (value: string) => {
  fireEvent.change(screen.getByLabelText("Host"), { target: { value } });
};

const RULE: EgressRule = { id: "r-1", host: "api.example.com", proto: "tcp", action: "allow" };

describe("AllowlistManager", () => {
  it("submitting calls onAdd and clears the form once it resolves", async () => {
    const onAdd = vi.fn().mockResolvedValue(undefined);
    render(<AllowlistManager rules={[]} onRemove={vi.fn()} onAdd={onAdd} />);
    fillHost("api.example.com");
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    await waitFor(() =>
      expect(onAdd).toHaveBeenCalledWith(expect.objectContaining({ host: "api.example.com" })),
    );
    await waitFor(() => expect((screen.getByLabelText("Host") as HTMLInputElement).value).toBe(""));
  });

  // Item #10 from the audit: onAdd used to be called WITHOUT awaiting, and
  // the form cleared synchronously right after - a failure looked exactly
  // like success (the typed values vanished either way).
  it("a failed add does NOT clear the form, and surfaces an error", async () => {
    const onAdd = vi.fn().mockRejectedValue(new Error("daemon unreachable"));
    render(<AllowlistManager rules={[]} onRemove={vi.fn()} onAdd={onAdd} />);
    fillHost("api.example.com");
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    await waitFor(() =>
      expect(screen.getByTestId("allowlist-add-error").textContent).toMatch(/daemon unreachable/),
    );
    // The host the user typed is still there - not silently wiped like a
    // successful submit would do.
    expect((screen.getByLabelText("Host") as HTMLInputElement).value).toBe("api.example.com");
    // Still retryable: the button is not stuck disabled.
    expect(screen.getByRole("button", { name: "Add rule" }).hasAttribute("disabled")).toBe(false);
  });

  it("removing a rule confirms then calls onRemove", async () => {
    const onRemove = vi.fn().mockResolvedValue(undefined);
    render(<AllowlistManager rules={[RULE]} onRemove={onRemove} onAdd={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm remove?" }));

    await waitFor(() => expect(onRemove).toHaveBeenCalledWith("r-1"));
  });

  // Last of the controls the audit flagged as failing silently: onRemove used
  // to be called fire-and-forget with no await/catch anywhere in the chain
  // (row, view handler, or IPC wrapper), so a rejection went unhandled - the
  // row just sat there looking untouched, indistinguishable from the click
  // doing nothing.
  it("a failed remove does NOT drop the rule, and surfaces an error", async () => {
    const onRemove = vi.fn().mockRejectedValue(new Error("daemon unreachable"));
    render(<AllowlistManager rules={[RULE]} onRemove={onRemove} onAdd={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm remove?" }));

    await waitFor(() =>
      expect(screen.getByTestId("allowlist-remove-error").textContent).toMatch(/daemon unreachable/),
    );
    // The rule is still on screen - not silently dropped like a successful
    // remove would do.
    expect(screen.getByText("api.example.com")).toBeTruthy();
    // Still retryable: the button reverted to "Remove" and is not stuck
    // disabled.
    expect(screen.getByRole("button", { name: "Remove" }).hasAttribute("disabled")).toBe(false);
  });
});
