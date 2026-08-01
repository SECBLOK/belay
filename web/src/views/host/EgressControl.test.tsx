import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  getEgressAllowlist: vi.fn(),
  addEgressRule: vi.fn(),
  removeEgressRule: vi.fn(),
  setEgressMode: vi.fn(),
  setInlineEgress: vi.fn(),
  getNetEnrich: vi.fn(),
  setNetEnrich: vi.fn(),
}));

import * as api from "../../lib/api";
import EgressControl from "./EgressControl";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getEgressAllowlist).mockResolvedValue([]);
  vi.mocked(api.getNetEnrich).mockResolvedValue(false);
  vi.mocked(api.setEgressMode).mockResolvedValue(undefined);
  vi.mocked(api.setInlineEgress).mockResolvedValue(undefined);
  vi.mocked(api.setNetEnrich).mockResolvedValue({ ok: true });
  vi.mocked(api.addEgressRule).mockResolvedValue({ id: "r-1", host: "x", proto: "tcp", action: "allow" });
  vi.mocked(api.removeEgressRule).mockResolvedValue(undefined);
});

describe("EgressControl", () => {
  it("switching mode on success calls setEgressMode and reflects the new mode", async () => {
    render(<EgressControl />);
    await waitFor(() => expect(screen.getByText("Egress mode")).toBeTruthy());

    fireEvent.click(screen.getByText("Block"));
    await waitFor(() => expect(api.setEgressMode).toHaveBeenCalledWith("enforce"));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Block" }).getAttribute("aria-pressed")).toBe("true"),
    );
  });

  // Item #9 (highest priority): the mode buttons used to flip local state
  // BEFORE the daemon confirmed the change, then silently swallow a
  // rejection - the control would visibly flip to the new setting while the
  // daemon never actually changed. This misrepresents a security posture.
  it("a failed mode change does NOT show the new mode, and surfaces an error", async () => {
    vi.mocked(api.setEgressMode).mockRejectedValue(new Error("daemon unreachable"));
    render(<EgressControl />);
    await waitFor(() => expect(screen.getByText("Egress mode")).toBeTruthy());

    // Starts on "Alert (detect only)" (monitor is the default).
    expect(screen.getByRole("button", { name: "Alert (detect only)" }).getAttribute("aria-pressed")).toBe(
      "true",
    );

    fireEvent.click(screen.getByText("Block"));
    await waitFor(() =>
      expect(screen.getByTestId("egress-mode-error").textContent).toMatch(/daemon unreachable/),
    );

    // Still shows the OLD mode as active - the failed click must not read as
    // having taken effect.
    expect(screen.getByRole("button", { name: "Alert (detect only)" }).getAttribute("aria-pressed")).toBe(
      "true",
    );
    expect(screen.getByRole("button", { name: "Block" }).getAttribute("aria-pressed")).toBe("false");
    // Retryable: the button is not stuck disabled.
    expect((screen.getByRole("button", { name: "Block" }) as HTMLButtonElement).disabled).toBe(false);
  });

  // setNetEnrich never rejects (it fail-softs to {ok:false}), so the bug here
  // was worse than a swallowed catch: the toggle always "succeeded" from the
  // UI's point of view regardless of the daemon's actual answer.
  it("a failed enrich toggle does NOT flip the switch, and surfaces an error", async () => {
    vi.mocked(api.setNetEnrich).mockResolvedValue({ ok: false, error: "daemon unreachable" });
    render(<EgressControl />);
    await waitFor(() => expect(screen.getByText("Enrich destinations")).toBeTruthy());

    const sw = screen.getByRole("switch", { name: /enrich destinations/i });
    expect(sw.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(sw);

    await waitFor(() =>
      expect(screen.getByTestId("enrich-toggle-error").textContent).toMatch(/daemon unreachable/),
    );
    expect(sw.getAttribute("aria-checked")).toBe("false");
  });

  it("a failed inline-enforcement toggle does NOT flip the switch, and surfaces an error", async () => {
    vi.mocked(api.setInlineEgress).mockRejectedValue(new Error("kernel module missing"));
    render(<EgressControl />);
    await waitFor(() => expect(screen.getByText("Egress allowlist")).toBeTruthy());

    fireEvent.click(screen.getByText("Advanced"));
    const switches = await screen.findAllByRole("switch");
    // [0] is the always-visible Enrich toggle; [1] is Inline enforcement.
    const inlineSwitch = switches[1];
    expect(inlineSwitch.getAttribute("aria-checked")).toBe("false");

    fireEvent.click(inlineSwitch); // currently off -> opens the confirm dialog
    fireEvent.click(screen.getByText("Enable")); // confirm -> actually calls onToggle(true)

    await waitFor(() =>
      expect(screen.getByTestId("inline-toggle-error").textContent).toMatch(/kernel module missing/),
    );
    expect(inlineSwitch.getAttribute("aria-checked")).toBe("false");
  });
});
