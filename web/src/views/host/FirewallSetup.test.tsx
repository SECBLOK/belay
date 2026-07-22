import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  getProposedRuleset: vi.fn(),
  getAutoProposedRuleset: vi.fn(),
  applyFirewall: vi.fn(),
  confirmFirewall: vi.fn(),
  revertFirewall: vi.fn(),
  getFirewallStatus: vi.fn(),
}));

import * as api from "../../lib/api";
import FirewallSetup from "./FirewallSetup";

// EXACT shape returned by the live daemon (firewall feature ON):
//   • allow rules OMIT `comment`
//   • the default-drop rule OMITS `port`
//   • proto is "tcp" | "udp" | "any"; action is "allow" | "deny"
// This is the data that was live when the desktop app blanked, captured verbatim.
const REAL_RULESET = {
  description: "Proposed least-privilege ruleset for 8 listening service(s)",
  rules: [
    { id: "auto-0", host: "0.0.0.0", port: 4280, proto: "tcp", action: "allow" },
    { id: "auto-1", host: "0.0.0.0", port: 5432, proto: "tcp", action: "allow" },
    { id: "auto-2", host: "0.0.0.0", port: 9050, proto: "tcp", action: "allow" },
    { id: "auto-3", host: "0.0.0.0", port: 11434, proto: "tcp", action: "allow" },
    { id: "auto-4", host: "0.0.0.0", port: 34459, proto: "tcp", action: "allow" },
    { id: "auto-5", host: "0.0.0.0", port: 36537, proto: "tcp", action: "allow" },
    { id: "auto-6", host: "0.0.0.0", port: 40611, proto: "tcp", action: "allow" },
    { id: "auto-7", host: "0.0.0.0", port: 41721, proto: "tcp", action: "allow" },
    { id: "default-drop", host: "0.0.0.0/0", proto: "any", action: "deny", comment: "default drop" },
  ],
  generated_at: "2026-06-29T00:17:09Z",
};

const REAL_STATUS = {
  active: false,
  mode: "off",
  handle: null,
  revert_deadline: null,
  rule_count: 0,
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getProposedRuleset).mockResolvedValue(REAL_RULESET as never);
  vi.mocked(api.getFirewallStatus).mockResolvedValue(REAL_STATUS as never);
});

describe("FirewallSetup with real daemon payloads", () => {
  it("renders the populated ruleset without throwing (regression: blank screen)", async () => {
    render(<FirewallSetup />);

    // Reaches the idle state and renders the rule table + apply button.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Apply proposed firewall ruleset/i })).toBeTruthy(),
    );
    // The default-drop rule (which omits `port`) renders a placeholder, not a crash.
    expect(screen.getByText("default drop")).toBeTruthy();
    // The "Auto setup" entry point is present in the idle state.
    expect(screen.getByRole("button", { name: /Auto setup/i })).toBeTruthy();
    // Summary reflects all 9 rules.
    expect(screen.getByText(/9 rules proposed/i)).toBeTruthy();
  });

  it("shows a clean error (not a crash) when the daemon returns a ruleset without rules", async () => {
    // An outdated daemon can return a shape lacking `rules`; must not throw
    // `ruleset.rules.filter`.
    vi.mocked(api.getProposedRuleset).mockResolvedValue({ description: "x" } as never);
    render(<FirewallSetup />);
    await waitFor(() =>
      expect(screen.getByText(/unexpected firewall response/i)).toBeTruthy(),
    );
  });

  it("renders the auto-detected proposal without throwing", async () => {
    vi.mocked(api.getAutoProposedRuleset).mockResolvedValue(REAL_RULESET as never);
    render(<FirewallSetup />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Apply proposed firewall ruleset/i })).toBeTruthy(),
    );
    // No throw on initial render is the core assertion; the table is present.
    expect(screen.getByRole("table", { name: /Proposed firewall rules/i })).toBeTruthy();
  });

  // Regression: the daemon reports revert_deadline in epoch SECONDS, but
  // DeadMansSwitchPanel's deadlineMs is epoch MS. Passing the seconds value
  // straight through made the countdown ~1.7e12 ms in the past, so the confirm
  // dialog "expired" instantly — it flashed and auto-reverted before the user
  // could click. The fix multiplies by 1000; this pins it.
  it("shows a real countdown (not an instant revert) for an active rollback window", async () => {
    const nowSecs = Math.floor(Date.now() / 1000);
    vi.mocked(api.getFirewallStatus).mockResolvedValue({
      active: true,
      mode: "on",
      handle: "fw-handle-1",
      revert_deadline: nowSecs + 120, // epoch SECONDS, ~2 minutes out
      rule_count: 9,
    } as never);

    render(<FirewallSetup />);

    // The pending-confirm panel shows a live countdown ("Auto-reverts in" …),
    // proving deadlineMs was interpreted as a FUTURE time.
    await waitFor(() => expect(screen.getByText(/Auto-reverts in/i)).toBeTruthy());
    // And the operator can still act — the confirm control is present.
    expect(
      screen.getByRole("button", { name: /Keep these rules/i }),
    ).toBeTruthy();
    // Crucially, it did NOT instantly auto-revert (the bug's symptom).
    expect(api.revertFirewall).not.toHaveBeenCalled();
  });
});
