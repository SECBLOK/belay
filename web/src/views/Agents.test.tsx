import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { it, expect, vi, beforeEach, describe } from "vitest";
import Agents from "./Agents";

vi.mock("../lib/api", () => ({
  listAgents: vi.fn(),
  protectAgent: vi.fn(),
  unprotectAgent: vi.fn(),
}));

import { listAgents, protectAgent, unprotectAgent } from "../lib/api";

const mockListAgents = listAgents as ReturnType<typeof vi.fn>;
const mockProtectAgent = protectAgent as ReturnType<typeof vi.fn>;
const mockUnprotectAgent = unprotectAgent as ReturnType<typeof vi.fn>;

const AGENT_FIXTURE = {
  name: "claude-code",
  settings: ["/home/user/.claude/settings.json"],
  risky: ["bypassPermissions", "enableAllProjectMcpServers"],
  interception: "hook",
  mcp_config: [],
};

beforeEach(() => {
  mockListAgents.mockReset();
  mockProtectAgent.mockReset();
  mockUnprotectAgent.mockReset();
});

describe("Agents view — list state", () => {
  it("renders agent name as heading", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());
  });

  it("renders humanized risky-flag chip — NOT the raw flag as only visible text", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);
    // Raw flag must NOT appear as a plain text node at top level
    await waitFor(() =>
      expect(screen.getByText(/permission prompts are off/i)).toBeTruthy()
    );
    // "bypassPermissions" raw flag should appear only in title attribute, not as
    // visible text node (it may be in a title= attr which getByText won't match)
    expect(screen.queryAllByText("bypassPermissions").length).toBe(0);
  });

  it("renders plain-English interception label for 'hook'", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/guarded via hook/i)).toBeTruthy()
    );
  });

  it("renders second humanized risky-flag chip for enableAllProjectMcpServers", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/all mcp servers auto-enabled/i)).toBeTruthy()
    );
  });

  it("shows 'No risky settings' in muted style when risky is empty", async () => {
    mockListAgents.mockResolvedValue([{ ...AGENT_FIXTURE, risky: [] }]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/no risky settings/i)).toBeTruthy()
    );
  });

  it("shows settings path in secondary mono style", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/settings\.json/i)).toBeTruthy()
    );
  });

  it("omits 'Where it lives' section when settings is empty", async () => {
    mockListAgents.mockResolvedValue([{ ...AGENT_FIXTURE, settings: [] }]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());
    expect(screen.queryByText(/where it lives/i)).toBeNull();
  });

  it("maps mcp-proxy interception to plain English", async () => {
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, interception: "mcp-proxy" },
    ]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/guarded via mcp proxy/i)).toBeTruthy()
    );
  });

  it("maps config-policy interception to plain English", async () => {
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, interception: "config-policy" },
    ]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/guarded via config policy/i)).toBeTruthy()
    );
  });
});

describe("Agents view — protection badge", () => {
  it("shows '✓ Protected' when the agent is protected", async () => {
    mockListAgents.mockResolvedValue([{ ...AGENT_FIXTURE, protected: true }]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText(/protected/i)).toBeTruthy());
    expect(screen.getByText(/✓ Protected/)).toBeTruthy();
    expect(screen.queryByText(/not protected/i)).toBeNull();
  });

  it("does NOT show green '✓ Protected' for a protected codex hook - it needs trust", async () => {
    // Regression: Codex only enforces a hook after the user trusts it, and its
    // hook coverage has gaps. A green "Protected" for an installed-but-untrusted
    // codex hook is false confidence (a beta tester's .env was read while Belay
    // showed Protected). Codex must show an action-needed state + a caveat.
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, name: "codex", settings: ["/home/user/.codex/hooks.json"], risky: [], protected: true },
    ]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("codex")).toBeTruthy());
    expect(screen.queryByText(/✓ Protected/)).toBeNull();
    expect(screen.getByText(/finish in codex/i)).toBeTruthy();
    expect(screen.getByText(/action needed to activate/i)).toBeTruthy();
  });

  it("shows 'Not protected' when the agent is not protected", async () => {
    mockListAgents.mockResolvedValue([{ ...AGENT_FIXTURE, protected: false }]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText(/not protected/i)).toBeTruthy());
  });
});

describe("Agents view — connected tools (MCP servers + skills)", () => {
  it("renders detected MCP server names", async () => {
    // risky:[] so the "All MCP servers auto-enabled" chip can't collide with
    // the "MCP servers" section label matcher.
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, risky: [], mcp_servers: ["agent-reach", "discord-setup"], skills: [] },
    ]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("agent-reach")).toBeTruthy());
    expect(screen.getByText("discord-setup")).toBeTruthy();
    // The section label shows the count.
    expect(screen.getByText(/mcp servers/i)).toBeTruthy();
  });

  it("collapses a long skills list to chips + '+N more'", async () => {
    const skills = Array.from({ length: 20 }, (_, i) => `skill-${i}`);
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, mcp_servers: [], skills },
    ]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("skill-0")).toBeTruthy());
    // Default max is 8 → 12 hidden behind a "+12 more" pill.
    expect(screen.getByText(/\+12 more/)).toBeTruthy();
    // A skill past the cap is not rendered as a visible chip.
    expect(screen.queryByText("skill-19")).toBeNull();
  });

  it("omits the tools sections when both lists are empty", async () => {
    // risky:[] so no "All MCP servers auto-enabled" chip trips the matcher.
    mockListAgents.mockResolvedValue([
      { ...AGENT_FIXTURE, risky: [], mcp_servers: [], skills: [] },
    ]);
    render(<Agents />);
    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());
    expect(screen.queryByText(/mcp servers/i)).toBeNull();
    expect(screen.queryByText(/^skills$/i)).toBeNull();
  });
});

describe("Agents view — actions", () => {
  it("clicking Protect calls protectAgent(name) and refreshes", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    mockProtectAgent.mockResolvedValue("ok");
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    const protectBtn = screen.getByRole("button", { name: /^protect$/i });
    await act(async () => {
      fireEvent.click(protectBtn);
    });

    expect(mockProtectAgent).toHaveBeenCalledWith("claude-code");
    // listAgents called again on success (initial + refresh = 2)
    await waitFor(() => expect(mockListAgents).toHaveBeenCalledTimes(2));
  });

  it("clicking Unprotect shows inline confirm before calling unprotectAgent", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    mockUnprotectAgent.mockResolvedValue("ok");
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    // First click shows confirm UI — unprotectAgent must NOT be called yet
    const unprotectBtn = screen.getByRole("button", { name: /^unprotect$/i });
    await act(async () => {
      fireEvent.click(unprotectBtn);
    });
    expect(mockUnprotectAgent).not.toHaveBeenCalled();

    // Confirm dialog/inline confirm should appear
    const confirmBtn = screen.getByRole("button", { name: /yes.*unprotect|confirm/i });
    await act(async () => {
      fireEvent.click(confirmBtn);
    });
    expect(mockUnprotectAgent).toHaveBeenCalledWith("claude-code");
  });

  it("shows the daemon's real error text on a failed Protect, not a generic fallback", async () => {
    // Tauri commands returning `Result<T, String>` reject with the raw
    // string itself (not a wrapped Error) — regression test for the bug
    // where doProtect/doUnprotect discarded that string and showed
    // "Something went wrong" instead of the actual, actionable message.
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    mockProtectAgent.mockRejectedValue(
      "belay protect failed: hermes config already defines a `hooks:` block",
    );
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    const protectBtn = screen.getByRole("button", { name: /^protect$/i });
    await act(async () => {
      fireEvent.click(protectBtn);
    });

    await waitFor(() =>
      expect(screen.getByText(/hermes config already defines/)).toBeTruthy(),
    );
    expect(screen.queryByText(/something went wrong/i)).toBeNull();
  });

  it("clicking Cancel on Unprotect confirm does NOT call unprotectAgent", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    const unprotectBtn = screen.getByRole("button", { name: /^unprotect$/i });
    await act(async () => {
      fireEvent.click(unprotectBtn);
    });

    const cancelBtn = screen.getByRole("button", { name: /cancel/i });
    await act(async () => {
      fireEvent.click(cancelBtn);
    });

    expect(mockUnprotectAgent).not.toHaveBeenCalled();
    // Confirm UI gone — Unprotect button is back
    expect(screen.getByRole("button", { name: /^unprotect$/i })).toBeTruthy();
  });

  it("shows inline success message after protect", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    mockProtectAgent.mockResolvedValue("ok");
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /^protect$/i }));
    });

    await waitFor(() =>
      expect(screen.getByText(/protection updated/i)).toBeTruthy()
    );
  });

  it("disables buttons while action is in flight", async () => {
    mockListAgents.mockResolvedValue([AGENT_FIXTURE]);
    let resolveProtect!: (v: string) => void;
    mockProtectAgent.mockReturnValue(
      new Promise<string>((r) => { resolveProtect = r; })
    );
    render(<Agents />);

    await waitFor(() => expect(screen.getByText("claude-code")).toBeTruthy());

    const protectBtn = screen.getByRole("button", {
      name: /^protect$/i,
    }) as HTMLButtonElement;
    fireEvent.click(protectBtn);

    // Button should be disabled while in-flight
    await waitFor(() => expect(protectBtn.disabled).toBe(true));

    await act(async () => { resolveProtect("ok"); });
  });
});

describe("Agents view — special states", () => {
  it("shows loading state on mount before data arrives", () => {
    mockListAgents.mockReturnValue(new Promise(() => {}));
    render(<Agents />);
    expect(screen.getByText(/loading/i)).toBeTruthy();
  });

  it("shows empty state when listAgents returns empty array", async () => {
    mockListAgents.mockResolvedValue([]);
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/no ai agents detected yet/i)).toBeTruthy()
    );
  });

  it("shows calm desktop-only note (not a raw error) when listAgents rejects with desktop-only error", async () => {
    mockListAgents.mockRejectedValue(
      new Error("listAgents: Available in the Belay desktop app")
    );
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getAllByText(/desktop app/i).length).toBeGreaterThanOrEqual(1)
    );
    // Must NOT show the raw "listAgents:" prefix
    expect(screen.queryByText(/listAgents:/)).toBeNull();
  });

  it("shows error state for non-desktop-only errors", async () => {
    mockListAgents.mockRejectedValue(new Error("Network error"));
    render(<Agents />);
    await waitFor(() =>
      expect(screen.getByText(/something went wrong/i)).toBeTruthy()
    );
  });
});
