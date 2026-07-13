import { render, screen, fireEvent, act } from "@testing-library/react";
import { it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock the IPC layer so the "Explain with AI" gating/fetch can be driven
// deterministically per-test, without a real daemon/Tauri bridge.
const aiStatusMock = vi.fn();
const explainActionMock = vi.fn();
vi.mock("../lib/ipc", () => ({
  aiStatus: (...a: unknown[]) => aiStatusMock(...a),
  explainAction: (...a: unknown[]) => explainActionMock(...a),
}));

import ApprovalCard from "./ApprovalCard";
import type { EgressPending } from "./ApprovalCard";

const pending = { id: "a1", agent: "Claude Code", tool: "Bash",
  input: { command: "cat ~/.aws/credentials" }, reason: "Reads cloud credentials",
  rule: "secrets.aws_credentials", risk: "high" };

const pendingLow = { id: "a2", agent: "Claude Code", tool: "Bash",
  input: { command: "echo hello" }, reason: "Echo command",
  rule: "recon.basic", risk: "low" };

beforeEach(() => {
  vi.useFakeTimers();
  aiStatusMock.mockReset().mockResolvedValue(false);
  explainActionMock.mockReset().mockResolvedValue(null);
});
afterEach(() => vi.useRealTimers());

// Fake timers pause real setTimeout-based polling (testing-library's
// findBy/waitFor), so drain pending microtasks explicitly instead — same
// pattern as ApprovalSurface.test.tsx.
const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

it("shows agent name, plain-English human label, original reason, and target path", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  // Agent name in header
  expect(screen.getByText("Claude Code")).toBeTruthy();
  // Curated summary headline (from explainFor) — not the raw rule id
  expect(screen.getByText(/read your saved credentials, keys, or passwords/i)).toBeTruthy();
  // Original reason from daemon
  expect(screen.getByText(/Reads cloud credentials/)).toBeTruthy();
  // Target in labelled mono box
  expect(screen.getByTestId("target").textContent).toContain("~/.aws/credentials");
});

it("shows 'Command it wants to run:' label for command input", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(screen.getByText("Command it wants to run:")).toBeTruthy();
});

it("shows calm countdown copy with 'Auto-blocks in'", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(screen.getByText(/Auto-blocks in/)).toBeTruthy();
});

it("shows plain-English 'what this is' and 'what could go wrong' copy for a known rule", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  // secrets.* → secrets copy from ruleCopy (System B)
  expect(screen.getByText(/files that hold your passwords, keys, or logins/)).toBeTruthy();
  expect(screen.getByText(/sign in to your accounts or cloud services as you/)).toBeTruthy();
});

it("demotes the rule id to a footnote at the bottom", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(screen.getByText(/secrets\.aws_credentials/)).toBeTruthy();
});

it("collapses the command behind a 'Show command' toggle that does not reset the countdown", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  // The target element stays in the DOM; the toggle reveals it.
  const toggle = screen.getByRole("button", { name: /show command/i });
  expect(toggle.getAttribute("aria-expanded")).toBe("false");
  // Reading is always allowed — before the keystroke guard arms the actions.
  fireEvent.click(toggle);
  expect(screen.getByTestId("target").textContent).toContain("~/.aws/credentials");
});

it("Always allow on low-risk resolves with scope=always in one click", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pendingLow} onResolve={onResolve} timeoutMs={20000} />);
  // ~1s keystroke guard: buttons are disabled until the guard elapses
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Always allow"));
  expect(onResolve).toHaveBeenCalledWith("a2", "allow", "always");
});

it("Always allow on high-risk requires a second confirm click", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pending} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  // First click: reveals confirm button, does NOT yet resolve
  fireEvent.click(screen.getByText("Always allow"));
  expect(onResolve).not.toHaveBeenCalled();
  // Second click on the confirm button: resolves with always
  fireEvent.click(screen.getByText(/Confirm — always allow/));
  expect(onResolve).toHaveBeenCalledWith("a1", "allow", "always");
});

it("counts down and timeout-denies", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pending} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(20000); });
  expect(onResolve).toHaveBeenCalledWith("a1", "deny", "once");
});

it("high-risk card has no default (autofocused) button", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(document.activeElement?.tagName).not.toBe("BUTTON");
});

it("Allow once is the prominent (first) action button", () => {
  render(<ApprovalCard pending={pending} onResolve={vi.fn()} timeoutMs={20000} />);
  // "Allow once" should appear before "Always allow" in the DOM
  const buttons = screen.getAllByRole("button");
  const allowOnceIdx = buttons.findIndex((b) => b.textContent === "Allow once");
  const alwaysIdx = buttons.findIndex((b) => b.textContent === "Always allow");
  expect(allowOnceIdx).toBeLessThan(alwaysIdx);
});

it("Allow once resolves with scope=once", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pending} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Allow once"));
  expect(onResolve).toHaveBeenCalledWith("a1", "allow", "once");
});

// ── Explain & Advise (Task 8): 5-field explanation + severity badge ────────────

const pendingExplain = {
  id: "x1", agent: "Claude Code", tool: "Bash",
  input: { command: "cat .env" }, reason: "reads env",
  rule: "secrets.env_dump", severity: "high",
  explain: {
    summary: "Reads your secrets",
    what: "It opened your .env file",
    why_risky: "Someone could steal them",
    normal_use: "Rarely needed for most tasks",
    suggested_action: "Deny if unexpected",
  },
};

it("shows the 5-field explanation and a severity label", () => {
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  // Curated summary as the headline
  expect(screen.getByText(/Reads your secrets/)).toBeTruthy();
  // why_risky
  expect(screen.getByText(/steal them/)).toBeTruthy();
  // normal_use
  expect(screen.getByText(/Rarely needed/)).toBeTruthy();
  // suggested_action
  expect(screen.getByText(/Deny if unexpected/)).toBeTruthy();
  // Severity label — text, not color-only
  expect(screen.getByText(/High/)).toBeTruthy();
});

it("severity badge carries an accessible text label", () => {
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(screen.getByLabelText(/Severity: High/i)).toBeTruthy();
});

// ── Task 9: restrained, severity-tiered visual flare ───────────────────────────

const crit = (severity: string) => ({
  id: "c1", agent: "Claude Code", tool: "Bash", input: { command: "rm -rf /" },
  reason: "destructive", rule: "destructive.rm_rf", severity,
});

it("applies the critical accent only for critical severity", () => {
  const { rerender, container } = render(
    <ApprovalCard pending={crit("critical")} onResolve={vi.fn()} timeoutMs={20000} />,
  );
  expect(container.querySelector(".alert-critical-pulse")).toBeTruthy();
  rerender(<ApprovalCard pending={crit("low")} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(container.querySelector(".alert-critical-pulse")).toBeNull();
});

it("gives the card a gentle entrance class", () => {
  const { container } = render(
    <ApprovalCard pending={crit("high")} onResolve={vi.fn()} timeoutMs={20000} />,
  );
  expect(container.querySelector(".alert-enter")).toBeTruthy();
});

// ── Severity-tiered button emphasis + heading semantics ────────────────────────

it("on a critical pending, Deny leads (filled) and Allow once recedes to a ghost", () => {
  render(<ApprovalCard pending={crit("critical")} onResolve={vi.fn()} timeoutMs={20000} />);
  const allow = screen.getByText("Allow once");
  const deny = screen.getByText("Deny"); // exact match, not "Deny & stop agent"
  // Allow once is a ghost/outline button: has a border, no filled allow background.
  expect(allow.className).toContain("border");
  expect(allow.getAttribute("style") ?? "").not.toContain("semantic-allow");
  // Deny keeps the filled/primary emphasis.
  expect(deny.getAttribute("style") ?? "").toContain("semantic-deny");
});

it("on a low pending, Allow once keeps the filled allow emphasis", () => {
  render(<ApprovalCard pending={crit("low")} onResolve={vi.fn()} timeoutMs={20000} />);
  const allow = screen.getByText("Allow once");
  expect(allow.getAttribute("style") ?? "").toContain("semantic-allow");
});

it("renders the explanation section labels as <h3> headings", () => {
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  const labels = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
  expect(labels).toContain("What this is");
  expect(labels).toContain("What could go wrong");
  expect(labels.some((t) => t?.includes("Is this normal?"))).toBe(true);
  expect(labels).toContain("Suggested action");
});

it("Always allow requires a second confirm click on critical severity", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={crit("critical")} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Always allow"));
  expect(onResolve).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText(/Confirm — always allow/));
  expect(onResolve).toHaveBeenCalledWith("c1", "allow", "always");
});

// ── Egress variant tests ──────────────────────────────────────────────────────

const pendingEgress: EgressPending = {
  kind: "egress",
  id: "e1",
  agent: "Python Agent",
  dest: "api.openai.com:443",
  binary: "/usr/bin/python3",
  risk: "medium",
};

it("egress variant renders binary and dest", () => {
  render(<ApprovalCard pending={pendingEgress} onResolve={vi.fn()} timeoutMs={20000} />);
  expect(screen.getByTestId("egress-binary").textContent).toContain("/usr/bin/python3");
  expect(screen.getByTestId("egress-dest").textContent).toContain("api.openai.com:443");
});

it("egress variant 'Always' resolves with scope always in one click after keystroke guard", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pendingEgress} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Always"));
  expect(onResolve).toHaveBeenCalledWith("e1", "allow", "always");
});

it("egress variant 'Allow once' resolves allow+once", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pendingEgress} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Allow once"));
  expect(onResolve).toHaveBeenCalledWith("e1", "allow", "once");
});

it("egress variant 'Deny' resolves deny+once", () => {
  const onResolve = vi.fn();
  render(<ApprovalCard pending={pendingEgress} onResolve={onResolve} timeoutMs={20000} />);
  act(() => { vi.advanceTimersByTime(1100); });
  fireEvent.click(screen.getByText("Deny"));
  expect(onResolve).toHaveBeenCalledWith("e1", "deny", "once");
});

// ── Task 6: on-demand "Explain with AI" affordance ─────────────────────────────

it("hides the 'Explain with AI' button when the daemon reports AI disabled", async () => {
  aiStatusMock.mockResolvedValue(false);
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  await flush();
  expect(screen.queryByRole("button", { name: /explain with ai/i })).toBeNull();
  // Curated explanation still renders regardless.
  expect(screen.getByText(/Reads your secrets/)).toBeTruthy();
});

it("shows 'Explain with AI' when enabled; clicking renders the AI text and label, curated explanation stays", async () => {
  aiStatusMock.mockResolvedValue(true);
  explainActionMock.mockResolvedValue({
    summary: "AI: reads a secrets file",
    what: "It opened a file holding credentials",
    why_risky: "AI-detected risk: credentials could leak",
    normal_use: "AI: rarely necessary",
    suggested_action: "AI: deny unless expected",
  });
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  await flush();

  const button = screen.getByRole("button", { name: /explain with ai/i });
  fireEvent.click(button);
  await flush();

  expect(explainActionMock).toHaveBeenCalledWith(
    pendingExplain.tool,
    pendingExplain.input,
    pendingExplain.rule,
  );
  // AI-generated text renders...
  expect(screen.getByText(/AI-detected risk: credentials could leak/)).toBeTruthy();
  // ...clearly labelled as AI-generated, via a trust chip (visible text +
  // accessible name both convey "AI-generated" and "may be imperfect")...
  expect(screen.getByText(/AI · may be imperfect/i)).toBeTruthy();
  expect(screen.getByRole("img", { name: /AI-generated.*may be imperfect/i })).toBeTruthy();
  // ...and the curated explanation from earlier is STILL present.
  expect(screen.getByText(/Reads your secrets/)).toBeTruthy();
  expect(screen.getByText(/Someone could steal them/)).toBeTruthy();
});

it("does not update state (or throw) when unmounted while an AI explain fetch is in flight", async () => {
  aiStatusMock.mockResolvedValue(true);
  let resolveExplain: ((v: unknown) => void) | undefined;
  explainActionMock.mockImplementation(
    () => new Promise((resolve) => { resolveExplain = resolve; }),
  );
  const { unmount } = render(
    <ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />,
  );
  await flush();

  const button = screen.getByRole("button", { name: /explain with ai/i });
  fireEvent.click(button);
  await flush(); // fetch is now in flight (loading), but explainAction has not resolved yet

  unmount();

  // Resolving the in-flight promise post-unmount must not throw or warn about
  // setting state on an unmounted component (the mountedRef guard swallows it).
  await expect(
    act(async () => {
      resolveExplain?.({
        summary: "late", what: "late", why_risky: "late",
        normal_use: "late", suggested_action: "late",
      });
      await Promise.resolve();
      await Promise.resolve();
    }),
  ).resolves.not.toThrow();
});

it("shows a graceful 'AI explanation unavailable' message when explainAction returns null", async () => {
  aiStatusMock.mockResolvedValue(true);
  explainActionMock.mockResolvedValue(null);
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  await flush();

  const button = screen.getByRole("button", { name: /explain with ai/i });
  fireEvent.click(button);
  await flush();

  expect(screen.getByText(/AI explanation unavailable/i)).toBeTruthy();
  // Curated explanation is unaffected.
  expect(screen.getByText(/Reads your secrets/)).toBeTruthy();
});

it("collapses and re-expands the AI opinion without refetching", async () => {
  aiStatusMock.mockResolvedValue(true);
  explainActionMock.mockResolvedValue({
    summary: "AI: reads a secrets file",
    what: "It opened a file holding credentials",
    why_risky: "AI-detected risk: credentials could leak",
    normal_use: "AI: rarely necessary",
    suggested_action: "AI: deny unless expected",
  });
  render(<ApprovalCard pending={pendingExplain} onResolve={vi.fn()} timeoutMs={20000} />);
  await flush();

  fireEvent.click(screen.getByRole("button", { name: /explain with ai/i }));
  await flush();
  expect(explainActionMock).toHaveBeenCalledTimes(1);
  expect(screen.getByText(/AI-detected risk: credentials could leak/)).toBeTruthy();

  // Collapse: the AI opinion body disappears, a re-expand toggle appears.
  fireEvent.click(screen.getByRole("button", { name: /hide ai opinion/i }));
  expect(screen.queryByText(/AI-detected risk: credentials could leak/)).toBeNull();
  const showToggle = screen.getByRole("button", { name: /show ai opinion/i });

  // Re-expand: the cached explanation reappears with no second fetch.
  fireEvent.click(showToggle);
  expect(screen.getByText(/AI-detected risk: credentials could leak/)).toBeTruthy();
  expect(explainActionMock).toHaveBeenCalledTimes(1);
});
