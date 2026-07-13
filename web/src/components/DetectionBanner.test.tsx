import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { it, expect, vi, beforeEach, describe } from "vitest";

vi.mock("../lib/api", () => ({ listAgents: vi.fn() }));
import { listAgents } from "../lib/api";
import DetectionBanner from "./DetectionBanner";

const mockListAgents = listAgents as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockListAgents.mockReset();
  localStorage.clear();
});

describe("DetectionBanner", () => {
  it("shows detected agent names in plain English", async () => {
    mockListAgents.mockResolvedValue([{ name: "claude-code" }, { name: "openclaw" }]);
    render(<DetectionBanner onNavigate={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByText(/we found 2 ai tools/i)).toBeTruthy(),
    );
    expect(screen.getByText(/Claude Code and Openclaw/)).toBeTruthy();
  });

  it("renders nothing when detection is unavailable (browser / rejects)", async () => {
    mockListAgents.mockRejectedValue(new Error("Available in the Belay desktop app"));
    const { container } = render(<DetectionBanner onNavigate={vi.fn()} />);
    await waitFor(() => expect(mockListAgents).toHaveBeenCalled());
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when no agents are detected", async () => {
    mockListAgents.mockResolvedValue([]);
    const { container } = render(<DetectionBanner onNavigate={vi.fn()} />);
    await waitFor(() => expect(mockListAgents).toHaveBeenCalled());
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when every detected agent is already protected", async () => {
    mockListAgents.mockResolvedValue([{ name: "claude-code", protected: true }]);
    const { container } = render(<DetectionBanner onNavigate={vi.fn()} />);
    await waitFor(() => expect(mockListAgents).toHaveBeenCalled());
    expect(container.firstChild).toBeNull();
  });

  it("counts only unprotected agents", async () => {
    mockListAgents.mockResolvedValue([
      { name: "claude-code", protected: true },
      { name: "codex", protected: false },
    ]);
    render(<DetectionBanner onNavigate={vi.fn()} />);
    // Only codex is unprotected → "1 AI tool", and Claude Code is not mentioned.
    await waitFor(() => expect(screen.getByText(/we found 1 ai tool/i)).toBeTruthy());
    expect(screen.getByText(/\bCodex\b/)).toBeTruthy();
    expect(screen.queryByText(/Claude Code/)).toBeNull();
  });

  it("'Review & protect' navigates to the agents tab", async () => {
    mockListAgents.mockResolvedValue([{ name: "claude-code" }]);
    const onNavigate = vi.fn();
    render(<DetectionBanner onNavigate={onNavigate} />);
    const btn = await screen.findByRole("button", { name: /review & protect/i });
    fireEvent.click(btn);
    expect(onNavigate).toHaveBeenCalledWith("agents");
  });

  it("'Not now' dismisses and persists the dismissal", async () => {
    mockListAgents.mockResolvedValue([{ name: "claude-code" }]);
    const { container } = render(<DetectionBanner onNavigate={vi.fn()} />);
    const btn = await screen.findByRole("button", { name: /not now/i });
    await act(async () => {
      fireEvent.click(btn);
    });
    expect(container.firstChild).toBeNull();
    expect(localStorage.getItem("belay.detectionBanner.dismissed")).toBe("1");
  });

  it("stays hidden when already dismissed", async () => {
    localStorage.setItem("belay.detectionBanner.dismissed", "1");
    mockListAgents.mockResolvedValue([{ name: "claude-code" }]);
    const { container } = render(<DetectionBanner onNavigate={vi.fn()} />);
    await waitFor(() => expect(mockListAgents).toHaveBeenCalled());
    expect(container.firstChild).toBeNull();
  });
});
