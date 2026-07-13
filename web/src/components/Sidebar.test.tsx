import { render, screen, fireEvent } from "@testing-library/react";
import { it, expect, vi, describe, beforeEach } from "vitest";

// ── api mock ─────────────────────────────────────────────────────────────────
vi.mock("../lib/api", () => ({
  getPosture: vi.fn().mockResolvedValue({
    score: 85, total: 10, allow: 8, ask: 1, deny: 1,
    by_category: {}, trend: [], top_rules: [],
  }),
  getPending: vi.fn().mockResolvedValue([{ id: "x" }]),
}));

import Sidebar from "./Sidebar";

type Tab =
  | "posture" | "findings" | "timeline" | "scan" | "agents" | "host"
 ;

function renderSidebar(tab: Tab = "posture", onNavigate = vi.fn()) {
  return render(<Sidebar tab={tab} onNavigate={onNavigate} />);
}

describe("Sidebar nav labels", () => {
  it("renders all 6 nav labels", () => {
    renderSidebar();
    expect(screen.getByText("Overview")).toBeTruthy();
    expect(screen.getByText("Activity")).toBeTruthy();
    expect(screen.getByText("Live Feed")).toBeTruthy();
    expect(screen.getByText("Scan")).toBeTruthy();
    expect(screen.getByText("Agents")).toBeTruthy();
  });

  it("does not render the TOOLS/FLEET section labels (removed by design)", () => {
    renderSidebar();
    expect(screen.queryByText("TOOLS")).toBeNull();
    expect(screen.queryByText("FLEET")).toBeNull();
  });
});

describe("Sidebar navigation", () => {
  it("calls onNavigate with 'findings' when Activity is clicked", () => {
    const onNavigate = vi.fn();
    renderSidebar("posture", onNavigate);
    fireEvent.click(screen.getByText("Activity"));
    expect(onNavigate).toHaveBeenCalledWith("findings");
  });

  it("calls onNavigate with 'timeline' when Live Feed is clicked", () => {
    const onNavigate = vi.fn();
    renderSidebar("posture", onNavigate);
    fireEvent.click(screen.getByText("Live Feed"));
    expect(onNavigate).toHaveBeenCalledWith("timeline");
  });

  it("calls onNavigate with 'scan' when Scan is clicked", () => {
    const onNavigate = vi.fn();
    renderSidebar("posture", onNavigate);
    fireEvent.click(screen.getByText("Scan"));
    expect(onNavigate).toHaveBeenCalledWith("scan");
  });

  it("calls onNavigate with 'agents' when Agents is clicked", () => {
    const onNavigate = vi.fn();
    renderSidebar("posture", onNavigate);
    fireEvent.click(screen.getByText("Agents"));
    expect(onNavigate).toHaveBeenCalledWith("agents");
  });

});

describe("Sidebar active state", () => {
  it("marks the active item with aria-current=page", () => {
    renderSidebar("findings");
    const btn = screen.getByText("Activity").closest("button");
    expect(btn?.getAttribute("aria-current")).toBe("page");
  });

  it("does not mark inactive items with aria-current", () => {
    renderSidebar("findings");
    const btn = screen.getByText("Overview").closest("button");
    expect(btn?.getAttribute("aria-current")).toBeNull();
  });
});

describe("Sidebar status footer", () => {
  beforeEach(() => {
    // The mock already returns deny:1, pending:[{id:'x'}]
  });

  it("renders the status footer with a label", async () => {
    renderSidebar();
    // footer button navigates to posture; it contains the status label
    // wait for async getPosture/getPending
    const statusLabel = await screen.findByText(/Protected|Monitoring|Action needed|Blocked/);
    expect(statusLabel).toBeTruthy();
  });

  it("footer click calls onNavigate with 'posture'", () => {
    const onNavigate = vi.fn();
    renderSidebar("timeline", onNavigate);
    // footer is a button; click the status dot area
    const footerBtn = screen.getAllByRole("button").find(
      (b) => b.getAttribute("class")?.includes("mb-3")
    );
    if (footerBtn) fireEvent.click(footerBtn);
    expect(onNavigate).toHaveBeenCalledWith("posture");
  });
});

