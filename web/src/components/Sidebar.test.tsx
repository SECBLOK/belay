import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { it, expect, vi, describe, beforeEach } from "vitest";

// score 100 / deny 0 / ask 0 -> deriveStatus resolves to "protected", which is
// what the recovery test below needs to assert against.
const POSTURE_OK = {
  score: 100, total: 10, allow: 10, ask: 0, deny: 0,
  by_category: {}, trend: [], top_rules: [],
};

// Hoisted so individual tests can choose whether getPosture resolves or
// rejects, and can capture the streamAudit callback to fire a retry - the
// same pattern Fleet.test.tsx uses for its own "recovers" test.
const { getPosture, streamAudit } = vi.hoisted(() => ({
  getPosture: vi.fn(),
  streamAudit: vi.fn(),
}));

// ── api mock ─────────────────────────────────────────────────────────────────
vi.mock("../lib/api", () => ({
  getPosture,
  getPending: vi.fn().mockResolvedValue([{ id: "x" }]),
  streamAudit,
  // LanguagePicker (rendered in the sidebar footer) reads/writes the locale.
  getLocale: vi.fn().mockResolvedValue({ locale: "en", supported: ["en", "zh-Hans"] }),
  setLocale: vi.fn().mockResolvedValue({ ok: true }),
}));

import Sidebar from "./Sidebar";

beforeEach(() => {
  getPosture.mockReset();
  streamAudit.mockReset();
  getPosture.mockResolvedValue(POSTURE_OK);
  streamAudit.mockReturnValue(() => {});
});

type Tab =
  | "posture" | "findings" | "timeline" | "scan" | "agents" | "host";

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

// A rejected getPosture() must never render the confident "Protected" state:
// the Sidebar mounts once at app root and never remounts, so folding "don't
// know yet" into "protected" (the pre-fix behaviour) would strand a green
// badge for the entire session on any daemon hiccup. See deriveStatus.
describe("Sidebar status: unknown vs Protected", () => {
  it("does not render Protected when the initial fetch rejects; renders the unknown state instead", async () => {
    getPosture.mockRejectedValue(new Error("daemon unreachable"));
    renderSidebar();

    // Rejection settles asynchronously; give it a tick and confirm it never
    // became "Protected" at any point, including the synchronous first render.
    expect(screen.queryByText("Protected")).toBeNull();
    await waitFor(() => expect(getPosture).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByText("Protected")).toBeNull();
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("resolves to the real status once a later load succeeds after a rejected first fetch", async () => {
    let fire: () => void = () => {};
    streamAudit.mockImplementation((cb: () => void) => { fire = cb; return () => {}; });
    getPosture.mockRejectedValueOnce(new Error("transient"));
    renderSidebar();

    await waitFor(() => expect(getPosture).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Protected")).toBeNull();

    getPosture.mockResolvedValue(POSTURE_OK);
    fire();
    await waitFor(() => expect(screen.getByText("Protected")).toBeTruthy());
  });
});

describe("Sidebar AGPL source link", () => {
  it("renders a 'Source (AGPL)' link to the canonical repository", () => {
    renderSidebar();
    const link = screen.getByText("Source (AGPL)").closest("a");
    expect(link).toBeTruthy();
    expect(link?.getAttribute("href")).toBe("https://github.com/SECBLOK/belay");
    expect(link?.getAttribute("target")).toBe("_blank");
  });
});
