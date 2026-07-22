import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  listSkills: vi.fn(),
  approveSkill: vi.fn(),
  listQuarantine: vi.fn(),
  restoreQuarantine: vi.fn(),
  deleteQuarantine: vi.fn(),
}));

import * as api from "../../lib/api";
import HostSkills from "./HostSkills";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.listSkills).mockResolvedValue([
    { agent: "claude", name: "greeter", path: "/home/u/.claude/skills/greeter", recommendation: "safe", severity: null, finding_count: 0, drift: "clean" },
    { agent: "claude", name: "sketchy", path: "/home/u/.claude/skills/sketchy", recommendation: "donotinstall", severity: "critical", finding_count: 3, drift: "drifted" },
    { agent: "codex", name: "fresh", path: "/home/u/.codex/skills/fresh", recommendation: "caution", severity: "medium", finding_count: 1, drift: "unbaselined" },
  ]);
  vi.mocked(api.approveSkill).mockResolvedValue([]);
  vi.mocked(api.listQuarantine).mockResolvedValue([
    { id: "f-1", original_path: "/tmp/evil.sh", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "rce", severity: "critical", kind: "file" },
    { id: "d-1", original_path: "/home/u/.claude/skills/banned", quarantined_at: "2026-06-01T00:00:00Z", rule_id: "skill", severity: "high", kind: "dir" },
  ]);
  vi.mocked(api.restoreQuarantine).mockResolvedValue(undefined);
  vi.mocked(api.deleteQuarantine).mockResolvedValue(undefined);
});

describe("HostSkills", () => {
  it("lists installed skills with recommendation + drift chips", async () => {
    render(<HostSkills />);
    await waitFor(() => expect(screen.getByText("greeter")).toBeTruthy());

    expect(screen.getByText("sketchy")).toBeTruthy();
    expect(screen.getByText(/do not install/i)).toBeTruthy();
    expect(screen.getByText("Drifted")).toBeTruthy();
    expect(screen.getByText("Unbaselined")).toBeTruthy();
    expect(screen.getByText("3 findings")).toBeTruthy();
  });

  it("shows only quarantined skill directories, never files", async () => {
    render(<HostSkills />);
    // The kind:"dir" entry is a skill; the kind:"file" entry must not appear here.
    await waitFor(() => expect(screen.getByText("banned")).toBeTruthy());
    expect(screen.queryByText("evil.sh")).toBeNull();
  });

  it("clean skills expose no approve action; drifted ones re-approve", async () => {
    render(<HostSkills />);
    await waitFor(() => expect(screen.getByText("greeter")).toBeTruthy());

    // greeter is clean → no Approve/Re-approve; fresh is unbaselined → Approve.
    expect(screen.queryByRole("button", { name: /approve greeter/i })).toBeNull();
    expect(screen.getByRole("button", { name: /approve fresh/i })).toBeTruthy();

    const reApprove = screen.getByRole("button", { name: /re-approve sketchy/i });
    fireEvent.click(reApprove);
    await waitFor(() =>
      expect(api.approveSkill).toHaveBeenCalledWith("/home/u/.claude/skills/sketchy"),
    );
  });
});
