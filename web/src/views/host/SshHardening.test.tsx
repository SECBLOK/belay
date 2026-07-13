import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  getHardeningPosture: vi.fn().mockResolvedValue({
    score: 55,
    checks: [
      {
        id: "PermitRootLogin",
        label: "PermitRootLogin yes",
        status: "fail",
        detail: "Set PermitRootLogin to 'no' or 'prohibit-password' in /etc/ssh/sshd_config.",
      },
    ],
  }),
  getSshGuard: vi.fn().mockResolvedValue({
    enabled: true,
    max_auth_tries: 3,
    ban_threshold: 5,
    ban_duration_secs: 3600,
    permit_root_login: true,
  }),
  setSshGuard: vi.fn().mockResolvedValue(undefined),
  listBans: vi.fn().mockResolvedValue([
    {
      id: "ban-1",
      target: "192.168.1.100",
      kind: "ip",
      banned_at: "2026-06-01T10:00:00Z",
      expires_at: "2026-06-01T11:00:00Z",
      reason: "Too many failed auth attempts",
    },
  ]),
  unban: vi.fn().mockResolvedValue(undefined),
}));

import * as api from "../../lib/api";
import SshHardening from "./SshHardening";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getHardeningPosture).mockResolvedValue({
    score: 55,
    checks: [
      {
        id: "PermitRootLogin",
        label: "PermitRootLogin yes",
        status: "fail",
        detail: "Set PermitRootLogin to 'no' or 'prohibit-password' in /etc/ssh/sshd_config.",
      },
    ],
  });
  vi.mocked(api.getSshGuard).mockResolvedValue({
    enabled: true,
    max_auth_tries: 3,
    ban_threshold: 5,
    ban_duration_secs: 3600,
    permit_root_login: true,
  });
  vi.mocked(api.setSshGuard).mockResolvedValue(undefined);
  vi.mocked(api.listBans).mockResolvedValue([
    {
      id: "ban-1",
      target: "192.168.1.100",
      kind: "ip",
      banned_at: "2026-06-01T10:00:00Z",
      expires_at: "2026-06-01T11:00:00Z",
      reason: "Too many failed auth attempts",
    },
  ]);
  vi.mocked(api.unban).mockResolvedValue(undefined);
});

describe("SshHardening", () => {
  it("a PermitRootLogin yes finding renders humanized label and 'How to fix' expander", async () => {
    render(<SshHardening />);

    // Wait for posture to load
    await waitFor(() =>
      expect(screen.getByText(/root login/i)).toBeTruthy()
    );

    // Humanized label must be visible (not raw id)
    expect(screen.getByText(/permit root login/i)).toBeTruthy();

    // "How to fix" expander must be present
    expect(screen.getByRole("button", { name: /how to fix/i })).toBeTruthy();
  });

  it("Unban shows confirm before calling unban", async () => {
    render(<SshHardening />);

    // Wait for ban list to load
    await waitFor(() => expect(screen.getByText("192.168.1.100")).toBeTruthy());

    // unban should not have been called yet
    expect(api.unban).not.toHaveBeenCalled();

    // Click Unban button
    const unbanBtn = screen.getByRole("button", { name: /^unban$/i });
    fireEvent.click(unbanBtn);

    // Confirm prompt should appear
    expect(screen.getByText(/unban this ip/i)).toBeTruthy();

    // unban still NOT called
    expect(api.unban).not.toHaveBeenCalled();

    // Click confirm
    const confirmBtn = screen.getByRole("button", { name: /yes, unban/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => expect(api.unban).toHaveBeenCalledWith("ban-1"));
  });
});
