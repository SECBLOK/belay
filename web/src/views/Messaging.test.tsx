import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { it, expect, vi, beforeEach, describe } from "vitest";
import Messaging from "./Messaging";

vi.mock("../lib/api", () => ({
  getChannels: vi.fn(),
  channelAllowRemove: vi.fn(),
  channelPairStart: vi.fn(),
  setChannel: vi.fn(),
  removeChannel: vi.fn(),
  setInbound: vi.fn(),
  restartDaemon: vi.fn(),
  setChannelEnabled: vi.fn(),
  openExternalUrl: vi.fn(),
}));

import {
  getChannels,
  channelAllowRemove,
  channelPairStart,
  setChannel,
  removeChannel,
  setInbound,
  restartDaemon,
  setChannelEnabled,
  openExternalUrl,
} from "../lib/api";

const mockGet = getChannels as ReturnType<typeof vi.fn>;
const mockRemove = channelAllowRemove as ReturnType<typeof vi.fn>;
const mockPair = channelPairStart as ReturnType<typeof vi.fn>;
const mockSetChannel = setChannel as ReturnType<typeof vi.fn>;
const mockRemoveChannel = removeChannel as ReturnType<typeof vi.fn>;
const mockSetInbound = setInbound as ReturnType<typeof vi.fn>;
const mockRestart = restartDaemon as ReturnType<typeof vi.fn>;
const mockSetChannelEnabled = setChannelEnabled as ReturnType<typeof vi.fn>;
const mockOpenExternalUrl = openExternalUrl as ReturnType<typeof vi.fn>;

const CONFIGURED = {
  ok: true,
  channels: {
    max_replies_per_min: 10,
    adapters: {
      telegram: true,
      discord: false,
      whatsapp: false,
      matrix: false,
      mattermost: false,
      slack: false,
      ntfy: false,
      webhook: false,
      teams: false,
      wecom: false,
    },
    inbound: { bind: "127.0.0.1:8787", line: true, slack: false },
    allow: [{ platform: "telegram", principal: "4242" }],
    disabled: [],
    fields_set: {},
  },
};

// Telegram administratively disabled + its bot_token already saved — exercises
// the new "Disabled" pill and per-field "Saved" badge, both real backend data.
const DISABLED_WITH_SAVED_FIELD = {
  ok: true,
  channels: {
    ...CONFIGURED.channels,
    disabled: ["telegram"],
    fields_set: { telegram: ["bot_token"] },
  },
};

beforeEach(() => {
  mockGet.mockReset();
  mockRemove.mockReset();
  mockPair.mockReset();
  mockSetChannel.mockReset();
  mockRemoveChannel.mockReset();
  mockSetInbound.mockReset();
  mockRestart.mockReset();
  mockSetChannelEnabled.mockReset();
  mockOpenExternalUrl.mockReset();
  mockSetChannel.mockResolvedValue({ ok: true });
  mockRemoveChannel.mockResolvedValue({ ok: true });
  mockSetInbound.mockResolvedValue({ ok: true });
  mockRestart.mockResolvedValue({ ok: true });
  mockSetChannelEnabled.mockResolvedValue({ ok: true });
  mockOpenExternalUrl.mockResolvedValue(undefined);
});

describe("Messaging view", () => {
  it("shows a disabled state when channels are off", async () => {
    mockGet.mockResolvedValue({ ok: false, error: "channels not enabled" });
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Messaging is off")).toBeTruthy());
    expect(screen.getByText("channels not enabled")).toBeTruthy();
  });

  it("renders connectors, the enrolled approver, and inbound status", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    // The configured Telegram connector shows a "Configured" badge (only one on).
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    expect(screen.getAllByText("Telegram").length).toBeGreaterThan(0);
    // Enrolled approver id is shown.
    expect(screen.getByText(/4242/)).toBeTruthy();
    // Inbound bind is surfaced.
    expect(screen.getByText("127.0.0.1:8787")).toBeTruthy();
  });

  it("removes an approver via channelAllowRemove", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    mockRemove.mockResolvedValue({ ok: true });
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Remove")).toBeTruthy());
    fireEvent.click(screen.getByText("Remove"));
    await waitFor(() =>
      expect(mockRemove).toHaveBeenCalledWith("telegram", "4242"),
    );
  });

  it("starts pairing and shows the one-time code", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    mockPair.mockResolvedValue({
      ok: true,
      platform: "telegram",
      code: "GH7KQ2AB",
      instructions: "DM `pair GH7KQ2AB` from the telegram account to enroll",
    });
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Pair via Telegram")).toBeTruthy());
    fireEvent.click(screen.getByText("Pair via Telegram"));
    await waitFor(() => expect(mockPair).toHaveBeenCalledWith("telegram"));
    // The code modal surfaces the code in its own box ("pair <code>").
    await waitFor(() => expect(screen.getByText("pair GH7KQ2AB")).toBeTruthy());
  });

  it("shows a Bot token field when Telegram is selected", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    // Telegram is the default selection; click it explicitly to be sure.
    await waitFor(() => expect(screen.getByText("Connectors")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Telegram" }));
    expect(screen.getByLabelText("Bot token")).toBeTruthy();
  });

  it("saves a connector via setChannel then restartDaemon", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    // Wait for the loaded view (not just the always-present field) — the form
    // re-seeds from `view` once it arrives, which would otherwise race with
    // typing into the field right after mount and silently drop the edit.
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Bot token"), {
      target: { value: "123:abcSECRET" },
    });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() =>
      // No approver ids typed → allow is omitted, so the save leaves the
      // allowlist untouched (add-only field; removals happen under Approvers).
      expect(mockSetChannel).toHaveBeenCalledWith(
        "telegram",
        { bot_token: "123:abcSECRET" },
        undefined,
      ),
    );
    await waitFor(() => expect(mockRestart).toHaveBeenCalled());
  });

  it("adds approver ids by unioning them with the existing allowlist (never wipes)", async () => {
    mockGet.mockResolvedValue(CONFIGURED); // telegram already has approver 4242
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Add approver IDs"), {
      target: { value: "9999" },
    });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() =>
      expect(mockSetChannel).toHaveBeenCalledWith(
        "telegram",
        {},
        ["4242", "9999"],
      ),
    );
  });

  it("toggles enable/disable via setChannelEnabled then restartDaemon", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    // Telegram starts enabled (not in view.disabled) — the switch is checked.
    await waitFor(() => expect(screen.getByRole("switch")).toBeTruthy());
    fireEvent.click(screen.getByRole("switch"));
    await waitFor(() =>
      expect(mockSetChannelEnabled).toHaveBeenCalledWith("telegram", false),
    );
    await waitFor(() => expect(mockRestart).toHaveBeenCalled());
  });

  it("shows a Saved badge for a field present in fields_set", async () => {
    mockGet.mockResolvedValue(DISABLED_WITH_SAVED_FIELD);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByLabelText("Bot token")).toBeTruthy());
    expect(screen.getByText("Saved")).toBeTruthy();
  });

  it("shows a Disabled pill when the platform id is in view.disabled", async () => {
    mockGet.mockResolvedValue(DISABLED_WITH_SAVED_FIELD);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Disabled")).toBeTruthy());
  });

  it("routes the setup guide link through openExternalUrl, not a bare navigation", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    const link = await screen.findByText("Open setup guide");
    const evt = fireEvent.click(link);
    // fireEvent.click returns false when preventDefault() was called — proving
    // the anchor's default navigation never fires; only the controlled opener does.
    expect(evt).toBe(false);
    await waitFor(() =>
      expect(mockOpenExternalUrl).toHaveBeenCalledWith(
        "https://core.telegram.org/bots#how-do-i-create-a-bot",
      ),
    );
  });

  it("filters the connector list via the search box", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Discord" })).toBeTruthy());
    fireEvent.change(screen.getByPlaceholderText('Try "discord"'), {
      target: { value: "discord" },
    });
    expect(screen.queryByRole("button", { name: "Telegram" })).toBeNull();
    expect(screen.getByRole("button", { name: "Discord" })).toBeTruthy();
  });

  it("warns about Discord's Message Content Intent when Discord is selected", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Discord" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Discord" }));
    // The #1 dead-bot trap must be called out before the token fields.
    expect(screen.getByText(/Message Content Intent/)).toBeTruthy();
  });

  it("states the default-deny approval model", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText(/default-deny/)).toBeTruthy());
  });

  it("does NOT wipe in-progress edits when an unrelated refresh fires (form-reset race)", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    // Start typing a secret.
    fireEvent.change(screen.getByLabelText("Bot token"), { target: { value: "SECRET123" } });
    // Trigger an UNRELATED mutation that calls refresh() (the enable toggle).
    fireEvent.click(screen.getByRole("switch"));
    await waitFor(() => expect(mockRestart).toHaveBeenCalled());
    // The typed value must survive the refresh (previously it was silently wiped).
    expect((screen.getByLabelText("Bot token") as HTMLInputElement).value).toBe("SECRET123");
  });

  it("omits a blank secret field from the setChannel payload", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    // Leave Bot token blank and save.
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(mockSetChannel).toHaveBeenCalled());
    const [, config] = mockSetChannel.mock.calls[0];
    expect(config.bot_token).toBeUndefined();
  });

  it("does not restart the daemon when setChannel fails", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    mockSetChannel.mockResolvedValue({ ok: false, error: "bad token" });
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Configured")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Bot token"), { target: { value: "x" } });
    fireEvent.click(screen.getByText("Save changes"));
    await waitFor(() => expect(mockSetChannel).toHaveBeenCalled());
    expect(mockRestart).not.toHaveBeenCalled();
    expect(screen.getByText("bad token")).toBeTruthy();
  });

  it("removes a connector via removeChannel then restartDaemon", async () => {
    mockGet.mockResolvedValue(CONFIGURED);
    render(<Messaging />);
    await waitFor(() => expect(screen.getByText("Remove connector")).toBeTruthy());
    fireEvent.click(screen.getByText("Remove connector"));
    await waitFor(() => expect(mockRemoveChannel).toHaveBeenCalledWith("telegram"));
    await waitFor(() => expect(mockRestart).toHaveBeenCalled());
  });
});
