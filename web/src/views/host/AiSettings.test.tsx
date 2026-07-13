import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  getAiConfig: vi.fn().mockResolvedValue({
    mode: "off",
    provider: "ollama",
    model: "qwen2.5",
    base_url: null,
    cloud_consent: false,
    key_present: false,
  }),
  setAiConfig: vi.fn().mockResolvedValue({ ok: true }),
  setAiKey: vi.fn().mockResolvedValue({ ok: true, key_present: true }),
}));

import * as api from "../../lib/api";
import AiSettings from "./AiSettings";

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getAiConfig).mockResolvedValue({
    mode: "off",
    provider: "ollama",
    model: "qwen2.5",
    base_url: null,
    cloud_consent: false,
    key_present: false,
  });
  vi.mocked(api.setAiConfig).mockResolvedValue({ ok: true });
  vi.mocked(api.setAiKey).mockResolvedValue({ ok: true, key_present: true });
});

describe("AiSettings", () => {
  it("renders the loaded config", async () => {
    render(<AiSettings />);

    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    // "Off" mode is selected; the off-mode explanation text is shown.
    const offTab = screen.getByRole("radio", { name: /^off$/i });
    expect(offTab.getAttribute("aria-checked")).toBe("true");
    expect(screen.getByText(/ai explanations are disabled/i)).toBeTruthy();
  });

  it("selecting Cloud with consent unchecked leaves Save disabled", async () => {
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));

    // Cloud-specific fields appear, including the required consent checkbox.
    const consentBox = await screen.findByRole("checkbox");
    expect((consentBox as HTMLInputElement).checked).toBe(false);

    const saveBtn = screen.getByRole("button", { name: /^save$/i });
    expect((saveBtn as HTMLButtonElement).disabled).toBe(true);

    // Clicking Save while blocked must not call the API.
    fireEvent.click(saveBtn);
    expect(api.setAiConfig).not.toHaveBeenCalled();
  });

  it("checking consent enables Save; clicking Save calls setAiConfig with cloud_consent true", async () => {
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));

    const consentBox = await screen.findByRole("checkbox");
    fireEvent.click(consentBox);
    expect((consentBox as HTMLInputElement).checked).toBe(true);

    const saveBtn = screen.getByRole("button", { name: /^save$/i });
    expect((saveBtn as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(saveBtn);

    await waitFor(() =>
      expect(api.setAiConfig).toHaveBeenCalledWith(
        expect.objectContaining({ mode: "cloud", cloud_consent: true }),
      ),
    );
  });

  // ── Multi-provider + per-provider model dropdowns ─────────────────────────

  it("Cloud mode shows a provider dropdown listing more than 2 providers", async () => {
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));

    const providerSelect = (await screen.findByLabelText(/^provider$/i)) as HTMLSelectElement;
    const optionLabels = Array.from(providerSelect.options).map((o) => o.textContent);
    expect(optionLabels.length).toBeGreaterThan(2);
    expect(optionLabels).toContain("Google Gemini");
    expect(optionLabels).toContain("Groq");
  });

  it("selecting a provider populates the model dropdown with that provider's models and sets its default", async () => {
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));
    const providerSelect = (await screen.findByLabelText(/^provider$/i)) as HTMLSelectElement;

    fireEvent.change(providerSelect, { target: { value: "gemini" } });
    expect(providerSelect.value).toBe("gemini");

    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    const modelOptionLabels = Array.from(modelSelect.options).map((o) => o.textContent);
    expect(modelOptionLabels.some((label) => label?.includes("Gemini 2.5 Flash"))).toBe(true);
    // Gemini's default model is selected automatically.
    expect(modelSelect.value).toBe("gemini-2.5-flash");
  });

  it("selecting Custom… in the model dropdown reveals a free-text input; typing and saving sends that exact string", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-sonnet-5",
      base_url: null,
      cloud_consent: true,
      key_present: false,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    expect(screen.queryByLabelText(/custom model id/i)).toBeNull();

    fireEvent.change(modelSelect, { target: { value: "__custom__" } });

    const customInput = (await screen.findByLabelText(/custom model id/i)) as HTMLInputElement;
    expect(customInput.value).toBe("");

    fireEvent.change(customInput, { target: { value: "claude-my-custom-preview" } });

    const saveBtn = screen.getByRole("button", { name: /^save$/i });
    fireEvent.click(saveBtn);

    await waitFor(() =>
      expect(api.setAiConfig).toHaveBeenCalledWith(
        expect.objectContaining({ model: "claude-my-custom-preview" }),
      ),
    );
    // The sentinel value itself must never be sent to the daemon.
    const [savedConfig] = vi.mocked(api.setAiConfig).mock.calls[0];
    expect(savedConfig.model).not.toBe("__custom__");
  });

  it("a loaded config whose model isn't in the provider's list starts in custom mode with the value prefilled", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-legacy-unlisted-model",
      base_url: null,
      cloud_consent: true,
      key_present: false,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    expect(modelSelect.value).toBe("__custom__");

    const customInput = screen.getByLabelText(/custom model id/i) as HTMLInputElement;
    expect(customInput.value).toBe("claude-legacy-unlisted-model");
  });

  it("Local mode has no provider dropdown and shows Ollama's curated model list", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "local",
      provider: "ollama",
      model: "qwen2.5",
      base_url: null,
      cloud_consent: false,
      key_present: false,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    expect(screen.queryByLabelText(/^provider$/i)).toBeNull();

    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    expect(modelSelect.value).toBe("qwen2.5");
    const modelOptionLabels = Array.from(modelSelect.options).map((o) => o.textContent);
    expect(modelOptionLabels.some((label) => label?.includes("Llama 3.2"))).toBe(true);
  });

  it("switching from Local to Cloud resets provider to a cloud provider and its default model", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "local",
      provider: "ollama",
      model: "qwen2.5",
      base_url: null,
      cloud_consent: false,
      key_present: false,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());
    expect(screen.getByRole("radio", { name: /^local$/i }).getAttribute("aria-checked")).toBe("true");

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));

    // Provider resets to a valid cloud provider (never the stale "ollama"),
    // landing on that provider's curated default model rather than a blank
    // or stale value.
    const providerSelect = (await screen.findByLabelText(/^provider$/i)) as HTMLSelectElement;
    expect(providerSelect.value).toBe("openai");
    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    expect(modelSelect.value).toBe("gpt-5.4-mini");

    // The consent sentence reflects the reset provider, not the old local one.
    expect(screen.getByText(/to OpenAI/i)).toBeTruthy();
    expect(screen.queryByText(/to Ollama/i)).toBeNull();
  });

  it("switching from Cloud to Local resets provider to ollama and its default model", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-opus-4",
      base_url: null,
      cloud_consent: true,
      key_present: true,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());
    expect(screen.getByRole("radio", { name: /^cloud$/i }).getAttribute("aria-checked")).toBe("true");

    fireEvent.click(screen.getByRole("radio", { name: /^local$/i }));

    expect(screen.queryByLabelText(/^provider$/i)).toBeNull();
    const modelSelect = screen.getByLabelText(/^model$/i) as HTMLSelectElement;
    expect(modelSelect.value).toBe("llama3.2");
  });

  it("does not update state (or throw) when unmounted while getAiConfig is in flight", async () => {
    let resolveGetConfig: ((v: Awaited<ReturnType<typeof api.getAiConfig>>) => void) | undefined;
    vi.mocked(api.getAiConfig).mockImplementation(
      () => new Promise((resolve) => { resolveGetConfig = resolve; }),
    );

    const { unmount } = render(<AiSettings />);
    // The load() effect has fired and is now awaiting getAiConfig(); unmount
    // before it resolves — mirrors the ApprovalCard unmount-race regression test.
    unmount();

    await expect(
      act(async () => {
        resolveGetConfig?.({
          mode: "off",
          provider: "ollama",
          model: "qwen2.5",
          base_url: null,
          cloud_consent: false,
          key_present: false,
        });
        await Promise.resolve();
        await Promise.resolve();
      }),
    ).resolves.not.toThrow();
  });

  it("does not update state (or throw) when unmounted while setAiConfig is in flight", async () => {
    let resolveSetConfig: ((v: Awaited<ReturnType<typeof api.setAiConfig>>) => void) | undefined;
    vi.mocked(api.setAiConfig).mockImplementation(
      () => new Promise((resolve) => { resolveSetConfig = resolve; }),
    );

    const { unmount } = render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    fireEvent.click(screen.getByRole("radio", { name: /^cloud$/i }));
    const consentBox = await screen.findByRole("checkbox");
    fireEvent.click(consentBox);
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

    // setAiConfig() is now in flight; unmount before it resolves.
    unmount();

    await expect(
      act(async () => {
        resolveSetConfig?.({ ok: true });
        await Promise.resolve();
        await Promise.resolve();
      }),
    ).resolves.not.toThrow();
  });

  // ── API key field (write-only, owner-only 0600 storage) ──────────────────

  it("API key field is a password input and never shows the key back", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-opus-4",
      base_url: null,
      cloud_consent: true,
      key_present: false,
    });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const keyInput = screen.getByLabelText(/api key/i) as HTMLInputElement;
    expect(keyInput.type).toBe("password");
    expect(keyInput.getAttribute("autocomplete")).toBe("off");
    // Write-only: never pre-filled with a stored key.
    expect(keyInput.value).toBe("");
  });

  it("entering a key and clicking Save key calls setAiKey and reflects saved state", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-opus-4",
      base_url: null,
      cloud_consent: true,
      key_present: false,
    });
    vi.mocked(api.setAiKey).mockResolvedValue({ ok: true, key_present: true });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const keyInput = screen.getByLabelText(/api key/i) as HTMLInputElement;
    fireEvent.change(keyInput, { target: { value: "sk-entered-secret-value" } });

    const saveKeyBtn = screen.getByRole("button", { name: /save key/i });
    fireEvent.click(saveKeyBtn);

    await waitFor(() => expect(api.setAiKey).toHaveBeenCalledWith("sk-entered-secret-value"));

    // Input is cleared after a successful save — never reflects the key back.
    await waitFor(() => expect(keyInput.value).toBe(""));
    await waitFor(() => expect(screen.getByText(/key saved/i)).toBeTruthy());
    // The "no key yet" hint is gone now that key_present flipped to true.
    expect(screen.queryByText(/belay_ai_key/i)).toBeNull();
  });

  it("Clear calls setAiKey with an empty string and reflects the cleared state", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-opus-4",
      base_url: null,
      cloud_consent: true,
      key_present: true,
    });
    vi.mocked(api.setAiKey).mockResolvedValue({ ok: true, key_present: false });
    render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const clearBtn = screen.getByRole("button", { name: /^clear$/i });
    fireEvent.click(clearBtn);

    await waitFor(() => expect(api.setAiKey).toHaveBeenCalledWith(""));
    await waitFor(() => expect(screen.getByText(/belay_ai_key/i)).toBeTruthy());
  });

  it("does not update state (or throw) when unmounted while setAiKey is in flight", async () => {
    vi.mocked(api.getAiConfig).mockResolvedValue({
      mode: "cloud",
      provider: "anthropic",
      model: "claude-opus-4",
      base_url: null,
      cloud_consent: true,
      key_present: false,
    });
    let resolveSetKey: ((v: Awaited<ReturnType<typeof api.setAiKey>>) => void) | undefined;
    vi.mocked(api.setAiKey).mockImplementation(
      () => new Promise((resolve) => { resolveSetKey = resolve; }),
    );

    const { unmount } = render(<AiSettings />);
    await waitFor(() => expect(screen.getByRole("radiogroup", { name: /ai mode/i })).toBeTruthy());

    const keyInput = screen.getByLabelText(/api key/i) as HTMLInputElement;
    fireEvent.change(keyInput, { target: { value: "sk-in-flight" } });
    fireEvent.click(screen.getByRole("button", { name: /save key/i }));

    unmount();

    await expect(
      act(async () => {
        resolveSetKey?.({ ok: true, key_present: true });
        await Promise.resolve();
        await Promise.resolve();
      }),
    ).resolves.not.toThrow();
  });
});
