// AI Explanations settings panel: mode/provider/model + cloud-consent gate.
// Rendered by the top-level "AI Explanations" sidebar view (views/Ai.tsx).
//
// Feature `ai` is off by default; when the daemon wasn't built with it (or
// this isn't the desktop app), getAiConfig() resolves to null and the panel
// renders an "unavailable" state instead of crashing.

import { useEffect, useRef, useState } from "react";
import { getAiConfig, setAiConfig, setAiKey } from "../../lib/api";
import type { AiConfig, AiMode } from "../../lib/api";
import {
  CLOUD_PROVIDERS,
  LOCAL_PROVIDER,
  providerById,
  CUSTOM_MODEL_ID,
  type AiProvider,
  type AiModel,
} from "../../lib/aiProviders";

const MODES: readonly AiMode[] = ["off", "local", "cloud"] as const;

// The curated model list for whichever provider is currently active (Cloud:
// the selected cloud provider; Local: the fixed Ollama entry). Falls back to
// an empty list so a missing/renamed catalog entry never crashes the panel.
const modelsFor = (mode: AiMode, provider: string): AiModel[] =>
  mode === "local" ? LOCAL_PROVIDER?.models ?? [] : providerById(provider)?.models ?? [];

// A loaded/selected model that isn't in the active provider's curated list is
// "custom" — the free-text field takes over from the dropdown so BYOK users
// aren't limited to the curated set (aggregators like Together/OpenRouter
// host hundreds of models we can't enumerate).
const isCustomModel = (mode: AiMode, provider: string, model: string): boolean =>
  !modelsFor(mode, provider).some((m) => m.id === model);

// ── Config panel ──────────────────────────────────────────────────────────────

interface AiConfigPanelProps {
  config: AiConfig;
  onSaved: (c: AiConfig) => void;
}

function AiConfigPanel({ config, onSaved }: AiConfigPanelProps) {
  const [mode, setMode] = useState<AiMode>(config.mode);
  const [provider, setProvider] = useState(config.provider);
  const [model, setModel] = useState(config.model);
  // Whether the Model control is showing the free-text "Custom…" entry
  // rather than the curated dropdown. Derived at load from whether the
  // saved model is actually in the active provider's list — an unrecognized
  // model (hand-edited config, retired model id, aggregator model) must
  // start in custom mode with its value intact, not silently reset.
  const [modelIsCustom, setModelIsCustom] = useState<boolean>(
    isCustomModel(config.mode, config.provider, config.model),
  );
  const [baseUrl, setBaseUrl] = useState(config.base_url ?? "");
  const [cloudConsent, setCloudConsent] = useState(config.cloud_consent);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // API key field state. Write-only, independent of the mode/provider/model
  // consent form above: `keyInput` never gets pre-filled from `config` (the
  // key itself is never sent back from the daemon), and `keyPresent` mirrors
  // `config.key_present` but is updated locally on save/clear so the hint
  // text flips immediately without a full config reload.
  const [keyInput, setKeyInput] = useState("");
  const [keyPresent, setKeyPresent] = useState<boolean>(config.key_present ?? false);
  const [keySaving, setKeySaving] = useState(false);
  const [keySaved, setKeySaved] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);

  // Unmount guard: the panel can go away mid-save (user leaves Host→AI while
  // setAiConfig()/setAiKey() is in flight) — every post-`await` setState
  // below must check this first. The "saved" banners' timeouts are tracked
  // separately so they can be cleared on unmount (and before starting a new
  // one), otherwise they fire setSaved(false)/setKeySaved(false) 3s after a
  // save even if the tree is long gone.
  const mountedRef = useRef(true);
  const savedTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const keySavedTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Focuses the free-text field the moment the user picks "Custom…" from
  // either model dropdown, so they can start typing immediately.
  const customModelInputRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (savedTimeoutRef.current) clearTimeout(savedTimeoutRef.current);
      if (keySavedTimeoutRef.current) clearTimeout(keySavedTimeoutRef.current);
    };
  }, []);
  useEffect(() => {
    if (modelIsCustom) customModelInputRef.current?.focus();
  }, [modelIsCustom]);

  // Picking a different cloud provider defaults the model to that
  // provider's recommended pick rather than leaving a stale (or now
  // meaningless) model id from the previous provider selected.
  const handleProviderChange = (nextProvider: string) => {
    setProvider(nextProvider);
    setModel(providerById(nextProvider)?.defaultModel ?? "");
    setModelIsCustom(false);
  };

  // Shared by the Local and Cloud model <select>s: the sentinel value shows
  // the free-text field (cleared, ready for entry); any real model id
  // selects it directly and drops back into dropdown mode.
  const handleModelSelectChange = (value: string) => {
    if (value === CUSTOM_MODEL_ID) {
      setModelIsCustom(true);
      setModel("");
    } else {
      setModelIsCustom(false);
      setModel(value);
    }
  };

  // Switching modes must not leave a provider/model combo from the previous
  // mode stranded: Local's provider ("ollama") is never a valid Cloud
  // provider, and a Local model name (e.g. "qwen2.5") must never be silently
  // sent to a cloud API. Off is hidden, so its fields are left untouched.
  // Rather than clearing to blank, each reset lands on that provider's
  // curated default model so Save is immediately meaningful.
  const handleModeChange = (next: AiMode) => {
    if (next === "cloud") {
      if (!CLOUD_PROVIDERS.some((p) => p.id === provider)) {
        const fallback: AiProvider = CLOUD_PROVIDERS[0];
        setProvider(fallback.id);
        setModel(fallback.defaultModel);
        setModelIsCustom(false);
      }
    } else if (next === "local") {
      setProvider("ollama");
      if (!(LOCAL_PROVIDER?.models ?? []).some((m) => m.id === model)) {
        setModel(LOCAL_PROVIDER?.defaultModel ?? "");
      }
      setModelIsCustom(false);
    }
    setMode(next);
  };

  const isDirty =
    mode !== config.mode ||
    provider !== config.provider ||
    model !== config.model ||
    baseUrl !== (config.base_url ?? "") ||
    cloudConsent !== config.cloud_consent;

  // The UI enforces the same rule the daemon enforces (AiConfig::from_args):
  // cloud mode may not be saved without explicit consent, since it sends the
  // flagged action (redacted) off-box.
  const consentBlocked = mode === "cloud" && !cloudConsent;
  const canSave = isDirty && !consentBlocked;

  const handleSave = async () => {
    if (consentBlocked) {
      setError("Cloud mode requires consent — check the box above.");
      return;
    }
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const next: AiConfig = {
        mode,
        provider,
        model,
        base_url: baseUrl.trim() === "" ? null : baseUrl,
        cloud_consent: cloudConsent,
        key_present: config.key_present,
      };
      const result = await setAiConfig(next);
      if (!mountedRef.current) return;
      if (result.ok) {
        setSaved(true);
        onSaved(next);
        if (savedTimeoutRef.current) clearTimeout(savedTimeoutRef.current);
        savedTimeoutRef.current = setTimeout(() => {
          savedTimeoutRef.current = null;
          if (mountedRef.current) setSaved(false);
        }, 3000);
      } else {
        setError(result.error ?? "Save failed.");
      }
    } finally {
      if (mountedRef.current) setSaving(false);
    }
  };

  // Shared by "Save key" and "Clear" — both round-trip through setAiKey(),
  // just with a different value (`keyInput` vs. `""`).
  const submitKey = async (value: string) => {
    setKeySaving(true);
    setKeySaved(false);
    setKeyError(null);
    try {
      const result = await setAiKey(value);
      if (!mountedRef.current) return;
      if (result.ok) {
        // Write-only: the input is cleared on every successful save/clear —
        // it never reflects a previously-saved key back.
        setKeyInput("");
        setKeyPresent(result.key_present ?? value.trim() !== "");
        setKeySaved(true);
        if (keySavedTimeoutRef.current) clearTimeout(keySavedTimeoutRef.current);
        keySavedTimeoutRef.current = setTimeout(() => {
          keySavedTimeoutRef.current = null;
          if (mountedRef.current) setKeySaved(false);
        }, 3000);
      } else {
        setKeyError(result.error ?? "Failed to save key.");
      }
    } finally {
      if (mountedRef.current) setKeySaving(false);
    }
  };

  const handleSaveKey = () => submitKey(keyInput);
  const handleClearKey = () => submitKey("");

  return (
    <div className="rounded-xl bg-white p-5 space-y-4" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      <div>
        <p className="text-xs text-[#8E8E93] mt-0.5">
          Generates a plain-English second opinion on flagged actions. Local mode never leaves
          this machine; Cloud mode requires your consent.
        </p>
      </div>

      {/* Mode selector — same iOS-style track+pill as the Host section nav
          (SegmentedNav): grey track, white active pill with accent text. */}
      <div
        role="radiogroup"
        aria-label="AI mode"
        className="flex gap-1 p-1 rounded-xl"
        style={{ background: "rgba(0,0,0,0.05)", border: "1px solid rgba(0,0,0,0.06)" }}
      >
        {MODES.map((m) => {
          const isActive = mode === m;
          return (
            <button
              key={m}
              role="radio"
              aria-checked={isActive}
              onClick={() => handleModeChange(m)}
              className="px-3 py-1.5 rounded-lg text-sm font-medium capitalize transition-colors"
              style={{
                background: isActive ? "white" : "transparent",
                color: isActive ? "var(--accent)" : "#636366",
                boxShadow: isActive ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
                border: isActive ? "1px solid rgba(0,0,0,0.08)" : "1px solid transparent",
              }}
            >
              {m}
            </button>
          );
        })}
      </div>

      {mode === "off" && (
        <p className="text-xs text-[#636366]">
          AI explanations are disabled. Curated explanations remain available regardless.
        </p>
      )}

      {mode === "local" && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4">
            <label className="space-y-1">
              <span className="text-xs text-[#8E8E93]">Model</span>
              <select
                value={modelIsCustom ? CUSTOM_MODEL_ID : model}
                onChange={(e) => handleModelSelectChange(e.target.value)}
                className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
                style={{ border: "1px solid rgba(0,0,0,0.14)" }}
              >
                {(LOCAL_PROVIDER?.models ?? []).map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                    {m.note ? ` — ${m.note}` : ""}
                  </option>
                ))}
                <option value={CUSTOM_MODEL_ID}>Custom…</option>
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs text-[#8E8E93]">Base URL (optional)</span>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://localhost:11434"
                className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
                style={{ border: "1px solid rgba(0,0,0,0.14)" }}
              />
            </label>
          </div>
          {modelIsCustom && (
            <input
              type="text"
              aria-label="Custom model id"
              ref={customModelInputRef}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="Enter model id, e.g. llama3.3"
              className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
              style={{ border: "1px solid rgba(0,0,0,0.14)" }}
            />
          )}
        </div>
      )}

      {mode === "cloud" && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4">
            <label className="space-y-1">
              <span className="text-xs text-[#8E8E93]">Provider</span>
              <select
                value={provider}
                onChange={(e) => handleProviderChange(e.target.value)}
                className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
                style={{ border: "1px solid rgba(0,0,0,0.14)" }}
              >
                {CLOUD_PROVIDERS.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs text-[#8E8E93]">Model</span>
              <select
                value={modelIsCustom ? CUSTOM_MODEL_ID : model}
                onChange={(e) => handleModelSelectChange(e.target.value)}
                className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
                style={{ border: "1px solid rgba(0,0,0,0.14)" }}
              >
                {(providerById(provider)?.models ?? []).map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                    {m.note ? ` — ${m.note}` : ""}
                  </option>
                ))}
                <option value={CUSTOM_MODEL_ID}>Custom…</option>
              </select>
            </label>
          </div>
          {modelIsCustom && (
            <input
              type="text"
              aria-label="Custom model id"
              ref={customModelInputRef}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="Enter model id, e.g. gpt-4.1-2025-04-14"
              className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
              style={{ border: "1px solid rgba(0,0,0,0.14)" }}
            />
          )}

          <label className="flex items-start gap-2 text-xs text-[#1C1C1E]">
            <input
              type="checkbox"
              checked={cloudConsent}
              onChange={(e) => setCloudConsent(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              I understand this sends the flagged action (redacted) to{" "}
              {providerById(provider)?.label ?? (provider || "the provider")}.
            </span>
          </label>

          <div className="space-y-1.5 pt-1" style={{ borderTop: "1px solid rgba(0,0,0,0.06)" }}>
            <div className="flex items-end gap-2">
              <label className="flex-1 space-y-1">
                <span className="text-xs text-[#8E8E93]">API key</span>
                <input
                  type="password"
                  autoComplete="off"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  placeholder={
                    keyPresent
                      ? "•••••••• (key saved)"
                      : `Paste your ${providerById(provider)?.label ?? "provider"} API key`
                  }
                  className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
                  style={{ border: "1px solid rgba(0,0,0,0.14)" }}
                />
              </label>
              <button
                onClick={handleSaveKey}
                disabled={keyInput.trim() === "" || keySaving}
                className="px-3 py-1.5 rounded-lg text-sm font-semibold disabled:opacity-40 whitespace-nowrap"
                style={{ background: "var(--accent)", color: "#fff" }}
              >
                {keySaving ? "Saving…" : "Save key"}
              </button>
            </div>
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs text-[#8E8E93]">
                {keyPresent
                  ? "Stored on this machine, owner-only."
                  : "(or set the BELAY_AI_KEY env var)"}
              </p>
              {keyPresent && (
                <button
                  onClick={handleClearKey}
                  disabled={keySaving}
                  className="text-xs hover:underline disabled:opacity-40 shrink-0"
                  style={{ color: "#8E8E93" }}
                >
                  Clear
                </button>
              )}
            </div>
            {keyError && (
              <p className="text-xs" style={{ color: "var(--semantic-deny)" }}>
                {keyError}
              </p>
            )}
            {keySaved && (
              <p className="text-xs" style={{ color: "var(--semantic-allow)" }}>
                Key saved.
              </p>
            )}
          </div>
        </div>
      )}

      {isDirty && (
        <button
          onClick={handleSave}
          disabled={!canSave || saving}
          aria-describedby={consentBlocked ? "ai-consent-required-hint" : undefined}
          className="px-4 py-1.5 rounded-lg text-sm font-semibold disabled:opacity-40"
          style={{ background: "var(--accent)", color: "#fff" }}
        >
          {saving ? "Saving…" : "Save"}
        </button>
      )}
      {consentBlocked && isDirty && (
        <p id="ai-consent-required-hint" className="text-xs" style={{ color: "var(--semantic-ask)" }}>
          Cloud mode requires consent — check the box above to enable Save.
        </p>
      )}
      {error && (
        <p className="text-xs" style={{ color: "var(--semantic-deny)" }}>
          {error}
        </p>
      )}
      {saved && (
        <p className="text-xs" style={{ color: "var(--semantic-allow)" }}>
          Settings saved.
        </p>
      )}
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

type LoadState =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "ready"; config: AiConfig }
  | { kind: "error"; message: string };

export default function AiSettings() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });

  // Unmount guard: the initial load() is fired from an effect with no
  // cleanup of its own, so if the user leaves Host→AI before getAiConfig()
  // resolves, the post-`await` setState below must be a no-op.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = async () => {
    setState({ kind: "loading" });
    try {
      const config = await getAiConfig();
      if (!mountedRef.current) return;
      setState(config ? { kind: "ready", config } : { kind: "unavailable" });
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  };

  useEffect(() => {
    load();
  }, []);

  if (state.kind === "loading") {
    return (
      <div
        className="rounded-xl px-5 py-8 text-center text-sm text-[#8E8E93]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        Loading AI settings…
      </div>
    );
  }

  if (state.kind === "unavailable") {
    // Distinguish the two reasons getAiConfig() returns null so the box is
    // actionable: (a) running in a browser (not the desktop app), or (b) in the
    // desktop app but the daemon was built without the off-by-default `ai`
    // feature, so it doesn't expose the AI config commands.
    const inDesktop =
      typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-2"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        {inDesktop ? (
          <>
            <p className="text-[#1C1C1E] font-medium">AI explanations aren’t enabled yet</p>
            <p>
              This is a bring-your-own-key feature and it’s <strong>off by default</strong>.
              The running daemon was built without the AI module, so the provider,
              model, and API-key controls can’t load. Rebuild and restart the daemon
              with the <code>ai</code> feature enabled to use Local (on-device Ollama)
              or Cloud (your choice of provider, your key) explanations.
            </p>
            <p className="text-[#8E8E93]">
              Curated (non-AI) explanations for flagged actions always remain available.
            </p>
          </>
        ) : (
          <>
            <p className="text-[#1C1C1E] font-medium">Open the desktop app to configure AI</p>
            <p>
              AI explanation settings (provider, model, and your API key) are managed
              from the Belay desktop app, which talks to the local daemon.
            </p>
            <p className="text-[#8E8E93]">
              Curated (non-AI) explanations for flagged actions always remain available here.
            </p>
          </>
        )}
      </div>
    );
  }

  if (state.kind === "error") {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366] space-y-1"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <p className="text-[#1C1C1E] font-medium">Something went wrong</p>
        <p className="font-mono text-xs text-[#8E8E93]">{state.message}</p>
        <button onClick={load} className="text-xs hover:underline mt-1" style={{ color: "#0856B3" }}>
          Try again
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <AiConfigPanel
        config={state.config}
        onSaved={(config) => setState({ kind: "ready", config })}
      />
    </div>
  );
}
