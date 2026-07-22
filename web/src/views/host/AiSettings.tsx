// AI settings panel: Connection (mode/provider/model + cloud-consent gate) plus
// the Explanations and Skill Judge sections that route off it. Rendered by the
// top-level "AI" sidebar view (views/Ai.tsx).
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
import ModelPicker from "../../components/ModelPicker";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

const MODES: readonly AiMode[] = ["off", "local", "cloud"] as const;

// The mode value ("off"/"local"/"cloud") is an enum compared in logic and sent
// to the daemon - it must never be translated. Only its DISPLAYED label is.
const MODE_LABEL: Record<AiMode, MessageDescriptor> = {
  off: msg`Off`,
  local: msg`Local`,
  cloud: msg`Cloud`,
};

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
  const { t } = useLingui();
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
  // Per-task model routing + judge toggles (spec §4, §6.1). null model = inherit
  // the global `model`. Both judge flags default off (security default).
  const [explainModel, setExplainModel] = useState<string | null>(config.explain_model ?? null);
  const [judgeModel, setJudgeModel] = useState<string | null>(config.skill_judge_model ?? null);
  const [judgeEnabled, setJudgeEnabled] = useState<boolean>(config.skill_judge_enabled ?? false);
  const [judgeGate, setJudgeGate] = useState<boolean>(config.skill_judge_gate_enabled ?? false);
  const aiOff = mode === "off";
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
    cloudConsent !== config.cloud_consent ||
    explainModel !== (config.explain_model ?? null) ||
    judgeModel !== (config.skill_judge_model ?? null) ||
    judgeEnabled !== (config.skill_judge_enabled ?? false) ||
    judgeGate !== (config.skill_judge_gate_enabled ?? false);

  // The UI enforces the same rule the daemon enforces (AiConfig::from_args):
  // cloud mode may not be saved without explicit consent, since it sends the
  // flagged action (redacted) off-box.
  const consentBlocked = mode === "cloud" && !cloudConsent;
  const canSave = isDirty && !consentBlocked;

  const handleSave = async () => {
    if (consentBlocked) {
      setError(t`Cloud mode requires consent — check the box above.`);
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
        explain_model: explainModel && explainModel.trim() !== "" ? explainModel : null,
        skill_judge_model: (judgeEnabled || judgeGate) && judgeModel && judgeModel.trim() !== "" ? judgeModel : null,
        skill_judge_enabled: judgeEnabled,
        skill_judge_gate_enabled: judgeGate,
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
        setError(result.error ?? t`Save failed.`);
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
        setKeyError(result.error ?? t`Failed to save key.`);
      }
    } finally {
      if (mountedRef.current) setKeySaving(false);
    }
  };

  const handleSaveKey = () => submitKey(keyInput);
  const handleClearKey = () => submitKey("");

  return (
    <div className="lg-glass p-5 space-y-4" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      <div>
        <p className="text-xs text-[var(--text-tertiary)] mt-0.5">
          <Trans>
            One connection powers plain-English explanations and the optional Skill Judge.
            Local mode never leaves this machine; Cloud mode requires your consent.
          </Trans>
        </p>
      </div>

      {/* Mode selector — same iOS-style track+pill as the Host section nav
          (SegmentedNav): grey track, white active pill with accent text. */}
      <div
        role="radiogroup"
        aria-label={t`AI mode`}
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
              className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
              style={{
                background: isActive ? "white" : "transparent",
                color: isActive ? "var(--accent)" : "#636366",
                boxShadow: isActive ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
                border: isActive ? "1px solid rgba(0,0,0,0.08)" : "1px solid transparent",
              }}
            >
              {t(MODE_LABEL[m])}
            </button>
          );
        })}
      </div>

      {mode === "off" && (
        <p className="text-xs text-[#636366]">
          <Trans>AI explanations are disabled. Curated explanations remain available regardless.</Trans>
        </p>
      )}

      {mode === "local" && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4">
            <label className="space-y-1">
              <span className="text-xs text-[var(--text-tertiary)]"><Trans>Model</Trans></span>
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
                <option value={CUSTOM_MODEL_ID}>{t`Custom…`}</option>
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-xs text-[var(--text-tertiary)]"><Trans>Base URL (optional)</Trans></span>
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
              aria-label={t`Custom model id`}
              ref={customModelInputRef}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={t`Enter model id, e.g. llama3.3`}
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
              <span className="text-xs text-[var(--text-tertiary)]"><Trans>Provider</Trans></span>
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
              <span className="text-xs text-[var(--text-tertiary)]">Model</span>
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
              aria-label={t`Custom model id`}
              ref={customModelInputRef}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder={t`Enter model id, e.g. gpt-4.1-2025-04-14`}
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
              <Trans>
                I understand this sends the flagged action (redacted) to{" "}
                {providerById(provider)?.label ?? (provider || t`the provider`)}.
              </Trans>
            </span>
          </label>

          <div className="space-y-1.5 pt-1" style={{ borderTop: "1px solid rgba(0,0,0,0.06)" }}>
            <div className="flex items-end gap-2">
              <label className="flex-1 space-y-1">
                <span className="text-xs text-[var(--text-tertiary)]"><Trans>API key</Trans></span>
                <input
                  type="password"
                  autoComplete="off"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  placeholder={
                    keyPresent
                      ? t`•••••••• (key saved)`
                      : t`Paste your ${providerById(provider)?.label ?? "provider"} API key`
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
                {keySaving ? t`Saving…` : t`Save key`}
              </button>
            </div>
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs text-[var(--text-tertiary)]">
                {keyPresent
                  ? t`Stored on this machine, owner-only.`
                  : t`(or set the BELAY_AI_KEY env var)`}
              </p>
              {keyPresent && (
                <button
                  onClick={handleClearKey}
                  disabled={keySaving}
                  className="text-xs hover:underline disabled:opacity-40 shrink-0"
                  style={{ color: "var(--text-tertiary)" }}
                >
                  <Trans>Clear</Trans>
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
                <Trans>Key saved.</Trans>
              </p>
            )}
          </div>
        </div>
      )}

      {/* ── Explanations ─────────────────────────────────────────────
          Implicitly active whenever AI is on (no explain_enabled flag).
          Low-stakes → NO "Recommended" segment (cheap inherited model is
          correct). Greyed when AI is off. (spec §3.3, §4) */}
      <div
        className="space-y-2 pt-3"
        style={{ borderTop: "1px solid rgba(0,0,0,0.06)", opacity: aiOff ? 0.45 : 1 }}
        aria-disabled={aiOff}
      >
        <div>
          <p className="text-sm font-semibold text-[#1C1C1E]"><Trans>Explanations</Trans></p>
          <p className="text-xs text-[var(--text-tertiary)]">
            {aiOff ? t`Active whenever AI is on.` : t`Plain-English second opinion on flagged actions — active.`}
          </p>
        </div>
        {!aiOff && (
          <ModelPicker
            label={t`Explanation model`}
            value={explainModel}
            inherited={model || t`(global model)`}
            onChange={setExplainModel}
          />
        )}
      </div>

      {/* ── Skill Judge ──────────────────────────────────────────────
          Two independent checkboxes → the two backend flags, both off by
          default, both require mode != off. The ONLY place we nudge a
          stronger model (Recommended segment + "why"). (spec §3.3, §4) */}
      <div
        className="space-y-2 pt-3"
        style={{ borderTop: "1px solid rgba(0,0,0,0.06)", opacity: aiOff ? 0.45 : 1 }}
        aria-disabled={aiOff}
      >
        <div>
          <p className="text-sm font-semibold text-[#1C1C1E]"><Trans>Skill Judge</Trans></p>
          <p className="text-xs text-[var(--text-tertiary)]">
            <Trans>Uses the LLM to catch malicious agent skills. Off by default.</Trans>
          </p>
        </div>
        <label className="flex items-start gap-2 text-sm text-[#1C1C1E]">
          <input
            type="checkbox"
            className="mt-0.5"
            disabled={aiOff}
            checked={judgeEnabled}
            onChange={(e) => setJudgeEnabled(e.target.checked)}
          />
          <span>
            <Trans>Judge new / changed skills</Trans>
            <span className="block text-xs text-[var(--text-tertiary)]"><Trans>Background watcher on skill files.</Trans></span>
          </span>
        </label>
        <label className="flex items-start gap-2 text-sm text-[#1C1C1E]">
          <input
            type="checkbox"
            className="mt-0.5"
            disabled={aiOff}
            checked={judgeGate}
            onChange={(e) => setJudgeGate(e.target.checked)}
          />
          <span>
            <Trans>Also gate installs</Trans>
            <span className="block text-xs text-[var(--text-tertiary)]"><Trans>Synchronous check at install time (~1–5s).</Trans></span>
          </span>
        </label>
        {!aiOff && (judgeEnabled || judgeGate) && (
          <ModelPicker
            label={t`Judge model`}
            value={judgeModel}
            inherited={model || t`(global model)`}
            recommended={config.recommendations?.recommended_judge}
            note={config.recommendations?.note}
            onChange={setJudgeModel}
          />
        )}
      </div>

      {isDirty && (
        <button
          onClick={handleSave}
          disabled={!canSave || saving}
          aria-describedby={consentBlocked ? "ai-consent-required-hint" : undefined}
          className="px-4 py-1.5 rounded-lg text-sm font-semibold disabled:opacity-40"
          style={{ background: "var(--accent)", color: "#fff" }}
        >
          {saving ? t`Saving…` : t`Save`}
        </button>
      )}
      {consentBlocked && isDirty && (
        <p id="ai-consent-required-hint" className="text-xs" style={{ color: "var(--semantic-ask)" }}>
          <Trans>Cloud mode requires consent — check the box above to enable Save.</Trans>
        </p>
      )}
      {error && (
        <p className="text-xs" style={{ color: "var(--semantic-deny)" }}>
          {error}
        </p>
      )}
      {saved && (
        <p className="text-xs" style={{ color: "var(--semantic-allow)" }}>
          <Trans>Settings saved.</Trans>
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
        className="rounded-xl px-5 py-8 text-center text-sm text-[var(--text-tertiary)]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        <Trans>Loading AI settings…</Trans>
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
            <p className="text-[#1C1C1E] font-medium"><Trans>AI explanations aren’t enabled yet</Trans></p>
            <p>
              <Trans>
                This is a bring-your-own-key feature and it’s <strong>off by default</strong>.
                The running daemon was built without the AI module, so the provider,
                model, and API-key controls can’t load. Rebuild and restart the daemon
                with the <code>ai</code> feature enabled to use Local (on-device Ollama)
                or Cloud (your choice of provider, your key) explanations.
              </Trans>
            </p>
            <p className="text-[var(--text-tertiary)]">
              <Trans>Curated (non-AI) explanations for flagged actions always remain available.</Trans>
            </p>
          </>
        ) : (
          <>
            <p className="text-[#1C1C1E] font-medium"><Trans>Open the desktop app to configure AI</Trans></p>
            <p>
              <Trans>
                AI explanation settings (provider, model, and your API key) are managed
                from the Belay desktop app, which talks to the local daemon.
              </Trans>
            </p>
            <p className="text-[var(--text-tertiary)]">
              <Trans>Curated (non-AI) explanations for flagged actions always remain available here.</Trans>
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
        <p className="text-[#1C1C1E] font-medium"><Trans>Something went wrong</Trans></p>
        <p className="font-mono text-xs text-[var(--text-tertiary)]">{state.message}</p>
        <button onClick={load} className="text-xs hover:underline mt-1" style={{ color: "#0856B3" }}>
          <Trans>Try again</Trans>
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
