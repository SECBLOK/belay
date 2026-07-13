// Curated catalog of BYOK AI providers + their current models, for the AI
// Explanations settings picker. UI-ONLY: the daemon passes the raw provider+model
// strings straight through to rig-core, so this list can be edited freely without
// any daemon change. Every model dropdown also offers a "Custom…" free-text entry
// (see CUSTOM_MODEL_ID) for aggregators (Together/OpenRouter host hundreds) and
// newer models not yet listed here.
//
// Model IDs verified against official provider docs (mid-2026 deep-research pass).
// `id` is the EXACT string the provider API accepts. Deprecated/retired models are
// intentionally excluded; the Custom option covers anything missing.
//
// Provider `id` values match rig-core 0.39 module names and the daemon's
// `AiConfig.provider` validation set (daemon/src/ai/config.rs::from_args).

export interface AiModel {
  /** Exact API model string passed to the provider. */
  id: string;
  /** Short human-facing name. */
  label: string;
  /** 3–8 word hint (speed/quality/reasoning/context). */
  note?: string;
}

export interface AiProvider {
  /** Lowercase id — matches rig-core + daemon validation. */
  id: string;
  /** Human-facing provider name. */
  label: string;
  /** `cloud` needs an API key + consent; `local` (Ollama) runs on-device. */
  kind: "cloud" | "local";
  /** Curated current models, best/most-balanced first. */
  models: AiModel[];
  /** Default model id when this provider is selected. */
  defaultModel: string;
}

/** Sentinel model id: selecting it reveals a free-text field for any model id. */
export const CUSTOM_MODEL_ID = "__custom__";

/** Cloud providers (need a key), then the local provider (Ollama). */
export const AI_PROVIDERS: AiProvider[] = [
  {
    id: "openai",
    label: "OpenAI",
    kind: "cloud",
    defaultModel: "gpt-5.4-mini",
    models: [
      { id: "gpt-5.4-mini", label: "GPT-5.4 Mini", note: "fast, cheap, strong" },
      { id: "gpt-5.4", label: "GPT-5.4", note: "everyday flagship" },
      { id: "gpt-5.5", label: "GPT-5.5", note: "most capable" },
      { id: "gpt-5.4-nano", label: "GPT-5.4 Nano", note: "fastest, cheapest" },
      { id: "o3", label: "o3", note: "reasoning" },
      { id: "o3-pro", label: "o3-pro", note: "deep reasoning" },
    ],
  },
  {
    id: "anthropic",
    label: "Anthropic",
    kind: "cloud",
    defaultModel: "claude-sonnet-5",
    models: [
      { id: "claude-sonnet-5", label: "Claude Sonnet 5", note: "best speed/quality balance" },
      { id: "claude-opus-4-8", label: "Claude Opus 4.8", note: "most capable" },
      { id: "claude-fable-5", label: "Claude Fable 5", note: "frontier, long-running" },
      { id: "claude-haiku-4-5-20251001", label: "Claude Haiku 4.5", note: "fastest" },
      { id: "claude-opus-4-7", label: "Claude Opus 4.7", note: "prior-gen flagship" },
      { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6", note: "1M context" },
    ],
  },
  {
    id: "gemini",
    label: "Google Gemini",
    kind: "cloud",
    defaultModel: "gemini-2.5-flash",
    models: [
      { id: "gemini-2.5-flash", label: "Gemini 2.5 Flash", note: "best price/performance" },
      { id: "gemini-3.5-flash", label: "Gemini 3.5 Flash", note: "newest, agentic" },
      { id: "gemini-2.5-pro", label: "Gemini 2.5 Pro", note: "advanced reasoning" },
      { id: "gemini-3.1-flash-lite", label: "Gemini 3.1 Flash-Lite", note: "cost-efficient" },
      { id: "gemini-2.5-flash-lite", label: "Gemini 2.5 Flash-Lite", note: "fastest, cheapest" },
    ],
  },
  {
    id: "xai",
    label: "xAI (Grok)",
    kind: "cloud",
    defaultModel: "grok-4.1-fast",
    models: [
      { id: "grok-4.1-fast", label: "Grok 4.1 Fast", note: "cheap, 2M context" },
      { id: "grok-4.5", label: "Grok 4.5", note: "newest flagship" },
      { id: "grok-4.3", label: "Grok 4.3", note: "1M context, low hallucination" },
      { id: "grok-4-fast-reasoning", label: "Grok 4 Fast (Reasoning)", note: "cost-efficient reasoning" },
      { id: "grok-code-fast-1", label: "Grok Code Fast 1", note: "agentic coding" },
      { id: "grok-3", label: "Grok 3", note: "legacy, cheapest" },
    ],
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    kind: "cloud",
    defaultModel: "deepseek-v4-flash",
    models: [
      { id: "deepseek-v4-flash", label: "DeepSeek V4 Flash", note: "fast, cheap, 1M context" },
      { id: "deepseek-v4-pro", label: "DeepSeek V4 Pro", note: "flagship reasoning" },
    ],
  },
  {
    id: "mistral",
    label: "Mistral",
    kind: "cloud",
    defaultModel: "mistral-small-latest",
    models: [
      { id: "mistral-small-latest", label: "Mistral Small", note: "SOTA small, multimodal" },
      { id: "mistral-medium-latest", label: "Mistral Medium", note: "cost-efficient" },
      { id: "mistral-large-latest", label: "Mistral Large", note: "flagship reasoning" },
      { id: "magistral-medium-latest", label: "Magistral Medium", note: "dedicated reasoning" },
      { id: "codestral-latest", label: "Codestral", note: "code, low latency" },
      { id: "ministral-8b-latest", label: "Ministral 8B", note: "small, cheap" },
    ],
  },
  {
    id: "groq",
    label: "Groq",
    kind: "cloud",
    defaultModel: "openai/gpt-oss-120b",
    models: [
      { id: "openai/gpt-oss-120b", label: "GPT-OSS 120B", note: "open-weight, fast inference" },
      { id: "openai/gpt-oss-20b", label: "GPT-OSS 20B", note: "smaller, faster" },
      { id: "qwen/qwen3.6-27b", label: "Qwen 3.6 27B", note: "reasoning + vision" },
      { id: "groq/compound", label: "Groq Compound", note: "agentic, web search" },
      { id: "groq/compound-mini", label: "Groq Compound Mini", note: "lighter agentic" },
    ],
  },
  {
    id: "cohere",
    label: "Cohere",
    kind: "cloud",
    defaultModel: "command-r-plus-08-2024",
    models: [
      { id: "command-r-plus-08-2024", label: "Command R+", note: "balanced, 128K context" },
      { id: "command-a-03-2025", label: "Command A", note: "flagship, 256K context" },
      { id: "command-r-08-2024", label: "Command R", note: "fast, cheaper" },
      { id: "command-r7b-12-2024", label: "Command R7B", note: "small, low-cost" },
      { id: "command-a-reasoning-08-2025", label: "Command A Reasoning", note: "extended thinking" },
      { id: "command-a-plus-05-2026", label: "Command A+", note: "newest, multilingual" },
    ],
  },
  {
    id: "perplexity",
    label: "Perplexity",
    kind: "cloud",
    defaultModel: "sonar",
    models: [
      { id: "sonar", label: "Sonar", note: "cheap, grounded search" },
      { id: "sonar-pro", label: "Sonar Pro", note: "deeper retrieval, 200K context" },
      { id: "sonar-reasoning", label: "Sonar Reasoning", note: "real-time reasoning + search" },
      { id: "sonar-reasoning-pro", label: "Sonar Reasoning Pro", note: "exposes reasoning" },
    ],
  },
  {
    id: "together",
    label: "Together AI",
    kind: "cloud",
    defaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    models: [
      { id: "meta-llama/Llama-3.3-70B-Instruct-Turbo", label: "Llama 3.3 70B Turbo", note: "reliable workhorse" },
      { id: "Qwen/Qwen2.5-72B-Instruct-Turbo", label: "Qwen 2.5 72B Turbo", note: "strong multilingual" },
      { id: "deepseek-ai/DeepSeek-V3", label: "DeepSeek V3", note: "widely used general" },
      { id: "openai/gpt-oss-120b", label: "GPT-OSS 120B", note: "open-weight" },
    ],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    kind: "cloud",
    defaultModel: "anthropic/claude-sonnet-4.5",
    models: [
      { id: "anthropic/claude-sonnet-4.5", label: "Claude Sonnet 4.5", note: "balanced" },
      { id: "anthropic/claude-opus-4.8", label: "Claude Opus 4.8", note: "flagship, 1M context" },
      { id: "openai/gpt-4o", label: "GPT-4o", note: "widely used" },
      { id: "deepseek/deepseek-chat", label: "DeepSeek Chat", note: "high volume" },
      { id: "meta-llama/llama-3.3-70b-instruct", label: "Llama 3.3 70B", note: "open model" },
    ],
  },
  {
    id: "minimax",
    label: "MiniMax",
    kind: "cloud",
    defaultModel: "MiniMax-M2.7-highspeed",
    models: [
      { id: "MiniMax-M2.7-highspeed", label: "MiniMax M2.7 (High Speed)", note: "fast, ~100 tok/s" },
      { id: "MiniMax-M3", label: "MiniMax M3", note: "flagship, 1M context" },
      { id: "MiniMax-M2.7", label: "MiniMax M2.7", note: "stronger reasoning" },
      { id: "MiniMax-M2.5-highspeed", label: "MiniMax M2.5 (High Speed)", note: "prior-gen, fast" },
      { id: "MiniMax-M2.5", label: "MiniMax M2.5", note: "prior-gen, code-tuned" },
      { id: "MiniMax-M2", label: "MiniMax M2", note: "cheapest, 200K context" },
    ],
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    kind: "local",
    defaultModel: "llama3.2",
    models: [
      { id: "llama3.2", label: "Llama 3.2", note: "small, fast default" },
      { id: "qwen3", label: "Qwen 3", note: "strong quality/size" },
      { id: "qwen2.5", label: "Qwen 2.5", note: "widely used, multilingual" },
      { id: "deepseek-r1", label: "DeepSeek-R1", note: "reasoning-focused" },
      { id: "gemma3", label: "Gemma 3", note: "efficient, Google" },
      { id: "mistral", label: "Mistral 7B", note: "reliable general-purpose" },
      { id: "llama3.1", label: "Llama 3.1", note: "most-pulled overall" },
      { id: "qwen2.5-coder", label: "Qwen 2.5 Coder", note: "code-specialized" },
    ],
  },
];

/** Lookup a provider by id. */
export const providerById = (id: string): AiProvider | undefined =>
  AI_PROVIDERS.find((p) => p.id === id);

/** Cloud providers only (need a key), in catalog order. */
export const CLOUD_PROVIDERS: AiProvider[] = AI_PROVIDERS.filter((p) => p.kind === "cloud");

/** The local (Ollama) provider entry. */
export const LOCAL_PROVIDER: AiProvider | undefined = AI_PROVIDERS.find((p) => p.kind === "local");
