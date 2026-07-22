import { describe, expect, it } from "vitest";
import type { AiConfig, AiRecommendation } from "./api";

describe("AiConfig shape (routing + judge fields)", () => {
  it("accepts the new optional fields and the recommendations object", () => {
    const rec: AiRecommendation = {
      fast: "claude-haiku-4-5",
      recommended_judge: "claude-sonnet-5",
      note: "Sonnet for the more demanding judge task.",
    };
    const cfg: AiConfig = {
      mode: "cloud",
      provider: "anthropic",
      model: "claude-haiku-4-5",
      base_url: null,
      cloud_consent: true,
      key_present: true,
      explain_model: null,
      skill_judge_model: "claude-sonnet-5",
      skill_judge_enabled: true,
      skill_judge_gate_enabled: false,
      recommendations: rec,
    };
    expect(cfg.skill_judge_enabled).toBe(true);
    expect(cfg.recommendations?.recommended_judge).toBe("claude-sonnet-5");
  });

  it("still type-checks with only the legacy fields (back-compat)", () => {
    const legacy: AiConfig = {
      mode: "off",
      provider: "ollama",
      model: "qwen2.5",
      base_url: null,
      cloud_consent: false,
    };
    expect(legacy.skill_judge_enabled).toBeUndefined();
  });
});
