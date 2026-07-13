import { it, expect, vi } from "vitest";
import { getPosture } from "./api";
it("getPosture calls /api/posture", async () => {
  globalThis.fetch = vi.fn().mockResolvedValue({ json: async () => ({ score: 85 }) }) as any;
  expect((await getPosture()).score).toBe(85);
});
