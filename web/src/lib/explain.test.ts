import { it, expect } from "vitest";
import { explainFor, humanizeRule } from "./explain";

it("prefers the daemon-provided explain block", () => {
  const e = explainFor({
    rules: ["secrets.env_dump"],
    severity: "high",
    explain: {
      summary: "Reads your .env secrets",
      what: "",
      why_risky: "",
      normal_use: "",
      suggested_action: "",
    },
  });
  expect(e.summary).toBe("Reads your .env secrets");
  expect(e.category).toBe("secrets");
  expect(e.severity).toBe("high");
});

it("falls back to category copy when no explain", () => {
  const e = explainFor({ rules: ["secrets.unknown_new"] });
  expect(e.summary.toLowerCase()).toContain("credential");
  expect(e.category).toBe("secrets");
});

it("derives severity from category when the row omits it", () => {
  const e = explainFor({ rules: ["destructive.rm_rf"] });
  expect(e.severity).toBe("critical");
});

it("uses a calm generic default for an unknown category", () => {
  const e = explainFor({ rules: ["mystery.thing"] });
  expect(e.summary.length).toBeGreaterThan(0);
  expect(e.category).toBe("mystery");
});

it("resolves an aliased daemon category instead of using it verbatim", () => {
  // The daemon emits category="persistence", but the fallback tables are keyed
  // "persist". Without alias resolution this missed → GENERIC copy + "medium".
  const e = explainFor({ rules: ["persistence.cron"], category: "persistence" });
  expect(e.category).toBe("persist");
  expect(e.severity).toBe("high");
  expect(e.summary).toContain("keeps running");
  // egress↔exfil alias resolves the same way (not the GENERIC default).
  const g = explainFor({ rules: ["exfil.host"], category: "exfil" });
  expect(g.category).toBe("egress");
  expect(g.severity).toBe("medium");
  expect(g.summary).toContain("send data");
});

it("re-exports humanizeRule so existing imports keep working", () => {
  expect(humanizeRule("secrets.env_dump")).toMatch(/credential/i);
});
