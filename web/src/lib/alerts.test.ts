import { describe, it, expect } from "vitest";
import { classifyAlert, isAlertEvent } from "./alerts";

describe("classifyAlert", () => {
  it("maps an MCP injection-marker row", () => {
    const a = classifyAlert({ ts: "2026-07-18T00:00:00Z", session: "s1", event: "mcp/response_alert", tool: "github", reason: "prompt-injection marker", severity: "high" });
    expect(a?.kind).toBe("injection");
    expect(a?.title).toMatch(/injection marker/i);
    expect(a?.detail).toContain("github");
  });

  it("maps a secret-redaction row and never leaks a value", () => {
    const a = classifyAlert({ ts: "2026-07-18T00:00:00Z", session: "s1", event: "mcp/secret_redacted", reason: "aws_key ×2" });
    expect(a?.kind).toBe("secret");
    expect(a?.detail).toBe("aws_key ×2");
  });

  it("maps a gate row carrying the injection→action correlation rule", () => {
    const a = classifyAlert({ ts: "2026-07-18T00:00:00Z", session: "s1", tool: "Bash", verdict: "allow", rules: ["correlate.injection_to_action"], reason: "curl after untrusted ingest" });
    expect(a?.kind).toBe("correlation");
    expect(a?.title).toMatch(/risky action/i);
  });

  it("returns null for an ordinary gate decision", () => {
    expect(classifyAlert({ ts: "x", tool: "Bash", verdict: "deny", rules: ["cmd.rm_rf"], reason: "rm -rf" })).toBeNull();
  });

  it("maps a self-approval-blocked resolution (and reads ts_ms)", () => {
    const a = classifyAlert({ ts_ms: 1_800_000_000_000, session: "s1", event: "approval.resolved", tool: "Bash", decision: "deny", source: "local", resolver_agent_lineage: true, self_approval_blocked: true });
    expect(a?.kind).toBe("self_approval");
    expect(a?.title).toMatch(/self-approval blocked/i);
    // ts_ms was normalized to a parseable ISO string.
    expect(Number.isNaN(Date.parse(a!.ts))).toBe(false);
  });

  it("maps a channel resolution with human-verified provenance", () => {
    const a = classifyAlert({ ts_ms: 1_800_000_000_000, session: "s1", event: "approval.resolved", tool: "Write", decision: "allow", source: "channel", resolver_agent_lineage: false, self_approval_blocked: false });
    expect(a?.kind).toBe("resolution");
    expect(a?.title).toMatch(/allowed via messaging channel/i);
    expect(a?.detail).toMatch(/human-verified/i);
  });

  it("ignores routine local/timeout resolutions and approval.respond duplicates", () => {
    expect(classifyAlert({ ts_ms: 1, event: "approval.resolved", tool: "Bash", decision: "allow", source: "local", resolver_agent_lineage: false, self_approval_blocked: false })).toBeNull();
    expect(classifyAlert({ ts_ms: 1, event: "approval.respond", decision: "allow", self_approval_blocked: false })).toBeNull();
  });
});

describe("isAlertEvent", () => {
  it("is true only for the pure observability event rows", () => {
    expect(isAlertEvent({ event: "mcp/response_alert" })).toBe(true);
    expect(isAlertEvent({ event: "mcp/secret_redacted" })).toBe(true);
    // A correlation gate row still carries a verdict — it is NOT a pure event
    // and must stay in the decision feed.
    expect(isAlertEvent({ verdict: "allow", rules: ["correlate.injection_to_action"] })).toBe(false);
    expect(isAlertEvent({ verdict: "deny" })).toBe(false);
  });
});
