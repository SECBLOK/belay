import { describe, it, expect } from "vitest";
import { extractEgressDest } from "./egressDest";

describe("extractEgressDest", () => {
  it("extracts the destination from an egress bypass row", () => {
    const row = {
      reason: "hook bypass: raw connect to new destination 203.0.113.9:443",
      rules: ["bypass.new_destination"],
    };
    expect(extractEgressDest(row)).toBe("203.0.113.9:443");
  });

  it("extracts a hostname destination", () => {
    const row = {
      reason: "hook bypass: raw connect to new destination api.anthropic.com:443",
      rules: ["bypass.new_destination"],
    };
    expect(extractEgressDest(row)).toBe("api.anthropic.com:443");
  });

  it("returns null for a non-egress row", () => {
    const row = {
      reason: "Tried a destructive action (delete/wipe)",
      rules: ["destructive.rm_rf"],
    };
    expect(extractEgressDest(row)).toBeNull();
  });

  it("returns null for a row with no rules and an unrelated reason", () => {
    const row = { reason: "no findings", rules: [] };
    expect(extractEgressDest(row)).toBeNull();
  });

  it("returns null when the egress rule fires but the reason has no parseable dest", () => {
    const row = {
      reason: "hook bypass: raw connect to new destination",
      rules: ["bypass.new_destination"],
    };
    expect(extractEgressDest(row)).toBeNull();
  });

  it("returns null when reason is missing entirely", () => {
    const row = { rules: ["bypass.new_destination"] };
    expect(extractEgressDest(row)).toBeNull();
  });

  it("falls back to matching the reason text when rules is absent", () => {
    const row = { reason: "hook bypass: raw connect to new destination 10.0.0.5:8080" };
    expect(extractEgressDest(row)).toBe("10.0.0.5:8080");
  });

  it("returns null for a null/undefined row", () => {
    expect(extractEgressDest(null)).toBeNull();
    expect(extractEgressDest(undefined)).toBeNull();
  });
});
