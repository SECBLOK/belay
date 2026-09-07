import { render, screen } from "@testing-library/react";
import { it, expect } from "vitest";
import ExplanationPanel from "./ExplanationPanel";
import type { Explanation } from "../lib/explain";

const ex: Explanation = {
  summary: "s",
  what: "It opened the file",
  why_risky: "Someone could leak it",
  normal_use: "Rarely needed",
  suggested_action: "Deny if unexpected",
  severity: "high",
  category: "secrets",
};

it("renders each field label as an <h3> heading", () => {
  render(<ExplanationPanel ex={ex} />);
  const labels = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
  expect(labels).toContain("What this is");
  expect(labels).toContain("What could go wrong");
  expect(labels.some((t) => t?.includes("Is this normal?"))).toBe(true);
  expect(labels).toContain("Suggested action");
});

it("places the suggested action last (the takeaway lands at the bottom)", () => {
  const { container } = render(<ExplanationPanel ex={ex} />);
  const headings = [...container.querySelectorAll("h3")].map((h) => h.textContent);
  expect(headings[headings.length - 1]).toBe("Suggested action");
});

// The standards mappings render BELOW the suggested action, which refines the
// invariant above rather than dropping it: the action stays the last piece of
// ADVICE, and the mappings are provenance you consult afterwards. The test
// pins both halves so a future change cannot quietly promote a footnote into
// the takeaway slot.
it("keeps the suggested action as the last advice, with standards as a footnote below", () => {
  const { container } = render(
    <ExplanationPanel ex={{ ...ex, owasp: "ASI04", atlas: "AML.ModifyAgentConfig" }} />,
  );
  const headings = [...container.querySelectorAll("h3")].map((h) => h.textContent);
  expect(headings[headings.length - 2]).toBe("Suggested action");
  expect(headings[headings.length - 1]).toBe("Standards");
});

it("renders both mappings, and neither competes with the action for emphasis", () => {
  render(<ExplanationPanel ex={{ ...ex, owasp: "ASI04", atlas: "AML.ModifyAgentConfig" }} />);
  const line = screen.getByText("ASI04 · AML.ModifyAgentConfig");
  expect(line).toBeTruthy();
  // Recessed: secondary colour and small type, unlike the action's font-medium
  // primary text. Guards the "footnote, not takeaway" intent above.
  expect(line.className).toContain("text-text-secondary");
  expect(line.className).toContain("text-xs");
});

it("renders whichever mapping exists when a rule authors only one", () => {
  render(<ExplanationPanel ex={{ ...ex, atlas: "AML.Exfiltration" }} />);
  expect(screen.getByText("AML.Exfiltration")).toBeTruthy();
  expect(screen.getByRole("heading", { level: 3, name: "Standards" })).toBeTruthy();
});

it("omits the standards block entirely when the rule maps to nothing", () => {
  render(<ExplanationPanel ex={ex} />);
  expect(screen.queryByText("Standards")).toBeNull();
});

it("omits fields that are absent", () => {
  render(
    <ExplanationPanel
      ex={{ summary: "s", severity: "low", category: "recon", suggested_action: "Deny it" }}
    />,
  );
  expect(screen.queryByText("What this is")).toBeNull();
  expect(screen.queryByText("What could go wrong")).toBeNull();
  expect(screen.getByText("Suggested action")).toBeTruthy();
  expect(screen.getByText("Deny it")).toBeTruthy();
});
