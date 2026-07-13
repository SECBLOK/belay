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
