import { render, screen } from "@testing-library/react";
import { it, expect } from "vitest";
import StatusRing, { STATES } from "./StatusRing";

it("renders the right label per state", () => {
  const { rerender } = render(<StatusRing state="protected" />);
  expect(screen.getByText("Protected")).toBeTruthy();
  rerender(<StatusRing state="monitoring" />);
  expect(screen.getByText("Monitoring")).toBeTruthy();
  rerender(<StatusRing state="action" />);
  expect(screen.getByText("Action needed")).toBeTruthy();
  rerender(<StatusRing state="blocked" />);
  expect(screen.getByText("Threat blocked")).toBeTruthy();
});
it("shows the guard-dog mascot with a per-state pose + accessible label", () => {
  const { rerender } = render(<StatusRing state="blocked" />);
  // Threat blocked → the guard/stop pose, labelled for screen readers.
  const guard = screen.getByAltText("Threat blocked") as HTMLImageElement;
  expect(guard.getAttribute("src")).toContain("guard");
  rerender(<StatusRing state="protected" />);
  expect((screen.getByAltText("Protected") as HTMLImageElement).getAttribute("src")).toContain("happy");
});
it("exposes a glyph alongside color+label for every state", () => {
  for (const s of Object.keys(STATES) as (keyof typeof STATES)[])
    expect(STATES[s].glyph).toBeTruthy();
});
