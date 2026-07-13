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
it("uses one color per state via the status tokens", () => {
  render(<StatusRing state="blocked" />);
  expect(screen.getByTestId("ring-arc").getAttribute("stroke")).toBe("var(--status-blocked)");
});
it("exposes a glyph alongside color+label for every state", () => {
  for (const s of Object.keys(STATES) as (keyof typeof STATES)[])
    expect(STATES[s].glyph).toBeTruthy();
});
