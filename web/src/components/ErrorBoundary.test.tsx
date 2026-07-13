import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useState } from "react";
import ErrorBoundary from "./ErrorBoundary";

function Boom({ message }: { message: string }): never {
  throw new Error(message);
}

beforeEach(() => {
  // React logs caught errors to console.error; silence it for clean test output.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ErrorBoundary", () => {
  it("renders children when nothing throws", () => {
    render(
      <ErrorBoundary label="Firewall setup">
        <div>healthy content</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText("healthy content")).toBeTruthy();
  });

  it("shows a localized fallback (not a blank) when a child throws", () => {
    render(
      <ErrorBoundary label="Firewall setup">
        <Boom message="kaboom in firewall" />
      </ErrorBoundary>,
    );
    // The region label and the error message are both surfaced.
    expect(screen.getByText(/Firewall setup hit an unexpected error/)).toBeTruthy();
    expect(screen.getByText("kaboom in firewall")).toBeTruthy();
    expect(screen.getByRole("alert")).toBeTruthy();
  });

  it("recovers after the underlying error is fixed and Try again is clicked", () => {
    // A wrapper whose child throws until a button flips it to healthy.
    function Harness() {
      const [fixed, setFixed] = useState(false);
      return (
        <>
          <button onClick={() => setFixed(true)}>fix it</button>
          <ErrorBoundary label="Firewall setup">
            {fixed ? <div>recovered content</div> : <Boom message="still broken" />}
          </ErrorBoundary>
        </>
      );
    }
    render(<Harness />);
    expect(screen.getByText("still broken")).toBeTruthy();

    // Repair the underlying cause, then reset the boundary.
    fireEvent.click(screen.getByRole("button", { name: "fix it" }));
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(screen.getByText("recovered content")).toBeTruthy();
  });
});
