import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import Host from "./Host";

describe("Host view", () => {
  it("renders Host sub-nav and switches to Firewall section", async () => {
    render(<Host />);
    expect(screen.getByRole("tab", { name: /firewall/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /firewall/i }));
    await waitFor(() => expect(screen.getByText(/firewall setup/i)).toBeTruthy());
  });
});
