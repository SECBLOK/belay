import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../lib/api", () => ({
  enrichDest: vi.fn(),
}));

import * as api from "../../lib/api";
import DestOwner from "./DestOwner";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("DestOwner", () => {
  it("renders owner/ASN/country once enrichDest resolves", async () => {
    vi.mocked(api.enrichDest).mockResolvedValue({
      hostname: "api.anthropic.com",
      asn: "13335",
      as_name: "CLOUDFLARENET",
      country: "US",
    });

    render(<DestOwner dest="1.1.1.1" />);

    await waitFor(() => expect(screen.getByText(/CLOUDFLARENET/)).toBeTruthy());
    expect(screen.getByText(/US/)).toBeTruthy();
  });

  it("renders nothing when enrichDest resolves null", async () => {
    vi.mocked(api.enrichDest).mockResolvedValue(null);

    const { container } = render(<DestOwner dest="8.8.8.8" />);

    await waitFor(() => expect(api.enrichDest).toHaveBeenCalledWith("8.8.8.8"));
    expect(container.textContent).toBe("");
  });

  it("caches per-dest: two mounts of the same dest call enrichDest once", async () => {
    vi.mocked(api.enrichDest).mockResolvedValue({
      hostname: "cache-test.example",
      asn: "999",
      as_name: "CACHETEST",
      country: "DE",
    });

    render(<DestOwner dest="9.9.9.9" />);
    render(<DestOwner dest="9.9.9.9" />);

    await waitFor(() => expect(screen.getAllByText(/CACHETEST/).length).toBe(2));
    expect(api.enrichDest).toHaveBeenCalledTimes(1);
  });
});
