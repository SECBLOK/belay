import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import CveTable from "../../components/host/CveTable";
import type { CveFinding } from "../../lib/hostTypes";

// Extend CveFinding with kev flag for this view
interface CveWithKev extends CveFinding {
  kev: boolean;
}

const kevFinding: CveWithKev = {
  cve_id: "CVE-2024-1111",
  package: "openssl",
  installed_version: "3.0.0",
  fixed_version: "3.0.1",
  severity: "critical",
  description: "Exploited vulnerability in openssl",
  published_at: "2024-01-01T00:00:00Z",
  kev: true,
  epss: 0.94,
};

const nonKevFinding: CveWithKev = {
  cve_id: "CVE-2024-2222",
  package: "curl",
  installed_version: "7.0.0",
  fixed_version: "7.0.1",
  severity: "medium",
  description: "Minor curl vulnerability",
  published_at: "2024-02-01T00:00:00Z",
  kev: false,
};

describe("CveTable", () => {
  it("renders KEV finding first and shows 'Exploited in the wild' badge", () => {
    // Pass KEV second to ensure sorting is done by the component (not data order)
    render(<CveTable findings={[nonKevFinding, kevFinding]} />);

    // Both CVEs must be present
    expect(screen.getByText("CVE-2024-1111")).toBeTruthy();
    expect(screen.getByText("CVE-2024-2222")).toBeTruthy();

    // "Exploited in the wild" badge must appear for KEV
    expect(screen.getByText(/exploited in the wild/i)).toBeTruthy();

    // KEV row must come BEFORE non-KEV row in DOM
    const rows = screen.getAllByRole("row");
    // rows[0] = thead tr, rows[1] = first data row, rows[2] = second data row
    const firstDataRow = rows[1];
    const secondDataRow = rows[2];
    expect(firstDataRow.textContent).toContain("CVE-2024-1111");
    expect(secondDataRow.textContent).toContain("CVE-2024-2222");
  });

  it("surfaces EPSS as a percentage, and an em dash when absent", () => {
    render(<CveTable findings={[kevFinding, nonKevFinding]} />);
    // kevFinding.epss 0.94 → "94%"
    expect(screen.getByText("94%")).toBeTruthy();
    // nonKevFinding carries no epss → em-dash placeholder
    expect(screen.getByText("—")).toBeTruthy();
  });
});
