// CveTable — KEV-first sorted CVE findings table.
// KEV badge is the loudest chip: red fill + "Exploited in the wild".
// Color is never the only signal (paired with text labels).

import type { CveFinding } from "../../lib/hostTypes";
import SeverityDot from "./SeverityDot";
import KevBadge from "./KevBadge";

const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function sortFindings(findings: CveFinding[]): CveFinding[] {
  return [...findings].sort((a, b) => {
    // KEV first
    const aKev = a.kev ? 1 : 0;
    const bKev = b.kev ? 1 : 0;
    if (bKev !== aKev) return bKev - aKev;
    // Then by severity
    const aSev = SEV_RANK[a.severity] ?? 0;
    const bSev = SEV_RANK[b.severity] ?? 0;
    if (bSev !== aSev) return bSev - aSev;
    // Then by CVE ID (descending = newer)
    return b.cve_id.localeCompare(a.cve_id);
  });
}

interface CveTableProps {
  findings: CveFinding[];
}

export default function CveTable({ findings }: CveTableProps) {
  if (findings.length === 0) {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        No CVE findings.
      </div>
    );
  }

  const sorted = sortFindings(findings);

  return (
    <div className="rounded-xl overflow-hidden bg-white" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      <table className="w-full text-sm" aria-label="CVE findings">
        <thead>
          <tr
            className="text-[11px] uppercase tracking-widest text-[#8E8E93] border-b"
            style={{ borderColor: "rgba(0,0,0,0.08)" }}
          >
            <th className="text-left px-4 py-2.5 font-medium" aria-sort="descending">CVE</th>
            <th className="text-left px-4 py-2.5 font-medium">Package</th>
            <th className="text-left px-4 py-2.5 font-medium" aria-sort="none">Severity</th>
            <th className="text-left px-4 py-2.5 font-medium">EPSS</th>
            <th className="text-left px-4 py-2.5 font-medium">Fixed in</th>
            <th className="text-left px-4 py-2.5 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f) => (
            <tr
              key={f.cve_id}
              className="border-b last:border-0"
              style={{ borderColor: "rgba(0,0,0,0.06)" }}
            >
              <td className="px-4 py-3 font-mono text-xs text-[#1C1C1E] font-medium whitespace-nowrap">
                {f.cve_id}
              </td>
              <td className="px-4 py-3 text-xs text-[#636366] font-mono">
                {f.package}
                <span className="text-[#8E8E93] ml-1">{f.installed_version}</span>
              </td>
              <td className="px-4 py-3">
                <SeverityDot severity={f.severity} />
              </td>
              <td
                className="px-4 py-3 text-xs font-mono tabular-nums text-[#636366]"
                title="EPSS — probability of exploitation within 30 days"
              >
                {f.epss != null ? `${Math.round(f.epss * 100)}%` : <span className="text-[#8E8E93]">—</span>}
              </td>
              <td className="px-4 py-3 text-xs font-mono text-[#636366]">
                {f.fixed_version ?? <span className="text-[#C8312A]">No fix</span>}
              </td>
              <td className="px-4 py-3">
                {f.kev && <KevBadge />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
