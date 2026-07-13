import type { Pending } from "./ApprovalCard";
import { humanizeRule } from "../lib/humanize";
import { severityOf } from "./dash";

type Decision = "allow" | "deny";

// Roll ≥2 simultaneous pendings into ONE digest card, grouped by human label,
// with a severity dot per group and batch actions. Single-pending falls through
// to ApprovalCard upstream (the approval surface decides which to render).
export default function BatchDigest({
  pendings, onResolveAll, onExpand,
}: {
  pendings: Pending[];
  onResolveAll: (d: Decision) => void;
  onExpand: () => void;
}) {
  // Group by human label (not raw rule id), preserving first-seen order.
  // Key: human label string; value: { items, rule (first seen), severity }
  const groups = new Map<string, { items: Pending[]; rule: string }>();
  for (const p of pendings) {
    const label = humanizeRule(p.rule);
    const entry = groups.get(label) ?? { items: [], rule: p.rule };
    entry.items.push(p);
    groups.set(label, entry);
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black/40 backdrop-blur-sm p-4">
      <div className="bg-white rounded-modal p-6 max-w-md w-full space-y-4" style={{ boxShadow: "var(--shadow-modal)" }} role="alertdialog" aria-label="Approvals required">
        <div className="text-text-primary font-semibold text-title1">
          {pendings.length} pending approvals
        </div>
        <ul className="space-y-2">
          {[...groups.entries()].map(([label, { items, rule }]) => {
            // Derive severity color from the representative rule of this group.
            const sev = severityOf("ask", [rule]);
            const dotColor = sev?.color ?? "var(--separator)";
            return (
              <li key={label} className="flex items-center justify-between bg-window rounded-card px-3 py-2">
                <div className="flex items-center gap-2 min-w-0">
                  {/* Severity dot */}
                  <span
                    className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                    style={{ background: dotColor }}
                    aria-hidden="true"
                  />
                  <span className="text-text-primary text-sm break-words">{label}</span>
                </div>
                <span className="text-text-secondary tabular ml-3 flex-shrink-0">{items.length}</span>
              </li>
            );
          })}
        </ul>
        <div className="space-y-2">
          {/* Deny all: prominent (filled) — safe default for non-technical users */}
          <button
            className="w-full py-2 rounded-pill font-medium text-white"
            style={{ background: "var(--semantic-deny)" }}
            onClick={() => onResolveAll("deny")}
          >
            Deny all
          </button>
          <div className="grid grid-cols-2 gap-2">
            {/* Allow all: de-emphasized (outline/ghost) */}
            <button
              className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
              onClick={() => onResolveAll("allow")}
            >
              Allow all
            </button>
            <button
              className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm"
              onClick={onExpand}
            >
              Review individually
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
