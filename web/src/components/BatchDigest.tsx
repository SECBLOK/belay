import { useState } from "react";
import type { Pending } from "./ApprovalCard";
import { humanizeRule } from "../lib/humanize";
import { severityOf } from "./dash";
import { Plural, Trans, useLingui } from "@lingui/react/macro";

type Decision = "allow" | "deny";

// Tauri usually rejects with a plain string (the Rust command's Err
// payload); stay defensive about Error-shaped values too.
function errorMessage(e: unknown): string {
  return String((e as { message?: string } | undefined)?.message ?? e);
}

// Roll ≥2 simultaneous pendings into ONE digest card, grouped by human label,
// with a severity dot per group and batch actions. Single-pending falls through
// to ApprovalCard upstream (the approval surface decides which to render).
export default function BatchDigest({
  pendings, onResolveAll, onExpand,
}: {
  pendings: Pending[];
  onResolveAll: (d: Decision) => Promise<void>;
  onExpand: () => void;
}) {
  const { t } = useLingui();
  // `void x().then(...)` upstream used to fire-and-forget the whole batch: a
  // rejection (e.g. the daemon restarting mid-batch) vanished into an
  // unhandled rejection and the dialog just sat there with no feedback.
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resolveAll = async (d: Decision) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await onResolveAll(d);
      // On success the surface drains `pendings` and this dialog unmounts;
      // no need to clear `busy` for an unmounted component.
    } catch (err) {
      setBusy(false);
      setError(errorMessage(err));
    }
  };

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
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4"
      style={{ background: "rgba(18,20,31,0.46)", backdropFilter: "blur(4px)", WebkitBackdropFilter: "blur(4px)" }}>
      <div className="lg-modal alert-enter p-6 max-w-md w-full space-y-4" role="alertdialog" aria-label={t`Approvals required`}>
        <div className="text-text-primary font-semibold text-title1">
          <Plural value={pendings.length} one="# pending approval" other="# pending approvals" />
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
        {error && (
          <p role="alert" data-testid="batch-resolve-error" className="text-xs" style={{ color: "var(--semantic-deny)" }}>
            <Trans>Could not send your response: {error}</Trans>{" "}
            <Trans>Tap a button below to try again.</Trans>
          </p>
        )}

        <div className="space-y-2">
          {/* Deny all: prominent (filled) — safe default for non-technical users */}
          <button
            disabled={busy}
            className="w-full py-2 rounded-pill font-medium text-white disabled:opacity-60"
            style={{ background: "var(--semantic-deny)" }}
            onClick={() => void resolveAll("deny")}
          >
            <Trans>Deny all</Trans>
          </button>
          <div className="grid grid-cols-2 gap-2">
            {/* Allow all: de-emphasized (outline/ghost) */}
            <button
              disabled={busy}
              className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm disabled:opacity-60"
              onClick={() => void resolveAll("allow")}
            >
              <Trans>Allow all</Trans>
            </button>
            <button
              disabled={busy}
              className="py-2 rounded-pill border border-[var(--separator)] text-text-secondary text-sm disabled:opacity-60"
              onClick={onExpand}
            >
              <Trans>Review individually</Trans>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
