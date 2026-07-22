// QuarantineList — shows quarantined files with Restore (primary inline-confirm first)
// and Delete (red inline-confirm). Reversible-first: Restore is the primary action.

import { useState } from "react";
import type { QuarantineEntry } from "../../lib/hostTypes";
import SeverityDot from "./SeverityDot";

type ConfirmKind = "restore" | "delete";

interface RowState {
  busy: boolean;
  confirm: ConfirmKind | null;
}

interface QuarantineRowProps {
  entry: QuarantineEntry;
  noun: string;
  onRestore: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

function QuarantineRow({ entry, noun, onRestore, onDelete }: QuarantineRowProps) {
  const [state, setState] = useState<RowState>({ busy: false, confirm: null });

  const filename = entry.original_path.split("/").pop() ?? entry.original_path;
  const quarantinedDate = new Date(entry.quarantined_at).toLocaleDateString();

  const doRestore = async () => {
    setState((s) => ({ ...s, busy: true, confirm: null }));
    try {
      await onRestore(entry.id);
    } finally {
      setState((s) => ({ ...s, busy: false }));
    }
  };

  const doDelete = async () => {
    setState((s) => ({ ...s, busy: true, confirm: null }));
    try {
      await onDelete(entry.id);
    } finally {
      setState((s) => ({ ...s, busy: false }));
    }
  };

  return (
    <div
      className="py-3 px-4 border-b last:border-0 space-y-2"
      style={{ borderColor: "rgba(0,0,0,0.08)" }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-mono text-[#1C1C1E] truncate max-w-xs" title={entry.original_path}>
          {filename}
        </span>
        <SeverityDot severity={entry.severity} />
        <span className="text-xs text-[var(--text-tertiary)]">{quarantinedDate}</span>
      </div>
      <p className="text-xs text-[var(--text-tertiary)] font-mono truncate" title={entry.original_path}>
        {entry.original_path}
      </p>

      {/* Actions */}
      <div className="flex items-center gap-2 flex-wrap">
        {state.confirm === "restore" ? (
          <>
            <span className="text-xs text-[#636366]">Restore this {noun} to its original location?</span>
            <button
              onClick={doRestore}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-semibold disabled:opacity-40"
              style={{ background: "rgba(24,125,52,0.06)", color: "#187D34" }}
            >
              Yes, restore
            </button>
            <button
              onClick={() => setState((s) => ({ ...s, confirm: null }))}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-medium disabled:opacity-40"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              Cancel
            </button>
          </>
        ) : state.confirm === "delete" ? (
          <>
            <span className="text-xs text-[#636366]">Permanently delete this quarantined {noun}?</span>
            <button
              onClick={doDelete}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-semibold disabled:opacity-40"
              style={{ background: "rgba(200,49,42,0.06)", color: "#C8312A" }}
            >
              Yes, delete permanently
            </button>
            <button
              onClick={() => setState((s) => ({ ...s, confirm: null }))}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-medium disabled:opacity-40"
              style={{ background: "rgba(0,0,0,0.06)", color: "#1C1C1E" }}
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            {/* Restore is PRIMARY */}
            <button
              onClick={() => setState((s) => ({ ...s, confirm: "restore" }))}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: "rgba(24,125,52,0.06)", color: "#187D34" }}
            >
              Restore
            </button>
            {/* Delete is SECOND, red */}
            <button
              onClick={() => setState((s) => ({ ...s, confirm: "delete" }))}
              disabled={state.busy}
              className="px-3 py-1 rounded text-[12px] font-medium disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: "rgba(200,49,42,0.06)", color: "#C8312A" }}
            >
              Delete
            </button>
          </>
        )}
      </div>
    </div>
  );
}

interface QuarantineListProps {
  entries: QuarantineEntry[];
  /** Singular noun for the quarantined items — "file" (default) or "skill". */
  noun?: string;
  onRestore: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

export default function QuarantineList({ entries, noun = "file", onRestore, onDelete }: QuarantineListProps) {
  if (entries.length === 0) {
    return (
      <div
        className="rounded-xl px-5 py-6 text-sm text-[#636366]"
        style={{ background: "#F5F5F7", border: "1px solid rgba(0,0,0,0.08)" }}
      >
        No {noun}s in quarantine.
      </div>
    );
  }

  return (
    <div className="lg-glass overflow-hidden">
      <div
        className="px-4 py-2.5 border-b text-[11px] uppercase tracking-widest text-[var(--text-tertiary)]"
        style={{ borderColor: "rgba(0,0,0,0.08)" }}
      >
        Quarantined {noun}s{" "}
        <span className="font-mono tabular-nums text-[#636366] normal-case tracking-normal">
          {entries.length}
        </span>
      </div>
      {entries.map((entry) => (
        <QuarantineRow
          key={entry.id}
          entry={entry}
          noun={noun}
          onRestore={onRestore}
          onDelete={onDelete}
        />
      ))}
    </div>
  );
}
