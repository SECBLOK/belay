// ProposedRuleTable — renders a proposed firewall ruleset with a PINNED,
// visually-distinct SSH-exemption row so the user always sees that SSH is
// preserved before applying.
//
// Accessibility: semantic <table> with aria-sort on sortable headers.
// Color is never the sole signal: action type is shown as text + badge.

import type { ProposedRuleset, EgressRule } from "../../lib/hostTypes";

// ── Action badge ──────────────────────────────────────────────────────────────

const ACTION_STYLE: Record<EgressRule["action"], { bg: string; color: string }> = {
  allow: { bg: "rgba(27,140,58,0.10)", color: "#1B8C3A" },
  deny:  { bg: "rgba(200,49,42,0.10)", color: "#C8312A" },
};

function ActionBadge({ action }: { action: EgressRule["action"] }) {
  const s = ACTION_STYLE[action];
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold uppercase"
      style={{ background: s.bg, color: s.color }}
      aria-label={`Action: ${action}`}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: s.color }} aria-hidden />
      {action}
    </span>
  );
}

// ── SSH exemption detection ───────────────────────────────────────────────────

/** Heuristic: a rule is the SSH exemption if it allows port 22 TCP. */
function isSshExemption(rule: EgressRule): boolean {
  return rule.action === "allow" && rule.port === 22 && rule.proto === "tcp";
}

// ── Table row ─────────────────────────────────────────────────────────────────

interface RuleRowProps {
  rule: EgressRule;
  pinned?: boolean;
}

function RuleRow({ rule, pinned }: RuleRowProps) {
  return (
    <tr
      className="border-b last:border-0"
      style={
        pinned
          ? {
              borderColor: "rgba(10,102,214,0.18)",
              background: "rgba(10,102,214,0.045)",
            }
          : { borderColor: "rgba(0,0,0,0.06)" }
      }
      aria-label={pinned ? "SSH exemption — always preserved" : undefined}
    >
      {/* Host */}
      <td className="px-4 py-3 font-mono text-xs text-[#1C1C1E] max-w-[180px] truncate" title={rule.host}>
        {rule.host}
        {pinned && (
          <span
            className="ml-2 text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
            style={{ background: "rgba(10,102,214,0.12)", color: "#0A66D6" }}
            aria-label="SSH exemption pinned row"
          >
            SSH
          </span>
        )}
      </td>
      {/* Port */}
      <td className="px-4 py-3 font-mono text-xs text-[#636366]">
        {rule.port != null ? rule.port : "—"}
      </td>
      {/* Protocol */}
      <td className="px-4 py-3 text-xs text-[#636366] uppercase">{rule.proto}</td>
      {/* Action */}
      <td className="px-4 py-3">
        <ActionBadge action={rule.action} />
      </td>
      {/* Comment */}
      <td
        className="px-4 py-3 text-xs text-[#8E8E93] max-w-[200px] truncate"
        title={rule.comment}
      >
        {pinned ? "SSH access preserved" : (rule.comment ?? "")}
      </td>
    </tr>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export interface ProposedRuleTableProps {
  ruleset: ProposedRuleset;
}

export default function ProposedRuleTable({ ruleset }: ProposedRuleTableProps) {
  // Separate SSH-exemption rules (pinned at top) from the rest.
  const sshRules = ruleset.rules.filter(isSshExemption);
  const otherRules = ruleset.rules.filter((r) => !isSshExemption(r));
  const hasSshExemption = sshRules.length > 0;

  return (
    <div className="rounded-xl overflow-hidden bg-white" style={{ border: "1px solid rgba(0,0,0,0.08)" }}>
      {/* Summary header */}
      <div
        className="px-4 py-3 flex items-start justify-between gap-4 border-b"
        style={{ borderColor: "rgba(0,0,0,0.08)", background: "#FAFAFA" }}
      >
        <div className="space-y-0.5">
          <p className="text-xs font-semibold text-[#1C1C1E]">{ruleset.description}</p>
          <p className="text-[11px] text-[#8E8E93]">
            {ruleset.rules.length} rule{ruleset.rules.length !== 1 ? "s" : ""} proposed
            {(() => {
              // Guard against an empty/invalid generated_at (e.g. a daemon stub),
              // which would otherwise render "Generated Invalid Date".
              const t = Date.parse(ruleset.generated_at);
              return Number.isNaN(t) ? null : (
                <>
                  {" · "}Generated {new Date(t).toLocaleString()}
                </>
              );
            })()}
          </p>
        </div>
        {hasSshExemption && (
          <span
            className="shrink-0 text-[11px] font-semibold px-2 py-1 rounded"
            style={{ background: "rgba(27,140,58,0.10)", color: "#1B8C3A" }}
            aria-label="SSH port 22 is preserved in this ruleset"
          >
            SSH preserved
          </span>
        )}
      </div>

      {ruleset.rules.length === 0 ? (
        <div className="px-5 py-6 text-sm text-[#8E8E93]">No rules proposed.</div>
      ) : (
        <table className="w-full text-sm" aria-label="Proposed firewall rules">
          <thead>
            <tr
              className="text-[11px] uppercase tracking-widest text-[#8E8E93] border-b"
              style={{ borderColor: "rgba(0,0,0,0.08)" }}
            >
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none">Host</th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none">Port</th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none">Protocol</th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none">Action</th>
              <th className="text-left px-4 py-2.5 font-medium">Comment</th>
            </tr>
          </thead>
          <tbody>
            {/* Pinned SSH-exemption rows */}
            {sshRules.map((rule) => (
              <RuleRow key={rule.id} rule={rule} pinned />
            ))}
            {/* Remaining rules */}
            {otherRules.map((rule) => (
              <RuleRow key={rule.id} rule={rule} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
