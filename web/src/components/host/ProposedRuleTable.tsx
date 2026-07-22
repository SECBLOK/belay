// ProposedRuleTable — renders a proposed firewall ruleset with a PINNED,
// visually-distinct SSH-exemption row so the user always sees that SSH is
// preserved before applying.
//
// Accessibility: semantic <table> with aria-sort on sortable headers.
// Color is never the sole signal: action type is shown as text + badge.

import type { ProposedRuleset, EgressRule } from "../../lib/hostTypes";
import { Trans, Plural, useLingui } from "@lingui/react/macro";

// ── Action badge ──────────────────────────────────────────────────────────────

const ACTION_STYLE: Record<EgressRule["action"], { bg: string; color: string }> = {
  allow: { bg: "rgba(24,125,52,0.06)", color: "#187D34" },
  deny:  { bg: "rgba(200,49,42,0.06)", color: "#C8312A" },
};

function ActionBadge({ action }: { action: EgressRule["action"] }) {
  const { t } = useLingui();
  const s = ACTION_STYLE[action];
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold uppercase"
      style={{ background: s.bg, color: s.color }}
      aria-label={t`Action: ${action}`}
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
  const { t } = useLingui();
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
      aria-label={pinned ? t`SSH exemption — always preserved` : undefined}
    >
      {/* Host */}
      <td className="px-4 py-3 font-mono text-xs text-[#1C1C1E] max-w-[180px] truncate" title={rule.host}>
        {rule.host}
        {pinned && (
          <span
            className="ml-2 text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded"
            style={{ background: "rgba(10,102,214,0.12)", color: "#0A66D6" }}
            aria-label={t`SSH exemption pinned row`}
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
        className="px-4 py-3 text-xs text-[var(--text-tertiary)] max-w-[200px] truncate"
        title={rule.comment}
      >
        {pinned ? <Trans>SSH access preserved</Trans> : (rule.comment ?? "")}
      </td>
    </tr>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export interface ProposedRuleTableProps {
  ruleset: ProposedRuleset;
}

export default function ProposedRuleTable({ ruleset }: ProposedRuleTableProps) {
  const { t } = useLingui();
  // Separate SSH-exemption rules (pinned at top) from the rest.
  const sshRules = ruleset.rules.filter(isSshExemption);
  const otherRules = ruleset.rules.filter((r) => !isSshExemption(r));
  const hasSshExemption = sshRules.length > 0;

  return (
    <div className="lg-glass overflow-hidden">
      {/* Summary header */}
      <div
        className="px-4 py-3 flex items-start justify-between gap-4 border-b"
        style={{ borderColor: "rgba(0,0,0,0.08)", background: "#FAFAFA" }}
      >
        <div className="space-y-0.5">
          <p className="text-xs font-semibold text-[#1C1C1E]">{ruleset.description}</p>
          <p className="text-[11px] text-[var(--text-tertiary)]">
            <Plural
              value={ruleset.rules.length}
              one="# rule proposed"
              other="# rules proposed"
            />
            {(() => {
              // Guard against an empty/invalid generated_at (e.g. a daemon stub),
              // which would otherwise render "Generated Invalid Date".
              const ts = Date.parse(ruleset.generated_at);
              if (Number.isNaN(ts)) return null;
              const generated = new Date(ts).toLocaleString();
              return (
                <>
                  {" · "}<Trans>Generated {generated}</Trans>
                </>
              );
            })()}
          </p>
        </div>
        {hasSshExemption && (
          <span
            className="shrink-0 text-[11px] font-semibold px-2 py-1 rounded"
            style={{ background: "rgba(24,125,52,0.06)", color: "#187D34" }}
            aria-label={t`SSH port 22 is preserved in this ruleset`}
          >
            <Trans>SSH preserved</Trans>
          </span>
        )}
      </div>

      {ruleset.rules.length === 0 ? (
        <div className="px-5 py-6 text-sm text-[var(--text-tertiary)]"><Trans>No rules proposed.</Trans></div>
      ) : (
        <table className="w-full text-sm" aria-label={t`Proposed firewall rules`}>
          <thead>
            <tr
              className="text-[11px] uppercase tracking-widest text-[var(--text-tertiary)] border-b"
              style={{ borderColor: "rgba(0,0,0,0.08)" }}
            >
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Host</Trans></th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Port</Trans></th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Protocol</Trans></th>
              <th className="text-left px-4 py-2.5 font-medium" aria-sort="none"><Trans>Action</Trans></th>
              <th className="text-left px-4 py-2.5 font-medium"><Trans>Comment</Trans></th>
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
