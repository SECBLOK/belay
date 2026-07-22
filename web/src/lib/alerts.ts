// Classification of the alert-only (informational) audit events surfaced on the
// Alerts feed. These detectors observe and record but never block, so they are
// grouped and styled apart from gate decisions in the Live Feed.

import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";

export type AlertKind = "injection" | "secret" | "correlation" | "self_approval" | "resolution";

export interface AlertItem {
  /** Stable de-dupe key (hash-chain hash when present, else a content composite). */
  id: string;
  ts: string;
  session: string;
  kind: AlertKind;
  title: string;
  /** Human-readable secondary line (server/tool + reason). Never a secret value. */
  detail: string;
}

// Audit `event` strings written by the alert-only detectors. These rows carry
// no gate verdict — they are pure observability.
export const ALERT_EVENTS = new Set(["mcp/response_alert", "mcp/secret_redacted"]);

// The injection→action correlation signal rides ON a gate row (which has its
// own verdict); the rule id appears in that row's rules[].
export const CORRELATION_RULE = "correlate.injection_to_action";

/** True for pure observability rows that carry no gate verdict. These are
 *  excluded from the decision-oriented Live Feed and shown on Alerts instead. */
export function isAlertEvent(row: any): boolean {
  return typeof row?.event === "string" && ALERT_EVENTS.has(row.event);
}

// Alert-only events use an ISO `ts`; approval-provenance rows use epoch `ts_ms`.
// Normalize to a single ISO string so the feed sorts/renders both uniformly.
const tsOf = (row: any): string =>
  row?.ts ?? (typeof row?.ts_ms === "number" ? new Date(row.ts_ms).toISOString() : "");

const keyOf = (row: any): string =>
  row?.hash ?? `${tsOf(row)}|${row?.session ?? ""}|${row?.event ?? ""}|${row?.tool ?? ""}`;

/** Map a raw audit row to an AlertItem, or null when it is not an alert. Covers
 *  the two alert-only events, gate rows carrying the injection→action
 *  correlation rule, and approval-provenance rows (self-approval-blocked +
 *  channel-resolved) from the separate approvals store. */
export function classifyAlert(row: any): AlertItem | null {
  const ts = tsOf(row);
  const session = row?.session ?? "";

  if (row?.event === "mcp/response_alert") {
    return {
      id: keyOf(row), ts, session, kind: "injection",
      title: i18n._(msg`Injection marker in MCP response`),
      detail: [row.tool, row.reason].filter(Boolean).join(" · "),
    };
  }
  if (row?.event === "mcp/secret_redacted") {
    return {
      id: keyOf(row), ts, session, kind: "secret",
      title: i18n._(msg`Secret redacted from MCP response`),
      // The reason carries types + count only — never the secret value itself.
      detail: row.reason ?? "",
    };
  }
  if (Array.isArray(row?.rules) && row.rules.includes(CORRELATION_RULE)) {
    return {
      id: keyOf(row), ts, session, kind: "correlation",
      title: i18n._(msg`Risky action after untrusted ingest`),
      detail: [row.tool, row.reason].filter(Boolean).join(" · "),
    };
  }
  // Approval provenance (from the separate approvals store). Only the
  // authoritative `approval.resolved` row is classified — `approval.respond`
  // is a near-duplicate of the same local resolution and would double-count.
  if (row?.event === "approval.resolved") {
    const decided = row.decision === "allow" ? i18n._(msg`Allowed`) : i18n._(msg`Denied`);
    if (row.self_approval_blocked === true) {
      return {
        id: keyOf(row), ts, session, kind: "self_approval",
        title: i18n._(msg`Self-approval blocked`),
        detail: [row.tool, i18n._(msg`an agent tried to approve its own request — the guard denied it`)]
          .filter(Boolean).join(" · "),
      };
    }
    // Only channel (messaging) resolutions are surfaced — local UI/CLI and
    // timeout resolutions are routine and already visible as the gate decision.
    if (row.source === "channel") {
      // resolver_agent_lineage === false means ancestry did NOT tie the resolver
      // to the gated agent → treated as human-verified.
      const human = row.resolver_agent_lineage === false;
      return {
        id: keyOf(row), ts, session, kind: "resolution",
        title: i18n._(msg`${decided} via messaging channel`),
        detail: [row.tool, human ? i18n._(msg`human-verified`) : i18n._(msg`agent lineage detected`)]
          .filter(Boolean).join(" · "),
      };
    }
  }
  return null;
}
