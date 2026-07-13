// Pure helper: pulls the destination out of a blocked-egress audit row so the
// Activity feed can render a <DestOwner> chip without any daemon schema
// change. The daemon audits raw-connect bypasses with a `reason` string of
// the form "hook bypass: raw connect to new destination <DEST>" and tags the
// row with rule id "bypass.new_destination" (see daemon/src/engine/mod.rs).
const DEST_RE = /connect to new destination (\S+)/;
const BYPASS_RULE = "bypass.new_destination";

interface AuditRowLike {
  reason?: unknown;
  rules?: unknown;
  rule?: unknown;
}

/**
 * Returns the raw destination string (host[:port]) for an egress
 * bypass-new-destination audit row, or `null` when the row isn't one (or the
 * destination can't be parsed out of the reason text).
 */
export function extractEgressDest(row: AuditRowLike | null | undefined): string | null {
  if (!row) return null;

  const rules = Array.isArray(row.rules) ? (row.rules as unknown[]) : [];
  const rule = typeof row.rule === "string" ? row.rule : undefined;
  const isBypassRule = rules.includes(BYPASS_RULE) || rule === BYPASS_RULE;

  const reason = typeof row.reason === "string" ? row.reason : "";
  const match = reason.match(DEST_RE);

  if (!isBypassRule && !match) return null;
  return match ? match[1] : null;
}
