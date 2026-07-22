// Shared explanation renderer — the single source of truth for the plain-English
// "what / why / is-this-normal / what-to-do" copy shown on every user surface.
//
// It consolidates the previously-scattered category copy tables (humanize.ts's
// PREFIX_MAP headline + ruleCopy.ts's what/risk) behind one `explainFor()` with a
// clear precedence: the daemon's curated per-rule `explain` block (authored in
// rules/catalog.yaml) wins; then a web-side per-rule-id override; then the
// category fallback; then a calm generic default. No new dependencies.

import type { Explain, Severity } from "./api";
import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

export type { Explain } from "./api";
// Re-exported so existing `import { humanizeRule } from ".../explain"` and the
// legacy `.../humanize` import both resolve to one implementation.
export { humanizeRule } from "./humanize";

/** Rendered explanation, ready for the ApprovalCard / notification surfaces. */
export interface Explanation {
  summary: string;
  what?: string;
  why_risky?: string;
  normal_use?: string;
  suggested_action?: string;
  severity: Severity;
  category: string;
}

// Five-field copy without the resolved severity/category (added by explainFor).
type Copy = Omit<Explanation, "severity" | "category">;

// Same shape as Copy but each field is a translation descriptor, resolved to
// the active locale by resolveCopy at call time. This is the CLIENT-side
// fallback prose, used only for rules the daemon ships no `explain` for
// (synthetic rules like correlate.*); the daemon's own catalogue prose is
// already localized server-side and wins above.
type CopyMsg = {
  summary: MessageDescriptor;
  what?: MessageDescriptor;
  why_risky?: MessageDescriptor;
  normal_use?: MessageDescriptor;
  suggested_action?: MessageDescriptor;
};
function resolveCopy(c: CopyMsg): Copy {
  const r = (m?: MessageDescriptor) => (m ? i18n._(m) : undefined);
  return {
    summary: i18n._(c.summary),
    what: r(c.what),
    why_risky: r(c.why_risky),
    normal_use: r(c.normal_use),
    suggested_action: r(c.suggested_action),
  };
}

// Daemon category prefixes → canonical fallback key. Keeps `egress`/`exfil` and
// `persist`/`persistence` collapsed onto one entry.
const CATEGORY_ALIASES: Record<string, string> = {
  exfil: "egress",
  persistence: "persist",
};

/** Bare category prefix (before the first ".") with aliases applied. */
export function resolveCategory(ruleIdOrCategory: string): string {
  const raw = (ruleIdOrCategory ?? "").split(".")[0].toLowerCase();
  return CATEGORY_ALIASES[raw] ?? raw;
}

// Category → severity tier, used only when the row carries no daemon severity.
const CATEGORY_SEVERITY: Record<string, Severity> = {
  destructive: "critical",
  rce: "critical",
  secrets: "high",
  persist: "high",
  egress: "medium",
  tamper: "medium",
  mcp: "medium",
  ingest: "low",
  recon: "low",
};

// Category fallback copy (migrated + expanded from ruleCopy.ts's RULE_COPY into
// the 5-field template). Prose is plain-English and path-free.
export const CATEGORY_FALLBACK: Record<string, CopyMsg> = {
  destructive: {
    summary: msg`Tries to delete or overwrite files or data permanently.`,
    what: msg`The agent wants to delete or overwrite files or data permanently.`,
    why_risky: msg`You could lose files, history, or a database with no way to get them back.`,
    normal_use: msg`Build scripts clear specific build folders — but rarely your home or the whole disk.`,
    suggested_action: msg`Deny unless you know exactly which folder this was meant to clear.`,
  },
  rce: {
    summary: msg`Tries to run code it downloaded or built on the fly.`,
    what: msg`The agent wants to run code it downloaded or built on the fly.`,
    why_risky: msg`Unknown code could run on your computer and do anything you can do.`,
    normal_use: msg`Installers and build steps do this, usually from sources you already trust.`,
    suggested_action: msg`Deny unless you started an install or build you recognise.`,
  },
  secrets: {
    summary: msg`Tries to read your saved credentials, keys, or passwords.`,
    what: msg`The agent is trying to open files that hold your passwords, keys, or logins.`,
    why_risky: msg`Someone could steal these and sign in to your accounts or cloud services as you.`,
    normal_use: msg`Rarely. Most tasks never need to read your raw credential files.`,
    suggested_action: msg`Deny unless you asked it to configure something with these keys.`,
  },
  egress: {
    summary: msg`Tries to send data from your computer out to the internet.`,
    what: msg`The agent wants to send data from your computer out to the internet.`,
    why_risky: msg`Private files or secrets could be uploaded somewhere you don't control.`,
    normal_use: msg`Downloading packages is normal; uploading your files to unknown hosts is not.`,
    suggested_action: msg`Deny unless you recognise where it is connecting.`,
  },
  persist: {
    summary: msg`Tries to set something up so it keeps running on its own.`,
    what: msg`The agent wants to set something up so it keeps running on its own.`,
    why_risky: msg`A program could keep running and watching your computer after you close the agent.`,
    normal_use: msg`Some tools register background services on purpose during setup.`,
    suggested_action: msg`Deny unless you are installing a tool that runs in the background by design.`,
  },
  recon: {
    summary: msg`Scans your computer to learn what's installed and where things are.`,
    what: msg`The agent is searching your computer to learn what's installed and where things are.`,
    why_risky: msg`This mapping is often the first step before something sensitive gets taken.`,
    normal_use: msg`Some setup steps inspect your system; broad scans are less common.`,
    suggested_action: msg`Allow if you asked it to inspect your setup; otherwise deny.`,
  },
  ingest: {
    summary: msg`Pulls in outside content that the agent will then act on.`,
    what: msg`The agent is loading external data or instructions to work with.`,
    why_risky: msg`Hidden instructions in that content could redirect what the agent does next.`,
    normal_use: msg`Reading docs or data you pointed it at is normal; unexpected sources are not.`,
    suggested_action: msg`Allow if you recognise the source; otherwise deny.`,
  },
  tamper: {
    summary: msg`Tries to change Belay's or another tool's safety settings.`,
    what: msg`The agent is trying to change Belay's or another tool's safety settings.`,
    why_risky: msg`Turning off these protections could let later harmful actions slip through unnoticed.`,
    normal_use: msg`Almost never. You rarely need an agent to change your security settings.`,
    suggested_action: msg`Deny unless you deliberately asked it to change a security setting.`,
  },
  mcp: {
    summary: msg`One of the agent's tools hides what it actually does behind a vague description.`,
    what: msg`One of the agent's tools is hiding what it actually does behind a vague description.`,
    why_risky: msg`The tool could quietly do something different from what it claims.`,
    normal_use: msg`Well-behaved tools describe themselves clearly; vague ones deserve a second look.`,
    suggested_action: msg`Deny unless you trust the source of this tool.`,
  },
};

// Per-rule-id web overrides (keyed by the FULL dotted id, e.g. "secrets.env_dump").
// The daemon's curated `explain` block is the primary source, so this stays empty
// by default — it is the browser-only extension point when a specific rule needs
// wording that differs from its category fallback.
const RULE_KB: Record<string, CopyMsg> = {};

const GENERIC: CopyMsg = {
  summary: msg`An action that needs your review.`,
  why_risky: msg`Belay flagged this as potentially unsafe.`,
  suggested_action: msg`Deny unless you recognise and expect this action.`,
};

/** Input row shape — a subset of Finding / Pending, transport-agnostic. */
export interface ExplainRow {
  rules: string[];
  explain?: Explain;
  reason?: string;
  severity?: Severity | string;
  category?: string;
}

const isSeverity = (s: unknown): s is Severity =>
  s === "info" || s === "low" || s === "medium" || s === "high" || s === "critical";

/**
 * Resolve the explanation for a row. Precedence:
 *   1. row.explain (daemon-curated, per-rule) — when it has a non-empty summary
 *   2. per-rule-id web override (RULE_KB)
 *   3. category fallback (CATEGORY_FALLBACK)
 *   4. generic default
 * Severity: row.severity if valid, else derived from category, else "medium".
 */
export function explainFor(row: ExplainRow): Explanation {
  const category = resolveCategory(row.category || row.rules?.[0] || "");
  const severity: Severity = isSeverity(row.severity)
    ? row.severity
    : CATEGORY_SEVERITY[category] ?? "medium";

  // 1. Daemon-provided explain wins when it actually carries a summary.
  if (row.explain && row.explain.summary && row.explain.summary.trim()) {
    const e = row.explain;
    return {
      summary: e.summary,
      what: e.what || undefined,
      why_risky: e.why_risky || undefined,
      normal_use: e.normal_use || undefined,
      suggested_action: e.suggested_action || undefined,
      severity,
      category,
    };
  }

  // 2/3/4. Per-rule-id override → category fallback → generic default.
  const copy = RULE_KB[row.rules?.[0] ?? ""] ?? CATEGORY_FALLBACK[category] ?? GENERIC;
  return { ...resolveCopy(copy), severity, category };
}
