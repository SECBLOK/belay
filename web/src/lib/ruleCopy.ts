// System B — longer "what this is / what could go wrong" copy keyed by rule
// category, for the approval dialog. The copy now lives in ONE place
// (lib/explain.ts's CATEGORY_FALLBACK); this module is a thin compatibility
// shim so existing `ruleCopyFor(...)` / `RULE_COPY` callers keep working while
// migrating to `explainFor(...)`.

import { CATEGORY_FALLBACK, resolveCategory } from "./explain";
import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";

export interface RuleCopy {
  what: string;
  risk: string;
}

const FALLBACK: RuleCopy = {
  what: i18n._(msg`An action that needs your review`),
  risk: i18n._(msg`Belay flagged this as potentially unsafe.`),
};

// Project a canonical category's 5-field copy down to the legacy {what, risk}
// pair. CATEGORY_FALLBACK now holds translation descriptors, so resolve them to
// the active locale here.
const catCopy = (cat: string): RuleCopy => {
  const c = CATEGORY_FALLBACK[cat];
  return c
    ? { what: c.what ? i18n._(c.what) : FALLBACK.what, risk: c.why_risky ? i18n._(c.why_risky) : FALLBACK.risk }
    : FALLBACK;
};

// Legacy category-keyed table (kept for back-compat; derived from the single
// source above). `exfil`/`persist` mirror the daemon aliases egress/persistence.
export const RULE_COPY: Record<string, RuleCopy> = {
  rce: catCopy("rce"),
  destructive: catCopy("destructive"),
  secrets: catCopy("secrets"),
  exfil: catCopy("egress"),
  persist: catCopy("persist"),
  recon: catCopy("recon"),
  tamper: catCopy("tamper"),
  mcp: catCopy("mcp"),
};

export function ruleCopyFor(ruleIdOrCategory: string): RuleCopy {
  return catCopy(resolveCategory(ruleIdOrCategory ?? ""));
}
