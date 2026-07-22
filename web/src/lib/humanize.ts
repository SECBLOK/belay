import { i18n } from "@lingui/core";
import { msg } from "@lingui/core/macro";
// Maps rule-id prefixes (before the first ".") to plain-English labels
// for non-technical users. Never expose raw rule IDs in user-facing copy.
// Category-prefix labels. Descriptors resolved at call time via the active
// locale, so a language change re-renders them.
import type { MessageDescriptor } from "@lingui/core";
const PREFIX_MAP: Record<string, MessageDescriptor> = {
  rce:         msg`Tried to run system code`,
  destructive: msg`Tried a destructive action (delete/wipe)`,
  secrets:     msg`Tried to read your credentials or passwords`,
  egress:      msg`Tried to send data off your computer`,
  persist:     msg`Tried to install itself permanently`,
  persistence: msg`Tried to install itself permanently`,
  recon:       msg`Scanned your system`,
  tamper:      msg`Tried to change security settings`,
  taint:       msg`Moved sensitive data toward the network/execution`,
  mcp:         msg`Suspicious AI-tool description`,
  correlate:   msg`Combined risky steps in one session`,
  bypass:      msg`Tried to bypass protection`,
  posture:     msg`A security weakness on your computer`,
  honeypot:    msg`Read a decoy secret (canary tripped)`,
};

const FALLBACK = msg`An action that needs your review`;

/**
 * Converts a raw daemon verdict token into a plain-English label.
 *   deny  → "Blocked"
 *   ask   → "Waiting"
 *   allow → "Allowed"
 */
export function verdictWord(verdict: string): string {
  if (verdict === "deny") return i18n._(msg`Blocked`);
  if (verdict === "ask") return i18n._(msg`Waiting`);
  if (verdict === "allow") return i18n._(msg`Allowed`);
  // Canary/honeytoken trip: a decoy was READ and detected post-hoc. Deliberately
  // NOT "Blocked" — Belay saw it but did not prevent it (detection-only tier).
  if (verdict === "detected") return i18n._(msg`Detected · not blocked`);
  return verdict;
}

/**
 * Converts a rule id (e.g. "secrets.aws_credentials") or category prefix
 * (e.g. "secrets") into a plain-English label safe to show non-technical users.
 */
export function humanizeRule(ruleIdOrCategory: string): string {
  if (!ruleIdOrCategory) return i18n._(FALLBACK);
  const prefix = ruleIdOrCategory.split(".")[0].toLowerCase();
  return i18n._(PREFIX_MAP[prefix] ?? FALLBACK);
}

// ── describeAction (System A) ──────────────────────────────────────────────
// Turns a raw audit/finding row into a calm, plain-English phrase describing
// what the agent actually did, never exposing absolute paths, flags, the home
// directory, or raw rule ids.

const MAX_TARGET = 40;

// Mirror the existing target resolution used across the views.
const targetOf = (input?: Record<string, unknown>): string | undefined => {
  const v = input?.command ?? input?.path ?? input?.file_path ?? input?.url;
  return typeof v === "string" ? v : undefined;
};

// Last path segment, e.g. "/a/b/api.ts" → "api.ts".
const basename = (p: string): string => {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : p;
};

// Hostname only from a URL, e.g. "https://docs.rs/serde/?q=x" → "docs.rs".
const host = (u: string): string => {
  try {
    return new URL(u).hostname;
  } catch {
    return u.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0];
  }
};

const truncate = (s: string): string =>
  s.length > MAX_TARGET ? `${s.slice(0, MAX_TARGET - 1)}…` : s;

const cap = (s: string): string => (s ? s[0].toUpperCase() + s.slice(1) : s);

// Friendly verb phrase for a Bash command, matched top-down by leading program.
function describeBash(command: string): string {
  const cmd = command.trim();
  // Tests must be matched before builds (e.g. "cargo test" ≠ build).
  if (/^(npm test|pytest|cargo test|go test)\b/.test(cmd)) return i18n._(msg`Ran the tests`);
  if (/^(cargo (build|check|run)|npm (run|build)|go build|make)\b/.test(cmd)) return i18n._(msg`Ran a build command`);
  if (/^git (status|diff|log|branch)\b/.test(cmd)) return i18n._(msg`Checked the project's version history`);
  if (/^git (add|commit)\b/.test(cmd)) return i18n._(msg`Saved a code change to version history`);
  if (/^git (fetch|pull)\b/.test(cmd)) return i18n._(msg`Downloaded the latest code changes`);
  if (/^(ls|find|tree)\b/.test(cmd)) return i18n._(msg`Listed files`);
  if (/^(cat|less|head|tail)\b/.test(cmd)) return i18n._(msg`Read a file`);
  if (/^(grep|rg|ag)\b/.test(cmd)) return i18n._(msg`Searched the project text`);
  if (/^(cd|pwd|echo|which)\b/.test(cmd)) return i18n._(msg`Checked the workspace`);
  if (/^(mkdir|touch|cp|mv)\b/.test(cmd)) return i18n._(msg`Organized project files`);
  if (/^docker build\b/.test(cmd)) return i18n._(msg`Built a container image`);
  if (/^python\b.*\.py\b/.test(cmd) || /^node\b.*\.js\b/.test(cmd)) return i18n._(msg`Ran a script`);
  return i18n._(msg`Ran a command`);
}

function describeTool(tool: string | undefined, input?: Record<string, unknown>): string {
  const raw = targetOf(input);
  const file = raw ? truncate(basename(raw)) : "";
  switch (tool) {
    case "Read": return file ? i18n._(msg`Read ${file}`) : i18n._(msg`Read a file`);
    case "Write": return file ? i18n._(msg`Created ${file}`) : i18n._(msg`Created a file`);
    case "Edit": return file ? i18n._(msg`Edited ${file}`) : i18n._(msg`Edited a file`);
    case "Skill": {
      const name = raw ? raw.split(":").pop() ?? raw : "";
      return name ? i18n._(msg`Used the ${name} skill`) : i18n._(msg`Used a skill`);
    }
    case "WebFetch": return raw ? i18n._(msg`Read a web page (${host(raw)})`) : i18n._(msg`Read a web page`);
    case "WebSearch": return raw ? i18n._(msg`Searched the web for "${truncate(raw)}"`) : i18n._(msg`Searched the web`);
    case "Grep": return raw ? i18n._(msg`Searched files for "${truncate(raw)}"`) : i18n._(msg`Searched files`);
    case "Glob": return i18n._(msg`Listed matching files`);
    case "NotebookEdit": return raw ? i18n._(msg`Edited a notebook (${truncate(basename(raw))})`) : i18n._(msg`Edited a notebook`);
    case "Bash": return raw ? describeBash(raw) : i18n._(msg`Ran a command`);
    default: return tool ? i18n._(msg`Ran ${cap(tool)}`) : i18n._(msg`Action`);
  }
}

export function describeAction(row: {
  tool?: string;
  verdict?: string;
  reason?: string;
  rules?: string[];
  input?: Record<string, unknown>;
}): string {
  const reason = row.reason?.trim();
  if (reason && reason.toLowerCase() !== "no findings") return reason;
  if (row.rules?.length) return humanizeRule(row.rules[0]);
  return describeTool(row.tool, row.input);
}
