// Maps rule-id prefixes (before the first ".") to plain-English labels
// for non-technical users. Never expose raw rule IDs in user-facing copy.
const PREFIX_MAP: Record<string, string> = {
  rce:         "Tried to run system code",
  destructive: "Tried a destructive action (delete/wipe)",
  secrets:     "Tried to read your credentials or passwords",
  egress:      "Tried to send data off your computer",
  persist:     "Tried to install itself permanently",
  persistence: "Tried to install itself permanently",
  recon:       "Scanned your system",
  tamper:      "Tried to change security settings",
  taint:       "Moved sensitive data toward the network/execution",
  mcp:         "Suspicious AI-tool description",
  correlate:   "Combined risky steps in one session",
  bypass:      "Tried to bypass protection",
  posture:     "A security weakness on your computer",
  honeypot:    "Read a decoy secret (canary tripped)",
};

const FALLBACK = "An action that needs your review";

/**
 * Converts a raw daemon verdict token into a plain-English label.
 *   deny  → "Blocked"
 *   ask   → "Waiting"
 *   allow → "Allowed"
 */
export function verdictWord(verdict: string): string {
  if (verdict === "deny") return "Blocked";
  if (verdict === "ask") return "Waiting";
  if (verdict === "allow") return "Allowed";
  // Canary/honeytoken trip: a decoy was READ and detected post-hoc. Deliberately
  // NOT "Blocked" — Belay saw it but did not prevent it (detection-only tier).
  if (verdict === "detected") return "Detected · not blocked";
  return verdict;
}

/**
 * Converts a rule id (e.g. "secrets.aws_credentials") or category prefix
 * (e.g. "secrets") into a plain-English label safe to show non-technical users.
 */
export function humanizeRule(ruleIdOrCategory: string): string {
  if (!ruleIdOrCategory) return FALLBACK;
  const prefix = ruleIdOrCategory.split(".")[0].toLowerCase();
  return PREFIX_MAP[prefix] ?? FALLBACK;
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
  if (/^(npm test|pytest|cargo test|go test)\b/.test(cmd)) return "Ran the tests";
  if (/^(cargo (build|check|run)|npm (run|build)|go build|make)\b/.test(cmd)) return "Ran a build command";
  if (/^git (status|diff|log|branch)\b/.test(cmd)) return "Checked the project's version history";
  if (/^git (add|commit)\b/.test(cmd)) return "Saved a code change to version history";
  if (/^git (fetch|pull)\b/.test(cmd)) return "Downloaded the latest code changes";
  if (/^(ls|find|tree)\b/.test(cmd)) return "Listed files";
  if (/^(cat|less|head|tail)\b/.test(cmd)) return "Read a file";
  if (/^(grep|rg|ag)\b/.test(cmd)) return "Searched the project text";
  if (/^(cd|pwd|echo|which)\b/.test(cmd)) return "Checked the workspace";
  if (/^(mkdir|touch|cp|mv)\b/.test(cmd)) return "Organized project files";
  if (/^docker build\b/.test(cmd)) return "Built a container image";
  if (/^python\b.*\.py\b/.test(cmd) || /^node\b.*\.js\b/.test(cmd)) return "Ran a script";
  return "Ran a command";
}

function describeTool(tool: string | undefined, input?: Record<string, unknown>): string {
  const raw = targetOf(input);
  const file = raw ? truncate(basename(raw)) : "";
  switch (tool) {
    case "Read": return file ? `Read ${file}` : "Read a file";
    case "Write": return file ? `Created ${file}` : "Created a file";
    case "Edit": return file ? `Edited ${file}` : "Edited a file";
    case "Skill": {
      const name = raw ? raw.split(":").pop() ?? raw : "";
      return name ? `Used the ${name} skill` : "Used a skill";
    }
    case "WebFetch": return raw ? `Read a web page (${host(raw)})` : "Read a web page";
    case "WebSearch": return raw ? `Searched the web for "${truncate(raw)}"` : "Searched the web";
    case "Grep": return raw ? `Searched files for "${truncate(raw)}"` : "Searched files";
    case "Glob": return "Listed matching files";
    case "NotebookEdit": return raw ? `Edited a notebook (${truncate(basename(raw))})` : "Edited a notebook";
    case "Bash": return raw ? describeBash(raw) : "Ran a command";
    default: return tool ? `Ran ${cap(tool)}` : "Action";
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
