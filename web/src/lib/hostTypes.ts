// Shared types for the Host tab (C1–C7 foundation).
// All sub-views import from here; do not inline these in view files.

// ── Egress mode ───────────────────────────────────────────────────────────────

export type EgressMode = "off" | "monitor" | "enforce";

// ── Host scan ─────────────────────────────────────────────────────────────────

export interface HostFinding {
  id: string;
  path: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  verdict: "malicious" | "suspicious" | "clean";
  reason: string;
  ts: string;
}

export interface ScanSchedule {
  enabled: boolean;
  /** cron expression, e.g. "0 3 * * *" for daily at 03:00 */
  cron: string;
  /** "full" | "quick" */
  scope: "full" | "quick";
}

// ── Quarantine ────────────────────────────────────────────────────────────────

export interface QuarantineEntry {
  id: string;
  original_path: string;
  quarantined_at: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** What was quarantined: an individual file (host malware scan) or a whole
   *  directory (a quarantined agent skill). Absent on older rows → treated as a
   *  file for backward compatibility. */
  kind?: "dir" | "file";
}

// ── Skills ────────────────────────────────────────────────────────────────────

/// One installed agent skill joined with its current scan verdict and
/// baseline-drift state. Wire form emitted by the `list_skills` command
/// (daemon `skills::SkillSummary`); enum strings are skillscan's own lowercase
/// forms.
export interface SkillSummary {
  agent: string;
  name: string;
  /** Absolute path to the skill directory. */
  path: string;
  recommendation: "safe" | "caution" | "donotinstall";
  /** Highest-severity finding, or null when the skill has no findings. */
  severity: "low" | "medium" | "high" | "critical" | null;
  finding_count: number;
  /** unbaselined = never approved; clean = matches approved baseline;
   *  drifted = content changed since approval. */
  drift: "unbaselined" | "clean" | "drifted";
}

// ── Firewall ──────────────────────────────────────────────────────────────────

export interface EgressRule {
  id: string;
  host: string;
  port?: number;
  proto: "tcp" | "udp" | "any";
  action: "allow" | "deny";
  comment?: string;
}

export interface ProposedRuleset {
  /** Human-readable summary of the proposed change */
  description: string;
  rules: EgressRule[];
  /** ISO-8601 timestamp when this proposal was generated */
  generated_at: string;
}

export interface FirewallStatus {
  active: boolean;
  mode: EgressMode;
  /** handle of the currently applied ruleset, if any */
  handle: string | null;
  /** server-side deadline for automatic revert (epoch ms), if a rollback window is active */
  revert_deadline: number | null;
  rule_count: number;
}

// ── SSH guard ─────────────────────────────────────────────────────────────────

export interface SshGuardConfig {
  enabled: boolean;
  max_auth_tries: number;
  ban_threshold: number;
  ban_duration_secs: number;
  permit_root_login: boolean;
}

export interface Ban {
  id: string;
  target: string;
  /** "ip" | "user" */
  kind: "ip" | "user";
  banned_at: string;
  expires_at: string | null;
  reason: string;
}

// ── Hardening ─────────────────────────────────────────────────────────────────

export interface HardeningPosture {
  score: number;
  checks: HardeningCheck[];
}

export interface HardeningCheck {
  id: string;
  label: string;
  status: "pass" | "fail" | "warn" | "skip";
  detail?: string;
}

// ── Vulnerability ─────────────────────────────────────────────────────────────

export interface CveFinding {
  cve_id: string;
  package: string;
  installed_version: string;
  fixed_version: string | null;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  published_at: string;
  /** True if this CVE appears in CISA's Known Exploited Vulnerabilities catalog */
  kev?: boolean;
  /** EPSS probability of exploitation within 30 days [0,1], or null when the
   *  advisory carries no EPSS score (bundled/open DB). */
  epss?: number | null;
}

export interface VulnPosture {
  scanned_at: string | null;
  job_id: string | null;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  findings: CveFinding[];
  /** False when this OS/bundle is not covered (rpm/rolling distros, or a
   *  bundle for a different ecosystem). The UI shows a neutral "not available
   *  on this OS" card instead of a misleading score. */
  supported: boolean;
  /** Human-readable reason when `supported === false`. */
  reason?: string | null;
}
