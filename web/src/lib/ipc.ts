// Tauri-backed implementations of the lib/api surface.
// Mirrors the exported names/shapes of lib/api.ts but routes data through the
// native Tauri IPC bridge (invoke/listen) instead of fetch/EventSource.
// lib/api.ts delegates here when running inside the Tauri desktop window.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { PostureSummary, Finding, Explain, AiConfig } from "./api";
import type {
  HostFinding,
  ScanSchedule,
  QuarantineEntry,
  ProposedRuleset,
  FirewallStatus,
  EgressRule,
  EgressMode,
  SshGuardConfig,
  Ban,
  HardeningPosture,
  VulnPosture,
} from "./hostTypes";

export const getPosture = (): Promise<PostureSummary> => invoke("get_posture");
export const getFindings = (): Promise<Finding[]> => invoke("get_findings");
export const getSessions = () => invoke("get_sessions");
export const getEgress = () => invoke("get_egress");

// The daemon's get_pending returns an OBJECT { pending: [ {id,session,tool,...} ] }
// (pending.rs::snapshot). Unwrap to the bare array the api/component layer expects,
// staying fail-safe so the dashboard never breaks if the command is missing/rejects.
export const getPending = (): Promise<any[]> =>
  invoke<{ pending: any[] }>("get_pending")
    .then((r) => r?.pending ?? [])
    .catch(() => []);

// resolve a parked approval. The api.ts caller passes (id, decision); scope is
// optional and defaults to "once" (a single allow/deny, no persistent rule).
export const resolve = (
  id: string,
  decision: "allow" | "deny",
  scope: "once" | "always" = "once",
) => invoke("respond_approval", { id, decision, scope });

// Toggle the daemon-held protection flag (Task 7).
export const setProtection = (on: boolean) => invoke("set_protection", { on });

// A hung `invoke` (e.g. the daemon accepted the connection but never replies —
// `uds::request` has no read timeout) must NOT leave the UI spinning forever.
// Race every AI IPC read against a fallback so the panel always settles into a
// definite state (unavailable / disabled) instead of an infinite "Loading…".
function withTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

/** Whether the daemon has AI explanations enabled. Fail-soft to false. */
export const aiStatus = (): Promise<boolean> =>
  withTimeout(
    invoke<{ ok?: boolean; enabled?: boolean }>("ai_status")
      .then((r) => r?.ok === true && r?.enabled === true)
      .catch(() => false),
    8000,
    false,
  );

/** On-demand AI explanation for a flagged action; null when unavailable. */
export const explainAction = (
  tool: string,
  input: Record<string, unknown>,
  rule?: string,
): Promise<Explain | null> =>
  withTimeout(
    invoke<{ ok?: boolean; explain?: Explain }>("explain_action", { tool, input, rule: rule ?? null })
      .then((r) => (r?.ok === true && r?.explain ? r.explain : null))
      .catch(() => null),
    // The daemon caps the model call at ~20s; allow headroom for cloud latency.
    30000,
    null,
  );

// Shell-out commands — desktop-only, no browser fallback.
export const runScan = (target: string) => invoke("run_scan", { target });
export const listAgents = () => invoke("list_agents");
export const protectAgent = (name: string) => invoke("protect_agent", { name });
export const unprotectAgent = (name: string) => invoke("unprotect_agent", { name });

// Recent audit rows (newest-first) to seed the Live Feed on open. Fail-safe to
// [] so the view still works (just empty until live events arrive).
export const getRecentAudit = (limit = 200): Promise<any[]> =>
  invoke<any[]>("get_recent_audit", { limit }).catch(() => []);

// Subscribe to the live audit feed emitted by the Rust side as "audit-event".
export function streamAudit(onRow: (row: any) => void): () => void {
  const un = listen("audit-event", (e: any) => onRow(e.payload));
  return () => {
    un.then((f) => f());
  };
}

// Richer audit stream mirroring api.ts's openAuditStream lifecycle hooks.
// Returns an EventSource-shaped handle whose close() tears down the Tauri listener.
export function openAuditStream(h: {
  onRow: (row: any) => void;
  onOpen?: () => void;
  onError?: () => void;
}): { close: () => void } {
  const un = listen("audit-event", (e: any) => h.onRow(e.payload));
  if (h.onOpen) un.then(() => h.onOpen!());
  return {
    close: () => {
      un.then((f) => f());
    },
  };
}

// ── Host control IPC wrappers (C1 foundation) ─────────────────────────────────
// Each mirrors the api.ts stub; the Tauri command names use snake_case.

// Host scan
export const runHostScan = (options?: { quick?: boolean }): Promise<{ jobId: string }> =>
  invoke("run_host_scan", { options: options ?? {} });

export const getScanResults = (jobId?: string): Promise<HostFinding[]> =>
  invoke("get_scan_results", { jobId: jobId ?? null });

// Schedule
export const getSchedule = (): Promise<ScanSchedule> =>
  invoke("get_host_scan_schedule");

export const setSchedule = (schedule: ScanSchedule): Promise<void> =>
  invoke("set_host_scan_schedule", { schedule });

// Quarantine
export const listQuarantine = (): Promise<QuarantineEntry[]> =>
  invoke("list_quarantine");

export const restoreQuarantine = (id: string): Promise<void> =>
  invoke("restore_quarantine", { id });

export const deleteQuarantine = (id: string): Promise<void> =>
  invoke("delete_quarantine", { id });

// Firewall
export const getProposedRuleset = (): Promise<ProposedRuleset> =>
  invoke("get_proposed_ruleset");

export const getAutoProposedRuleset = (): Promise<ProposedRuleset> =>
  invoke("get_auto_proposed_ruleset");

export const applyFirewall = (ruleset: ProposedRuleset): Promise<{ revertDeadline: number; handle: string }> =>
  invoke("apply_firewall", { ruleset });

export const confirmFirewall = (handle: string): Promise<void> =>
  invoke("confirm_firewall", { handle });

export const revertFirewall = (handle: string): Promise<void> =>
  invoke("revert_firewall", { handle });

export const getFirewallStatus = (): Promise<FirewallStatus> =>
  invoke("get_firewall_status");

// Egress allowlist
export const getEgressAllowlist = (): Promise<EgressRule[]> =>
  invoke("get_egress_allowlist");

export const addEgressRule = (rule: Omit<EgressRule, "id">): Promise<EgressRule> =>
  invoke("add_egress_rule", { rule });

export const removeEgressRule = (id: string): Promise<void> =>
  invoke("remove_egress_rule", { id });

export const setEgressMode = (mode: EgressMode): Promise<void> =>
  invoke("set_egress_mode", { mode });

export const setInlineEgress = (enabled: boolean): Promise<void> =>
  invoke("set_inline_egress", { enabled });

// Hardening
export const getHardeningPosture = (): Promise<HardeningPosture> =>
  invoke("get_hardening_posture");

// SSH guard
export const getSshGuard = (): Promise<SshGuardConfig> =>
  invoke("get_ssh_guard");

export const setSshGuard = (config: Partial<SshGuardConfig>): Promise<void> =>
  invoke("set_ssh_guard", { config });

export const listBans = (): Promise<Ban[]> =>
  invoke("list_bans");

export const unban = (id: string): Promise<void> =>
  invoke("unban", { id });

// AI explainer settings (feature `ai`, off by default). Raw pass-through —
// lib/api.ts's getAiConfig/setAiConfig do the isTauri() gating + response
// shaping (config unwrap / fail-soft-to-null / fail-soft-to-{ok:false}).
export const getAiConfig = (): Promise<{ ok?: boolean; config?: AiConfig }> =>
  withTimeout(
    invoke<{ ok?: boolean; config?: AiConfig }>("get_ai_config", {}).catch(() => ({})),
    8000,
    {},
  );

export const setAiConfig = (config: AiConfig): Promise<{ ok: boolean; error?: string }> =>
  invoke("set_ai_config", { config });

// Write-only: the daemon stores the key owner-only (0600) on disk and never
// returns it. `key_present` reflects whether a non-empty key ended up stored
// (or, for an empty `key`, that it was cleared).
export const setAiKey = (
  key: string,
): Promise<{ ok: boolean; key_present?: boolean; error?: string }> =>
  invoke<{ ok: boolean; key_present?: boolean; error?: string }>("set_ai_key", { key }).catch(
    () => ({ ok: false }),
  );

// Vulnerability
export const getVulnPosture = (): Promise<VulnPosture> =>
  invoke("get_vuln_posture");

export const scanHostVuln = (): Promise<{ jobId: string }> =>
  invoke("scan_host_vuln");

// ── Network destination enrichment (feature `netenrich`, off by default) ─────
// Display-only owner/ASN/country lookups for egress destinations — never
// gates an allow/deny decision. Raced against a timeout so a hung daemon
// never leaves an allowlist row stuck loading.

export interface Enrichment {
  hostname?: string;
  asn?: string;
  as_name?: string;
  country?: string;
}

/** Enrich a destination (host[:port]); null when disabled/unavailable/failed. */
export const enrichDest = (dest: string): Promise<Enrichment | null> =>
  withTimeout(
    invoke<{ ok?: boolean; enrichment?: Enrichment }>("enrich_dest", { dest })
      .then((r) => (r?.ok && r.enrichment ? r.enrichment : null))
      .catch(() => null),
    8000,
    null,
  );

/** Whether destination enrichment is currently enabled. Fail-soft to false. */
export const getNetEnrich = (): Promise<boolean> =>
  withTimeout(
    invoke<{ ok?: boolean; enabled?: boolean }>("get_net_enrich")
      .then((r) => r?.ok === true && r?.enabled === true)
      .catch(() => false),
    8000,
    false,
  );

/** Toggle destination enrichment on/off. */
export const setNetEnrich = (enabled: boolean): Promise<{ ok: boolean; error?: string }> =>
  invoke<{ ok: boolean; error?: string }>("set_net_enrich", { enabled }).catch(() => ({ ok: false }));

// ── Messaging channels (owner-gated daemon IPC) ──────────────────────────────

export interface ChannelsView {
  max_replies_per_min: number;
  adapters: Record<string, boolean>;
  inbound: { bind: string; line: boolean; slack: boolean } | null;
  allow: { platform: string; principal: string }[];
  /** Platform ids administratively disabled (config kept, adapter paused). */
  disabled: string[];
  /** Per-platform: which of ITS OWN keys currently hold a non-empty value —
   *  booleans only, never the value, so the GUI can show a per-field "Saved"
   *  mark. A platform absent from this map has no fields set. */
  fields_set: Record<string, string[]>;
}
/** Redacted config, or `{ok:false,error}` when channels are disabled/unreachable. */
export interface ChannelsResult {
  ok?: boolean;
  error?: string;
  channels?: ChannelsView;
}
export interface PairResult {
  ok: boolean;
  error?: string;
  code?: string;
  platform?: string;
  instructions?: string;
}

export const getChannels = (): Promise<ChannelsResult> => invoke("get_channels");
export const channelAllowAdd = (platform: string, principal: string): Promise<{ ok: boolean; error?: string }> =>
  invoke("channel_allow_add", { platform, principal });
export const channelAllowRemove = (platform: string, principal: string): Promise<{ ok: boolean; error?: string }> =>
  invoke("channel_allow_remove", { platform, principal });
export const channelPairStart = (platform: string): Promise<PairResult> =>
  invoke("channel_pair_start", { platform });

// Connector setup mutations. `config` carries only the platform's non-blank fields
// (blank secrets are omitted so the backend merge preserves the stored value);
// `allow` — when supplied — replaces that platform's allowlist. restartDaemon
// applies the persisted changes (a ~1s bounce of the daemon process).
export const setChannel = (
  platform: string,
  config: Record<string, unknown>,
  allow?: string[],
): Promise<{ ok: boolean; error?: string }> =>
  invoke("set_channel", { platform, config, ...(allow !== undefined ? { allow } : {}) });
export const removeChannel = (platform: string): Promise<{ ok: boolean; error?: string }> =>
  invoke("remove_channel", { platform });
export const setInbound = (inbound: unknown): Promise<{ ok: boolean; error?: string }> =>
  invoke("set_inbound", { inbound });
export const restartDaemon = (): Promise<{ ok: boolean }> => invoke("restart_daemon", {});

/** Real per-connector enable/disable (credentials kept; applies on next restart). */
export const setChannelEnabled = (platform: string, enabled: boolean): Promise<{ ok: boolean; error?: string }> =>
  invoke("set_channel_enabled", { platform, enabled });

/** Open a URL in the OS default browser (never the app's own webview). Only ever
 *  called with a static, hardcoded https:// reference URL — never user input. */
export const openExternalUrl = (url: string): Promise<void> => invoke("open_external_url", { url });
