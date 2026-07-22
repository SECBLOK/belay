import * as ipc from "./ipc";
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
  SkillSummary,
} from "./hostTypes";

// Auto-detect the native Tauri desktop window. When present, every data
// function below routes through the Tauri IPC bridge (lib/ipc) instead of
// HTTP fetch/EventSource — so the views import this module unchanged.
const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const BASE = (import.meta as any).env?.VITE_API ?? "";

// Warn loudly if the dashboard is pointed at a plaintext, non-loopback origin:
// any auth token (Bearer) would then travel in cleartext over the network.
// Same-origin ("") and loopback hosts are fine; remote servers must use https.
if (
  BASE.startsWith("http://") &&
  !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(BASE)
) {
  // eslint-disable-next-line no-console
  console.warn(
    `Belay: VITE_API points at a plaintext origin (${BASE}); auth tokens ` +
      `would be sent in cleartext. Use https:// for any remote server.`,
  );
}

const j = (p: string) => fetch(BASE + p).then((r) => r.json());

// Mutating fetch helper. Sends a JSON body when one is given; throws on a
// non-2xx response so the caller's promise rejects (the UI can surface it).
const jMut = async (method: string, p: string, body?: unknown): Promise<Response> => {
  const r = await fetch(BASE + p, {
    method,
    ...(body !== undefined
      ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }
      : {}),
  });
  if (!r.ok) throw new Error(`${method} ${p} failed: ${r.status}`);
  return r;
};

export interface TrendBucket { bucket: string; allow: number; ask: number; deny: number }
export interface RuleCount { rule_id: string; count: number; category: string }
export interface PostureSummary {
  total: number; allow: number; ask: number; deny: number; score: number;
  by_category: Record<string, number>;
  trend: TrendBucket[];
  top_rules: RuleCount[];
}
export const getPosture = (): Promise<PostureSummary> =>
  isTauri() ? ipc.getPosture() : j("/api/posture");

// Per-session trust grades (get_trust), worst-first. Desktop-only signal; the
// browser console has no daemon socket → empty list.
export interface TrustSession { session: string; grade: string; demerits: number }
export interface TrustSummary { sessions: TrustSession[] }
export const getTrust = (): Promise<TrustSummary> =>
  isTauri() ? ipc.getTrust() : Promise.resolve({ sessions: [] });

// Language. The daemon owns this so the GUI, tray, toast and CLI all agree;
// localStorage would not survive a reinstall and could not reach the tray.
// Outside Tauri (the `serve` dashboard) there is no daemon socket, so this
// reports English rather than pretending a picker would persist.
export interface LocaleState { locale: string; supported: string[] }
export const getLocale = (): Promise<LocaleState> =>
  isTauri() ? ipc.getLocale() : Promise.resolve({ locale: "en", supported: ["en"] });
export const setLocale = (locale: string): Promise<{ ok: boolean; error?: string }> =>
  isTauri()
    ? ipc.setLocale(locale)
    : Promise.resolve({ ok: false, error: "not available outside the desktop app" });

// Boot-start (autostart) state + toggle. Desktop-only: boot-start manages an OS
// service, which the browser (web `serve`) UI cannot do, so it reports
// unsupported there. `setBootStart` triggers an OS elevation prompt in the app.
export interface BootStart { enabled: boolean; supported: boolean }
export const getBootStart = (): Promise<BootStart> =>
  isTauri() ? ipc.getBootStart() : Promise.resolve({ enabled: false, supported: false });
export const setBootStart = (enabled: boolean): Promise<{ ok: boolean; pending: boolean }> =>
  isTauri()
    ? ipc.setBootStart(enabled)
    : Promise.reject(new Error("Start-on-boot is only available in the Belay desktop app."));
// Curated, rule-specific explanation carried from the daemon verdict
// (Explain & Advise). All five fields are authored per-rule in the catalog.
export interface Explain {
  summary: string;
  what: string;
  why_risky: string;
  normal_use: string;
  suggested_action: string;
}
// Winning-rule severity. Defined here in the OPEN portion of this file, above the
// section the open-source export strips, because core components that ship in the
// open build - ApprovalCard, SeverityBadge, explain.ts - import it. Declaring it
// inside that stripped section broke the mirror build (missing export).
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export interface Finding {
  ts: string; event: string; session: string; tool: string;
  verdict: "allow" | "ask" | "deny"; reason: string; rules: string[];
  input?: Record<string, unknown>;
  // Additive Explain & Advise fields (optional: absent on older/open-build rows).
  severity?: Severity;
  category?: string;
  explain?: Explain;
}
export const getFindings = (): Promise<Finding[]> =>
  isTauri() ? ipc.getFindings() : j("/api/findings?limit=1000");
export const getSessions = () =>
  isTauri() ? ipc.getSessions() : j("/api/sessions");
// Both transports resolve to a BARE array of pending entries. The Tauri bridge
// unwraps in lib/ipc; the REST endpoint returns the daemon's { pending: [...] }
// shape, so unwrap it here to keep callers (Sidebar, ApprovalSurface, tray)
// transport-agnostic.
export const getPending = (): Promise<any[]> =>
  isTauri()
    ? ipc.getPending()
    : j("/api/decisions/pending").then((r: any) => r?.pending ?? []);
/// The daemon's reply to `respond_approval`.
///
/// `ok` means the parked request was FOUND and resolved - not that the caller
/// got the decision it asked for. Those differ when the GateGuard self-approval
/// guard overrides an `allow` to `deny`, so `decision` (the effective outcome)
/// is what a caller must render, and `self_approval_blocked` says why it
/// differs from `requested`.
export interface ResolveResult {
  ok: boolean;
  decision?: "allow" | "deny";
  requested?: "allow" | "deny";
  self_approval_blocked?: boolean;
  error?: string;
}
export const resolve = (
  id: string,
  decision: "allow" | "deny",
  scope: "once" | "always" = "once",
): Promise<ResolveResult> =>
  isTauri()
    ? ipc.resolve(id, decision, scope)
    : fetch(`${BASE}/api/decisions/${id}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision, scope }),
      }).then((r) => r.json());
export const getEgress = () =>
  isTauri() ? ipc.getEgress() : j("/api/egress");
// Shell-out commands — only available in the desktop app.
const desktopOnly = (name: string) =>
  Promise.reject(new Error(`${name}: Available in the Belay desktop app`));
export const runScan = (target: string) =>
  isTauri() ? ipc.runScan(target) : desktopOnly("runScan");
export const listAgents = () =>
  isTauri() ? ipc.listAgents() : desktopOnly("listAgents");
export const protectAgent = (name: string) =>
  isTauri() ? ipc.protectAgent(name) : desktopOnly("protectAgent");
export const unprotectAgent = (name: string) =>
  isTauri() ? ipc.unprotectAgent(name) : desktopOnly("unprotectAgent");

// ── Messaging channels (desktop app; owner-gated daemon IPC) ─────────────────
export type { ChannelsView, ChannelsResult, PairResult } from "./ipc";
export const getChannels = (): Promise<ipc.ChannelsResult> =>
  isTauri()
    ? ipc.getChannels()
    : Promise.resolve({ ok: false, error: "Messaging is managed from the Belay desktop app" });
export const channelAllowAdd = (platform: string, principal: string) =>
  isTauri() ? ipc.channelAllowAdd(platform, principal) : desktopOnly("channelAllowAdd");
export const channelAllowRemove = (platform: string, principal: string) =>
  isTauri() ? ipc.channelAllowRemove(platform, principal) : desktopOnly("channelAllowRemove");
export const channelPairStart = (platform: string) =>
  isTauri() ? ipc.channelPairStart(platform) : desktopOnly("channelPairStart");
// Connector setup mutations. Desktop-only for the writes; restartDaemon resolves
// {ok:true} in the browser so the shared save flow degrades cleanly.
export const setChannel = (platform: string, config: Record<string, unknown>, allow?: string[]) =>
  isTauri() ? ipc.setChannel(platform, config, allow) : Promise.resolve({ ok: false, error: "desktop app" });
export const removeChannel = (platform: string) =>
  isTauri() ? ipc.removeChannel(platform) : Promise.resolve({ ok: false, error: "desktop app" });
export const setInbound = (inbound: unknown) =>
  isTauri() ? ipc.setInbound(inbound) : Promise.resolve({ ok: false, error: "desktop app" });
export const restartDaemon = () =>
  isTauri() ? ipc.restartDaemon() : Promise.resolve({ ok: true });
export const setChannelEnabled = (platform: string, enabled: boolean) =>
  isTauri() ? ipc.setChannelEnabled(platform, enabled) : Promise.resolve({ ok: false, error: "desktop app" });
// Best-effort in the browser (no Tauri opener available): fall back to window.open.
export const openExternalUrl = (url: string) =>
  isTauri() ? ipc.openExternalUrl(url) : Promise.resolve(void window.open(url, "_blank", "noopener,noreferrer"));
export function streamAudit(onRow: (row: any) => void): () => void {
  if (isTauri()) return ipc.streamAudit(onRow);
  const es = new EventSource(BASE + "/api/stream");
  es.addEventListener("audit", (e: MessageEvent) => onRow(JSON.parse(e.data)));
  return () => es.close();
}
// Snapshot of recent audit rows (newest-first) to seed the live Timeline on
// open, so the feed isn't blank until the next event lands. Desktop-only;
// browsers have no recent-audit endpoint, so fall back to an empty snapshot.
export function getRecentAudit(limit = 200): Promise<any[]> {
  if (isTauri()) return ipc.getRecentAudit(limit);
  return Promise.resolve([]);
}
// Approval-provenance rows (approval.resolved/respond) for the Alerts feed.
// Desktop-only store; the browser console has no endpoint → empty snapshot.
export function getRecentApprovals(limit = 200): Promise<any[]> {
  if (isTauri()) return ipc.getRecentApprovals(limit);
  return Promise.resolve([]);
}
// Richer audit stream exposing connection lifecycle, for the live Timeline view.
export function openAuditStream(h: { onRow: (row: any) => void; onOpen?: () => void; onError?: () => void }): EventSource {
  // Under Tauri this is an EventSource-shaped handle (only .close() is used by callers).
  if (isTauri()) return ipc.openAuditStream(h) as unknown as EventSource;
  const es = new EventSource(BASE + "/api/stream");
  es.addEventListener("audit", (e: MessageEvent) => h.onRow(JSON.parse(e.data)));
  if (h.onOpen) es.onopen = h.onOpen;
  if (h.onError) es.onerror = h.onError;
  return es;
}

// ── Host control API (C1 foundation stubs) ────────────────────────────────────
// Read-only queries go via j("/api/…") with an isTauri() fast-path;
// host-mutating operations are desktop-only (require the Tauri IPC bridge).

// Host scan. In the browser this POSTs to the server, which runs the malware
// scan synchronously and returns the findings directly (piece 1 has no job
// A host scan returns both the findings and HOW MANY files were scanned, so the
// UI can show "scanned N files — no threats" (a clean scan is otherwise
// indistinguishable from a no-op). The Tauri path returns a {jobId, scanned}
// handle then reads the cached findings; the browser path gets both from the
// POST response (degrading `scanned` to the finding count on an older server).
export interface HostScanResult { findings: HostFinding[]; scanned: number }
export const runHostScan = async (options?: { quick?: boolean }): Promise<HostScanResult> => {
  if (isTauri()) {
    const { scanned } = await ipc.runHostScan(options);
    const findings = await ipc.getScanResults();
    return { findings, scanned: scanned ?? findings.length };
  }
  const res = await fetch(BASE + "/api/host/scan", { method: "POST" }).then((r) => r.json());
  const findings: HostFinding[] = Array.isArray(res) ? res : (res.findings ?? []);
  const scanned = Array.isArray(res) ? findings.length : (res.scanned ?? findings.length);
  return { findings, scanned };
};

export const getScanResults = (jobId?: string): Promise<HostFinding[]> =>
  isTauri() ? ipc.getScanResults(jobId) : j(`/api/host/scan/results${jobId ? `?jobId=${jobId}` : ""}`);

// Schedule
export const getSchedule = (): Promise<ScanSchedule> =>
  isTauri() ? ipc.getSchedule() : j("/api/host/scan/schedule");

export const setSchedule = (schedule: ScanSchedule): Promise<void> =>
  isTauri()
    ? ipc.setSchedule(schedule)
    : fetch(`${BASE}/api/host/scan/schedule`, {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify(schedule),
      }).then(() => undefined);

// Quarantine
export const listQuarantine = (): Promise<QuarantineEntry[]> =>
  isTauri() ? ipc.listQuarantine() : j("/api/host/quarantine");

export const restoreQuarantine = (id: string): Promise<void> =>
  isTauri()
    ? ipc.restoreQuarantine(id)
    : jMut("POST", `/api/host/quarantine/${encodeURIComponent(id)}/restore`).then(() => undefined);

export const deleteQuarantine = (id: string): Promise<void> =>
  isTauri()
    ? ipc.deleteQuarantine(id)
    : jMut("DELETE", `/api/host/quarantine/${encodeURIComponent(id)}`).then(() => undefined);

// Skills — a desktop-only (host) surface. The hosted web console has no skills
// route, so the browser fallback resolves empty rather than hitting a 404.
export const listSkills = (): Promise<SkillSummary[]> =>
  isTauri() ? ipc.listSkills() : Promise.resolve([]);

export const approveSkill = (path: string): Promise<string[]> =>
  isTauri() ? ipc.approveSkill(path) : Promise.resolve([]);

// Firewall
export const getProposedRuleset = (): Promise<ProposedRuleset> =>
  isTauri() ? ipc.getProposedRuleset() : j("/api/host/firewall/proposed");

// One-click auto setup: auto-detect the system and return a pre-filled proposal.
export const getAutoProposedRuleset = (): Promise<ProposedRuleset> =>
  isTauri() ? ipc.getAutoProposedRuleset() : j("/api/host/firewall/auto-proposed");

export const applyFirewall = (ruleset: ProposedRuleset): Promise<{ revertDeadline: number; handle: string }> =>
  isTauri()
    ? ipc.applyFirewall(ruleset)
    : jMut("POST", "/api/host/firewall/apply", ruleset).then((r) => r.json());

export const confirmFirewall = (handle: string): Promise<void> =>
  isTauri()
    ? ipc.confirmFirewall(handle)
    : jMut("POST", "/api/host/firewall/confirm", { handle }).then(() => undefined);

export const revertFirewall = (handle: string): Promise<void> =>
  isTauri()
    ? ipc.revertFirewall(handle)
    : jMut("POST", "/api/host/firewall/revert", { handle }).then(() => undefined);

export const getFirewallStatus = (): Promise<FirewallStatus> =>
  isTauri() ? ipc.getFirewallStatus() : j("/api/host/firewall/status");

// Egress allowlist
export const getEgressAllowlist = (): Promise<EgressRule[]> =>
  isTauri() ? ipc.getEgressAllowlist() : j("/api/host/egress/allowlist");

export const addEgressRule = (rule: Omit<EgressRule, "id">): Promise<EgressRule> =>
  isTauri()
    ? ipc.addEgressRule(rule)
    : jMut("POST", "/api/host/egress/allowlist", rule).then((r) => r.json());

export const removeEgressRule = (id: string): Promise<void> =>
  isTauri()
    ? ipc.removeEgressRule(id)
    : jMut("DELETE", `/api/host/egress/allowlist/${encodeURIComponent(id)}`).then(() => undefined);

export const setEgressMode = (mode: EgressMode): Promise<void> =>
  isTauri()
    ? ipc.setEgressMode(mode)
    : jMut("PUT", "/api/host/egress/mode", { mode }).then(() => undefined);

export const setInlineEgress = (enabled: boolean): Promise<void> =>
  isTauri()
    ? ipc.setInlineEgress(enabled)
    : jMut("PUT", "/api/host/egress/inline", { enabled }).then(() => undefined);

// Hardening
export const getHardeningPosture = (): Promise<HardeningPosture> =>
  isTauri() ? ipc.getHardeningPosture() : j("/api/host/hardening");

// SSH guard
export const getSshGuard = (): Promise<SshGuardConfig> =>
  isTauri() ? ipc.getSshGuard() : j("/api/host/ssh-guard");

export const setSshGuard = (config: Partial<SshGuardConfig>): Promise<void> =>
  isTauri()
    ? ipc.setSshGuard(config)
    : fetch(`${BASE}/api/host/ssh-guard`, {
        method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify(config),
      }).then(() => undefined);

export const listBans = (): Promise<Ban[]> =>
  isTauri() ? ipc.listBans() : j("/api/host/ssh-guard/bans");

export const unban = (id: string): Promise<void> =>
  isTauri()
    ? ipc.unban(id)
    : jMut("DELETE", `/api/host/ssh-guard/bans/${encodeURIComponent(id)}`).then(() => undefined);

// ── AI explainer settings (feature `ai`, off by default; desktop-only) ────────
// There is NO server HTTP route for AI config — the daemon socket the settings
// panel talks to is local-only, so the browser (non-Tauri) build has nothing to
// call. Both wrappers fail soft rather than throw: getAiConfig -> null (renders
// as "unavailable"), setAiConfig -> {ok:false} (renders as a save error).

export type AiMode = "off" | "local" | "cloud";

/** A read-only per-provider model suggestion, injected into get_ai_config by the
 *  daemon (crate::ai::recommend). `null` for a provider we haven't researched. */
export interface AiRecommendation {
  fast: string;
  recommended_judge: string;
  note: string;
}

/** AI explainer config. Never carries a secret — the cloud key resolves from
 *  the daemon's `BELAY_AI_KEY` env var (if set) or else an owner-only
 *  (0600) key file the operator can populate in-app; `key_present` just
 *  flags whether either source currently holds a non-empty key, so the
 *  settings panel can hint at it without ever seeing (or round-tripping)
 *  the key itself. */
export interface AiConfig {
  mode: AiMode;
  provider: string;
  model: string;
  base_url: string | null;
  cloud_consent: boolean;
  key_present?: boolean;
  // Per-task model routing (spec: AI model routing). null/omitted = inherit the
  // global `model`. The daemon's from_args treats a null/absent value as "no
  // override" — see daemon/src/ai/config.rs.
  explain_model?: string | null;
  skill_judge_model?: string | null;
  // LLM skill judge, both off by default. skill_judge_enabled = background
  // watcher path; skill_judge_gate_enabled = synchronous install-gate.
  skill_judge_enabled?: boolean;
  skill_judge_gate_enabled?: boolean;
  // Read-only: populated by get_ai_config, never sent back on save.
  recommendations?: AiRecommendation | null;
}

export const getAiConfig = (): Promise<AiConfig | null> =>
  isTauri()
    ? ipc
        .getAiConfig()
        .then((r) => (r?.ok === true && r.config ? r.config : null))
        .catch(() => null)
    : Promise.resolve(null);

export const setAiConfig = (config: AiConfig): Promise<{ ok: boolean; error?: string }> =>
  isTauri()
    ? ipc.setAiConfig(config).catch(() => ({ ok: false, error: "ipc failed" }))
    : Promise.resolve({ ok: false, error: "desktop only" });

/** Save (or, with an empty string, clear) the BYOK cloud API key. Write-only
 *  — see `AiConfig.key_present` above; the key itself is never read back. */
export const setAiKey = (
  key: string,
): Promise<{ ok: boolean; key_present?: boolean; error?: string }> =>
  isTauri()
    ? ipc.setAiKey(key).catch(() => ({ ok: false, error: "ipc failed" }))
    : Promise.resolve({ ok: false, error: "desktop only" });

// Vulnerability
export const getVulnPosture = (): Promise<VulnPosture> =>
  isTauri() ? ipc.getVulnPosture() : j("/api/host/vuln");

export const scanHostVuln = (): Promise<{ jobId: string }> =>
  isTauri()
    ? ipc.scanHostVuln()
    : jMut("POST", "/api/host/vuln/scan").then((r) => r.json());

// ── Network destination enrichment (desktop app; feature `netenrich`) ────────
// Display-only owner/ASN/country chip for egress destinations. Browser
// (non-Tauri) has no daemon socket to call, so these degrade gracefully.
export type { Enrichment } from "./ipc";

export const enrichDest = (dest: string): Promise<ipc.Enrichment | null> =>
  isTauri() ? ipc.enrichDest(dest) : Promise.resolve(null);

export const getNetEnrich = (): Promise<boolean> =>
  isTauri() ? ipc.getNetEnrich() : Promise.resolve(false);

export const setNetEnrich = (enabled: boolean): Promise<{ ok: boolean; error?: string }> =>
  isTauri() ? ipc.setNetEnrich(enabled) : Promise.resolve({ ok: false, error: "desktop only" });
