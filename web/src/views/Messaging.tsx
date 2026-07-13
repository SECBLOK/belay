import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import {
  getChannels,
  channelAllowRemove,
  channelPairStart,
  setChannel,
  removeChannel,
  setInbound,
  restartDaemon,
  setChannelEnabled,
  openExternalUrl,
  type ChannelsView,
  type PairResult,
} from "../lib/api";

// ── Connector field schema ────────────────────────────────────────────────────
// `key` is the exact config struct field the Rust side merges — EXCEPT two
// specials: "allowedIds" (a comma list parsed into the set_channel `allow` arg,
// which replaces that platform's allowlist) and "slack_signing_secret" (routed
// to set_inbound, not set_channel). secret:true fields render as password inputs,
// are never pre-filled (get_channels never returns secrets), and are omitted from
// the config when left blank so the backend merge keeps the stored value.
type Field = {
  key: string;
  label: string;
  secret?: boolean;
  placeholder?: string;
  hint?: string;
  /** where the value goes on save; default = into the set_channel config */
  target?: "allow" | "inbound";
};

type Connector = {
  id: string;
  label: string;
  kind: "two-way" | "notify";
  guide?: string;
  /** A setup gotcha worth calling out prominently before the fields (e.g. a
   *  required toggle the user must flip elsewhere first). Rendered as a caution
   *  callout, mirroring the CLI wizard's bold pre-token warning. */
  warning?: string;
  /** Static, hardcoded public docs URL — never derived from user input. Opened
   *  via openExternalUrl (OS default browser), never the app's own webview. */
  docsUrl?: string;
  required: Field[];
  recommended: Field[];
  advanced: Field[];
};

const ALLOWED_IDS: Field = {
  key: "allowedIds",
  label: "Add approver IDs",
  target: "allow",
  placeholder: "ids to enroll, comma-separated",
  hint: "Enroll principals allowed to approve from this connector. This only adds; existing approvers are listed and removable under Approvers below.",
};

const CONNECTORS: Connector[] = [
  {
    id: "telegram",
    label: "Telegram",
    kind: "two-way",
    guide: "@BotFather → /newbot for the token; numeric id from @userinfobot.",
    docsUrl: "https://core.telegram.org/bots#how-do-i-create-a-bot",
    required: [{ key: "bot_token", label: "Bot token", secret: true }],
    recommended: [
      { key: "chat_id", label: "Chat ID", placeholder: "Home chat/DM id" },
      ALLOWED_IDS,
    ],
    advanced: [],
  },
  {
    id: "discord",
    label: "Discord",
    kind: "two-way",
    guide: "Discord Developer Portal → app → Bot → token.",
    warning:
      'Enable "Message Content Intent" (Bot → Privileged Gateway Intents) before saving. Without it the bot connects but can\'t read your Allow/Deny replies, so approvals silently do nothing.',
    docsUrl: "https://discord.com/developers/docs/quick-start/getting-started",
    required: [
      { key: "bot_token", label: "Bot token", secret: true },
      { key: "channel_id", label: "Channel ID", placeholder: "a 1:1 DM channel id" },
    ],
    recommended: [ALLOWED_IDS],
    advanced: [],
  },
  {
    id: "whatsapp",
    label: "WhatsApp",
    kind: "two-way",
    guide: "Twilio console → Account SID + Auth Token; from/to are whatsapp: numbers.",
    docsUrl: "https://www.twilio.com/docs/whatsapp/api",
    required: [
      { key: "account_sid", label: "Account SID" },
      { key: "auth_token", label: "Auth token", secret: true },
      { key: "from", label: "From", placeholder: "whatsapp:+1…" },
      { key: "to", label: "To", placeholder: "whatsapp:+1…" },
    ],
    recommended: [ALLOWED_IDS],
    advanced: [],
  },
  {
    id: "matrix",
    label: "Matrix",
    kind: "two-way",
    docsUrl: "https://spec.matrix.org/latest/client-server-api/#login",
    required: [
      { key: "access_token", label: "Access token", secret: true },
      { key: "room_id", label: "Room ID", placeholder: "a 1:1 direct room" },
    ],
    recommended: [{ ...ALLOWED_IDS, placeholder: "@user:server, …" }],
    advanced: [{ key: "base", label: "Homeserver base URL", placeholder: "https://matrix.org" }],
  },
  {
    id: "mattermost",
    label: "Mattermost",
    kind: "two-way",
    docsUrl: "https://developers.mattermost.com/integrate/reference/bot-accounts/",
    required: [
      { key: "token", label: "Token", secret: true },
      { key: "channel_id", label: "Channel ID", placeholder: "a DM channel (type D)" },
      { key: "base", label: "Server URL", placeholder: "https://mattermost.example.com" },
    ],
    recommended: [ALLOWED_IDS],
    advanced: [],
  },
  {
    id: "slack",
    label: "Slack",
    kind: "two-way",
    guide:
      "Slack app → Bot token + Signing Secret; add /hook/slack as the interactivity Request URL behind your TLS proxy.",
    docsUrl: "https://api.slack.com/authentication/basics",
    required: [
      { key: "token", label: "Bot token", secret: true, placeholder: "xoxb-…" },
      { key: "channel", label: "Channel", placeholder: "a DM/user id" },
    ],
    recommended: [ALLOWED_IDS],
    advanced: [
      { key: "base", label: "API base URL" },
      {
        key: "slack_signing_secret",
        label: "Signing secret",
        secret: true,
        target: "inbound",
        hint: "Verifies inbound interactivity callbacks (set on the inbound receiver).",
      },
    ],
  },
  {
    id: "ntfy",
    label: "ntfy",
    kind: "notify",
    docsUrl: "https://docs.ntfy.sh/publish/",
    required: [{ key: "topic", label: "Topic" }],
    recommended: [],
    advanced: [
      { key: "token", label: "Token", secret: true },
      { key: "base", label: "Server URL", placeholder: "https://ntfy.sh" },
    ],
  },
  {
    id: "webhook",
    label: "Webhook",
    kind: "notify",
    // Generic platform — no single public setup guide, matching Hermes leaving
    // docs_url empty for this kind of adapter.
    required: [{ key: "url", label: "URL", placeholder: "https://…" }],
    recommended: [],
    advanced: [],
  },
  {
    id: "teams",
    label: "Microsoft Teams",
    kind: "notify",
    guide: "Teams channel → Connectors → Incoming Webhook.",
    docsUrl:
      "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
    required: [{ key: "webhook_url", label: "Webhook URL", placeholder: "https://…" }],
    recommended: [],
    advanced: [],
  },
  {
    id: "wecom",
    label: "WeCom / 企业微信",
    kind: "notify",
    docsUrl: "https://developer.work.weixin.qq.com/document/path/91770",
    required: [
      {
        key: "webhook_url",
        label: "Webhook URL",
        placeholder: "group-robot URL with key",
      },
    ],
    recommended: [],
    advanced: [],
  },
];

const byId = (id: string) => CONNECTORS.find((c) => c.id === id);
const labelFor = (id: string) => byId(id)?.label ?? id;
const allFields = (c: Connector) => [...c.required, ...c.recommended, ...c.advanced];

// ── Connector badges ──────────────────────────────────────────────────────────
// Small brand-tinted circular glyphs so the connector list is scannable at a
// glance (rather than a plain dot + text). Decorative only, so the brand hex
// values below are a deliberate, narrow exception to the token-only rule —
// tokens.css has no (and shouldn't have) slots for ten fixed platform colors.
// Inline SVG, no external icon library or network fetch, following the same
// function-component/viewBox convention as Sidebar.tsx's nav icons.

function Badge({ bg, size = 20, children }: { bg: string; size?: number; children: ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className="shrink-0">
      <circle cx="12" cy="12" r="12" fill={bg} />
      {children}
    </svg>
  );
}

function LetterBadge({ letter, bg, size }: { letter: string; bg: string; size?: number }) {
  return (
    <Badge bg={bg} size={size}>
      <text x="12" y="16.2" textAnchor="middle" fontSize="10.5" fontWeight={700} fill="#fff">
        {letter}
      </text>
    </Badge>
  );
}

function TelegramIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#29A9EA" size={size}>
      <path
        d="M17.4 7.3 6.9 11.5c-.72.29-.71.7-.13.88l2.68.84 1.03 3.24c.14.36.25.5.5.5.24 0 .35-.1.48-.24l1.4-1.36 2.6 1.92c.48.27.82.13.94-.44l1.72-8.1c.2-.7-.26-1.02-.7-.9Z"
        fill="#fff"
      />
    </Badge>
  );
}

function DiscordIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#5865F2" size={size}>
      <path d="M8.7 8.9c1.9-.85 3.7-.85 5.6 0" stroke="#fff" strokeWidth="1.3" fill="none" strokeLinecap="round" />
      <path d="M7.4 15.1c2.9 1.25 6.3 1.25 9.2 0" stroke="#fff" strokeWidth="1.3" fill="none" strokeLinecap="round" />
      <ellipse cx="9.1" cy="11.6" rx="1.05" ry="1.3" fill="#fff" />
      <ellipse cx="14.9" cy="11.6" rx="1.05" ry="1.3" fill="#fff" />
    </Badge>
  );
}

function WhatsAppIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#25D366" size={size}>
      <path
        d="M12 6.6a5.4 5.4 0 0 0-4.6 8.3l-.7 2.5 2.6-.7A5.4 5.4 0 1 0 12 6.6Z"
        stroke="#fff"
        strokeWidth="1.1"
        fill="none"
      />
      <path
        d="M9.6 9.9c-.13.2-.5.55-.5 1.35 0 .8.5 1.6.6 1.7.1.15 1.2 1.9 3 2.55 1.5.55 1.8.45 2.1.4.3-.05 1-.4 1.15-.8.13-.4.13-.7.1-.8-.04-.1-.15-.15-.35-.24-.2-.1-1.05-.5-1.2-.55-.17-.06-.28-.1-.4.1-.13.2-.47.55-.57.65-.1.1-.2.1-.37.03-.2-.1-.75-.28-1.4-.87-.53-.47-.88-1.04-.98-1.24-.1-.2-.01-.3.08-.4.08-.1.2-.24.28-.36.1-.12.13-.2.2-.32.06-.13.03-.24-.02-.34-.05-.1-.4-.98-.56-1.33-.14-.32-.3-.28-.4-.28h-.32c-.1 0-.28.03-.42.24Z"
        fill="#fff"
      />
    </Badge>
  );
}

function MatrixIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#000000" size={size}>
      <path d="M9.2 6.5H7.4v11h1.8" stroke="#fff" strokeWidth="1.3" fill="none" strokeLinecap="round" />
      <path d="M14.8 6.5h1.8v11h-1.8" stroke="#fff" strokeWidth="1.3" fill="none" strokeLinecap="round" />
      <path d="M11.2 8.2v7.6" stroke="#fff" strokeWidth="1.3" strokeLinecap="round" />
    </Badge>
  );
}

function NtfyIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#2F80ED" size={size}>
      <path
        d="M12 6.6c-1.9 0-3.05 1.4-3.05 3.4 0 2.85-1.15 3.6-1.15 4.25 0 .33.28.38.57.38h7.26c.29 0 .57-.05.57-.38 0-.65-1.15-1.4-1.15-4.25 0-2-1.15-3.4-3.05-3.4Z"
        fill="#fff"
      />
      <path d="M10.7 15.9a1.3 1.3 0 0 0 2.6 0" stroke="#fff" strokeWidth="1" fill="none" strokeLinecap="round" />
    </Badge>
  );
}

function WebhookIcon({ size }: { size?: number }) {
  return (
    <Badge bg="#6B7280" size={size}>
      <path d="M8.3 14.7a2.5 2.5 0 1 1 3.5-3.5" stroke="#fff" strokeWidth="1.4" fill="none" strokeLinecap="round" />
      <path
        d="M9.4 9.3 12.5 6a2.3 2.3 0 1 1 3.3 3.3l-1.6 1.6"
        stroke="#fff"
        strokeWidth="1.4"
        fill="none"
        strokeLinecap="round"
      />
      <path d="M12.7 12 11 13.7" stroke="#fff" strokeWidth="1.4" fill="none" strokeLinecap="round" />
      <circle cx="16.3" cy="16.3" r="1.4" fill="#fff" />
    </Badge>
  );
}

const CONNECTOR_ICON: Record<string, (props: { size?: number }) => ReactElement> = {
  telegram: TelegramIcon,
  discord: DiscordIcon,
  whatsapp: WhatsAppIcon,
  matrix: MatrixIcon,
  mattermost: ({ size }) => <LetterBadge letter="M" bg="#0058CC" size={size} />,
  slack: ({ size }) => <LetterBadge letter="S" bg="#4A154B" size={size} />,
  ntfy: NtfyIcon,
  webhook: WebhookIcon,
  teams: ({ size }) => <LetterBadge letter="T" bg="#5059C9" size={size} />,
  wecom: ({ size }) => <LetterBadge letter="W" bg="#07C160" size={size} />,
};

function ConnectorIcon({ id, size }: { id: string; size?: number }) {
  const C = CONNECTOR_ICON[id];
  if (C) return <C size={size} />;
  return <LetterBadge letter={labelFor(id).charAt(0).toUpperCase()} bg="#8E8E93" size={size} />;
}

// Small muted-tone status pill — mirrors Hermes's SetupPill(active=false)/
// StatePill(tone="muted"). Only ever fed real booleans from the daemon
// (disabled / !configured), never fabricated.
function Pill({ children }: { children: ReactNode }) {
  return (
    <span
      className="inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[0.66rem] font-medium"
      style={{ background: "var(--surface-sunken)", color: "var(--text-secondary)" }}
    >
      {children}
    </span>
  );
}

// Small chevron that rotates 90° open/closed — replaces the old ▸/▾ glyph swap
// (Hermes's DisclosureCaret).
function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="14"
      height="14"
      aria-hidden="true"
      className={`shrink-0 transition-transform duration-150 ${open ? "rotate-90" : "rotate-0"}`}
    >
      <path
        d="M9 6l6 6-6 6"
        stroke="currentColor"
        strokeWidth="2"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ExternalLinkGlyph() {
  return (
    <svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true" className="shrink-0">
      <path
        d="M14 5h5v5M19 5 10 14M18 13v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"
        stroke="currentColor"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// Compact enable/disable switch (Hermes's size="xs" Switch, ported to our
// tokens — accent when on, a neutral hairline-derived track when off). Real:
// callers wire onCheckedChange straight to setChannelEnabled.
function ToggleSwitch({
  checked,
  onCheckedChange,
  disabled,
  label,
}: {
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className="relative inline-flex h-[18px] w-8 shrink-0 items-center rounded-full transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
      style={{ background: checked ? "var(--accent)" : "var(--border-default)" }}
    >
      <span
        aria-hidden="true"
        className="inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform"
        style={{ transform: checked ? "translateX(15px)" : "translateX(2px)" }}
      />
    </button>
  );
}

export default function Messaging() {
  const [view, setView] = useState<ChannelsView | null>(null);
  const [disabled, setDisabled] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ kind: "ok" | "err"; msg: string } | null>(null);
  const [pair, setPair] = useState<PairResult | null>(null);

  const [selected, setSelected] = useState<string>("telegram");
  const [form, setForm] = useState<Record<string, string>>({});
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  // In-flight guards so a fast double-click can't fire duplicate IPC calls.
  const [pairingId, setPairingId] = useState<string | null>(null);
  const [removingKey, setRemovingKey] = useState<string | null>(null);

  const connector = useMemo(() => byId(selected) ?? CONNECTORS[0], [selected]);

  const visibleConnectors = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return CONNECTORS;
    return CONNECTORS.filter((c) => c.id.toLowerCase().includes(q) || c.label.toLowerCase().includes(q));
  }, [query]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getChannels();
      if (r.ok && r.channels) {
        setView(r.channels);
        setDisabled(null);
      } else {
        setView(null);
        // "unknown command" means a daemon IS answering but doesn't have the
        // messaging feature — almost always a second/older Belay install
        // whose daemon grabbed the shared control socket first. Make that
        // actionable instead of cryptic.
        const err = r.error ?? "Messaging is not enabled in this build.";
        setDisabled(
          err === "unknown command"
            ? "A daemon without messaging is answering — usually a second Belay install, or a BELAY_BIN env var pointing at an older/open build. Quit all Belay apps, `unset BELAY_BIN` if set, then relaunch so this build's daemon takes over."
            : err,
        );
      }
    } catch (e) {
      setView(null);
      setDisabled((e as Error)?.message ?? "Could not reach the daemon.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Seed the form ONCE per selected connector, after `view` first loads. We must
  // NOT re-seed on every `view` change: refresh() replaces `view` with a new
  // object after every mutation on the page (save/toggle/removeAllow/pairing), and
  // re-seeding then would silently wipe whatever the user is currently typing into
  // an unrelated field. `seededFor` guards that — save()/removeConnector() reset
  // it to force a deliberate re-seed (blanking secrets, re-reading the allowlist).
  // Every field starts blank. Secrets are blank because the daemon never returns
  // them; the "Add approver IDs" field is blank because it is add-only (the live
  // allowlist is shown, and removed, in the Approvers section below) so it can
  // never sit pre-filled with a personal id or wipe the list on Save.
  const seededFor = useRef<string | null>(null);
  useEffect(() => {
    const c = byId(selected);
    if (!c || !view) return; // wait for the view before seeding
    if (seededFor.current === selected) return; // already seeded this connector
    seededFor.current = selected;
    const next: Record<string, string> = {};
    for (const f of allFields(c)) {
      next[f.key] = "";
    }
    setForm(next);
    setAdvancedOpen(false);
  }, [selected, view]);

  // Pairing modal is aria-modal; honor Escape-to-close (focus is moved into the
  // dialog via autoFocus on its Done button).
  useEffect(() => {
    if (!pair) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPair(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [pair]);

  const flash = (kind: "ok" | "err", msg: string) => {
    setToast({ kind, msg });
    window.setTimeout(() => setToast(null), 3500);
  };

  const setField = (key: string, val: string) =>
    setForm((f) => ({ ...f, [key]: val }));

  const save = async () => {
    const c = connector;
    setSaving(true);
    try {
      // 1. Build the config from non-blank, non-special fields.
      const config: Record<string, unknown> = {};
      let signingSecret: string | null = null;
      let allow: string[] | undefined;
      for (const f of allFields(c)) {
        const raw = (form[f.key] ?? "").trim();
        if (f.target === "allow") {
          // Add-only: union any newly typed ids with the platform's EXISTING
          // approvers, so a Save can never wipe the allowlist (removal happens in
          // the Approvers section). Leave `allow` undefined when nothing was
          // typed, so a pure-config save leaves the allowlist untouched.
          const added = raw
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
          if (added.length > 0) {
            const existing = (view?.allow ?? [])
              .filter((a) => a.platform === c.id)
              .map((a) => a.principal);
            allow = Array.from(new Set([...existing, ...added]));
          }
        } else if (f.target === "inbound") {
          if (raw) signingSecret = raw;
        } else if (raw) {
          config[f.key] = raw;
        }
      }

      // 3. Persist the connector config + allowlist.
      const r = await setChannel(c.id, config, allow);
      if (r && r.ok === false) {
        flash("err", r.error ?? "Save failed");
        return;
      }

      // 4. Inbound receiver secret (Slack interactivity) → set_inbound. Send ONLY
      // this field; the daemon merges it (bind serde-defaults) so a hand-set bind
      // or line_channel_secret is preserved.
      if (signingSecret) {
        const ir = await setInbound({ slack_signing_secret: signingSecret });
        if (ir && ir.ok === false) {
          flash("err", ir.error ?? "Inbound save failed");
          return;
        }
      }

      // 5. Apply — restart the daemon. 6/7. Refresh + toast. Reset the seed
      // guard so the refreshed view re-seeds the form (blanks every field,
      // including the add-only approver box) — a deliberate post-save reset,
      // unlike unrelated refreshes; the new approver now shows under Approvers.
      await restartDaemon();
      seededFor.current = null;
      await refresh();
      flash("ok", "Saved — daemon restarting…");
    } catch (e) {
      flash("err", (e as Error)?.message ?? "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const removeConnector = async () => {
    setSaving(true);
    try {
      const r = await removeChannel(connector.id);
      if (r && r.ok === false) {
        flash("err", r.error ?? "Remove failed");
        return;
      }
      await restartDaemon();
      seededFor.current = null;
      await refresh();
      flash("ok", `Removed ${connector.label} — daemon restarting…`);
    } catch (e) {
      flash("err", (e as Error)?.message ?? "Remove failed");
    } finally {
      setSaving(false);
    }
  };

  // Real per-connector enable/disable (mirrors Hermes's updateMessagingPlatform).
  // Credentials are kept either way; disabling just stops the adapter on the
  // next restart, so we bounce the daemon the same way Save does.
  const toggleEnabled = async (next: boolean) => {
    const id = connector.id;
    setTogglingId(id);
    try {
      const r = await setChannelEnabled(id, next);
      if (r && r.ok === false) {
        flash("err", r.error ?? "Could not update");
        return;
      }
      await restartDaemon();
      await refresh();
      flash("ok", `${next ? "Enabled" : "Disabled"} ${connector.label} — daemon restarting…`);
    } catch (e) {
      flash("err", (e as Error)?.message ?? "Could not update");
    } finally {
      setTogglingId(null);
    }
  };

  const removeAllow = async (platform: string, principal: string) => {
    const key = `${platform}:${principal}`;
    if (removingKey === key) return; // ignore a double-click while in flight
    setRemovingKey(key);
    try {
      const r = await channelAllowRemove(platform, principal);
      if (r.ok) {
        flash("ok", `Removed ${principal} from ${labelFor(platform)}`);
        await refresh();
      } else {
        flash("err", r.error ?? "Remove failed");
      }
    } catch (e) {
      flash("err", (e as Error)?.message ?? "Remove failed");
    } finally {
      setRemovingKey(null);
    }
  };

  const startPair = async (platform: string) => {
    if (pairingId) return; // one pairing request at a time
    setPairingId(platform);
    try {
      const r = await channelPairStart(platform);
      if (r.ok && r.code) {
        setPair(r);
      } else {
        flash("err", r.error ?? "Could not start pairing");
      }
    } catch (e) {
      flash("err", (e as Error)?.message ?? "Could not start pairing");
    } finally {
      setPairingId(null);
    }
  };

  const pairablePlatforms = CONNECTORS.filter(
    (p) => p.kind === "two-way" && view?.adapters?.[p.id],
  );
  const configured = !!view?.adapters?.[connector.id];
  const platformEnabled = !(view?.disabled ?? []).includes(connector.id);

  // ── Field renderer ──────────────────────────────────────────────────────────
  // ListRow-style layout: label (+ optional "Saved" badge) and description on
  // Hermes stacks each field as label -> hint -> full-width input, never
  // side-by-side — matching that exactly instead of a settings-style row.
  const renderField = (f: Field) => {
    const id = `${connector.id}-${f.key}`;
    const isSaved = !!view?.fields_set?.[connector.id]?.includes(f.key);
    return (
      <div key={f.key} className="flex flex-col gap-2">
        <div>
          <span className="flex flex-wrap items-center gap-2">
            <label htmlFor={id} className="text-sm font-semibold text-[var(--text-primary)]">
              {f.label}
            </label>
            {isSaved && (
              <span className="text-[0.66rem] font-medium text-[var(--accent)]">Saved</span>
            )}
          </span>
          {f.hint && <p className="mt-0.5 text-[13px] text-[var(--text-secondary)]">{f.hint}</p>}
        </div>
        <input
          id={id}
          type={f.secret ? "password" : "text"}
          autoComplete="off"
          value={form[f.key] ?? ""}
          onChange={(e) => setField(f.key, e.target.value)}
          placeholder={f.secret ? "leave blank to keep current" : f.placeholder}
          className="w-full rounded-md border border-[var(--border-hairline)] bg-[var(--surface-base)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
        />
      </div>
    );
  };

  const section = (title: string, fields: Field[]) =>
    fields.length === 0 ? null : (
      <div className="flex flex-col gap-4">
        <h3 className="text-[0.7rem] font-semibold uppercase tracking-[0.14em] text-[var(--text-secondary)]">
          {title}
        </h3>
        <div className="flex flex-col gap-5">{fields.map(renderField)}</div>
      </div>
    );

  const docsUrl = connector.docsUrl;

  return (
    <div className="px-8 py-6 max-w-5xl mx-auto text-left">
      <header className="mb-6 pb-5 border-b border-[var(--border-hairline)]">
        <h1 className="text-lg font-semibold text-[var(--text-primary)]">Messaging</h1>
        <p className="text-[13px] text-[var(--text-secondary)] mt-1 max-w-2xl">
          Approve or deny parked actions from a chat app. Two-way channels can approve;
          notify-only channels alert you to approve elsewhere.
        </p>
      </header>

      {loading && <p className="text-sm text-[var(--text-secondary)]">Loading…</p>}

      {!loading && disabled && (
        <div
          className="rounded-lg border border-[var(--border-hairline)] bg-[var(--surface-overlay)] p-5 text-sm text-[var(--text-secondary)]"
          role="status"
        >
          <p className="font-medium text-[var(--text-primary)] mb-1">Messaging is off</p>
          <p>{disabled}</p>
          <p className="mt-2">
            Enable it by running a daemon built with <code>--features channels</code> and adding a{" "}
            <code>~/.belay/channels.json</code> (0600) with your bot credentials.
          </p>
        </div>
      )}

      {!loading && view && (
        <div className="flex flex-col gap-6">
          {/* Master–detail connector setup */}
          <div className="flex flex-col md:flex-row gap-5">
            {/* Left rail: connector list */}
            <nav className="md:w-56 shrink-0">
              <h2 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-secondary)] mb-2">
                Connectors
              </h2>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder='Try "discord"'
                aria-label="Search connectors"
                className="mb-2 w-full rounded-md border border-[var(--border-hairline)] bg-[var(--surface-base)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[var(--accent)]"
              />
              <ul className="flex flex-col gap-0.5">
                {visibleConnectors.map((c) => {
                  const on = !!view.adapters?.[c.id];
                  const active = c.id === selected;
                  return (
                    <li key={c.id}>
                      <button
                        onClick={() => setSelected(c.id)}
                        aria-current={active ? "true" : undefined}
                        className="w-full flex items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors"
                        style={{
                          background: active ? "var(--accent-subtle)" : "transparent",
                          color: active ? "var(--accent)" : "var(--text-primary)",
                        }}
                      >
                        <ConnectorIcon id={c.id} />
                        <span className="truncate font-medium flex-1 min-w-0">{c.label}</span>
                        {on && (
                          <span
                            aria-hidden="true"
                            className="h-1.5 w-1.5 rounded-full shrink-0"
                            style={{ background: "var(--semantic-allow)" }}
                          />
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
              {visibleConnectors.length === 0 && (
                <p className="px-2.5 py-2 text-[12px] text-[var(--text-secondary)]">No connectors match.</p>
              )}
            </nav>

            {/* Right pane: selected connector form. Deliberately BORDERLESS (no
                card box/background) — matches the Hermes reference exactly: the
                detail pane sits flat on the page, separated from the nav rail by
                whitespace alone, structured internally by section labels +
                hairline dividers rather than a bounding box. */}
            <section className="flex-1 min-w-0">
              <div className="flex items-start gap-3 mb-5">
                <ConnectorIcon id={connector.id} size={28} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="min-w-0 truncate text-base font-semibold text-[var(--text-primary)] leading-tight">
                      {connector.label}
                    </h2>
                    {/* Real, always-true-when-shown facts only — no fabricated
                        "gateway stopped" pill (we have no such split). */}
                    {!platformEnabled && <Pill>Disabled</Pill>}
                    {!configured && <Pill>Needs setup</Pill>}
                  </div>
                  <p className="flex items-center gap-1.5 mt-1 text-[11px] text-[var(--text-secondary)]">
                    <span className="inline-flex items-center gap-1.5">
                      <span
                        aria-hidden="true"
                        className="h-1.5 w-1.5 rounded-full shrink-0"
                        style={{
                          background: configured ? "var(--semantic-allow)" : "var(--text-tertiary)",
                        }}
                      />
                      {configured ? "Configured" : "Not set up"}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>{connector.kind === "two-way" ? "Two-way" : "Notify-only"}</span>
                  </p>
                </div>
              </div>

              {connector.warning && (
                <div
                  className="mb-6 rounded-md border px-3.5 py-2.5 text-[13px] leading-snug"
                  role="note"
                  style={{
                    borderColor: "var(--semantic-ask)",
                    background: "color-mix(in srgb, var(--semantic-ask) 10%, transparent)",
                    color: "var(--text-primary)",
                  }}
                >
                  <span className="font-semibold" style={{ color: "var(--semantic-ask)" }}>
                    Before you start:{" "}
                  </span>
                  {connector.warning}
                </div>
              )}

              {(connector.guide || docsUrl) && (
                <div className="mb-6">
                  <h3 className="text-[0.7rem] font-semibold uppercase tracking-[0.14em] text-[var(--text-secondary)] mb-1">
                    Get your credentials
                  </h3>
                  {connector.guide && (
                    <p className="text-[13px] text-[var(--text-secondary)] leading-snug">{connector.guide}</p>
                  )}
                  {docsUrl && (
                    <div className={connector.guide ? "mt-2.5" : ""}>
                      <a
                        href={docsUrl}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => {
                          // Route through the validated external opener instead of
                          // letting the webview resolve the anchor (a packaged
                          // build's relative href would otherwise resolve to a
                          // local file path and fail to open).
                          e.preventDefault();
                          void openExternalUrl(docsUrl);
                        }}
                        className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-[var(--accent)] hover:underline"
                      >
                        Open setup guide
                        <ExternalLinkGlyph />
                      </a>
                    </div>
                  )}
                </div>
              )}

              <div className="flex flex-col gap-6">
                {section("Required", connector.required)}
                {section("Recommended", connector.recommended)}

                {connector.advanced.length > 0 && (
                  <div className="flex flex-col gap-3">
                    <button
                      onClick={() => setAdvancedOpen((o) => !o)}
                      aria-expanded={advancedOpen}
                      aria-controls={`advanced-${connector.id}`}
                      className="flex items-center gap-1.5 text-[0.7rem] font-semibold uppercase tracking-[0.14em] text-[var(--text-secondary)] text-left hover:text-[var(--text-primary)]"
                    >
                      <ChevronIcon open={advancedOpen} />
                      Advanced ({connector.advanced.length})
                    </button>
                    {advancedOpen && (
                      <div id={`advanced-${connector.id}`} className="flex flex-col gap-1">
                        {connector.advanced.map(renderField)}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Docked action bar — Hermes separates this from the fields above
                  with whitespace alone (no hairline), Switch on the left (real
                  enable/disable), Save + Remove on the right. */}
              <div className="flex flex-wrap items-center gap-4 mt-8">
                <div className="flex items-center gap-2">
                  <ToggleSwitch
                    checked={platformEnabled}
                    disabled={togglingId === connector.id}
                    onCheckedChange={(next) => void toggleEnabled(next)}
                    label={`${platformEnabled ? "Disable" : "Enable"} ${connector.label}`}
                  />
                  <span className="text-[13px] font-medium text-[var(--text-primary)]">Enabled</span>
                </div>
                <div className="ml-auto flex items-center gap-4">
                  <button
                    onClick={() => void save()}
                    disabled={saving}
                    className="text-sm font-medium px-4 py-2 rounded-md bg-[var(--accent)] text-white hover:opacity-90 disabled:opacity-50"
                  >
                    {saving ? "Saving…" : "Save changes"}
                  </button>
                  {configured && (
                    <button
                      onClick={() => void removeConnector()}
                      disabled={saving}
                      className="text-[13px] font-medium text-[var(--semantic-deny)] hover:underline disabled:opacity-50"
                    >
                      Remove connector
                    </button>
                  )}
                </div>
              </div>
            </section>
          </div>

          {/* Page-level sections (not per-connector) — deliberately borderless,
              same flat style as the detail pane above, separated by hairline
              top-dividers rather than card boxes. Full width; no left offset,
              since there's no card edge left to align with. */}
          <section className="border-t border-[var(--border-hairline)] pt-6">
            <h2 className="text-base font-semibold text-[var(--text-primary)] mb-2">Inbound receiver</h2>
            {view.inbound ? (
              <p className="text-sm text-[var(--text-secondary)]">
                Listening on <code>{view.inbound.bind}</code> — verifiers:{" "}
                {view.inbound.line ? "Line " : ""}
                {view.inbound.slack ? "Slack" : ""}
                {!view.inbound.line && !view.inbound.slack ? "none" : ""}. Expose it via your TLS
                reverse proxy; callbacks are signature-verified.
              </p>
            ) : (
              <p className="text-sm text-[var(--text-secondary)]">
                Not configured. Two-way webhook platforms (Slack/Line) need the inbound receiver.
              </p>
            )}
          </section>

          {/* Approvers (allowlist) */}
          <section className="border-t border-[var(--border-hairline)] pt-6">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-base font-semibold text-[var(--text-primary)]">Approvers</h2>
              <span className="text-[11px] text-[var(--text-secondary)]">
                {view.allow.length} enrolled · max {view.max_replies_per_min}/min each
              </span>
            </div>
            <p className="text-[13px] text-[var(--text-secondary)] mb-3">
              Approvals are default-deny: only the enrolled principals below can allow or deny alerts.
            </p>
            {view.allow.length === 0 ? (
              <p className="text-sm text-[var(--text-secondary)]">
                No one is enrolled yet. Start a pairing below, then reply <code>pair &lt;code&gt;</code>{" "}
                from the account you want to approve with.
              </p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {view.allow.map((a) => (
                  <li
                    key={`${a.platform}:${a.principal}`}
                    className="flex items-center justify-between rounded-md border border-[var(--border-hairline)] bg-[var(--surface-base)] px-3 py-2"
                  >
                    <span className="text-sm text-[var(--text-primary)] min-w-0 truncate">
                      <span className="text-[var(--text-secondary)]">{labelFor(a.platform)}</span>{" "}
                      · {a.principal}
                    </span>
                    <button
                      onClick={() => void removeAllow(a.platform, a.principal)}
                      disabled={removingKey === `${a.platform}:${a.principal}`}
                      className="text-[12px] font-medium text-[var(--semantic-deny)] hover:underline shrink-0 disabled:opacity-50"
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {/* Pair a new approver */}
          <section className="border-t border-[var(--border-hairline)] pt-6">
            <h2 className="text-base font-semibold text-[var(--text-primary)] mb-2">Pair an approver</h2>
            <p className="text-sm text-[var(--text-secondary)] mb-3">
              Generates a one-time code. The approver DMs <code>pair &lt;code&gt;</code> from the
              account to enroll — the daemon captures their id automatically.
            </p>
            <div className="flex flex-wrap gap-2">
              {pairablePlatforms.map((p) => (
                <button
                  key={p.id}
                  onClick={() => void startPair(p.id)}
                  disabled={pairingId !== null}
                  className="text-sm font-medium px-3 py-1.5 rounded-md bg-[var(--accent-subtle)] text-[var(--accent)] hover:opacity-90 disabled:opacity-50"
                >
                  {pairingId === p.id ? "Starting…" : `Pair via ${p.label}`}
                </button>
              ))}
              {pairablePlatforms.length === 0 && (
                <span className="text-sm text-[var(--text-secondary)]">
                  Configure a two-way connector first.
                </span>
              )}
            </div>
          </section>
        </div>
      )}

      {/* Pairing code modal */}
      {pair && pair.code && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
          role="dialog"
          aria-modal="true"
          onClick={() => setPair(null)}
        >
          <div
            className="bg-[var(--surface-base)] rounded-xl p-6 max-w-sm w-full mx-4 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-base font-semibold text-[var(--text-primary)] mb-1">
              Pair via {labelFor(pair.platform ?? "")}
            </h3>
            <p className="text-sm text-[var(--text-secondary)] mb-4">{pair.instructions}</p>
            <div className="text-center text-2xl font-mono font-bold tracking-[0.3em] text-[var(--accent)] bg-[var(--accent-subtle)] rounded-lg py-3 select-all">
              pair {pair.code}
            </div>
            <button
              autoFocus
              onClick={() => {
                setPair(null);
                void refresh();
              }}
              className="mt-4 w-full text-sm font-medium px-3 py-2 rounded-md bg-[var(--accent)] text-white hover:opacity-90"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && (
        <div
          className="fixed bottom-6 right-6 z-50 rounded-md px-4 py-2.5 text-sm shadow-lg"
          role="status"
          style={{
            background: toast.kind === "ok" ? "var(--semantic-allow)" : "var(--semantic-deny)",
            color: "white",
          }}
        >
          {toast.msg}
        </div>
      )}
    </div>
  );
}
