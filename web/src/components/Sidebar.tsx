import { useEffect, useState, type ReactElement, type ReactNode } from "react";
import { getPosture, getPending } from "../lib/api";
import type { PostureSummary } from "../lib/api";

type Tab =
  | "posture" | "findings" | "timeline" | "scan" | "agents" | "host" | "ai" | "messaging"
 ;

interface SidebarProps {
  tab: Tab;
  onNavigate: (t: Tab) => void;
}

// ─── inline SVG icons (18px viewBox 0 0 24 24, stroke-based) ─────────────────

function IconOverview({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  );
}

function IconActivity({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

function IconLiveFeed({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49" />
      <path d="M7.76 7.76a6 6 0 0 0 0 8.49" />
      <path d="M20.07 4.93a10 10 0 0 1 0 14.14" />
      <path d="M3.93 4.93a10 10 0 0 0 0 14.14" />
    </svg>
  );
}

function IconScan({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2" />
      <path d="M17 3h2a2 2 0 0 1 2 2v2" />
      <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
      <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
      <line x1="3" y1="12" x2="21" y2="12" />
    </svg>
  );
}

function IconAgents({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <path d="M8 21h8" />
      <path d="M12 17v4" />
    </svg>
  );
}


// Shield with a host/computer symbol — represents Host Protection.
function IconHost({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      {/* outer shield */}
      <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2Z" />
      {/* inner computer screen */}
      <rect x="8.5" y="8" width="7" height="5" rx="0.75" />
      <path d="M10 13v1.5M14 13v1.5M9.5 14.5h5" />
    </svg>
  );
}

// Chat bubble — represents Messaging (approve from a chat app).
function IconMessaging({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
    </svg>
  );
}

// Chat bubble with a small sparkle — represents AI Explanations.
function IconAi({ active }: { active: boolean }) {
  const col = active ? "var(--accent)" : "#8E8E93";
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={col} strokeWidth={active ? 2 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 10.5a7.5 7.5 0 0 1-11.2 6.5L3 18l1.2-3.6a7.5 7.5 0 1 1 15.8-3.9z" />
      <path d="M17 3.5l.6 1.4 1.4.6-1.4.6-.6 1.4-.6-1.4-1.4-.6 1.4-.6.6-1.4z" fill={col} stroke="none" />
    </svg>
  );
}


function BrandLogo() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <defs>
        <clipPath id="brandLogoClip">
          <path
            fillRule="evenodd"
            clipRule="evenodd"
            d="M6,4 L15,4 L18,8 L14,11 L18,13 L19,17 L15,20 L6,20 Z
               M9,7 L13,7 L15.5,9.3 L13,11.5 L9,11.5 Z
               M9,12.5 L13,12.5 L16,15.3 L13,18 L9,18 Z"
          />
        </clipPath>
      </defs>
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        fill="#084EA8"
        d="M6,4 L15,4 L18,8 L14,11 L18,13 L19,17 L15,20 L6,20 Z
           M9,7 L13,7 L15.5,9.3 L13,11.5 L9,11.5 Z
           M9,12.5 L13,12.5 L16,15.3 L13,18 L9,18 Z"
      />
      <polygon points="4,3 20,3 20,11 4,15" fill="#0A66D6" clipPath="url(#brandLogoClip)" />
    </svg>
  );
}

// ─── status helpers (mirrors TrayPopover logic) ───────────────────────────────

type StatusState = "protected" | "monitoring" | "action" | "blocked";

function deriveStatus(posture: PostureSummary | null): StatusState {
  if (!posture) return "protected";
  const score = posture.score ?? 100;
  const deny = posture.deny ?? 0;
  const ask = posture.ask ?? 0;
  if (deny > 0 || score < 60) return "action";
  if (ask > 0) return "monitoring";
  return "protected";
}

const STATUS_META: Record<StatusState, { color: string; label: string }> = {
  protected:  { color: "var(--semantic-allow)", label: "Protected"     },
  monitoring: { color: "var(--semantic-info)",  label: "Monitoring"    },
  action:     { color: "var(--semantic-ask)",   label: "Action needed" },
  blocked:    { color: "var(--semantic-deny)",  label: "Blocked"       },
};

// ─── nav config ──────────────────────────────────────────────────────────────

interface NavItem {
  tab: Tab;
  label: string;
  Icon: (props: { active: boolean }) => ReactElement;
}

const PRIMARY_NAV: NavItem[] = [
  { tab: "posture",   label: "Overview",    Icon: IconOverview  },
  { tab: "findings",  label: "Activity",    Icon: IconActivity  },
  { tab: "timeline",  label: "Live Feed",   Icon: IconLiveFeed  },
];

const TOOLS_NAV: NavItem[] = [
  { tab: "scan",   label: "Scan",   Icon: IconScan   },
  { tab: "agents", label: "Agents", Icon: IconAgents },
];


const PROTECTION_NAV: NavItem[] = [
  { tab: "host", label: "Host Protection", Icon: IconHost },
  { tab: "ai", label: "AI Explanations", Icon: IconAi },
  { tab: "messaging", label: "Messaging", Icon: IconMessaging },
];


// ─── main component ───────────────────────────────────────────────────────────

export default function Sidebar({ tab, onNavigate }: SidebarProps) {
  const [posture, setPosture]         = useState<PostureSummary | null>(null);
  const [pendingCount, setPendingCount] = useState(0);
  const [collapsed, setCollapsed]     = useState(false);

  // collapse when window is narrow (guard: jsdom / older browsers may lack matchMedia)
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(max-width: 699px)");
    const handler = (e: MediaQueryListEvent) => setCollapsed(e.matches);
    setCollapsed(mq.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // fetch posture + pending (resilient, never throws — mirrors TrayPopover)
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const p = await getPosture();
        if (!cancelled) setPosture(p);
      } catch {
        // non-fatal
      }
      try {
        const pending = await getPending();
        if (!cancelled) setPendingCount(Array.isArray(pending) ? pending.length : 0);
      } catch {
        // non-fatal
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const statusState = deriveStatus(posture);
  const { color: statusColor, label: statusLabel } = STATUS_META[statusState];
  const hasDeny = (posture?.deny ?? 0) > 0;

  const w = collapsed ? "w-14" : "w-[220px]";

  return (
    <aside
      className={`${w} shrink-0 flex flex-col h-screen bg-[var(--surface-overlay)] border-r border-[rgba(0,0,0,0.08)] transition-[width] duration-200 overflow-hidden`}
    >
      {/* identity */}
      <div className={`flex items-center gap-2.5 px-3 py-4 ${collapsed ? "justify-center" : ""}`}>
        <BrandLogo />
        {!collapsed && (
          <span className="font-semibold text-[15px] text-[#0A66D6] whitespace-nowrap">Belay</span>
        )}
      </div>

      {/* nav */}
      <nav className="flex-1 flex flex-col gap-0.5 overflow-y-auto py-1">
        {/* primary group — no label */}
        {PRIMARY_NAV.map(({ tab: t, label, Icon }) => {
          const active = tab === t;
          const showDot = t === "timeline" && !active && hasDeny;
          return (
            <NavRow
              key={t}
              active={active}
              label={label}
              collapsed={collapsed}
              onClick={() => onNavigate(t)}
              dot={showDot}
              aria-current={active ? "page" : undefined}
            >
              <Icon active={active} />
            </NavRow>
          );
        })}

        {/* tools group — separated by a subtle hairline, no label */}
        <GroupSeparator collapsed={collapsed} />
        {TOOLS_NAV.map(({ tab: t, label, Icon }) => {
          const active = tab === t;
          return (
            <NavRow
              key={t}
              active={active}
              label={label}
              collapsed={collapsed}
              onClick={() => onNavigate(t)}
              aria-current={active ? "page" : undefined}
            >
              <Icon active={active} />
            </NavRow>
          );
        })}


        {/* protection group — host hardening, firewall, SSH guard, vuln scan */}
        <GroupSeparator collapsed={collapsed} />
        {PROTECTION_NAV.map(({ tab: t, label, Icon }) => {
          const active = tab === t;
          return (
            <NavRow
              key={t}
              active={active}
              label={label}
              collapsed={collapsed}
              onClick={() => onNavigate(t)}
              aria-current={active ? "page" : undefined}
            >
              <Icon active={active} />
            </NavRow>
          );
        })}

      </nav>

      {/* status footer */}
      <button
        onClick={() => onNavigate("posture")}
        className={`flex items-center gap-2.5 mx-2 mb-3 px-3 py-2.5 rounded-md hover:bg-[rgba(0,0,0,0.04)] transition-colors text-left ${collapsed ? "justify-center" : ""}`}
        title={collapsed ? `${statusLabel}${pendingCount > 0 ? ` · ${pendingCount} pending` : ""}` : undefined}
      >
        {/* colored dot */}
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{ background: statusColor }}
        />
        {!collapsed && (
          <span className="flex flex-col min-w-0">
            <span className="text-sm font-medium text-[#1C1C1E] leading-tight truncate">{statusLabel}</span>
            <span
              className="text-[11px] leading-tight"
              style={{ color: pendingCount > 0 ? "var(--semantic-ask)" : "#8E8E93" }}
            >
              {pendingCount > 0 ? `${pendingCount} action${pendingCount > 1 ? "s" : ""} pending` : "0 pending"}
            </span>
          </span>
        )}
      </button>
    </aside>
  );
}

// ─── sub-components ───────────────────────────────────────────────────────────

interface NavRowProps {
  active: boolean;
  label: string;
  collapsed: boolean;
  onClick: () => void;
  children: ReactNode;
  dot?: boolean;
  "aria-current"?: "page" | undefined;
}

function NavRow({ active, label, collapsed, onClick, children, dot, "aria-current": ariaCurrent }: NavRowProps) {
  return (
    <div className="relative mx-2">
      <button
        onClick={onClick}
        aria-current={ariaCurrent}
        title={collapsed ? label : undefined}
        className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors
          ${active
            ? "bg-[var(--accent-subtle)] text-[var(--accent)]"
            : "text-[#636366] hover:bg-[rgba(0,0,0,0.04)] hover:text-[#1C1C1E]"
          }
          ${collapsed ? "justify-center" : ""}
        `}
      >
        {children}
        {!collapsed && <span>{label}</span>}
      </button>
      {dot && (
        <span
          className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full"
          style={{ background: "var(--semantic-ask)" }}
          aria-label="new deny events"
        />
      )}
    </div>
  );
}

// Subtle group divider that replaces the old uppercase section labels:
// a faint inset hairline + small breathing room when expanded; just space
// when the sidebar is collapsed to icons-only.
function GroupSeparator({ collapsed }: { collapsed: boolean }) {
  if (collapsed) return <div className="h-2" aria-hidden />;
  return (
    <div className="my-1.5 mx-4 border-t border-[rgba(0,0,0,0.06)]" aria-hidden />
  );
}
