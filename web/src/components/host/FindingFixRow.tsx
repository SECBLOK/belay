// FindingFixRow — displays a hardening check with a humanized label and
// a "How to fix" expander showing the fix detail.

import { useState } from "react";
import type { HardeningCheck } from "../../lib/hostTypes";

// Map raw check IDs to human-readable labels. Falls back to the check's own label.
const HUMANIZED: Record<string, string> = {
  PermitRootLogin:           "Permit Root Login",
  PasswordAuthentication:    "Password Authentication",
  PermitEmptyPasswords:      "Permit Empty Passwords",
  X11Forwarding:             "X11 Forwarding",
  MaxAuthTries:              "Max Auth Tries",
  Protocol:                  "SSH Protocol Version",
  AllowTcpForwarding:        "Allow TCP Forwarding",
  GatewayPorts:              "Gateway Ports",
  IgnoreRhosts:              "Ignore Rhosts",
  HostbasedAuthentication:   "Host-based Authentication",
  UsePAM:                    "PAM Authentication",
  LoginGraceTime:            "Login Grace Time",
  ClientAliveInterval:       "Client Alive Interval",
  ClientAliveCountMax:       "Client Alive Count Max",
};

const STATUS_STYLE: Record<string, { color: string; label: string; bg: string }> = {
  pass: { color: "#1B8C3A", label: "Pass",    bg: "rgba(27,140,58,0.10)" },
  fail: { color: "#C8312A", label: "Fail",    bg: "rgba(200,49,42,0.10)" },
  warn: { color: "#B27B00", label: "Warning", bg: "rgba(178,123,0,0.10)" },
  skip: { color: "#8E8E93", label: "Skip",    bg: "rgba(0,0,0,0.06)" },
};

interface FindingFixRowProps {
  check: HardeningCheck;
}

export default function FindingFixRow({ check }: FindingFixRowProps) {
  const [expanded, setExpanded] = useState(false);

  const humanLabel = HUMANIZED[check.id] ?? check.label;
  const status = STATUS_STYLE[check.status] ?? STATUS_STYLE.skip;
  const hasFix = !!check.detail;

  return (
    <div
      className="py-3 px-4 border-b last:border-0 space-y-1"
      style={{ borderColor: "rgba(0,0,0,0.08)" }}
    >
      <div className="flex items-center gap-2 flex-wrap">
        {/* Status badge — color + text, never color-only */}
        <span
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide"
          style={{ background: status.bg, color: status.color }}
          aria-label={`Status: ${status.label}`}
        >
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: status.color }} aria-hidden />
          {status.label}
        </span>

        <span className="text-sm text-[#1C1C1E] font-medium">{humanLabel}</span>

        {hasFix && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-[11px] underline-offset-2 hover:underline"
            style={{ color: "#0856B3" }}
            aria-expanded={expanded}
            aria-label="How to fix"
          >
            How to fix
          </button>
        )}
      </div>

      {expanded && check.detail && (
        <p
          className="text-xs text-[#636366] font-mono leading-relaxed pl-1 pt-1"
          style={{ background: "#F5F5F7", borderRadius: 6, padding: "6px 8px" }}
        >
          {check.detail}
        </p>
      )}
    </div>
  );
}
