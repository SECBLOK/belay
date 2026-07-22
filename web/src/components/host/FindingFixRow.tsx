// FindingFixRow — displays a hardening check with a humanized label and
// a "How to fix" expander showing the fix detail.

import { useState } from "react";
import type { HardeningCheck } from "../../lib/hostTypes";
import { Trans, useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

// Map raw check IDs to human-readable labels. Falls back to the check's own label.
const HUMANIZED: Record<string, MessageDescriptor> = {
  PermitRootLogin:           msg`Permit Root Login`,
  PasswordAuthentication:    msg`Password Authentication`,
  PermitEmptyPasswords:      msg`Permit Empty Passwords`,
  X11Forwarding:             msg`X11 Forwarding`,
  MaxAuthTries:              msg`Max Auth Tries`,
  Protocol:                  msg`SSH Protocol Version`,
  AllowTcpForwarding:        msg`Allow TCP Forwarding`,
  GatewayPorts:              msg`Gateway Ports`,
  IgnoreRhosts:              msg`Ignore Rhosts`,
  HostbasedAuthentication:   msg`Host-based Authentication`,
  UsePAM:                    msg`PAM Authentication`,
  LoginGraceTime:            msg`Login Grace Time`,
  ClientAliveInterval:       msg`Client Alive Interval`,
  ClientAliveCountMax:       msg`Client Alive Count Max`,
};

const STATUS_STYLE: Record<string, { color: string; label: MessageDescriptor; bg: string }> = {
  pass: { color: "#187D34", label: msg`Pass`,    bg: "rgba(24,125,52,0.06)" },
  fail: { color: "#C8312A", label: msg`Fail`,    bg: "rgba(200,49,42,0.06)" },
  warn: { color: "#916400", label: msg`Warning`, bg: "rgba(145,100,0,0.06)" },
  skip: { color: "#6C6C71", label: msg`Skip`,    bg: "rgba(0,0,0,0.06)" },
};

interface FindingFixRowProps {
  check: HardeningCheck;
}

export default function FindingFixRow({ check }: FindingFixRowProps) {
  const { t } = useLingui();
  const [expanded, setExpanded] = useState(false);

  const humanDesc = HUMANIZED[check.id];
  const humanLabel = humanDesc ? t(humanDesc) : check.label;
  const status = STATUS_STYLE[check.status] ?? STATUS_STYLE.skip;
  const statusLabel = t(status.label);
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
          aria-label={t`Status: ${statusLabel}`}
        >
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: status.color }} aria-hidden />
          {statusLabel}
        </span>

        <span className="text-sm text-[#1C1C1E] font-medium">{humanLabel}</span>

        {hasFix && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-[11px] underline-offset-2 hover:underline"
            style={{ color: "#0856B3" }}
            aria-expanded={expanded}
            aria-label={t`How to fix`}
          >
            <Trans>How to fix</Trans>
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
