import { useRef, type KeyboardEvent } from "react";
import { useLingui } from "@lingui/react/macro";
import { msg } from "@lingui/core/macro";
import type { MessageDescriptor } from "@lingui/core";

interface SegmentedNavProps {
  sections: readonly string[];
  active: string;
  onChange: (s: string) => void;
}

// Tab labels, keyed by the section id (which is what drives navigation and the
// active-tab comparison — never the label). Acronyms (AI, SSH) stay full-caps.
// A section with no entry here falls back to a capitalized id, so an unmapped
// section still renders (in English) rather than breaking.
const SECTION_LABEL: Record<string, MessageDescriptor> = {
  overview: msg`Overview`,
  files: msg`Files`,
  skills: msg`Skills`,
  firewall: msg`Firewall`,
  network: msg`Network`,
  ai: msg`AI`,
  ssh: msg`SSH`,
  vulnerabilities: msg`Vulnerabilities`,
};

export default function SegmentedNav({ sections, active, onChange }: SegmentedNavProps) {
  const { t } = useLingui();
  const labelFor = (section: string): string =>
    SECTION_LABEL[section]
      ? t(SECTION_LABEL[section])
      : section[0].toUpperCase() + section.slice(1);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next: number | null = null;
    if (e.key === "ArrowRight") {
      next = (index + 1) % sections.length;
    } else if (e.key === "ArrowLeft") {
      next = (index - 1 + sections.length) % sections.length;
    } else if (e.key === "Home") {
      next = 0;
    } else if (e.key === "End") {
      next = sections.length - 1;
    }
    if (next !== null) {
      e.preventDefault();
      tabRefs.current[next]?.focus();
      onChange(sections[next]);
    }
  };

  return (
    <div
      role="tablist"
      aria-label={t`Host sections`}
      className="flex gap-1 p-1 lg-control"
    >
      {sections.map((section, index) => {
        const isActive = active === section;
        return (
          <button
            key={section}
            role="tab"
            aria-selected={isActive}
            tabIndex={isActive ? 0 : -1}
            ref={(el) => { tabRefs.current[index] = el; }}
            onClick={() => onChange(section)}
            onKeyDown={(e) => handleKeyDown(e, index)}
            className="lg-tap px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
            style={{
              background: isActive ? "var(--lg-fill-hover)" : "transparent",
              color: isActive ? "var(--accent, #6B3DE8)" : "#636366",
              boxShadow: isActive ? "var(--lg-shadow-card)" : "none",
              border: isActive ? "1px solid var(--lg-rim)" : "1px solid transparent",
            }}
          >
            {labelFor(section)}
          </button>
        );
      })}
    </div>
  );
}
