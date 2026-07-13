import { useRef, type KeyboardEvent } from "react";

interface SegmentedNavProps {
  sections: readonly string[];
  active: string;
  onChange: (s: string) => void;
}

// Tab labels: most sections just need a capitalized first letter, but
// acronyms (AI, SSH) must render as full-caps rather than Title-case
// ("Ai", "Ssh"). Add new acronyms here as they're introduced.
const LABELS: Record<string, string> = {
  ai: "AI",
  ssh: "SSH",
};

const labelFor = (section: string): string =>
  LABELS[section] ?? section[0].toUpperCase() + section.slice(1);

export default function SegmentedNav({ sections, active, onChange }: SegmentedNavProps) {
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
      aria-label="Host sections"
      className="flex gap-1 p-1 rounded-xl"
      style={{ background: "rgba(0,0,0,0.05)", border: "1px solid rgba(0,0,0,0.06)" }}
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
            className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
            style={{
              background: isActive ? "white" : "transparent",
              color: isActive ? "var(--accent, #6B3DE8)" : "#636366",
              boxShadow: isActive ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
              border: isActive ? "1px solid rgba(0,0,0,0.08)" : "1px solid transparent",
            }}
          >
            {labelFor(section)}
          </button>
        );
      })}
    </div>
  );
}
