// A labelled toggle for enforcement mode controls.
// role="switch" + aria-checked satisfies WCAG 4.1.2.
// Defaults to OFF (detect-first) when the parent provides checked=false.

interface EnforcementToggleProps {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}

export default function EnforcementToggle({
  label,
  checked,
  onChange,
  disabled = false,
}: EnforcementToggleProps) {
  const handleClick = () => {
    if (!disabled) onChange(!checked);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === " " || e.key === "Enter") {
      e.preventDefault();
      if (!disabled) onChange(!checked);
    }
  };

  return (
    <div className="flex items-center gap-3">
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        className="relative inline-flex shrink-0 h-6 w-11 rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent,#6B3DE8)] focus-visible:ring-offset-1 disabled:opacity-40 disabled:cursor-not-allowed"
        style={{
          background: checked ? "var(--accent, #6B3DE8)" : "rgba(0,0,0,0.15)",
        }}
      >
        <span
          className="inline-block h-5 w-5 m-0.5 rounded-full bg-white transition-transform shadow-sm"
          style={{ transform: checked ? "translateX(20px)" : "translateX(0)" }}
          aria-hidden
        />
      </button>
      <span
        className="text-sm font-medium select-none"
        style={{ color: disabled ? "#8E8E93" : "#1C1C1E" }}
      >
        {label}
      </span>
    </div>
  );
}
