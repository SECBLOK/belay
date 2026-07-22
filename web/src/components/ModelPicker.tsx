// The "C+" model control (spec §3.2): a segmented Inherit / Recommended / Custom
// selector. The "Recommended" segment appears ONLY when the `recommended` prop is
// set — that single prop difference is what makes the Explanations row (no
// recommendation) and the Skill Judge row (recommendation + "why") the same
// component (spec §3.3). Emits null for Inherit; the parent maps null → drop the
// per-task override (inherit the global model).
import { useEffect, useRef, useState } from "react";
import { useLingui } from "@lingui/react/macro";

type Segment = "inherit" | "recommended" | "custom";

interface ModelPickerProps {
  value: string | null;
  inherited: string;
  recommended?: string;
  note?: string;
  label: string;
  onChange: (next: string | null) => void;
}

// Derive which segment a value corresponds to. null/"" is Inherit; an exact
// match of the recommended id is Recommended (only when one is offered);
// anything else is a Custom value the field should show verbatim.
function segmentFor(value: string | null, recommended?: string): Segment {
  if (value === null || value === "") return "inherit";
  if (recommended && value === recommended) return "recommended";
  return "custom";
}

export default function ModelPicker({
  value,
  inherited,
  recommended,
  note,
  label,
  onChange,
}: ModelPickerProps) {
  const { t } = useLingui();
  const [seg, setSeg] = useState<Segment>(segmentFor(value, recommended));
  const customRef = useRef<HTMLInputElement | null>(null);
  // Keep the active segment in sync if the parent replaces `value` (e.g. after a
  // provider switch changes the recommended id under us).
  useEffect(() => {
    setSeg((prev) => {
      // Don't yank the user out of Custom just because the field is momentarily
      // empty (they clicked Custom or backspaced the input) — an empty Custom
      // value only means "inherit" on save, not while editing.
      if (prev === "custom" && (value === "" || value === null)) return "custom";
      return segmentFor(value, recommended);
    });
  }, [value, recommended]);
  useEffect(() => {
    if (seg === "custom") customRef.current?.focus();
  }, [seg]);

  const pick = (next: Segment) => {
    setSeg(next);
    if (next === "inherit") onChange(null);
    else if (next === "recommended" && recommended) onChange(recommended);
    else if (next === "custom") onChange(value && value !== recommended ? value : "");
  };

  const segBtn = (key: Segment, text: string) => {
    const active = seg === key;
    return (
      <button
        key={key}
        type="button"
        role="radio"
        aria-checked={active}
        onClick={() => pick(key)}
        className="px-3 py-1 rounded-lg text-xs font-medium transition-colors"
        style={{
          background: active ? "white" : "transparent",
          color: active ? "var(--accent)" : "#636366",
          boxShadow: active ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
          border: active ? "1px solid rgba(0,0,0,0.08)" : "1px solid transparent",
        }}
      >
        {text}
      </button>
    );
  };

  return (
    <div className="space-y-1.5">
      <div
        role="radiogroup"
        aria-label={label}
        className="inline-flex gap-1 p-1 rounded-xl"
        style={{ background: "rgba(0,0,0,0.05)", border: "1px solid rgba(0,0,0,0.06)" }}
      >
        {segBtn("inherit", t`Inherit (${inherited})`)}
        {recommended ? segBtn("recommended", t`Recommended`) : null}
        {segBtn("custom", t`Custom…`)}
      </div>
      {seg === "custom" && (
        <input
          type="text"
          ref={customRef}
          aria-label={t`${label} custom id`}
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t`Enter model id`}
          className="w-full bg-white rounded-lg text-sm text-[#1C1C1E] px-3 py-2 outline-none"
          style={{ border: "1px solid rgba(0,0,0,0.14)" }}
        />
      )}
      {note && <p className="text-xs text-[var(--text-tertiary)]">{note}</p>}
    </div>
  );
}
