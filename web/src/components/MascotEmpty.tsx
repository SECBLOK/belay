import type { ReactNode } from "react";

// A calm, dog-themed empty state — the pup naps when there's nothing to guard.
export default function MascotEmpty({
  pose = "nap", title, children,
}: { pose?: "nap" | "happy" | "alert"; title?: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center gap-2 py-8 px-4">
      <img src={`/mascot/${pose}.png`} alt="" width={96} height={96}
        className="mascot-img"
        style={{ display: "block", filter: "drop-shadow(0 6px 10px rgba(17,24,39,0.14))", opacity: 0.96 }} />
      {title && <div className="text-sm font-medium text-[#1C1C1E] mt-1">{title}</div>}
      {children && <div className="text-xs text-[var(--text-tertiary)] max-w-xs">{children}</div>}
    </div>
  );
}
