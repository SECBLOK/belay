// KevBadge — loud chip for CISA Known Exploited Vulnerabilities.
// Red fill + text "Exploited in the wild". Color is never the only signal.

export default function KevBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold"
      style={{ background: "#C8312A", color: "#fff" }}
      aria-label="Known Exploited Vulnerability: Exploited in the wild"
    >
      <span className="w-1.5 h-1.5 rounded-full bg-white shrink-0" aria-hidden />
      Exploited in the wild
    </span>
  );
}
