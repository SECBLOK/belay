import { describeAction } from "../lib/humanize";
import { extractEgressDest } from "../lib/egressDest";
import DestOwner from "./host/DestOwner";

const ACCENT: Record<string, string> = {
  deny: "var(--status-blocked)", ask: "var(--status-action)", allow: "var(--status-protected)",
};
const hhmm = (ts: string) => { const d = new Date(ts); return Number.isNaN(+d) ? "--:--" : d.toTimeString().slice(0, 5); };

export default function ActivityFeed({ rows }: { rows: any[] }) {
  const sorted = [...rows].sort((a, b) => (a.ts < b.ts ? 1 : -1));
  return (
    <div className="flex flex-col">
      {sorted.map((r, i) => {
        const dest = extractEgressDest(r);
        return (
          <div key={r.hash ?? i} data-testid="feed-row"
            className="tl-enter flex items-center gap-3 h-11 px-3 border-b border-[var(--separator)]">
            <span data-testid="verdict-bar" className="self-stretch w-[3px] rounded"
              style={{ background: ACCENT[r.verdict] ?? "var(--separator)" }} />
            <span className="text-text-secondary text-mono tabular w-12">{hhmm(r.ts)}</span>
            <span className="text-text-primary text-body w-16">{r.tool}</span>
            <span className="text-text-secondary truncate flex-1" title={describeAction(r)}>{describeAction(r)}</span>
            {dest && <DestOwner dest={dest} />}
          </div>
        );
      })}
    </div>
  );
}
