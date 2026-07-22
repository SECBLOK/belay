// Small muted chip that shows an egress destination's owner/ASN/country,
// lazily fetched via the daemon's (display-only, feature `netenrich`) enrich
// IPC. Renders nothing while loading or when enrichment is unavailable — it
// must never introduce layout shift or spinner noise into a table row.
import { useEffect, useRef, useState } from "react";
import { enrichDest } from "../../lib/api";
import type { Enrichment } from "../../lib/api";

// Module-level cache so the same destination isn't re-fetched across rows or
// re-renders (an allowlist table can repeat the same host across rows, and
// StrictMode/re-mounts must not multiply lookups).
const cache = new Map<string, Enrichment | null>();
// Dedupe concurrent lookups for the same not-yet-cached dest (e.g. two rows
// for the same host mounting in the same tick) so enrichDest is called once.
const inflight = new Map<string, Promise<Enrichment | null>>();

function getEnrichment(dest: string): Promise<Enrichment | null> {
  if (cache.has(dest)) return Promise.resolve(cache.get(dest) ?? null);
  let pending = inflight.get(dest);
  if (!pending) {
    pending = enrichDest(dest).then((result) => {
      cache.set(dest, result);
      inflight.delete(dest);
      return result;
    });
    inflight.set(dest, pending);
  }
  return pending;
}

interface Props {
  dest: string;
}

export default function DestOwner({ dest }: Props) {
  const [enrichment, setEnrichment] = useState<Enrichment | null>(
    cache.has(dest) ? cache.get(dest) ?? null : null,
  );
  // Unmount guard: the fetch can resolve after the row/component is gone
  // (table re-render, view navigation) — the post-await setState must no-op.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    getEnrichment(dest).then((result) => {
      if (mountedRef.current) setEnrichment(result);
    });
  }, [dest]);

  if (!enrichment) return null;

  const parts: string[] = [];
  if (enrichment.hostname) parts.push(enrichment.hostname);
  if (enrichment.asn) {
    parts.push(`AS${enrichment.asn}${enrichment.as_name ? ` ${enrichment.as_name}` : ""}`);
  }
  if (enrichment.country) parts.push(enrichment.country);

  if (parts.length === 0) return null;

  return (
    <span
      className="text-xs text-[var(--text-tertiary)]"
      title="network owner"
      aria-label="network owner"
    >
      {parts.join(" · ")}
    </span>
  );
}
