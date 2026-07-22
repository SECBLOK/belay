// A little paw print + a walking-paws loader. The dog theme, threaded into the
// quiet moments (loading / empty).

export function Paw({ size = 16, color = "currentColor", className = "", style }: {
  size?: number; color?: string; className?: string; style?: React.CSSProperties;
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill={color} className={className}
      style={style} aria-hidden>
      {/* toe beans */}
      <ellipse cx="6.5" cy="9" rx="2.1" ry="2.7" />
      <ellipse cx="11.4" cy="6.2" rx="2.2" ry="2.9" />
      <ellipse cx="16.6" cy="7.4" rx="2.1" ry="2.7" />
      <ellipse cx="20.3" cy="11.6" rx="1.9" ry="2.4" />
      {/* main pad */}
      <path d="M12.5 12.2c3 0 5.6 2.1 5.6 4.7 0 2.1-1.9 3.3-4 3.3-1 0-1.1-.4-1.9-.4-.8 0-1 .4-1.9.4-2.1 0-4-1.2-4-3.3 0-2.6 3.2-4.7 6.2-4.7z" />
    </svg>
  );
}

// Walking paws — 4 alternating paws that step in sequence.
export function PawLoader({ size = 15, color = "var(--text-tertiary)", label = "Loading" }: {
  size?: number; color?: string; label?: string;
}) {
  return (
    <span className="paw-loader" role="status" aria-label={label}>
      {[0, 1, 2, 3].map((i) => (
        <Paw key={i} size={size} color={color}
          style={{ ["--paw-rot" as string]: i % 2 ? "12deg" : "-12deg" } as React.CSSProperties} />
      ))}
    </span>
  );
}
