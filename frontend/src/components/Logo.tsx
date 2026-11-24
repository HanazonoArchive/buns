/** The buns mark: a "b" inside a scanner's corner bracket. */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden className="brand-logo">
      <rect width="32" height="32" rx="9" fill="#4256e3" />
      <path d="M10.5 6.5v19" stroke="#fff" strokeWidth="3.8" strokeLinecap="round" />
      <circle cx="17" cy="19" r="5.6" fill="none" stroke="#fff" strokeWidth="3.8" />
      <path d="M21 6.5h4.5V11" fill="none" stroke="#a9b4ff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
