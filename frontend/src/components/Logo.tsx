export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden className="brand-logo">
      <rect width="32" height="32" rx="8" fill="#18233e" />
      <circle cx="11.5" cy="16" r="4.6" fill="#e8edf6" />
      <circle cx="20.5" cy="16" r="4.6" fill="#e8edf6" />
      <circle cx="16" cy="16" r="4.6" fill="#7083f0" />
    </svg>
  );
}
