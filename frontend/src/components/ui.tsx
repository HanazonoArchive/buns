import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, type LucideIcon } from "lucide-react";
import { SEVERITY_LABEL, type ReviewStatus, type Severity } from "../api";

export function usePoll<T>(load: () => Promise<T>, deps: unknown[], keepPolling: (v: T) => boolean, every = 1500) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string>("");
  const timer = useRef<number>();
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    window.clearTimeout(timer.current);
    try {
      const v = await load();
      if (!alive.current) return;
      setData(v);
      setError("");
      if (keepPolling(v)) timer.current = window.setTimeout(refresh, every);
    } catch (e) {
      if (alive.current) setError((e as Error).message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    alive.current = true;
    refresh();
    return () => {
      alive.current = false;
      window.clearTimeout(timer.current);
    };
  }, [refresh]);

  return { data, error, refresh, setData };
}

export function Sev({ s, size = "md" }: { s: Severity | ""; size?: "sm" | "md" | "lg" }) {
  if (!s) return <span className="dim">–</span>;
  return (
    <span className={`badge sev-${s} badge-${size}`}>
      <i aria-hidden className="dot" />
      {SEVERITY_LABEL[s]}
    </span>
  );
}

const STATUS_TEXT: Record<ReviewStatus, string> = {
  pending: "Needs review",
  confirmed: "Confirmed",
  rejected: "False positive",
};

export function ReviewTag({ s }: { s: ReviewStatus }) {
  return <span className={`tag tag-${s}`}>{STATUS_TEXT[s]}</span>;
}

export function ScanTag({ s, progress }: { s: string; progress?: number }) {
  const label = { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed" }[s] ?? s;
  return (
    <span className={`tag tag-scan-${s}`}>
      {s === "running" && <i className="pulse" aria-hidden />}
      {label}
      {s === "running" && progress !== undefined && <span className="tag-extra">{progress}%</span>}
    </span>
  );
}

export function PageHead({ title, sub, actions, kicker }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; kicker?: ReactNode }) {
  return (
    <header className="page-head">
      <div className="page-head-text">
        {kicker && <div className="kicker">{kicker}</div>}
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  icon: Icon,
  actions,
  children,
  className = "",
  flush,
}: {
  title?: ReactNode;
  icon?: LucideIcon;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section className={`panel ${flush ? "panel-flush" : ""} ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          <h2>
            {Icon && <Icon size={16} strokeWidth={2} aria-hidden />}
            {title}
          </h2>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function ErrorLine({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <p className="error-line" role="alert">
      <AlertCircle size={16} aria-hidden />
      <span>{msg}</span>
    </p>
  );
}

export function Empty({ icon: Icon, title, children, action }: { icon?: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      {Icon && (
        <span className="empty-icon">
          <Icon size={22} strokeWidth={1.75} aria-hidden />
        </span>
      )}
      <h3>{title}</h3>
      {children && <div className="empty-text">{children}</div>}
      {action}
    </div>
  );
}

export function Field({ label, hint, children, error }: { label: string; hint?: ReactNode; children: ReactNode; error?: string }) {
  return (
    <label className={`field${error ? " has-error" : ""}`}>
      <span className="field-label">{label}</span>
      {children}
      {error ? <span className="field-error">{error}</span> : hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

export function Skeleton({ rows = 4, height = 18 }: { rows?: number; height?: number }) {
  return (
    <div className="skeleton" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} style={{ height, width: `${92 - ((i * 17) % 35)}%` }} />
      ))}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} className={`switch${checked ? " on" : ""}`} onClick={() => onChange(!checked)}>
      <i />
    </button>
  );
}
