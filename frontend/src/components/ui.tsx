import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
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

export function Sev({ s, muted }: { s: Severity | ""; muted?: boolean }) {
  if (!s) return <span className="dim">–</span>;
  return (
    <span className={`sev sev-${s}${muted ? " sev-muted" : ""}`}>
      <i aria-hidden />
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

export function ScanTag({ s }: { s: string }) {
  const label = { queued: "Queued", running: "Running", completed: "Completed", failed: "Failed" }[s] ?? s;
  return <span className={`tag tag-scan-${s}`}>{label}</span>;
}

export function PageHead({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function ErrorLine({ msg }: { msg: string }) {
  if (!msg) return null;
  return (
    <p className="error-line" role="alert">
      {msg}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}
