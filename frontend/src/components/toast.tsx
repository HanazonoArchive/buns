import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, BellRing, CheckCircle2, Info, X } from "lucide-react";

type Kind = "success" | "error" | "info" | "alert";
interface Toast {
  id: number;
  kind: Kind;
  title: string;
  text?: string;
  action?: { label: string; onClick: () => void };
}

const Ctx = createContext<(t: Omit<Toast, "id">) => void>(() => {});

export const useToast = () => useContext(Ctx);

const ICON = { success: CheckCircle2, error: AlertTriangle, info: Info, alert: BellRing };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const next = useRef(1);

  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const push = useCallback(
    (t: Omit<Toast, "id">) => {
      const id = next.current++;
      setItems((xs) => [...xs.slice(-3), { ...t, id }]);
      window.setTimeout(() => dismiss(id), t.kind === "error" || t.kind === "alert" ? 8000 : 4500);
    },
    [dismiss],
  );

  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => {
          const Icon = ICON[t.kind];
          return (
            <div key={t.id} className={`toast toast-${t.kind}`}>
              <Icon size={18} className="toast-icon" aria-hidden />
              <div className="toast-body">
                <b>{t.title}</b>
                {t.text && <p>{t.text}</p>}
                {t.action && (
                  <button
                    className="link small"
                    onClick={() => {
                      t.action!.onClick();
                      dismiss(t.id);
                    }}
                  >
                    {t.action.label}
                  </button>
                )}
              </div>
              <button className="icon-btn toast-x" onClick={() => dismiss(t.id)} aria-label="Dismiss">
                <X size={15} />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}
