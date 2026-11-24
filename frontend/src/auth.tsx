import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, SIGNED_OUT, type Me } from "./api";

interface AuthState {
  me: Me;
  /** Assessors and the superadmin can change things; viewers only look. */
  canWrite: boolean;
  isSuperadmin: boolean;
  setMe: (me: Me) => void;
  signOut: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}

type Phase = { kind: "loading" } | { kind: "signed-out" } | { kind: "signed-in"; me: Me };

/** Renders `signedOut` until there is a session, then `children` with the account in context. */
export function AuthGate({ children, signedOut }: { children: ReactNode; signedOut: (onSignedIn: (me: Me) => void) => ReactNode }) {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });

  useEffect(() => {
    api.me().then(
      (me) => setPhase({ kind: "signed-in", me }),
      () => setPhase({ kind: "signed-out" }),
    );
    const onGone = () => setPhase({ kind: "signed-out" });
    window.addEventListener(SIGNED_OUT, onGone);
    return () => window.removeEventListener(SIGNED_OUT, onGone);
  }, []);

  // Pick up role or name changes made by the superadmin while this tab is open.
  useEffect(() => {
    if (phase.kind !== "signed-in") return;
    const t = window.setInterval(() => {
      api.me().then((me) => setPhase((p) => (p.kind === "signed-in" && JSON.stringify(p.me) === JSON.stringify(me) ? p : { kind: "signed-in", me })), () => {});
    }, 30000);
    return () => window.clearInterval(t);
  }, [phase.kind]);

  const setMe = useCallback((me: Me) => setPhase({ kind: "signed-in", me }), []);
  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setPhase({ kind: "signed-out" });
    }
  }, []);

  if (phase.kind === "loading") return <div className="boot" aria-busy="true" />;
  if (phase.kind === "signed-out") return <>{signedOut(setMe)}</>;
  const me = phase.me;
  return (
    <Ctx.Provider value={{ me, setMe, signOut, canWrite: me.role !== "viewer", isSuperadmin: me.role === "superadmin" }}>
      {children}
    </Ctx.Provider>
  );
}
