import { useState, type FormEvent } from "react";
import { KeyRound } from "lucide-react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useToast } from "./toast";

const MIN = 8;

/** Forced on first sign-in (no way out but changing it or signing out); optional from the account menu. */
export function ChangePassword({ forced, onClose }: { forced?: boolean; onClose?: () => void }) {
  const { me, setMe, signOut } = useAuth();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const mismatch = again.length > 0 && again !== next;
  const tooShort = next.length > 0 && next.length < MIN;
  const ready = current && next.length >= MIN && next === again && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError("");
    try {
      const updated = await api.changePassword(current, next);
      toast({ kind: "success", title: "Password changed", text: "Any other browser signed in as you was signed out." });
      setMe(updated);
      onClose?.();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => !forced && e.target === e.currentTarget && onClose?.()}>
      <form className="modal pw-modal" role="dialog" aria-modal="true" aria-labelledby="pw-title" onSubmit={submit}>
        <header className="modal-head">
          <div className="pw-head">
            <span className="pw-icon"><KeyRound size={18} /></span>
            <div>
              <h2 id="pw-title">{forced ? "Choose your own password" : "Change password"}</h2>
              <p className="dim small">
                {forced
                  ? `${me.email} is still using the password it was given. Replace it before you continue.`
                  : `Signed in as ${me.email}.`}
              </p>
            </div>
          </div>
        </header>
        <div className="modal-body pw-body">
          <label className="field">
            <span className="field-label">{forced ? "Password you signed in with" : "Current password"}</span>
            <input type="password" autoComplete="current-password" autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">New password</span>
            <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} aria-invalid={tooShort} />
            <span className={tooShort ? "field-error" : "field-hint"}>At least {MIN} characters. Not your email, and not the old one.</span>
          </label>
          <label className="field">
            <span className="field-label">Type it again</span>
            <input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} aria-invalid={mismatch} />
            {mismatch && <span className="field-error">The two passwords are different.</span>}
          </label>
          {error && <p className="login-error" role="alert">{error}</p>}
        </div>
        <footer className="modal-foot">
          {forced ? (
            <button type="button" className="btn" onClick={() => void signOut()}>Sign out</button>
          ) : (
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
          )}
          <button className="btn btn-primary" disabled={!ready}>{busy ? "Saving…" : "Save password"}</button>
        </footer>
      </form>
    </div>
  );
}
