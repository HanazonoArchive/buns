import { useEffect, useRef, useState } from "react";
import { KeyRound, LogOut } from "lucide-react";
import { initials, ROLE_LABEL } from "../api";
import { useAuth } from "../auth";
import { ChangePassword } from "./ChangePassword";

export function UserMenu() {
  const { me, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const [changing, setChanging] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  return (
    <div className="user-menu" ref={ref}>
      <button className="user-btn" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-haspopup="menu">
        <span className={`avatar role-${me.role}`}>{initials(me.name)}</span>
        <span className="user-btn-text">
          <span className="user-name">{me.name}</span>
          <span className={`user-role role-${me.role}`}>{ROLE_LABEL[me.role]}</span>
        </span>
      </button>
      {open && (
        <div className="user-pop" role="menu">
          <div className="user-pop-head">
            <span className={`avatar avatar-lg role-${me.role}`}>{initials(me.name)}</span>
            <div>
              <div className="strong">{me.name}</div>
              <div className="dim small">{me.email}</div>
              <div className="user-pop-meta">
                <span className={`user-role role-${me.role}`}>{ROLE_LABEL[me.role]}</span>
                {me.custom_id && <span className="dim small">ID <span className="mono">{me.custom_id}</span></span>}
              </div>
            </div>
          </div>
          <button role="menuitem" className="user-pop-item" onClick={() => { setOpen(false); setChanging(true); }}>
            <KeyRound size={15} /> Change password
          </button>
          <button role="menuitem" className="user-pop-item" onClick={() => void signOut()}>
            <LogOut size={15} /> Sign out
          </button>
        </div>
      )}
      {changing && <ChangePassword onClose={() => setChanging(false)} />}
    </div>
  );
}
