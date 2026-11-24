import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Check, Copy, KeyRound, Pencil, RefreshCw, Trash2, UserPlus, UsersRound } from "lucide-react";
import { ago, api, initials, ROLE_HELP, ROLE_LABEL, temporaryPassword, type Account, type Role } from "../api";
import { useAuth } from "../auth";
import { Modal } from "../components/Modal";
import { useToast } from "../components/toast";
import { Empty, ErrorLine, Field, PageHead, Skeleton } from "../components/ui";

type Assignable = Exclude<Role, "superadmin">;

function RolePicker({ value, onChange }: { value: Assignable; onChange: (r: Assignable) => void }) {
  return (
    <div className="role-pick" role="radiogroup" aria-label="Role">
      {(["assessor", "viewer"] as const).map((r) => (
        <label key={r} className={`role-opt role-${r} ${value === r ? "on" : ""}`}>
          <input type="radio" name="role" checked={value === r} onChange={() => onChange(r)} />
          <span className={`user-role role-${r}`}>{ROLE_LABEL[r]}</span>
          <span className="dim small">{ROLE_HELP[r]}</span>
        </label>
      ))}
    </div>
  );
}

function PasswordField({ value, onChange, label = "Temporary password" }: { value: string; onChange: (v: string) => void; label?: string }) {
  return (
    <Field label={label} hint="They sign in with this once, then must choose their own.">
      <span className="pw-input">
        <input className="mono" value={value} onChange={(e) => onChange(e.target.value)} autoComplete="off" spellCheck={false} />
        <button type="button" className="icon-btn" title="Generate another" aria-label="Generate another password" onClick={() => onChange(temporaryPassword())}>
          <RefreshCw size={15} />
        </button>
      </span>
    </Field>
  );
}

/** Shown once after creating an account or resetting a password, so the superadmin can pass it on. */
function Handover({ account, password, onClose }: { account: Account; password: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = `buns sign-in\nURL: ${window.location.origin}\nEmail: ${account.email}\nTemporary password: ${password}\nYou will be asked to choose your own password after signing in.`;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      /* clipboard blocked; the text is selectable */
    }
  };
  return (
    <Modal title={`Sign-in details for ${account.name}`} onClose={onClose} footer={<button className="btn btn-primary" onClick={onClose}>Done</button>}>
      <p className="dim small">Send these through your usual channel. The password is not shown again; reset it if it gets lost.</p>
      <pre className="handover">{text}</pre>
      <button className="btn btn-sm" onClick={copy}>
        {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy details"}
      </button>
    </Modal>
  );
}

function NewUser({ onClose, onCreated }: { onClose: () => void; onCreated: (a: Account, pw: string) => void }) {
  const [form, setForm] = useState({ name: "", email: "", role: "assessor" as Assignable, custom_id: "", password: temporaryPassword() });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr("");
    try {
      onCreated(await api.createUser(form), form.password);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Add a user"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy || !form.name.trim() || !form.email.trim()} onClick={() => submit()}>Create account</button>
        </>
      }
    >
      <form onSubmit={submit} className="form-grid">
        <Field label="Complete name">
          <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Juan Dela Cruz" autoComplete="off" />
        </Field>
        <div className="form-pair">
          <Field label="Email" hint="They sign in with this.">
            <input type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="juan@school.edu" autoComplete="off" />
          </Field>
          <Field label="Custom ID" hint="Optional. Employee or student ID.">
            <input className="mono" value={form.custom_id} onChange={(e) => setForm({ ...form, custom_id: e.target.value })} placeholder="2022-00417" autoComplete="off" />
          </Field>
        </div>
        <div className="field">
          <span className="field-label">Role</span>
          <RolePicker value={form.role} onChange={(role) => setForm({ ...form, role })} />
        </div>
        <PasswordField value={form.password} onChange={(password) => setForm({ ...form, password })} />
        <ErrorLine msg={err} />
        <button hidden />
      </form>
    </Modal>
  );
}

function EditUser({ account, onClose, onSaved }: { account: Account; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({ name: account.name, custom_id: account.custom_id, role: account.role as Assignable });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const isAdmin = account.role === "superadmin";

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    try {
      await api.updateUser(account.id, isAdmin ? { name: form.name, custom_id: form.custom_id } : form);
      onSaved();
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Edit ${account.name}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy || !form.name.trim()} onClick={() => submit()}>Save changes</button>
        </>
      }
    >
      <form onSubmit={submit} className="form-grid">
        <Field label="Email" hint="The sign-in email cannot be changed. Delete and re-create the account instead.">
          <input value={account.email} disabled />
        </Field>
        <div className="form-pair">
          <Field label="Complete name">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </Field>
          <Field label="Custom ID" hint="Optional.">
            <input className="mono" value={form.custom_id} onChange={(e) => setForm({ ...form, custom_id: e.target.value })} />
          </Field>
        </div>
        {isAdmin ? (
          <p className="dim small">The superadmin role is fixed to {account.email}.</p>
        ) : (
          <div className="field">
            <span className="field-label">Role</span>
            <RolePicker value={form.role} onChange={(role) => setForm({ ...form, role })} />
            <span className="field-hint">Takes effect right away; they do not need to sign in again.</span>
          </div>
        )}
        <ErrorLine msg={err} />
        <button hidden />
      </form>
    </Modal>
  );
}

function ResetPassword({ account, onClose, onDone }: { account: Account; onClose: () => void; onDone: (a: Account, pw: string) => void }) {
  const [password, setPassword] = useState(temporaryPassword());
  const [err, setErr] = useState("");
  const submit = async () => {
    try {
      onDone(await api.resetPassword(account.id, password), password);
    } catch (ex) {
      setErr((ex as Error).message);
    }
  };
  return (
    <Modal
      title={`Reset password for ${account.name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit}>Reset password</button>
        </>
      }
    >
      <div className="form-grid">
        <p className="dim small">Signs them out everywhere. They must choose a new password the next time they sign in.</p>
        <PasswordField value={password} onChange={setPassword} label="New temporary password" />
        <ErrorLine msg={err} />
      </div>
    </Modal>
  );
}

export default function Users() {
  const { me } = useAuth();
  const toast = useToast();
  const [rows, setRows] = useState<Account[] | null>(null);
  const [err, setErr] = useState("");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Account | null>(null);
  const [resetting, setResetting] = useState<Account | null>(null);
  const [handover, setHandover] = useState<{ account: Account; password: string } | null>(null);

  const load = useCallback(() => api.users().then(setRows, (e) => setErr(e.message)), []);
  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (a: Account) => {
    try {
      await api.updateUser(a.id, { active: !a.active });
      toast({ kind: "success", title: a.active ? `${a.name} disabled` : `${a.name} enabled`, text: a.active ? "They were signed out." : undefined });
      void load();
    } catch (ex) {
      toast({ kind: "error", title: "Could not change status", text: (ex as Error).message });
    }
  };

  const remove = async (a: Account) => {
    if (!window.confirm(`Delete the account of ${a.name} (${a.email})? Their past reviews keep their name.`)) return;
    try {
      await api.deleteUser(a.id);
      toast({ kind: "success", title: `${a.name} deleted` });
      void load();
    } catch (ex) {
      toast({ kind: "error", title: "Could not delete", text: (ex as Error).message });
    }
  };

  return (
    <>
      <PageHead
        title="Users"
        sub="Who can sign in to buns, and what they are allowed to do."
        actions={
          <button className="btn btn-primary" onClick={() => setAdding(true)}>
            <UserPlus size={16} /> Add user
          </button>
        }
      />
      <ErrorLine msg={err} />
      {!rows ? (
        <Skeleton rows={4} />
      ) : rows.length <= 1 ? (
        <>
          <UserTable rows={rows} me={me.id} onEdit={setEditing} onReset={setResetting} onToggle={toggle} onDelete={remove} />
          <Empty icon={UsersRound} title="Nobody else has an account yet" action={<button className="btn" onClick={() => setAdding(true)}><UserPlus size={16} /> Add the first user</button>}>
            Add your groupmates as assessors, and your adviser as a viewer if they only need to read results.
          </Empty>
        </>
      ) : (
        <UserTable rows={rows} me={me.id} onEdit={setEditing} onReset={setResetting} onToggle={toggle} onDelete={remove} />
      )}

      {adding && (
        <NewUser
          onClose={() => setAdding(false)}
          onCreated={(account, password) => {
            setAdding(false);
            setHandover({ account, password });
            void load();
          }}
        />
      )}
      {editing && (
        <EditUser
          account={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            toast({ kind: "success", title: "Changes saved" });
            setEditing(null);
            void load();
          }}
        />
      )}
      {resetting && (
        <ResetPassword
          account={resetting}
          onClose={() => setResetting(null)}
          onDone={(account, password) => {
            setResetting(null);
            setHandover({ account, password });
            void load();
          }}
        />
      )}
      {handover && <Handover {...handover} onClose={() => setHandover(null)} />}
    </>
  );
}

function UserTable({
  rows,
  me,
  onEdit,
  onReset,
  onToggle,
  onDelete,
}: {
  rows: Account[];
  me: number;
  onEdit: (a: Account) => void;
  onReset: (a: Account) => void;
  onToggle: (a: Account) => void;
  onDelete: (a: Account) => void;
}) {
  return (
    <div className="panel panel-flush">
      <table className="table users-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Role</th>
            <th>Status</th>
            <th>Last sign-in</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => {
            const admin = a.role === "superadmin";
            return (
              <tr key={a.id} className={a.active ? "" : "row-off"}>
                <td>
                  <div className="user-cell">
                    <span className={`avatar role-${a.role}`}>{initials(a.name)}</span>
                    <div>
                      <div className="strong">
                        {a.name} {a.id === me && <span className="dim small">(you)</span>}
                      </div>
                      <div className="dim small">{a.email}</div>
                      {a.custom_id && <div className="small mono dim">ID {a.custom_id}</div>}
                    </div>
                  </div>
                </td>
                <td><span className={`user-role role-${a.role}`}>{ROLE_LABEL[a.role]}</span></td>
                <td>
                  {!a.active ? (
                    <span className="status-text off">Disabled</span>
                  ) : a.must_change_password ? (
                    <span className="status-text wait">Waiting for first sign-in</span>
                  ) : (
                    <span className="status-text on">Active</span>
                  )}
                </td>
                <td className="dim small nowrap">{a.last_login_at ? ago(a.last_login_at) : "Never"}</td>
                <td className="row-actions">
                  <button className="icon-btn" title="Edit" aria-label={`Edit ${a.name}`} onClick={() => onEdit(a)}><Pencil size={15} /></button>
                  {!admin && (
                    <>
                      <button className="icon-btn" title="Reset password" aria-label={`Reset password for ${a.name}`} onClick={() => onReset(a)}><KeyRound size={15} /></button>
                      <button className="btn btn-sm" onClick={() => onToggle(a)}>{a.active ? "Disable" : "Enable"}</button>
                      <button className="icon-btn danger" title="Delete" aria-label={`Delete ${a.name}`} onClick={() => onDelete(a)}><Trash2 size={15} /></button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
