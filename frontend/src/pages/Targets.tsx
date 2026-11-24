import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronRight, Globe, Plus, Target as TargetIcon, UserRound } from "lucide-react";
import { api, plural } from "../api";
import { Modal } from "../components/Modal";
import { useToast } from "../components/toast";
import { Empty, ErrorLine, Field, PageHead, Skeleton, usePoll } from "../components/ui";

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function NewTarget({ onClose }: { onClose: () => void }) {
  const nav = useNavigate();
  const toast = useToast();
  const [form, setForm] = useState({
    name: "",
    base_url: "http://localhost:3000",
    authorization_notes: "",
    in_scope: "",
    out_of_scope: "/socket.io/",
    test_email: "",
    test_password: "",
    owner_name: "",
    owner_email: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const t = await api.createTarget({ ...form, in_scope: lines(form.in_scope), out_of_scope: lines(form.out_of_scope) });
      toast({ kind: "success", title: `${t.name} registered`, text: "Start a scan from its page." });
      nav(`/targets/${t.id}`);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Register a target"
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy} onClick={() => submit()}>Register target</button>
        </>
      }
    >
      <form onSubmit={submit} className="form-grid">
        <p className="dim small">Only hosts on the server's allow-list can be registered. Every request a scan makes is checked against the rules below.</p>
        <div className="form-pair">
          <Field label="Name">
            <input required value={form.name} onChange={set("name")} placeholder="OWASP Juice Shop (local lab)" />
          </Field>
          <Field label="Base URL" hint="Use http://juice-shop:3000 when buns runs in Docker Compose.">
            <input required value={form.base_url} onChange={set("base_url")} className="mono" />
          </Field>
        </div>
        <Field label="Authorisation" hint="Who owns the system and what allows you to test it. This text goes into the report.">
          <textarea required minLength={10} rows={3} value={form.authorization_notes} onChange={set("authorization_notes")} />
        </Field>
        <div className="form-pair">
          <Field label="In-scope paths" hint="One prefix per line. Empty means the whole origin.">
            <textarea rows={3} value={form.in_scope} onChange={set("in_scope")} placeholder={"/rest/\n/api/"} className="mono" />
          </Field>
          <Field label="Excluded paths" hint="Never requested, even inside an in-scope prefix.">
            <textarea rows={3} value={form.out_of_scope} onChange={set("out_of_scope")} className="mono" />
          </Field>
        </div>
        <fieldset className="form-group">
          <legend>System owner</legend>
          <p className="dim small">The person to tell when something breaks. Email alert channels can copy them automatically.</p>
          <div className="form-pair">
            <Field label="Name"><input value={form.owner_name} onChange={set("owner_name")} placeholder="Jannik Hollenbach" /></Field>
            <Field label="Email"><input type="email" value={form.owner_email} onChange={set("owner_email")} placeholder="owner@example.com" /></Field>
          </div>
        </fieldset>
        <fieldset className="form-group">
          <legend>Test account</legend>
          <p className="dim small">Optional. Used for the access-control checks that need a logged-in customer.</p>
          <div className="form-pair">
            <Field label="Email"><input type="email" value={form.test_email} onChange={set("test_email")} placeholder="jim@juice-sh.op" autoComplete="off" /></Field>
            <Field label="Password"><input type="password" value={form.test_password} onChange={set("test_password")} autoComplete="new-password" /></Field>
          </div>
        </fieldset>
        <ErrorLine msg={err} />
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

export default function Targets() {
  const { data, error } = usePoll(api.targets, [], () => false);
  const [adding, setAdding] = useState(false);

  return (
    <>
      <PageHead
        title="Targets"
        sub="Applications you are authorised to test, the paths a scan may touch, and who to tell when something breaks."
        actions={<button className="btn btn-primary" onClick={() => setAdding(true)}><Plus size={16} /> Register target</button>}
      />
      {adding && <NewTarget onClose={() => setAdding(false)} />}
      <ErrorLine msg={error} />
      {!data && <div className="panel"><Skeleton rows={3} height={24} /></div>}
      {data && data.length === 0 && (
        <Empty icon={TargetIcon} title="No targets yet" action={<button className="btn btn-primary" onClick={() => setAdding(true)}><Plus size={16} /> Register target</button>}>
          Register the local Juice Shop container to begin.
        </Empty>
      )}
      {data && data.length > 0 && (
        <ul className="target-list">
          {data.map((t) => (
            <li key={t.id}>
              <Link to={`/targets/${t.id}`} className="target-card">
                <span className="target-icon"><Globe size={20} aria-hidden /></span>
                <span className="target-main">
                  <span className="target-name">{t.name}</span>
                  <span className="mono dim small">{t.base_url}</span>
                </span>
                <span className="target-meta">
                  <span>{plural(t.scan_count, "scan")}</span>
                  <span>{plural(t.finding_count, "finding")}</span>
                  <span className={t.owner_email ? "" : "dim"}>
                    <UserRound size={13} aria-hidden /> {t.owner_name || t.owner_email || "No owner set"}
                  </span>
                </span>
                <ChevronRight size={18} className="dim" aria-hidden />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
