import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, plural } from "../api";
import { Empty, ErrorLine, Field, PageHead, usePoll } from "../components/ui";

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function NewTarget({ onCancel }: { onCancel: () => void }) {
  const nav = useNavigate();
  const [form, setForm] = useState({
    name: "",
    base_url: "http://localhost:3000",
    authorization_notes: "",
    in_scope: "",
    out_of_scope: "/socket.io/",
    test_email: "",
    test_password: "",
  });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const t = await api.createTarget({
        ...form,
        in_scope: lines(form.in_scope),
        out_of_scope: lines(form.out_of_scope),
      });
      nav(`/targets/${t.id}`);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <form className="panel form" onSubmit={submit}>
      <h2>Register a target</h2>
      <p className="dim">Only hosts on the server's allow-list can be registered. Every request a scan makes is checked against the rules below.</p>
      <div className="form-grid">
        <Field label="Name">
          <input required value={form.name} onChange={set("name")} placeholder="OWASP Juice Shop (local lab)" />
        </Field>
        <Field label="Base URL" hint="Use http://juice-shop:3000 when the platform runs in Docker Compose.">
          <input required value={form.base_url} onChange={set("base_url")} />
        </Field>
        <Field label="Authorisation" hint="Who owns the system and what allows you to test it. This text goes into the report.">
          <textarea required minLength={10} rows={3} value={form.authorization_notes} onChange={set("authorization_notes")} />
        </Field>
        <div className="form-pair">
          <Field label="In-scope paths" hint="One prefix per line. Leave empty to allow the whole origin.">
            <textarea rows={3} value={form.in_scope} onChange={set("in_scope")} placeholder={"/rest/\n/api/"} className="mono" />
          </Field>
          <Field label="Excluded paths" hint="Never requested, even if inside an in-scope prefix.">
            <textarea rows={3} value={form.out_of_scope} onChange={set("out_of_scope")} className="mono" />
          </Field>
        </div>
        <div className="form-pair">
          <Field label="Test account email" hint="Optional. Used for the access-control checks.">
            <input type="email" value={form.test_email} onChange={set("test_email")} placeholder="jim@juice-sh.op" autoComplete="off" />
          </Field>
          <Field label="Test account password">
            <input type="password" value={form.test_password} onChange={set("test_password")} autoComplete="new-password" />
          </Field>
        </div>
      </div>
      <ErrorLine msg={err} />
      <div className="form-actions">
        <button type="button" className="btn" onClick={onCancel}>Cancel</button>
        <button className="btn primary" disabled={busy}>Register target</button>
      </div>
    </form>
  );
}

export default function Targets() {
  const { data, error } = usePoll(api.targets, [], () => false);
  const [adding, setAdding] = useState(false);

  return (
    <>
      <PageHead
        title="Targets"
        sub="Applications you are authorised to test, with the paths a scan may touch."
        actions={!adding && <button className="btn primary" onClick={() => setAdding(true)}>Register target</button>}
      />
      {adding && <NewTarget onCancel={() => setAdding(false)} />}
      <ErrorLine msg={error} />
      {data && data.length === 0 && !adding && (
        <Empty>
          <p>No targets yet. Register the local Juice Shop container to begin.</p>
        </Empty>
      )}
      {data && data.length > 0 && (
        <ul className="targets">
          {data.map((t) => (
            <li key={t.id}>
              <Link to={`/targets/${t.id}`}>
                <span className="t-name">{t.name}</span>
                <span className="t-url mono">{t.base_url}</span>
                <span className="t-meta dim">
                  {plural(t.scan_count, "scan")}, {plural(t.finding_count, "finding")}
                  {t.out_of_scope.length > 0 && `, ${plural(t.out_of_scope.length, "exclusion")}`}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
