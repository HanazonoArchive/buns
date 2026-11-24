import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  BellRing,
  CheckCircle2,
  FileText,
  ListChecks,
  Lock,
  Pencil,
  Play,
  Radar,
  ShieldQuestion,
  Trash2,
  UserRound,
  XCircle,
} from "lucide-react";
import { useAuth } from "../auth";
import { api, CATEGORIES, CATEGORY_LABEL, when, type Category, type Target } from "../api";
import { Modal } from "../components/Modal";
import { useToast } from "../components/toast";
import { ErrorLine, Field, PageHead, Panel, ScanTag, Skeleton, Switch, usePoll } from "../components/ui";

const CATEGORY_HINT: Record<Category, string> = {
  authentication: "Login bypass, failed-login throttling, password policy",
  access_control: "Admin endpoints, other users' baskets (IDOR)",
  injection: "SQL injection and XSS in search and forms",
  info_disclosure: "Exposed files, stack traces, headers, directory listings",
};

function ScopeTester({ targetId, base }: { targetId: number; base: string }) {
  const [url, setUrl] = useState(base + "/");
  const [res, setRes] = useState<{ allowed: boolean; reason: string } | null>(null);
  const check = async (e: FormEvent) => {
    e.preventDefault();
    setRes(await api.scopeCheck(targetId, url));
  };
  return (
    <form className="scope-test" onSubmit={check}>
      <label htmlFor="scope-url">Check whether a URL may be requested</label>
      <div className="row">
        <input id="scope-url" className="mono" value={url} onChange={(e) => { setUrl(e.target.value); setRes(null); }} />
        <button className="btn">Check</button>
      </div>
      {res && (
        <p className={`scope-result ${res.allowed ? "ok" : "blocked"}`}>
          {res.allowed ? <CheckCircle2 size={16} aria-hidden /> : <XCircle size={16} aria-hidden />}
          <span><b>{res.allowed ? "Allowed." : "Blocked."}</b> {res.reason}</span>
        </p>
      )}
    </form>
  );
}

function OwnerEditor({ t, onClose, onSaved }: { t: Target; onClose: () => void; onSaved: (t: Target) => void }) {
  const [name, setName] = useState(t.owner_name);
  const [email, setEmail] = useState(t.owner_email);
  const [err, setErr] = useState("");
  const save = async () => {
    try {
      onSaved(await api.updateTarget(t.id, { owner_name: name, owner_email: email }));
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Modal title="System owner" onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" onClick={save}>Save owner</button></>}>
      <div className="form-grid">
        <p className="dim small">The person responsible for {t.name}. Email alert channels with "copy the target owner" turned on send to this address.</p>
        <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Email"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
        <ErrorLine msg={err} />
      </div>
    </Modal>
  );
}

function StartScan({ targetId, running }: { targetId: number; running: boolean }) {
  const nav = useNavigate();
  const toast = useToast();
  const [cats, setCats] = useState<Category[]>([...CATEGORIES]);
  const [active, setActive] = useState(true);
  const [ajax, setAjax] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const toggle = (c: Category) => setCats(cats.includes(c) ? cats.filter((x) => x !== c) : [...cats, c]);
  const start = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const s = await api.startScan(targetId, { categories: cats, active_scan: active, ajax_spider: ajax });
      toast({ kind: "info", title: `Scan ${s.id} started`, text: "You will be alerted when the analysis is ready." });
      nav(`/scans/${s.id}`);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <Panel title="New scan" icon={Radar} className="sticky-panel">
      <form onSubmit={start}>
        <fieldset className="cats">
          <legend>Assessment categories</legend>
          {CATEGORIES.map((c) => (
            <label key={c} className={`check-card${cats.includes(c) ? " on" : ""}`}>
              <input type="checkbox" checked={cats.includes(c)} onChange={() => toggle(c)} />
              <span>
                <b>{CATEGORY_LABEL[c]}</b>
                <small>{CATEGORY_HINT[c]}</small>
              </span>
            </label>
          ))}
        </fieldset>
        <fieldset className="opts">
          <legend>ZAP options</legend>
          <div className="opt-row">
            <span>
              <b>Active scan</b>
              <small>Sends attack payloads using only the rules for the categories above. A few minutes on Juice Shop.</small>
            </span>
            <Switch checked={active} onChange={setActive} label="Active scan" />
          </div>
          <div className="opt-row">
            <span>
              <b>AJAX spider</b>
              <small>Crawls the Angular front end in a headless browser. Finds more routes; adds about three minutes and needs Firefox or Chrome.</small>
            </span>
            <Switch checked={ajax} onChange={setAjax} label="AJAX spider" />
          </div>
        </fieldset>
        <ErrorLine msg={err} />
        <button className="btn btn-primary btn-block" disabled={busy || running || cats.length === 0}>
          <Play size={16} /> {running ? "A scan is already running" : "Start scan"}
        </button>
      </form>
    </Panel>
  );
}

export default function TargetDetail() {
  const id = Number(useParams().id);
  const nav = useNavigate();
  const toast = useToast();
  const { data: t, error, setData } = usePoll(() => api.target(id), [id], () => false);
  const { data: scans } = usePoll(() => api.scans(id), [id], (v) => v.some((s) => s.status === "running" || s.status === "queued"), 2000);
  const [editOwner, setEditOwner] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { canWrite } = useAuth();

  useEffect(() => setEditOwner(false), [id]);

  if (error) return <ErrorLine msg={error} />;
  if (!t) return <Skeleton rows={6} height={22} />;
  const running = !!scans?.some((s) => s.status === "running" || s.status === "queued");

  const remove = async () => {
    try {
      await api.deleteTarget(t.id);
      toast({ kind: "info", title: `${t.name} deleted` });
      nav("/targets");
    } catch (e) {
      toast({ kind: "error", title: "Could not delete", text: (e as Error).message });
      setConfirmDelete(false);
    }
  };

  return (
    <>
      <div className="crumbs"><Link to="/targets" className="inline"><ArrowLeft size={15} /> Targets</Link></div>
      <PageHead
        title={t.name}
        sub={<span className="mono">{t.base_url}</span>}
        actions={
          <>
            <Link className="btn" to={`/findings?target=${t.id}&status=`}><ListChecks size={16} /> Findings</Link>
            <Link className="btn" to={`/reports?target=${t.id}`}><FileText size={16} /> Report</Link>
          </>
        }
      />

      <div className="grid-main-side">
        <div className="stack">
          <Panel title="Authorisation" icon={Lock}>
            <p className="prose">{t.authorization_notes}</p>
          </Panel>

          <Panel title="Scope" icon={ShieldQuestion}>
            <dl className="rules">
              <dt>In scope</dt>
              <dd>{t.in_scope.length ? t.in_scope.map((p) => <code key={p}>{p}</code>) : <span>Every path on this origin</span>}</dd>
              <dt>Excluded</dt>
              <dd>{t.out_of_scope.length ? t.out_of_scope.map((p) => <code key={p}>{p}</code>) : <span className="dim">Nothing</span>}</dd>
              <dt>Test account</dt>
              <dd>
                {t.test_email ? <>{t.test_email}{!t.has_test_password && <span className="warn-text"> (no password saved)</span>}</> : <span className="dim">None. Session-based access checks are skipped.</span>}
              </dd>
            </dl>
            <ScopeTester targetId={t.id} base={t.base_url} />
          </Panel>

          <Panel title="Scans" icon={Radar} flush>
            {!scans || scans.length === 0 ? (
              <p className="dim pad">This target has not been scanned yet.</p>
            ) : (
              <table className="table">
                <thead><tr><th>Scan</th><th>Status</th><th>Started</th><th>Categories</th><th className="num">Findings</th></tr></thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td><Link to={`/scans/${s.id}`} className="strong">Scan {s.id}</Link></td>
                      <td><ScanTag s={s.status} progress={s.progress} /></td>
                      <td className="nowrap">{when(s.started_at ?? s.created_at)}</td>
                      <td className="small">{s.categories.map((c) => CATEGORY_LABEL[c]).join(", ")}</td>
                      <td className="num">{s.finding_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          {canWrite && <button className="link danger small inline" onClick={() => setConfirmDelete(true)}><Trash2 size={14} /> Delete this target</button>}
        </div>

        <div className="stack">
          <Panel title="System owner" icon={UserRound} actions={canWrite ? <button className="icon-btn" onClick={() => setEditOwner(true)} aria-label="Edit owner"><Pencil size={15} /></button> : undefined}>
            {t.owner_email || t.owner_name ? (
              <div className="owner">
                <span className="avatar" aria-hidden>{(t.owner_name || t.owner_email).slice(0, 1).toUpperCase()}</span>
                <span>
                  <b>{t.owner_name || "Owner"}</b>
                  <span className="dim small block">{t.owner_email || "No email"}</span>
                </span>
              </div>
            ) : (
              <p className="dim small">Nobody is set. Add the person responsible for this system so they can be told when a scan finds something serious.</p>
            )}
            <p className="small owner-hint">
              <BellRing size={14} aria-hidden />
              <span>Alerts go out through your <Link to="/settings">alert channels</Link>.</span>
            </p>
          </Panel>
          {canWrite ? (
            <StartScan targetId={t.id} running={running} />
          ) : (
            <Panel title="Start a scan" icon={Radar}>
              <p className="dim small">Your account is a Viewer. Ask an assessor to run scans against this target.</p>
            </Panel>
          )}
        </div>
      </div>

      {editOwner && <OwnerEditor t={t} onClose={() => setEditOwner(false)} onSaved={(nt) => { setData(nt); setEditOwner(false); toast({ kind: "success", title: "Owner saved" }); }} />}
      {confirmDelete && (
        <Modal
          title={`Delete ${t.name}?`}
          onClose={() => setConfirmDelete(false)}
          footer={<><button className="btn" onClick={() => setConfirmDelete(false)}>Keep it</button><button className="btn btn-danger" onClick={remove}><Trash2 size={15} /> Delete target</button></>}
        >
          <p>This removes the target with all its scans, findings, decisions and reports. It cannot be undone.</p>
        </Modal>
      )}
    </>
  );
}
