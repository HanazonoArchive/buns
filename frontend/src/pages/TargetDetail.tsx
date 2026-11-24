import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, CATEGORIES, CATEGORY_LABEL, when, type Category } from "../api";
import { ErrorLine, PageHead, ScanTag, usePoll } from "../components/ui";

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
      {res && <p className={res.allowed ? "ok-text" : "warn-text"}>{res.allowed ? "Allowed. " : "Blocked. "}{res.reason}</p>}
    </form>
  );
}

function StartScan({ targetId, running }: { targetId: number; running: boolean }) {
  const nav = useNavigate();
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
      nav(`/scans/${s.id}`);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  return (
    <form className="panel" onSubmit={start}>
      <h2>New scan</h2>
      <fieldset className="cats">
        <legend>Assessment categories</legend>
        {CATEGORIES.map((c) => (
          <label key={c} className="check">
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
        <label className="check">
          <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
          <span>
            <b>Active scan</b>
            <small>Sends attack payloads using only the rules for the categories above. Takes several minutes on Juice Shop.</small>
          </span>
        </label>
        <label className="check">
          <input type="checkbox" checked={ajax} onChange={(e) => setAjax(e.target.checked)} />
          <span>
            <b>AJAX spider</b>
            <small>Crawls the Angular front end in a headless browser. Finds more routes, adds about three minutes.</small>
          </span>
        </label>
      </fieldset>
      <ErrorLine msg={err} />
      <button className="btn primary" disabled={busy || running || cats.length === 0}>
        {running ? "A scan is already running" : "Start scan"}
      </button>
    </form>
  );
}

export default function TargetDetail() {
  const id = Number(useParams().id);
  const nav = useNavigate();
  const { data: t, error } = usePoll(() => api.target(id), [id], () => false);
  const { data: scans } = usePoll(() => api.scans(id), [id], (v) => v.some((s) => s.status === "running" || s.status === "queued"), 2000);

  if (error) return <ErrorLine msg={error} />;
  if (!t) return null;
  const running = !!scans?.some((s) => s.status === "running" || s.status === "queued");

  const remove = async () => {
    if (!window.confirm(`Delete ${t.name} with all its scans, findings and reports? This cannot be undone.`)) return;
    await api.deleteTarget(t.id);
    nav("/targets");
  };

  return (
    <>
      <div className="crumbs"><Link to="/targets">Targets</Link></div>
      <PageHead
        title={t.name}
        sub={<span className="mono">{t.base_url}</span>}
        actions={
          <>
            <Link className="btn" to={`/findings?target=${t.id}&status=`}>Findings</Link>
            <Link className="btn" to={`/reports?target=${t.id}`}>Report</Link>
          </>
        }
      />

      <div className="two wide-left">
        <div>
          <section className="panel">
            <h2>Authorisation</h2>
            <p className="prose">{t.authorization_notes}</p>
          </section>
          <section className="panel">
            <h2>Scope</h2>
            <dl className="rules">
              <dt>In scope</dt>
              <dd>{t.in_scope.length ? t.in_scope.map((p) => <code key={p}>{p}</code>) : <span>Every path on this origin</span>}</dd>
              <dt>Excluded</dt>
              <dd>{t.out_of_scope.length ? t.out_of_scope.map((p) => <code key={p}>{p}</code>) : <span className="dim">Nothing</span>}</dd>
              <dt>Test account</dt>
              <dd>{t.test_email ? <>{t.test_email}{!t.has_test_password && <span className="warn-text"> (no password saved)</span>}</> : <span className="dim">None. Session-based access checks will be skipped.</span>}</dd>
            </dl>
            <ScopeTester targetId={t.id} base={t.base_url} />
          </section>
          <section className="panel">
            <h2>Scans</h2>
            {!scans || scans.length === 0 ? (
              <p className="dim">This target has not been scanned yet.</p>
            ) : (
              <table className="list">
                <thead><tr><th>Scan</th><th>Status</th><th>Started</th><th>Categories</th><th className="num">Findings</th></tr></thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td><Link to={`/scans/${s.id}`}>Scan {s.id}</Link></td>
                      <td><ScanTag s={s.status} />{s.status === "running" && <span className="dim"> {s.progress}%</span>}</td>
                      <td>{when(s.started_at ?? s.created_at)}</td>
                      <td className="small">{s.categories.map((c) => CATEGORY_LABEL[c]).join(", ")}</td>
                      <td className="num">{s.finding_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
          <button className="link danger small" onClick={remove}>Delete this target</button>
        </div>
        <StartScan targetId={t.id} running={running} />
      </div>
    </>
  );
}
