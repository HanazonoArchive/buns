import { useEffect, useRef } from "react";
import { Link, useParams } from "react-router-dom";
import { api, CATEGORY_LABEL, pathOf, when } from "../api";
import { ErrorLine, PageHead, ScanTag, usePoll } from "../components/ui";

const PHASES: [string, string[]][] = [
  ["Reconnaissance", ["queued", "recon"]],
  ["Spider", ["spider", "ajax-spider"]],
  ["Passive scan", ["passive-scan"]],
  ["Active scan", ["active-scan", "collecting"]],
  ["cURL probes", ["curl-probes"]],
  ["Stored", ["storing", "completed"]],
];

export default function ScanView() {
  const id = Number(useParams().id);
  const { data: s, error } = usePoll(() => api.scan(id), [id], (v) => v.status === "queued" || v.status === "running", 1200);
  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    const el = logRef.current;
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight;
  }, [s?.log]);

  if (error) return <ErrorLine msg={error} />;
  if (!s) return null;

  const current = PHASES.findIndex(([, keys]) => keys.includes(s.phase));
  const done = s.status === "completed";
  const zapSkipped = s.log.includes("ZAP unavailable");
  const skipped = (i: number) => (zapSkipped && i >= 1 && i <= 3) || (i === 3 && !s.active_scan);

  return (
    <>
      <div className="crumbs"><Link to={`/targets/${s.target_id}`}>{s.target_name}</Link></div>
      <PageHead
        title={`Scan ${s.id}`}
        sub={<>Started {when(s.started_at ?? s.created_at)}{s.finished_at && <>, finished {when(s.finished_at)}</>}. {s.categories.map((c) => CATEGORY_LABEL[c]).join(", ")}.</>}
        actions={done && s.finding_count > 0 && <Link className="btn primary" to={`/findings?scan=${s.id}&status=pending`}>Review {s.finding_count} findings</Link>}
      />

      <section className="panel">
        <div className="progress-head">
          <ScanTag s={s.status} />
          <span className="mono">{s.progress}%</span>
        </div>
        <div className="progress" role="progressbar" aria-valuenow={s.progress} aria-valuemin={0} aria-valuemax={100}>
          <span style={{ width: `${s.progress}%` }} className={s.status === "failed" ? "failed" : ""} />
        </div>
        <ol className="phases">
          {PHASES.map(([label], i) => (
            <li
              key={label}
              className={skipped(i) && (done || i < current) ? "skipped" : done || i < current ? "past" : i === current ? (s.status === "failed" ? "failed" : "now") : ""}
            >
              {label}
              {skipped(i) && (done || i < current) && <small>skipped</small>}
            </li>
          ))}
        </ol>
        {s.status === "failed" && s.error && <p className="error-line">{s.error.split("\n")[0]}</p>}
      </section>

      <div className="two wide-left">
        <section className="panel">
          <h2>Activity log</h2>
          <pre className="log" ref={logRef} tabIndex={0}>{s.log || "Waiting to start…"}</pre>
        </section>
        <section className="panel">
          <h2>Endpoints seen <span className="dim">{s.endpoints.length}</span></h2>
          {s.endpoints.length === 0 ? (
            <p className="dim">Endpoints appear here when the scan finishes.</p>
          ) : (
            <ul className="endpoints">
              {s.endpoints.slice(0, 300).map((e) => (
                <li key={e.id}>
                  <span className="method">{e.method}</span>
                  <span className="mono ep-path">{pathOf(e.url)}</span>
                  {e.status_code && <span className={`code c${String(e.status_code)[0]}`}>{e.status_code}</span>}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}
