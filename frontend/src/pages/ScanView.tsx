import { useEffect, useRef } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, Bug, Check, Globe, Network, ScanEye, ScrollText, Search, Terminal, Zap } from "lucide-react";
import { api, CATEGORY_LABEL, pathOf, when } from "../api";
import { ErrorLine, PageHead, Panel, ScanTag, Skeleton, usePoll } from "../components/ui";

const PHASES = [
  { label: "Reconnaissance", keys: ["queued", "recon"], icon: Search },
  { label: "Spider", keys: ["spider", "ajax-spider"], icon: Network },
  { label: "Passive scan", keys: ["passive-scan"], icon: ScanEye },
  { label: "Active scan", keys: ["active-scan", "collecting"], icon: Zap },
  { label: "cURL probes", keys: ["curl-probes"], icon: Terminal },
  { label: "Stored", keys: ["storing", "completed"], icon: Check },
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
  if (!s) return <Skeleton rows={6} height={22} />;

  const current = PHASES.findIndex((p) => p.keys.includes(s.phase));
  const done = s.status === "completed";
  const zapSkipped = s.log.includes("ZAP unavailable");
  const skipped = (i: number) => (zapSkipped && i >= 1 && i <= 3) || (i === 3 && !s.active_scan);

  return (
    <>
      <div className="crumbs"><Link to={`/targets/${s.target_id}`} className="inline"><ArrowLeft size={15} /> {s.target_name}</Link></div>
      <PageHead
        title={`Scan ${s.id}`}
        sub={
          <>
            Started {when(s.started_at ?? s.created_at)}
            {s.finished_at && <>, finished {when(s.finished_at)}</>}. {s.categories.map((c) => CATEGORY_LABEL[c]).join(", ")}.
          </>
        }
        actions={
          done && s.finding_count > 0 && (
            s.new_finding_count > 0 ? (
              <Link className="btn btn-primary" to={`/findings?scan=${s.id}&status=pending`}>
                Review {s.new_finding_count} new {s.new_finding_count === 1 ? "finding" : "findings"} <ArrowRight size={16} />
              </Link>
            ) : (
              <Link className="btn" to={`/findings?scan=${s.id}&status=`}>
                View {s.finding_count} findings <ArrowRight size={16} />
              </Link>
            )
          )
        }
      />

      <section className="panel scan-progress">
        <div className="progress-head">
          <ScanTag s={s.status} />
          <span className="progress-pct">{s.progress}%</span>
        </div>
        <div className="progress" role="progressbar" aria-valuenow={s.progress} aria-valuemin={0} aria-valuemax={100}>
          <span style={{ width: `${s.progress}%` }} className={s.status === "failed" ? "failed" : done ? "done" : ""} />
        </div>
        <ol className="phases">
          {PHASES.map(({ label, icon: Icon }, i) => {
            const past = done || i < current;
            const cls = skipped(i) && past ? "skipped" : past ? "past" : i === current ? (s.status === "failed" ? "failed" : "now") : "";
            return (
              <li key={label} className={cls}>
                <span className="ph-icon"><Icon size={15} aria-hidden /></span>
                <span className="ph-label">
                  {label}
                  {skipped(i) && past && <small>skipped</small>}
                </span>
              </li>
            );
          })}
        </ol>
        {s.status === "failed" && s.error && <ErrorLine msg={s.error.split("\n")[0]} />}
        {done && (
          <p className="scan-summary">
            <Bug size={15} aria-hidden />
            {s.finding_count === s.new_finding_count
              ? `${s.finding_count} findings from ${s.endpoint_count} endpoints. Analysis runs in the background and you will be alerted when it is ready.`
              : `${s.finding_count} findings from ${s.endpoint_count} endpoints: ${s.new_finding_count} new, ${s.finding_count - s.new_finding_count} already known from earlier scans (their decisions are kept).`}
          </p>
        )}
      </section>

      <div className="grid-main-side">
        <Panel title="Activity log" icon={ScrollText} flush>
          <pre className="log" ref={logRef} tabIndex={0}>{s.log || "Waiting to start…"}</pre>
        </Panel>
        <Panel title={<>Endpoints seen <span className="count-chip">{s.endpoints.length}</span></>} icon={Globe} flush>
          {s.endpoints.length === 0 ? (
            <p className="dim pad">Endpoints appear here when the scan finishes.</p>
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
        </Panel>
      </div>
    </>
  );
}
