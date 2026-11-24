import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, CATEGORIES, CATEGORY_LABEL, fid, pathOf, SEVERITIES, SEVERITY_LABEL, type FindingSummary } from "../api";
import { Empty, ErrorLine, PageHead, ReviewTag, Sev, usePoll } from "../components/ui";

const STATUSES: [string, string][] = [
  ["pending", "Needs review"],
  ["confirmed", "Confirmed"],
  ["rejected", "False positives"],
  ["", "All"],
];

function AiCell({ f }: { f: FindingSummary }) {
  if (f.ai_status === "pending" || f.ai_status === "running") return <span className="dim">Analysing…</span>;
  if (f.ai_status === "failed") return <span className="warn-text">Analysis failed</span>;
  return (
    <span className="ai-cell">
      <Sev s={f.ai_severity} muted />
      {f.ai_cvss_score !== null && <span className="dim"> {f.ai_cvss_score.toFixed(1)}</span>}
    </span>
  );
}

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const nav = useNavigate();
  const status = params.get("status") ?? "pending";
  const category = params.get("category") ?? "";
  const severity = params.get("severity") ?? "";
  const target = params.get("target") ?? "";
  const scan = params.get("scan") ?? "";

  const { data: targets } = usePoll(api.targets, [], () => false);
  const { data, error } = usePoll(
    () => api.findings({ status, category, severity, target_id: target ? +target : undefined, scan_id: scan ? +scan : undefined }),
    [status, category, severity, target, scan],
    (rows) => rows.some((f) => f.ai_status === "pending" || f.ai_status === "running"),
    2500,
  );

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key === "status" && value === "") next.set("status", "");
    setParams(next, { replace: true });
  };

  const order = (data ?? []).map((f) => f.id);

  return (
    <>
      <PageHead
        title="Findings"
        sub="Everything the tools reported. Nothing goes into the report until someone confirms it against the evidence."
      />

      <div className="filters">
        <div className="seg" role="tablist" aria-label="Review status">
          {STATUSES.map(([v, label]) => (
            <button key={label} role="tab" aria-selected={status === v} className={status === v ? "on" : ""} onClick={() => set("status", v)}>
              {label}
            </button>
          ))}
        </div>
        <select aria-label="Severity" value={severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <select aria-label="Category" value={category} onChange={(e) => set("category", e.target.value)}>
          <option value="">Any category</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>)}
        </select>
        {targets && targets.length > 1 && (
          <select aria-label="Target" value={target} onChange={(e) => set("target", e.target.value)}>
            <option value="">All targets</option>
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        )}
        {scan && (
          <button className="chip" onClick={() => set("scan", "")}>
            Scan {scan} only <span aria-hidden>×</span>
            <span className="sr">Clear scan filter</span>
          </button>
        )}
      </div>

      <ErrorLine msg={error} />
      {data && data.length === 0 && (
        <Empty>
          {status === "pending" ? (
            <p>Nothing is waiting for review with these filters.</p>
          ) : (
            <p>No findings match these filters.</p>
          )}
        </Empty>
      )}
      {data && data.length > 0 && (
        <table className="list findings">
          <thead>
            <tr>
              <th className="stripe-col" aria-hidden />
              <th>Finding</th>
              <th>Endpoint</th>
              <th>Category</th>
              <th>Suggested</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {data.map((f) => (
              <tr
                key={f.id}
                className="clickable"
                onClick={() => nav(`/findings/${f.id}`, { state: { order } })}
              >
                <td className={`stripe sev-bg-${f.effective_severity}`} aria-hidden />
                <td>
                  <Link to={`/findings/${f.id}`} state={{ order }} onClick={(e) => e.stopPropagation()} className="title-link">
                    {f.title}
                  </Link>
                  <span className="meta parts">
                    <span>{fid(f.id)}</span>
                    <span>{f.source === "zap" ? "ZAP" : "cURL"}</span>
                    {f.occurrences > 1 && <span>seen {f.occurrences} times</span>}
                  </span>
                </td>
                <td className="endpoint">
                  <span className="method">{f.method}</span> {pathOf(f.url)}
                  {f.param && <span className="meta">parameter {f.param}</span>}
                </td>
                <td>{CATEGORY_LABEL[f.category]}</td>
                <td><AiCell f={f} /></td>
                <td>
                  <ReviewTag s={f.status} />
                  {f.status === "confirmed" && f.final_severity && <span className="meta"><Sev s={f.final_severity} /></span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
