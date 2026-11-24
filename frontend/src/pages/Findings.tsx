import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Bot, ChevronRight, Inbox, Loader2, Search, Sparkles, X } from "lucide-react";
import { api, CATEGORIES, CATEGORY_LABEL, fid, pathOf, SEVERITIES, SEVERITY_LABEL, type FindingSummary } from "../api";
import { Empty, ErrorLine, PageHead, ReviewTag, Sev, Skeleton, usePoll } from "../components/ui";

const STATUSES: [string, string][] = [
  ["pending", "Needs review"],
  ["confirmed", "Confirmed"],
  ["rejected", "False positives"],
  ["", "All"],
];

function AiCell({ f }: { f: FindingSummary }) {
  if (f.ai_status === "pending" || f.ai_status === "running")
    return (
      <span className="ai-status-pill analyzing">
        <Loader2 size={13} className="spin" aria-hidden />
        <span>Analysing</span>
      </span>
    );
  if (f.ai_status === "failed")
    return (
      <span className="ai-status-pill failed" title="Analysis failed">
        <Sparkles size={12} />
        <span>Failed</span>
      </span>
    );
  return (
    <span className="ai-status-pill done">
      <Bot size={13} className="ai-status-icon" aria-hidden />
      <Sev s={f.ai_severity} size="sm" />
      {f.ai_cvss_score !== null && <span className="mono cvss-score-tag">{f.ai_cvss_score.toFixed(1)}</span>}
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
  const [q, setQ] = useState("");

  const { data: targets } = usePoll(api.targets, [], () => false);
  const { data: all, error } = usePoll(
    () => api.findings({ target_id: target ? +target : undefined, scan_id: scan ? +scan : undefined }),
    [target, scan],
    (rows) => rows.some((f) => f.ai_status === "pending" || f.ai_status === "running"),
    2500,
  );

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value || key === "status") next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const base = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (all ?? []).filter(
      (f) =>
        (!category || f.category === category) &&
        (!severity || f.effective_severity === severity) &&
        (!needle || f.title.toLowerCase().includes(needle) || f.url.toLowerCase().includes(needle) || fid(f.id).toLowerCase().includes(needle)),
    );
  }, [all, category, severity, q]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { "": base.length, pending: 0, confirmed: 0, rejected: 0 };
    base.forEach((f) => (c[f.status] += 1));
    return c;
  }, [base]);

  const rows = status ? base.filter((f) => f.status === status) : base;
  const order = rows.map((f) => f.id);
  const filtered = !!(category || severity || q || scan || target);

  return (
    <>
      <PageHead title="Findings" sub="Everything the tools reported. Nothing reaches the report until an assessor confirms it against the evidence." />

      <div className="toolbar">
        <div className="seg" role="tablist" aria-label="Review status">
          {STATUSES.map(([v, label]) => (
            <button key={label} role="tab" aria-selected={status === v} className={status === v ? "on" : ""} onClick={() => set("status", v)}>
              {label}
              {all && <span className="seg-count">{counts[v]}</span>}
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <label className="search">
            <Search size={15} aria-hidden />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, path or ID" aria-label="Search findings" />
            {q && (
              <button className="icon-btn" onClick={() => setQ("")} aria-label="Clear search">
                <X size={14} />
              </button>
            )}
          </label>
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
        </div>
      </div>
      {scan && (
        <p className="filter-note">
          Showing scan {scan} only.{" "}
          <button className="link" onClick={() => set("scan", "")}>Show all scans</button>
        </p>
      )}

      <ErrorLine msg={error} />
      {!all && <div className="panel"><Skeleton rows={6} height={20} /></div>}
      {all && rows.length === 0 && (
        <Empty icon={Inbox} title={status === "pending" && !filtered ? "Nothing waiting for review" : "No findings match"}>
          {status === "pending" && !filtered
            ? "Run a scan, or look at confirmed findings to generate the report."
            : "Try a different filter or clear the search."}
        </Empty>
      )}
      {all && rows.length > 0 && (
        <div className="panel panel-flush">
          <table className="table findings">
            <thead>
              <tr>
                <th className="stripe-col" aria-hidden />
                <th>Finding</th>
                <th>Endpoint</th>
                <th>Category</th>
                <th>Suggested</th>
                <th>Decision</th>
                <th aria-hidden />
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className="clickable" onClick={() => nav(`/findings/${f.id}`, { state: { order } })}>
                  <td className={`stripe sev-bg-${f.effective_severity}`} aria-hidden />
                  <td>
                    <Link to={`/findings/${f.id}`} state={{ order }} onClick={(e) => e.stopPropagation()} className="row-title">
                      {f.title}
                    </Link>
                    <span className="cell-sub parts">
                      <span className="mono">{fid(f.id)}</span>
                      <span>{f.source === "zap" ? "OWASP ZAP" : "cURL probe"}</span>
                      {f.occurrences > 1 && <span>{f.occurrences} URLs</span>}
                    </span>
                  </td>
                  <td className="endpoint">
                    <span className="method">{f.method}</span> {pathOf(f.url)}
                    {f.param && <span className="cell-sub">parameter <code>{f.param}</code></span>}
                  </td>
                  <td>{CATEGORY_LABEL[f.category]}</td>
                  <td><AiCell f={f} /></td>
                  <td>
                    <ReviewTag s={f.status} />
                    {f.status === "confirmed" && f.final_severity && (
                      <span className="cell-sub"><Sev s={f.final_severity} size="sm" /></span>
                    )}
                  </td>
                  <td className="row-go" aria-hidden><ChevronRight size={16} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
