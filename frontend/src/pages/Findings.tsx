import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ChevronRight, Globe, Inbox, Loader2, Search, X } from "lucide-react";
import { api, CATEGORIES, CATEGORY_LABEL, fid, pathOf, SEVERITIES, SEVERITY_LABEL, store, type FindingSummary } from "../api";
import { Empty, ErrorLine, PageHead, Skeleton, usePoll } from "../components/ui";

const STATUSES: [string, string][] = [
  ["pending", "Needs review"],
  ["confirmed", "Confirmed"],
  ["rejected", "False positives"],
  ["", "All"],
];

function AiCell({ f }: { f: FindingSummary }) {
  if (f.ai_status === "pending" || f.ai_status === "running")
    return (
      <span className="suggest-wait">
        <Loader2 size={13} className="spin" aria-hidden /> Analysing
      </span>
    );
  if (f.ai_status === "failed") return <span className="suggest-failed">Analysis failed</span>;
  if (!f.ai_severity) return <span className="dim">–</span>;
  return (
    <span className="suggest">
      <span className={`suggest-sev sev-t-${f.ai_severity}`}>{SEVERITY_LABEL[f.ai_severity]}</span>
      {f.ai_cvss_score !== null && <span className="suggest-score">{f.ai_cvss_score.toFixed(1)}</span>}
    </span>
  );
}

const STATUS_TEXT = { pending: "Needs review", confirmed: "Confirmed", rejected: "False positive" } as const;

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const nav = useNavigate();
  const status = params.get("status") ?? "pending";
  const category = params.get("category") ?? "";
  const severity = params.get("severity") ?? "";
  // The chosen target is remembered, so switching pages does not reset it.
  const target = params.has("target") ? params.get("target") ?? "" : store.get("buns.findingsTarget");
  const scan = params.get("scan") ?? "";
  const [q, setQ] = useState("");

  const { data: targets } = usePoll(api.targets, [], () => false);
  const { data: fetched, error } = usePoll(
    () => api.findings({ scan_id: scan ? +scan : undefined }),
    [scan],
    (rows) => rows.some((f) => f.ai_status === "pending" || f.ai_status === "running"),
    2500,
  );

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value || key === "status" || key === "target") next.set(key, value);
    else next.delete(key);
    if (key === "target") store.set("buns.findingsTarget", value);
    setParams(next, { replace: true });
  };

  const multi = (targets?.length ?? 0) > 1;
  // Ignore a remembered target that no longer exists.
  const activeTarget = target && targets?.some((t) => String(t.id) === target) ? target : "";
  const perTarget = useMemo(() => {
    const c: Record<string, number> = {};
    (fetched ?? []).forEach((f) => (c[f.target_id] = (c[f.target_id] ?? 0) + 1));
    return c;
  }, [fetched]);
  const all = useMemo(
    () => (fetched ? fetched.filter((f) => !activeTarget || String(f.target_id) === activeTarget) : null),
    [fetched, activeTarget],
  );

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
  const filtered = !!(category || severity || q || scan || activeTarget);

  return (
    <>
      <PageHead title="Findings" sub="Everything the tools reported. Nothing reaches the report until an assessor confirms it against the evidence." />

      {multi && targets && (
        <div className="target-switch" role="tablist" aria-label="Target">
          <span className="target-switch-label">Target</span>
          <button role="tab" aria-selected={!activeTarget} className={!activeTarget ? "on" : ""} onClick={() => set("target", "")}>
            All targets <span className="seg-count">{fetched?.length ?? 0}</span>
          </button>
          {targets.map((t) => (
            <button key={t.id} role="tab" aria-selected={activeTarget === String(t.id)} className={activeTarget === String(t.id) ? "on" : ""} onClick={() => set("target", String(t.id))} title={t.base_url}>
              <Globe size={14} aria-hidden /> {t.name} <span className="seg-count">{perTarget[t.id] ?? 0}</span>
            </button>
          ))}
        </div>
      )}

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
                      {multi && !activeTarget && <span className="row-target"><Globe size={12} aria-hidden /> {f.target_name}</span>}
                      {f.times_seen > 1 && <span title={`Reported by ${f.times_seen} scans of this target`}>seen in {f.times_seen} scans</span>}
                      {f.not_in_latest_scan && (
                        <span className="row-gone" title="The latest scan covered this category but did not report it. It may have been fixed.">
                          not found in scan {f.not_in_latest_scan}
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="endpoint">
                    <span className="method">{f.method}</span> {pathOf(f.url)}
                    {f.param && <span className="cell-sub">parameter <code>{f.param}</code></span>}
                  </td>
                  <td>{CATEGORY_LABEL[f.category]}</td>
                  <td><AiCell f={f} /></td>
                  <td>
                    <span className={`status-text ${f.status}`}>{STATUS_TEXT[f.status]}</span>
                    {f.status === "confirmed" && f.final_severity && (
                      <span className={`status-sub sev-t-${f.final_severity}`}>as {SEVERITY_LABEL[f.final_severity]}</span>
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
