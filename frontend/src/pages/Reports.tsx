import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, Download, FileText, FileDown, Loader2 } from "lucide-react";
import { useAuth } from "../auth";
import { api, plural, store, when } from "../api";
import { useToast } from "../components/toast";
import { Empty, ErrorLine, Field, PageHead, Panel, Sev, usePoll } from "../components/ui";

export default function Reports() {
  const [params, setParams] = useSearchParams();
  const toast = useToast();
  const { data: targets } = usePoll(api.targets, [], () => false);
  const targetId = Number(params.get("target")) || targets?.[0]?.id || 0;
  const { data: dash } = usePoll(() => (targetId ? api.dashboard(targetId) : Promise.resolve(null)), [targetId], () => false);
  const { data: reports, refresh } = usePoll(() => api.reports(), [], () => false);
  const { me, canWrite } = useAuth();
  const [preparedBy, setPreparedBy] = useState(() => store.get("buns.preparedBy") || me.name);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => setErr(""), [targetId]);

  const generate = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      store.set("buns.preparedBy", preparedBy);
      const r = await api.createReport(targetId, preparedBy);
      await refresh();
      toast({ kind: "success", title: "Report generated", text: r.filename, action: { label: "Open PDF", onClick: () => window.open(api.reportUrl(r.id), "_blank") } });
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const names = Object.fromEntries((targets ?? []).map((t) => [t.id, t.name]));

  return (
    <>
      <PageHead title="Reports" sub="A PDF of the confirmed findings with their evidence, ratings and fixes, ready to hand to the system owner." />

      {!canWrite ? null : targets && targets.length === 0 ? (
        <Empty icon={FileText} title="Nothing to report yet">Register a target and review its findings before generating a report.</Empty>
      ) : (
        <Panel title="New report" icon={FileDown} className="report-form">
          <form onSubmit={generate}>
            <div className="form-pair">
              <Field label="Target">
                <select value={targetId} onChange={(e) => setParams({ target: e.target.value })}>
                  {targets?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
              </Field>
              <Field label="Prepared by">
                <input required value={preparedBy} onChange={(e) => setPreparedBy(e.target.value)} placeholder="Agsoy, Alves, Morales" />
              </Field>
            </div>
            {dash && (
              <div className="report-state">
                <div className="report-counts">
                  <span><b>{dash.confirmed}</b> confirmed</span>
                  <span><b>{dash.rejected}</b> in the appendix</span>
                  <span className={dash.pending ? "warn-text" : ""}><b>{dash.pending}</b> not reviewed</span>
                </div>
                {dash.confirmed > 0 && (
                  <div className="report-sev">
                    {(["critical", "high", "medium", "low", "info"] as const).filter((s) => dash.severity_confirmed[s]).map((s) => (
                      <span key={s} className="inline"><Sev s={s} size="sm" /> {dash.severity_confirmed[s]}</span>
                    ))}
                  </div>
                )}
                {dash.pending > 0 && (
                  <p className="callout warn">
                    <AlertTriangle size={16} aria-hidden />
                    <span>
                      {plural(dash.pending, "finding")} {dash.pending === 1 ? "has" : "have"} not been reviewed and will be left out.{" "}
                      <Link to={`/findings?target=${targetId}&status=pending`}>Review them first</Link>
                    </span>
                  </p>
                )}
              </div>
            )}
            <ErrorLine msg={err} />
            <button className="btn btn-primary" disabled={busy || !targetId || !dash?.confirmed}>
              {busy ? <Loader2 size={16} className="spin" /> : <FileDown size={16} />}
              {busy ? "Generating…" : "Generate PDF report"}
            </button>
          </form>
        </Panel>
      )}

      {reports && reports.length > 0 && (
        <Panel title="Generated reports" icon={FileText} flush>
          <table className="table">
            <thead><tr><th>File</th><th>Target</th><th className="num">Findings</th><th>Prepared by</th><th>Created</th><th aria-hidden /></tr></thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td className="mono small">{r.filename}</td>
                  <td>{names[r.target_id] ?? `Target ${r.target_id}`}</td>
                  <td className="num">{r.findings_count}</td>
                  <td>{r.prepared_by}</td>
                  <td className="nowrap">{when(r.created_at)}</td>
                  <td className="num">
                    <a href={api.reportUrl(r.id)} target="_blank" rel="noreferrer" className="btn btn-sm"><Download size={14} /> PDF</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </>
  );
}
