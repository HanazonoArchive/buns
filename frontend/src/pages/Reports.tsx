import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, plural, store, when } from "../api";
import { Empty, ErrorLine, Field, PageHead, usePoll } from "../components/ui";

export default function Reports() {
  const [params, setParams] = useSearchParams();
  const { data: targets } = usePoll(api.targets, [], () => false);
  const targetId = Number(params.get("target")) || targets?.[0]?.id || 0;
  const { data: dash } = usePoll(() => (targetId ? api.dashboard(targetId) : Promise.resolve(null)), [targetId], () => false);
  const { data: reports, refresh } = usePoll(() => api.reports(), [], () => false);
  const [preparedBy, setPreparedBy] = useState(() => store.get("buns.preparedBy"));
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
      window.open(api.reportUrl(r.id), "_blank");
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const names = Object.fromEntries((targets ?? []).map((t) => [t.id, t.name]));

  return (
    <>
      <PageHead title="Reports" sub="A PDF of the confirmed findings with their evidence, ratings and fixes." />

      {targets && targets.length === 0 ? (
        <Empty><p>Register a target and review its findings before generating a report.</p></Empty>
      ) : (
        <form className="panel report-form" onSubmit={generate}>
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
            <p className="report-state">
              The report will include <b>{plural(dash.confirmed, "confirmed finding")}</b>
              {dash.rejected > 0 && <> and list {plural(dash.rejected, "rejected candidate")} in an appendix</>}.
              {dash.pending > 0 && (
                <span className="warn-text">
                  {" "}{plural(dash.pending, "finding")} {dash.pending === 1 ? "has" : "have"} not been reviewed and will be left out.{" "}
                  <Link to={`/findings?target=${targetId}&status=pending`}>Review them first</Link>
                </span>
              )}
            </p>
          )}
          <ErrorLine msg={err} />
          <button className="btn primary" disabled={busy || !targetId || !dash?.confirmed}>
            {busy ? "Generating…" : "Generate PDF report"}
          </button>
        </form>
      )}

      {reports && reports.length > 0 && (
        <section className="panel">
          <h2>Generated reports</h2>
          <table className="list">
            <thead><tr><th>File</th><th>Target</th><th className="num">Findings</th><th>Prepared by</th><th>Created</th></tr></thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td><a href={api.reportUrl(r.id)} target="_blank" rel="noreferrer" className="mono small">{r.filename}</a></td>
                  <td>{names[r.target_id] ?? `Target ${r.target_id}`}</td>
                  <td className="num">{r.findings_count}</td>
                  <td>{r.prepared_by}</td>
                  <td>{when(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
