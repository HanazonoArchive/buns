import { Link } from "react-router-dom";
import { api, CATEGORIES, CATEGORY_LABEL, plural, SEVERITIES, SEVERITY_LABEL, when, type Dashboard } from "../api";
import { Empty, ErrorLine, PageHead, ScanTag, usePoll } from "../components/ui";

function SeverityBar({ d }: { d: Dashboard }) {
  const rows = SEVERITIES.map((s) => ({ s, c: d.severity_confirmed[s] ?? 0, o: d.severity_open[s] ?? 0 }));
  const max = Math.max(1, ...rows.map((r) => r.c + r.o));
  return (
    <div className="sevbars" role="table" aria-label="Findings by severity">
      {rows.map(({ s, c, o }) => (
        <div className="sevbar" role="row" key={s}>
          <span role="cell" className="sevbar-label">{SEVERITY_LABEL[s]}</span>
          <span role="cell" className="sevbar-track">
            <span className={`sevbar-fill sev-bg-${s}`} style={{ width: `${(c / max) * 100}%` }} title={`${c} confirmed`} />
            <span className={`sevbar-fill sevbar-open sev-bd-${s}`} style={{ width: `${(o / max) * 100}%` }} title={`${o} awaiting review`} />
          </span>
          <span role="cell" className="sevbar-n">
            <b>{c}</b>
            {o > 0 && <span className="dim"> +{o}</span>}
          </span>
        </div>
      ))}
      <p className="legend">
        <span className="legend-solid" /> confirmed <span className="legend-open" /> awaiting review
      </p>
    </div>
  );
}

export default function Overview() {
  const { data: d, error } = usePoll(() => api.dashboard(), [], (v) => v.scans_running > 0 || v.ai_done < v.findings, 3000);

  if (error) return <ErrorLine msg={error} />;
  if (!d) return null;

  if (d.targets === 0) {
    return (
      <>
        <PageHead title="Overview" />
        <Empty>
          <p>No target is registered yet. Register the lab application first; scans are limited to the scope you set there.</p>
          <Link className="btn primary" to="/targets">Register a target</Link>
        </Empty>
      </>
    );
  }

  const analysing = d.findings - d.ai_done;
  return (
    <>
      <PageHead title="Overview" />

      <section className="queue">
        {d.pending > 0 ? (
          <>
            <p className="queue-line">
              <b>{plural(d.pending, "finding")}</b> {d.pending === 1 ? "is" : "are"} waiting for a decision.
              {analysing > 0 && <span className="dim"> {analysing} still being analysed.</span>}
            </p>
            <Link className="btn primary" to="/findings?status=pending">Start reviewing</Link>
          </>
        ) : d.findings > 0 ? (
          <>
            <p className="queue-line">Every finding has been reviewed. The report can be generated.</p>
            <Link className="btn primary" to="/reports">Generate report</Link>
          </>
        ) : (
          <>
            <p className="queue-line">No findings yet. Run a scan against a registered target.</p>
            <Link className="btn primary" to="/targets">Choose a target</Link>
          </>
        )}
      </section>

      <dl className="tally">
        <div><dt>Scans</dt><dd>{d.scans}{d.scans_running > 0 && <small> ({d.scans_running} running)</small>}</dd></div>
        <div><dt>Findings</dt><dd>{d.findings}</dd></div>
        <div><dt>Confirmed</dt><dd>{d.confirmed}</dd></div>
        <div><dt>False positives</dt><dd>{d.rejected}</dd></div>
      </dl>

      <div className="two">
        <section className="panel">
          <h2>By severity</h2>
          <SeverityBar d={d} />
        </section>

        <section className="panel">
          <h2>By assessment category</h2>
          <table className="matrix">
            <thead>
              <tr><th>Category</th><th>Open</th><th>Confirmed</th><th>Rejected</th></tr>
            </thead>
            <tbody>
              {CATEGORIES.map((c) => {
                const r = d.by_category[c] ?? { pending: 0, confirmed: 0, rejected: 0 };
                return (
                  <tr key={c}>
                    <td><Link to={`/findings?category=${c}`}>{CATEGORY_LABEL[c]}</Link></td>
                    <td className={r.pending ? "" : "dim"}>{r.pending}</td>
                    <td className={r.confirmed ? "strong" : "dim"}>{r.confirmed}</td>
                    <td className="dim">{r.rejected}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      </div>

      <section className="panel">
        <h2>Recent scans</h2>
        {d.recent_scans.length === 0 ? (
          <p className="dim">No scans yet.</p>
        ) : (
          <table className="list">
            <thead>
              <tr><th>Scan</th><th>Target</th><th>Status</th><th>Started</th><th className="num">Endpoints</th><th className="num">Findings</th></tr>
            </thead>
            <tbody>
              {d.recent_scans.map((s) => (
                <tr key={s.id}>
                  <td><Link to={`/scans/${s.id}`}>Scan {s.id}</Link></td>
                  <td>{s.target_name}</td>
                  <td><ScanTag s={s.status} />{s.status === "running" && <span className="dim"> {s.progress}%</span>}</td>
                  <td>{when(s.started_at ?? s.created_at)}</td>
                  <td className="num">{s.endpoint_count}</td>
                  <td className="num">{s.finding_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {Object.keys(d.redactions).length > 0 && (
        <p className="footnote">
          Removed before any data left for analysis:{" "}
          {Object.entries(d.redactions)
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => `${v} ${k.replace("_", " ")}`)
            .join(", ")}
          .
        </p>
      )}
    </>
  );
}
