import { Link } from "react-router-dom";
import { ArrowRight, BellRing, CheckCircle2, Layers, Radar, ShieldAlert, ShieldCheck, ShieldX, Target as TargetIcon } from "lucide-react";
import { ago, api, CATEGORIES, CATEGORY_LABEL, localPath, plural, SEVERITIES, SEVERITY_LABEL, when, type Dashboard } from "../api";
import { DeliveryChips } from "../components/Bell";
import { Empty, ErrorLine, PageHead, Panel, ScanTag, Skeleton, usePoll } from "../components/ui";

function SeverityBars({ d }: { d: Dashboard }) {
  const rows = SEVERITIES.map((s) => ({ s, c: d.severity_confirmed[s] ?? 0, o: d.severity_open[s] ?? 0 }));
  const max = Math.max(1, ...rows.map((r) => r.c + r.o));
  return (
    <div className="sevbars" role="table" aria-label="Findings by severity">
      {rows.map(({ s, c, o }) => (
        <div className="sevbar" role="row" key={s}>
          <span role="cell" className="sevbar-label">
            <i className={`dot sev-bg-${s}`} aria-hidden />
            {SEVERITY_LABEL[s]}
          </span>
          <span role="cell" className="sevbar-track">
            {c > 0 && <span className={`sevbar-fill sev-bg-${s}`} style={{ width: `${(c / max) * 100}%` }} title={`${c} confirmed`} />}
            {o > 0 && (
              <span
                className={`sevbar-fill sevbar-open sev-bg-${s}`}
                style={{ width: `${(o / max) * 100}%` }}
                title={`${o} awaiting review`}
              />
            )}
          </span>
          <span role="cell" className="sevbar-n">
            {c === 0 && o === 0 ? (
              <span className="dim">—</span>
            ) : c === 0 ? (
              <span className="strong">{o} open</span>
            ) : o === 0 ? (
              <b>{c}</b>
            ) : (
              <>
                <b>{c}</b>
                <span className="dim"> +{o} open</span>
              </>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

function Queue({ d }: { d: Dashboard }) {
  const urgent = (d.severity_open.critical ?? 0) + (d.severity_open.high ?? 0);
  const analysing = d.findings - d.ai_done;
  if (d.pending > 0) {
    const parts = [];
    if (d.severity_open.critical) parts.push(`${d.severity_open.critical} critical`);
    if (d.severity_open.high) parts.push(`${d.severity_open.high} high`);
    return (
      <section className={`queue ${urgent ? "queue-urgent" : ""}`}>
        <span className="queue-icon">{urgent ? <ShieldAlert size={22} /> : <Layers size={22} />}</span>
        <div className="queue-text">
          <p className="queue-line">
            {plural(d.pending, "finding")} {d.pending === 1 ? "is" : "are"} waiting for a decision
          </p>
          <p className="queue-sub">
            {urgent ? `Including ${parts.join(" and ")}. Start with these.` : "Each one needs to be confirmed or rejected against its evidence."}
            {analysing > 0 && ` ${analysing} still being analysed.`}
          </p>
        </div>
        <Link className="btn btn-primary" to="/findings?status=pending">
          Start reviewing <ArrowRight size={16} aria-hidden />
        </Link>
      </section>
    );
  }
  if (d.findings > 0) {
    return (
      <section className="queue queue-done">
        <span className="queue-icon"><CheckCircle2 size={22} /></span>
        <div className="queue-text">
          <p className="queue-line">Every finding has been reviewed</p>
          <p className="queue-sub">{plural(d.confirmed, "confirmed vulnerability", "confirmed vulnerabilities")} can go into the report.</p>
        </div>
        <Link className="btn btn-primary" to="/reports">Generate report</Link>
      </section>
    );
  }
  return (
    <section className="queue">
      <span className="queue-icon"><Radar size={22} /></span>
      <div className="queue-text">
        <p className="queue-line">No findings yet</p>
        <p className="queue-sub">Run a scan against a registered target to start the assessment.</p>
      </div>
      <Link className="btn btn-primary" to="/targets">Choose a target</Link>
    </section>
  );
}

function Stat({ icon: Icon, label, value, note, tone = "" }: { icon: typeof Radar; label: string; value: number; note?: string; tone?: string }) {
  return (
    <div className={`stat ${tone}`}>
      <span className="stat-icon"><Icon size={17} aria-hidden /></span>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {note && <span className="stat-note">{note}</span>}
    </div>
  );
}

function RecentAlerts() {
  const { data } = usePoll(() => api.notifications({ limit: 6 }), [], () => true, 8000);
  if (!data) return <Skeleton rows={4} />;
  if (data.length === 0)
    return (
      <p className="dim small">
        No alerts yet. When a scan finds something serious, it appears here and goes out to your{" "}
        <Link to="/settings">alert channels</Link>.
      </p>
    );
  return (
    <ul className="alert-list">
      {data.map((n) => {
        const path = localPath(n.link);
        const inner = (
          <>
            <i className={`dot sev-bg-${n.severity || "none"}`} aria-hidden />
            <span className="alert-text">
              <span className="alert-title">{n.title}</span>
              <span className="alert-meta">
                {ago(n.created_at)}
                <DeliveryChips n={n} />
              </span>
            </span>
          </>
        );
        return <li key={n.id}>{path ? <Link to={path}>{inner}</Link> : <div>{inner}</div>}</li>;
      })}
    </ul>
  );
}

export default function Overview() {
  const { data: d, error } = usePoll(() => api.dashboard(), [], (v) => v.scans_running > 0 || v.ai_done < v.findings, 3000);

  if (error) return <ErrorLine msg={error} />;
  if (!d)
    return (
      <>
        <PageHead title="Overview" />
        <Skeleton rows={6} height={22} />
      </>
    );

  if (d.targets === 0) {
    return (
      <>
        <PageHead title="Overview" />
        <Empty icon={TargetIcon} title="Register the lab application first" action={<Link className="btn btn-primary" to="/targets">Register a target</Link>}>
          Scans are limited to the scope you set on the target, so nothing can be tested before one exists.
        </Empty>
      </>
    );
  }

  return (
    <>
      <PageHead title="Overview" sub="Where the assessment stands, and what needs attention next." />
      <Queue d={d} />

      <div className="stats">
        <Stat icon={Radar} label="Scans" value={d.scans} note={d.scans_running ? `${d.scans_running} running` : undefined} tone="stat-scans" />
        <Stat icon={ShieldAlert} label="Awaiting review" value={d.pending} tone={d.pending ? "stat-urgent" : "stat-pending"} />
        <Stat icon={ShieldCheck} label="Confirmed" value={d.confirmed} tone="stat-confirmed" />
        <Stat icon={ShieldX} label="False positives" value={d.rejected} tone="stat-rejected" />
      </div>

      <div className="grid-2">
        <Panel title="By severity" icon={ShieldAlert}>
          <SeverityBars d={d} />
        </Panel>
        <Panel title="By assessment category" icon={Layers} flush>
          <table className="table">
            <thead>
              <tr><th>Category</th><th className="num">Open</th><th className="num">Confirmed</th><th className="num">Rejected</th></tr>
            </thead>
            <tbody>
              {CATEGORIES.map((c) => {
                const r = d.by_category[c] ?? { pending: 0, confirmed: 0, rejected: 0 };
                return (
                  <tr key={c}>
                    <td><Link to={`/findings?category=${c}&status=`}>{CATEGORY_LABEL[c]}</Link></td>
                    <td className={`num ${r.pending ? "" : "dim"}`}>{r.pending}</td>
                    <td className={`num ${r.confirmed ? "strong" : "dim"}`}>{r.confirmed}</td>
                    <td className="num dim">{r.rejected}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Recent scans" icon={Radar} flush>
          {d.recent_scans.length === 0 ? (
            <p className="dim pad">No scans yet.</p>
          ) : (
            <table className="table">
              <thead>
                <tr><th>Scan</th><th>Status</th><th>Started</th><th className="num">Findings</th></tr>
              </thead>
              <tbody>
                {d.recent_scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link to={`/scans/${s.id}`} className="strong">Scan {s.id}</Link>
                      <span className="cell-sub">{s.target_name}</span>
                    </td>
                    <td><ScanTag s={s.status} progress={s.progress} /></td>
                    <td className="nowrap">{when(s.started_at ?? s.created_at)}</td>
                    <td className="num">{s.finding_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title="Recent alerts" icon={BellRing} actions={<Link to="/notifications" className="small">View all</Link>}>
          <RecentAlerts />
        </Panel>
      </div>

      {Object.keys(d.redactions).length > 0 && (
        <p className="footnote">
          <ShieldCheck size={14} aria-hidden /> Removed before any data left for analysis:{" "}
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
