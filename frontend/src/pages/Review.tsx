import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  api,
  CATEGORY_LABEL,
  fid,
  pathOf,
  SEVERITIES,
  SEVERITY_LABEL,
  store,
  when,
  type FindingDetail,
  type Severity,
} from "../api";
import { CodeBlock, CvssBreakdown, HttpMessage } from "../components/evidence";
import { ErrorLine, ReviewTag, Sev, usePoll } from "../components/ui";

type Tab = "request" | "response" | "reproduce" | "sent";

function Evidence({ f }: { f: FindingDetail }) {
  const [tab, setTab] = useState<Tab>(f.response_raw ? "response" : "request");
  const needles = useMemo(() => [f.evidence, f.attack].filter(Boolean), [f.evidence, f.attack]);
  const tabs: [Tab, string][] = [
    ["request", "Request"],
    ["response", "Response"],
    ["reproduce", "Reproduce with cURL"],
    ["sent", "Sent for analysis"],
  ];
  return (
    <section className="evidence" aria-label="Evidence">
      <div className="ev-summary">
        {f.attack && (
          <p>
            <span className="k">Payload</span>
            <code>{f.attack}</code>
          </p>
        )}
        {f.evidence && (
          <p>
            <span className="k">Matched</span>
            <code className="hl">{f.evidence}</code>
          </p>
        )}
        {!f.attack && !f.evidence && <p className="dim plain">The tool recorded no payload or matched string; read the exchange below.</p>}
        {f.affected_urls.length > 1 && (
          <details className="affected">
            <summary>Seen on {f.affected_urls.length} URLs. The exchange below is one example.</summary>
            <ul>{[...new Set(f.affected_urls.map(pathOf))].map((u) => <li key={u} className="mono">{u}</li>)}</ul>
          </details>
        )}
      </div>
      <div className="tabs" role="tablist">
        {tabs.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>
      <div className="tab-body">
        {tab === "request" && <HttpMessage raw={f.request_raw} needles={needles} empty="The tool did not record the request." />}
        {tab === "response" && <HttpMessage raw={f.response_raw} needles={needles} empty="The tool did not record the response." />}
        {tab === "reproduce" &&
          (f.curl_command ? (
            <div className="pad">
              <p className="dim small">
                Run this against the lab instance to see the behaviour yourself. Set <code>TOKEN</code> from a fresh login first if the
                request needs one.
              </p>
              <CodeBlock code={f.curl_command} label="shell" />
            </div>
          ) : (
            <p className="dim pad">No request was recorded, so there is nothing to replay.</p>
          ))}
        {tab === "sent" && (
          <div className="pad">
            {f.ai_payload ? (
              <>
                <p className="dim small">
                  Exactly what left the platform for analysis. Secrets and personal data were replaced before sending
                  {f.ai_redactions && Object.keys(f.ai_redactions).length > 0
                    ? `: ${Object.entries(f.ai_redactions)
                        .map(([k, v]) => `${v} ${k.replace("_", " ")}`)
                        .join(", ")}.`
                    : "; none were found in this finding."}
                </p>
                <CodeBlock code={JSON.stringify(f.ai_payload, null, 2)} label="json" />
              </>
            ) : (
              <p className="dim">Not analysed yet.</p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function Analysis({ f, onRetry }: { f: FindingDetail; onRetry: () => void }) {
  if (f.ai_status === "pending" || f.ai_status === "running") {
    return (
      <section className="analysis">
        <h2>Analysis</h2>
        <p className="dim">Analysing the evidence… this usually takes a few seconds.</p>
      </section>
    );
  }
  if (f.ai_status === "failed") {
    return (
      <section className="analysis">
        <h2>Analysis</h2>
        <p className="error-line">{f.ai_error || "The analysis failed."}</p>
        <button className="btn" onClick={onRetry}>Run analysis again</button>
        <p className="dim small">You can still decide on this finding from the evidence alone.</p>
      </section>
    );
  }
  const offline = f.ai_model === "offline-rules";
  return (
    <section className="analysis">
      <div className="analysis-head">
        <h2>Analysis</h2>
        <span className="model" title={offline ? "No AI key configured; text comes from the built-in rules engine" : ""}>
          {offline ? "Built-in rules" : f.ai_model}
        </span>
      </div>
      <p className="lead">{f.ai_summary}</p>
      {f.ai_impact && (
        <>
          <h3>Impact</h3>
          <p>{f.ai_impact}</p>
        </>
      )}
      {f.ai_rationale && (
        <>
          <h3>True or false positive</h3>
          <p>
            {f.ai_rationale}
            {f.ai_false_positive_hint && <span className="dim"> Confidence: {f.ai_false_positive_hint}.</span>}
          </p>
        </>
      )}
      <h3>
        Suggested rating <Sev s={f.ai_severity} />
      </h3>
      <CvssBreakdown vector={f.ai_cvss_vector} score={f.ai_cvss_score} />
      <button className="link small" onClick={onRetry}>Re-run analysis</button>
    </section>
  );
}

function Remediation({ f, onRetry }: { f: FindingDetail; onRetry: () => void }) {
  if (f.status !== "confirmed") return null;
  const r = f.remediation;
  return (
    <section className="remediation">
      <div className="analysis-head">
        <h2>Remediation</h2>
        {f.remediation_model && <span className="model">{f.remediation_model === "offline-rules" ? "Built-in rules" : f.remediation_model}</span>}
      </div>
      {(f.remediation_status === "running" || f.remediation_status === "none") && <p className="dim">Writing fix guidance for the confirmed finding…</p>}
      {f.remediation_status === "failed" && (
        <>
          <p className="error-line">{r?.error ?? "Remediation could not be generated."}</p>
          <button className="btn" onClick={onRetry}>Try again</button>
        </>
      )}
      {f.remediation_status === "done" && r && (
        <>
          {r.root_cause && <p className="lead">{r.root_cause}</p>}
          <ol className="steps">{r.steps?.map((s, i) => <li key={i}>{s}</li>)}</ol>
          {r.code_example && !r.code_example.startsWith("// No generic") && <CodeBlock code={r.code_example} label={r.code_language} />}
          {r.verification && (
            <p>
              <b>Check the fix.</b> {r.verification}
            </p>
          )}
          {r.references && r.references.length > 0 && <p className="dim small">See: {r.references.join("; ")}</p>}
          <button className="link small" onClick={onRetry}>Regenerate</button>
        </>
      )}
    </section>
  );
}

function DecisionBar({ f, onDone }: { f: FindingDetail; onDone: (f: FindingDetail, advance: boolean) => void }) {
  const suggested = (f.ai_severity || f.tool_severity) as Severity;
  const [reviewer, setReviewer] = useState(() => f.reviewer || store.get("buns.reviewer"));
  const [severity, setSeverity] = useState<Severity>((f.final_severity || suggested) as Severity);
  const [note, setNote] = useState(f.review_note);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    setSeverity((f.final_severity || suggested) as Severity);
    setNote(f.review_note);
    setErr("");
  }, [f.id, f.final_severity, f.review_note, suggested]);

  const decide = async (decision: "confirm" | "reject" | "reset") => {
    setBusy(true);
    setErr("");
    try {
      if (reviewer) store.set("buns.reviewer", reviewer);
      const out = await api.review(f.id, { decision, severity: decision === "confirm" ? severity : undefined, reviewer, note });
      onDone(out, decision !== "reset");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (f.status !== "pending") {
    return (
      <div className="decision decided">
        <p>
          <ReviewTag s={f.status} />
          {f.status === "confirmed" && <span>as <Sev s={f.final_severity} /></span>}
          <span>by <b>{f.reviewer}</b> on {when(f.reviewed_at)}</span>
          {f.review_note && <span className="dim">“{f.review_note}”</span>}
        </p>
        <button className="btn" disabled={busy} onClick={() => decide("reset")}>Reopen</button>
      </div>
    );
  }

  const changed = severity !== suggested;
  return (
    <div className="decision">
      <label className="d-field">
        <span>Assessor</span>
        <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="Your name" autoComplete="name" />
      </label>
      <label className="d-field">
        <span>Severity</span>
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={`sev-select sev-t-${severity}`}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
              {s === suggested ? " (suggested)" : ""}
            </option>
          ))}
        </select>
      </label>
      <label className="d-field grow">
        <span>Note {changed ? "(required: why the rating differs)" : "(required to reject)"}</span>
        <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you checked, or why it is a false positive" />
      </label>
      <div className="d-actions">
        <button className="btn" disabled={busy} onClick={() => decide("reject")}>Reject as false positive</button>
        <button className="btn primary" disabled={busy} onClick={() => decide("confirm")}>Confirm finding</button>
      </div>
      {err && <p className="error-line d-err" role="alert">{err}</p>}
    </div>
  );
}

export default function Review() {
  const { id } = useParams();
  const nav = useNavigate();
  const loc = useLocation();
  const order: number[] = (loc.state as { order?: number[] } | null)?.order ?? [];
  const fidNum = Number(id);

  const { data: f, error, refresh, setData } = usePoll(
    () => api.finding(fidNum),
    [fidNum],
    (v) => ["pending", "running"].includes(v.ai_status) || (v.status === "confirmed" && ["none", "running"].includes(v.remediation_status)),
    1500,
  );

  if (error) return <ErrorLine msg={error} />;
  if (!f) return null;

  const pos = order.indexOf(f.id);
  const next = pos >= 0 && pos < order.length - 1 ? order[pos + 1] : null;
  const prev = pos > 0 ? order[pos - 1] : null;

  const onDone = (out: FindingDetail, advance: boolean) => {
    setData(out);
    if (advance && out.status === "rejected" && next) nav(`/findings/${next}`, { state: { order } });
    else refresh();
  };

  return (
    <div className="review">
      <div className="crumbs">
        <Link to="/findings">Findings</Link>
        <span className="pager">
          {prev && <Link to={`/findings/${prev}`} state={{ order }}>Previous</Link>}
          {pos >= 0 && <span className="dim">{pos + 1} of {order.length}</span>}
          {next && <Link to={`/findings/${next}`} state={{ order }}>Next</Link>}
        </span>
      </div>

      <header className={`review-head sev-edge-${f.effective_severity}`}>
        <h1>{f.title}</h1>
        <dl className="facts">
          <div><dt>ID</dt><dd>{fid(f.id)}</dd></div>
          <div><dt>Endpoint</dt><dd className="mono">{f.method} {pathOf(f.url)}</dd></div>
          {f.param && <div><dt>Parameter</dt><dd className="mono">{f.param}</dd></div>}
          <div><dt>Category</dt><dd>{CATEGORY_LABEL[f.category]}</dd></div>
          <div><dt>OWASP</dt><dd>{f.owasp || "–"}</dd></div>
          {f.wstg && <div><dt>WSTG</dt><dd>{f.wstg}</dd></div>}
          {f.cwe_id && <div><dt>CWE</dt><dd><a href={`https://cwe.mitre.org/data/definitions/${f.cwe_id}.html`} target="_blank" rel="noreferrer">CWE-{f.cwe_id}</a></dd></div>}
          <div>
            <dt>Reported by</dt>
            <dd>
              {f.source === "zap" ? "OWASP ZAP" : "cURL probe"} <span className="dim">({f.tool_rule_id}, {SEVERITY_LABEL[f.tool_severity]}{f.tool_confidence && `, ${f.tool_confidence.toLowerCase()} confidence`})</span>
            </dd>
          </div>
        </dl>
        {f.description && f.source === "zap" && <p className="tool-desc">{f.description}</p>}
      </header>

      <div className="split">
        <Evidence f={f} />
        <div className="right">
          <Analysis f={f} onRetry={() => api.reanalyze(f.id).then(setData).then(refresh)} />
          <Remediation f={f} onRetry={() => api.remediate(f.id).then(setData).then(refresh)} />
        </div>
      </div>

      <DecisionBar f={f} onDone={onDone} />
      {f.status === "confirmed" && next && (
        <p className="after-decide">
          <Link className="btn" to={`/findings/${next}`} state={{ order }}>Next finding</Link>
        </p>
      )}
    </div>
  );
}
