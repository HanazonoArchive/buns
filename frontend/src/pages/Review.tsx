import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  BellRing,
  Check,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  FileSearch,
  Loader2,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Wrench,
  X,
} from "lucide-react";
import {
  ago,
  api,
  CATEGORY_LABEL,
  fid,
  pathOf,
  SEVERITIES,
  SEVERITY_LABEL,
  when,
  type FindingDetail,
  type Notice,
  type Severity,
} from "../api";
import { CodeBlock, CvssBreakdown, HttpMessage } from "../components/evidence";
import { DeliveryChips } from "../components/Bell";
import { useAuth } from "../auth";
import { useToast } from "../components/toast";
import { ErrorLine, Kbd, Sev, Skeleton, usePoll } from "../components/ui";

type Tab = "request" | "response" | "reproduce" | "sent";

const typing = (e: KeyboardEvent) => {
  const el = e.target as HTMLElement;
  return el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName);
};

function Lifecycle({ f, notices }: { f: FindingDetail; notices: Notice[] | null }) {
  const sent = (notices ?? []).flatMap((n) => n.deliveries).filter((d) => d.status === "sent");
  const analysed = f.ai_status === "done";
  const steps = [
    { icon: ScanSearch, label: "Detected", detail: `${f.source === "zap" ? "OWASP ZAP" : "cURL probe"}, ${ago(f.created_at)}`, state: "done" },
    {
      icon: FileSearch,
      label: "Analysed",
      detail: analysed ? (f.ai_model === "offline-rules" ? "Built-in rules" : f.ai_model) : f.ai_status === "failed" ? "Failed" : "In progress",
      state: analysed ? "done" : f.ai_status === "failed" ? "failed" : "now",
    },
    {
      icon: ShieldCheck,
      label: f.status === "rejected" ? "Rejected" : f.status === "pending" ? "Verify" : "Verified",
      detail: f.status === "pending" ? "Waiting for an assessor" : `${f.reviewer}, ${ago(f.reviewed_at)}`,
      state: f.status === "pending" ? (analysed ? "now" : "") : f.status === "rejected" ? "rejected" : "done",
    },
    {
      icon: Wrench,
      label: "Fix ready",
      detail:
        f.status !== "confirmed" ? "After confirmation" : f.remediation_status === "done" ? "Remediation written" : f.remediation_status === "failed" ? "Failed" : "Writing",
      state: f.status !== "confirmed" ? "" : f.remediation_status === "done" ? "done" : f.remediation_status === "failed" ? "failed" : "now",
    },
    {
      icon: BellRing,
      label: "Owner notified",
      detail: notices === null ? "" : notices.length === 0 ? "No alert sent" : sent.length ? `${sent.length} delivered, ${ago(notices[0].created_at)}` : "In-app only",
      state: notices && notices.length ? "done" : "",
    },
  ];
  return (
    <ol className="lifecycle" aria-label="Finding lifecycle">
      {steps.map(({ icon: Icon, label, detail, state }) => (
        <li key={label} className={`lc-${state || "todo"}`}>
          <span className="lc-icon"><Icon size={15} aria-hidden /></span>
          <span className="lc-text">
            <b>{label}</b>
            <span>{detail}</span>
          </span>
        </li>
      ))}
    </ol>
  );
}

function Evidence({ f }: { f: FindingDetail }) {
  const [tab, setTab] = useState<Tab>(f.response_raw ? "response" : "request");
  const needles = useMemo(() => [f.evidence, f.attack].filter(Boolean), [f.evidence, f.attack]);
  const urls = useMemo(() => [...new Set(f.affected_urls.map(pathOf))], [f.affected_urls]);
  const tabs: [Tab, string][] = [
    ["request", "Request"],
    ["response", "Response"],
    ["reproduce", "Reproduce"],
    ["sent", "Sent for analysis"],
  ];
  return (
    <section className="card evidence" aria-label="Evidence">
      <header className="card-head">
        <h2>Evidence</h2>
        <span className="dim small">Raw HTTP exchange recorded by the tool</span>
      </header>
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
        {!f.attack && !f.evidence && <p className="plain dim">No payload or matched string was recorded; read the exchange below.</p>}
        {urls.length > 1 && (
          <details className="affected">
            <summary>Seen on {urls.length} URLs. The exchange below is one example.</summary>
            <ul>{urls.map((u) => <li key={u} className="mono">{u}</li>)}</ul>
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
                Run this against the lab instance to see the behaviour yourself. Set <code>TOKEN</code> from a fresh login first if the request needs one.
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
                  Exactly what left the platform for analysis. Secrets and personal data were replaced first
                  {f.ai_redactions && Object.keys(f.ai_redactions).length > 0
                    ? `: ${Object.entries(f.ai_redactions).map(([k, v]) => `${v} ${k.replace("_", " ")}`).join(", ")}.`
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

function Analysis({ f, onRetry }: { f: FindingDetail; onRetry?: () => void }) {
  const offline = f.ai_model === "offline-rules";
  return (
    <section className="card analysis">
      <header className="card-head">
        <h2>Analysis</h2>
        {f.ai_status === "done" && (
          <span className="model" title={offline ? "No AI key configured; text comes from the built-in rules engine" : ""}>
            {offline ? "Built-in rules" : f.ai_model}
          </span>
        )}
      </header>
      <div className="card-body">
        {(f.ai_status === "pending" || f.ai_status === "running") && (
          <>
            <p className="dim inline"><Loader2 size={15} className="spin" aria-hidden /> Analysing the evidence. This usually takes a few seconds.</p>
            <Skeleton rows={5} />
          </>
        )}
        {f.ai_status === "failed" && (
          <>
            <ErrorLine msg={f.ai_error || "The analysis failed."} />
            {onRetry && <button className="btn" onClick={onRetry}><RotateCcw size={15} /> Run analysis again</button>}
            <p className="dim small">You can still decide on this finding from the evidence alone.</p>
          </>
        )}
        {f.ai_status === "done" && (
          <>
            <p className="lead">{f.ai_summary}</p>
            {f.ai_impact && (
              <div className="analysis-block">
                <h3>Impact</h3>
                <p>{f.ai_impact}</p>
              </div>
            )}
            {f.ai_rationale && (
              <div className="analysis-block">
                <h3>True or false positive</h3>
                <p>
                  {f.ai_rationale}
                  {f.ai_false_positive_hint && <span className="dim"> Confidence: {f.ai_false_positive_hint}.</span>}
                </p>
              </div>
            )}
            <div className="analysis-block">
              <h3>Suggested rating</h3>
              <CvssBreakdown vector={f.ai_cvss_vector} score={f.ai_cvss_score} severity={f.ai_severity} />
            </div>
            {onRetry && <button className="link small inline" onClick={onRetry}><RotateCcw size={13} /> Re-run analysis</button>}
          </>
        )}
      </div>
    </section>
  );
}

function Remediation({ f, onRetry }: { f: FindingDetail; onRetry?: () => void }) {
  if (f.status !== "confirmed") return null;
  const r = f.remediation;
  return (
    <section className="card remediation">
      <header className="card-head">
        <h2>Remediation</h2>
        {f.remediation_model && <span className="model">{f.remediation_model === "offline-rules" ? "Built-in rules" : f.remediation_model}</span>}
      </header>
      <div className="card-body">
        {(f.remediation_status === "running" || f.remediation_status === "none") && (
          <>
            <p className="dim inline"><Loader2 size={15} className="spin" aria-hidden /> Writing fix guidance for the confirmed finding.</p>
            <Skeleton rows={4} />
          </>
        )}
        {f.remediation_status === "failed" && (
          <>
            <ErrorLine msg={r?.error ?? "Remediation could not be generated."} />
            {onRetry && <button className="btn" onClick={onRetry}><RotateCcw size={15} /> Try again</button>}
          </>
        )}
        {f.remediation_status === "done" && r && (
          <>
            {r.root_cause && <p className="lead">{r.root_cause}</p>}
            <ol className="steps">{r.steps?.map((s, i) => <li key={i}>{s}</li>)}</ol>
            {r.code_example && !r.code_example.startsWith("// No generic") && <CodeBlock code={r.code_example} label={r.code_language} />}
            {r.verification && (
              <p className="verify">
                <Check size={15} aria-hidden /> <span><b>Check the fix.</b> {r.verification}</span>
              </p>
            )}
            {r.references && r.references.length > 0 && <p className="dim small">References: {r.references.join("; ")}</p>}
            {onRetry && <button className="link small inline" onClick={onRetry}><RotateCcw size={13} /> Regenerate</button>}
          </>
        )}
      </div>
    </section>
  );
}

function DecisionBar({ f, onDone }: { f: FindingDetail; onDone: (f: FindingDetail, decision: string) => void }) {
  const suggested = (f.ai_severity || f.tool_severity) as Severity;
  const { me, canWrite } = useAuth();
  const [severity, setSeverity] = useState<Severity>((f.final_severity || suggested) as Severity);
  const [note, setNote] = useState(f.review_note);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const noteRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setSeverity((f.final_severity || suggested) as Severity);
    setNote(f.review_note);
    setErr("");
  }, [f.id, f.final_severity, f.review_note, suggested]);

  const decide = useCallback(
    async (decision: "confirm" | "reject" | "reset") => {
      setBusy(true);
      setErr("");
      try {
        const out = await api.review(f.id, { decision, severity: decision === "confirm" ? severity : undefined, note });
        onDone(out, decision);
      } catch (e) {
        setErr((e as Error).message);
        if (/note|explain|why/i.test((e as Error).message)) noteRef.current?.focus();
      } finally {
        setBusy(false);
      }
    },
    [f.id, note, onDone, severity],
  );

  useEffect(() => {
    if (f.status !== "pending" || !canWrite) return;
    const onKey = (e: KeyboardEvent) => {
      if (typing(e) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "c") { e.preventDefault(); decide("confirm"); }
      if (e.key === "x") { e.preventDefault(); decide("reject"); }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [decide, f.status, canWrite]);

  if (f.status !== "pending") {
    return (
      <div className="decision decided">
        <p>
          <span className={`status-text ${f.status}`}>{f.status === "confirmed" ? "Confirmed" : "False positive"}</span>
          {f.status === "confirmed" && f.final_severity && (
            <span>as <span className={`status-text sev-t-${f.final_severity}`}>{SEVERITY_LABEL[f.final_severity as Severity]}</span></span>
          )}
          <span>by <b>{f.reviewer}</b>, {when(f.reviewed_at)}</span>
          {f.review_note && <span className="dim note-quote">“{f.review_note}”</span>}
        </p>
        {canWrite && <button className="btn" disabled={busy} onClick={() => decide("reset")}><RotateCcw size={15} /> Reopen</button>}
      </div>
    );
  }

  const changed = severity !== suggested;
  if (!canWrite) {
    return (
      <div className="decision decided">
        <p>
          <span className="status-text pending">Waiting for an assessor</span>
          <span className="dim">Your account is a Viewer, so you can read this finding but not decide on it.</span>
        </p>
      </div>
    );
  }
  return (
    <div className="decision">
      <div className="d-field d-who">
        <span>Assessor</span>
        <b title={me.email}>{me.name}</b>
      </div>
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
        <input ref={noteRef} value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you checked, or why it is a false positive" />
      </label>
      <div className="d-actions">
        <button className="btn" disabled={busy} onClick={() => decide("reject")} title="Shortcut: X">
          <X size={16} /> Reject <Kbd>X</Kbd>
        </button>
        <button className="btn btn-primary" disabled={busy} onClick={() => decide("confirm")} title="Shortcut: C">
          <Check size={16} /> Confirm <Kbd>C</Kbd>
        </button>
      </div>
      {err && <div className="d-err"><ErrorLine msg={err} /></div>}
    </div>
  );
}

export default function Review() {
  const { id } = useParams();
  const nav = useNavigate();
  const loc = useLocation();
  const toast = useToast();
  const order: number[] = (loc.state as { order?: number[] } | null)?.order ?? [];
  const fidNum = Number(id);

  const { canWrite } = useAuth();
  const { data: f, error, refresh, setData } = usePoll(
    () => api.finding(fidNum),
    [fidNum],
    (v) => ["pending", "running"].includes(v.ai_status) || (v.status === "confirmed" && ["none", "running"].includes(v.remediation_status)),
    1500,
  );
  const { data: notices, refresh: refreshNotices } = usePoll(
    () => api.notifications({ finding_id: fidNum, limit: 20 }),
    [fidNum],
    (v) => v.some((n) => n.deliveries.some((d) => d.status === "queued")),
    1500,
  );

  const pos = f ? order.indexOf(f.id) : -1;
  const next = pos >= 0 && pos < order.length - 1 ? order[pos + 1] : null;
  const prev = pos > 0 ? order[pos - 1] : null;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (typing(e) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "j" && next) nav(`/findings/${next}`, { state: { order } });
      if (e.key === "k" && prev) nav(`/findings/${prev}`, { state: { order } });
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [next, prev, nav, order]);

  if (error) return <ErrorLine msg={error} />;
  if (!f)
    return (
      <div className="review">
        <Skeleton rows={3} height={26} />
      </div>
    );

  const onDone = (out: FindingDetail, decision: string) => {
    setData(out);
    window.setTimeout(refreshNotices, 800);
    if (decision === "confirm") {
      toast({
        kind: "success",
        title: `Confirmed as ${SEVERITY_LABEL[out.final_severity as Severity]}`,
        text: "Fix guidance is being written. Subscribed alert channels are being notified.",
        action: next ? { label: "Next finding", onClick: () => nav(`/findings/${next}`, { state: { order } }) } : undefined,
      });
    } else if (decision === "reject") {
      toast({ kind: "info", title: "Marked as a false positive", text: "It will be listed in the report appendix with your note." });
      if (next) nav(`/findings/${next}`, { state: { order } });
    } else {
      toast({ kind: "info", title: "Finding reopened" });
    }
    refresh();
  };

  return (
    <div className="review">
      <div className="crumbs">
        <Link to="/findings" className="inline"><ArrowLeft size={15} /> Findings</Link>
        {pos >= 0 && (
          <span className="pager">
            <button className="icon-btn" disabled={!prev} onClick={() => prev && nav(`/findings/${prev}`, { state: { order } })} aria-label="Previous finding" title="Previous (K)">
              <ChevronLeft size={17} />
            </button>
            <span className="dim small">{pos + 1} of {order.length}</span>
            <button className="icon-btn" disabled={!next} onClick={() => next && nav(`/findings/${next}`, { state: { order } })} aria-label="Next finding" title="Next (J)">
              <ChevronRight size={17} />
            </button>
          </span>
        )}
      </div>

      <header className={`review-head edge-${f.effective_severity}`}>
        <div className="review-title">
          <Sev s={f.effective_severity} size="lg" />
          <h1>{f.title}</h1>
        </div>
        <dl className="facts">
          <div><dt>ID</dt><dd className="mono">{fid(f.id)}</dd></div>
          <div><dt>Endpoint</dt><dd className="mono">{f.method} {pathOf(f.url)}</dd></div>
          {f.param && <div><dt>Parameter</dt><dd className="mono">{f.param}</dd></div>}
          <div><dt>Category</dt><dd>{CATEGORY_LABEL[f.category]}</dd></div>
          <div><dt>OWASP</dt><dd>{f.owasp || "–"}</dd></div>
          {f.wstg && <div><dt>WSTG</dt><dd>{f.wstg}</dd></div>}
          {f.cwe_id && (
            <div>
              <dt>CWE</dt>
              <dd>
                <a href={`https://cwe.mitre.org/data/definitions/${f.cwe_id}.html`} target="_blank" rel="noreferrer" className="inline">
                  CWE-{f.cwe_id} <ExternalLink size={12} aria-hidden />
                </a>
              </dd>
            </div>
          )}
          {f.seen_in_scans.length > 0 && (
            <div>
              <dt>Seen in</dt>
              <dd>
                {f.seen_in_scans.map((sid, i) => (
                  <span key={sid}>
                    {i > 0 && ", "}
                    <Link to={`/scans/${sid}`}>scan {sid}</Link>
                  </span>
                ))}
                {f.not_in_latest_scan && <span className="row-gone"> (not found in scan {f.not_in_latest_scan})</span>}
              </dd>
            </div>
          )}
          <div>
            <dt>Tool rating</dt>
            <dd>
              {SEVERITY_LABEL[f.tool_severity]}
              {f.tool_confidence && <span className="dim">, {f.tool_confidence.toLowerCase()} confidence</span>}
            </dd>
          </div>
        </dl>
        <Lifecycle f={f} notices={notices} />
      </header>

      {f.description && f.source === "zap" && (
        <details className="tool-desc">
          <summary>What ZAP says about this rule</summary>
          <p>{f.description}</p>
        </details>
      )}

      <div className="split">
        <Evidence f={f} />
        <div className="right">
          <Analysis f={f} onRetry={canWrite ? () => api.reanalyze(f.id).then(setData).then(refresh) : undefined} />
          <Remediation f={f} onRetry={canWrite ? () => api.remediate(f.id).then(setData).then(refresh) : undefined} />
          {notices && notices.length > 0 && (
            <section className="card">
              <header className="card-head"><h2>Alerts sent</h2></header>
              <ul className="alert-list card-body">
                {notices.map((n) => (
                  <li key={n.id}>
                    <div>
                      <i className={`dot sev-bg-${n.severity || "none"}`} aria-hidden />
                      <span className="alert-text">
                        <span className="alert-title">{n.title}</span>
                        <span className="alert-meta">{ago(n.created_at)}<DeliveryChips n={n} /></span>
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>

      <p className="shortcuts dim small">
        Shortcuts: {canWrite && <><Kbd>C</Kbd> confirm, <Kbd>X</Kbd> reject, </>}<Kbd>J</Kbd> next, <Kbd>K</Kbd> previous
      </p>
      <DecisionBar f={f} onDone={onDone} />
    </div>
  );
}
