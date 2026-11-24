import { useMemo, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import type { Severity } from "../api";
import { Sev } from "./ui";

function prettyBody(body: string): string {
  const t = body.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return body;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return body;
  }
}

/** Wrap every occurrence of any needle in <mark>. */
function highlight(text: string, needles: string[]): ReactNode[] {
  const list = needles.map((n) => n.trim()).filter((n) => n.length >= 2);
  if (!list.length) return [text];
  const escaped = list.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`(${escaped.join("|")})`, "g");
  return text.split(re).map((part, i) => (i % 2 === 1 ? <mark key={i}>{part}</mark> : part));
}

function splitMessage(raw: string) {
  const norm = raw.replace(/\r\n/g, "\n");
  const i = norm.indexOf("\n\n");
  return i === -1 ? { head: norm, body: "" } : { head: norm.slice(0, i), body: norm.slice(i + 2) };
}

export function HttpMessage({ raw, needles, empty }: { raw: string; needles: string[]; empty: string }) {
  const [pretty, setPretty] = useState(true);
  const { head, body } = useMemo(() => splitMessage(raw), [raw]);
  const shownBody = useMemo(() => {
    if (!pretty) return body;
    const p = prettyBody(body);
    // Keep the raw form if pretty-printing would hide the evidence match.
    return needles.some((n) => n && body.includes(n) && !p.includes(n)) ? body : p;
  }, [body, pretty, needles]);

  if (!raw.trim()) return <p className="dim pad">{empty}</p>;
  const [start, ...headers] = head.split("\n");
  return (
    <div className="http">
      <pre className="http-pre">
        <span className="http-start">{highlight(start, needles)}</span>
        {"\n"}
        {headers.map((h, i) => {
          const c = h.indexOf(":");
          return (
            <span key={i} className="http-h">
              {c > 0 ? (
                <>
                  <span className="http-hn">{h.slice(0, c)}</span>
                  {highlight(h.slice(c), needles)}
                </>
              ) : (
                h
              )}
              {"\n"}
            </span>
          );
        })}
        {body && (
          <>
            {"\n"}
            <span className="http-body">{highlight(shownBody, needles)}</span>
          </>
        )}
      </pre>
      {body.trim().startsWith("{") && (
        <button className="link small http-toggle" onClick={() => setPretty(!pretty)}>
          {pretty ? "Show raw body" : "Format JSON"}
        </button>
      )}
    </div>
  );
}

const CVSS_NAMES: Record<string, [string, Record<string, string>]> = {
  AV: ["Attack vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
  AC: ["Attack complexity", { L: "Low", H: "High" }],
  PR: ["Privileges required", { N: "None", L: "Low", H: "High" }],
  UI: ["User interaction", { N: "None", R: "Required" }],
  S: ["Scope", { U: "Unchanged", C: "Changed" }],
  C: ["Confidentiality", { N: "None", L: "Low", H: "High" }],
  I: ["Integrity", { N: "None", L: "Low", H: "High" }],
  A: ["Availability", { N: "None", L: "Low", H: "High" }],
};

export function CvssBreakdown({ vector, score, severity }: { vector: string; score: number | null; severity?: Severity | "" }) {
  if (!vector) return null;
  const metrics = vector
    .replace(/^CVSS:3\.[01]\//, "")
    .split("/")
    .map((p) => p.split(":") as [string, string]);
  return (
    <div className="cvss">
      <div className="cvss-head">
        <span className="cvss-score">{score?.toFixed(1) ?? "–"}</span>
        <span className="cvss-meta">
          {severity && <Sev s={severity} size="sm" />}
          <code className="cvss-vector">{vector}</code>
        </span>
      </div>
      <dl className="cvss-grid">
        {metrics.map(([k, v]) => {
          const [name, values] = CVSS_NAMES[k] ?? [k, {}];
          return (
            <div key={k} className={`cvss-m cvss-${v}`}>
              <dt>{name}</dt>
              <dd>{values[v] ?? v}</dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

/** Text with `backticked` fragments shown as inline code. */
export function Inline({ text }: { text: string }) {
  const parts = text.split("`");
  if (parts.length < 3) return <>{text}</>;
  return <>{parts.map((p, i) => (i % 2 && i < parts.length - 1 ? <code key={i} className="ic">{p}</code> : <span key={i}>{p}</span>))}</>;
}

const FOLD_AT = 18;

export function CodeBlock({ code, label, fold }: { code: string; label?: string; fold?: boolean }) {
  const [copied, setCopied] = useState(false);
  const lines = code.split("\n").length;
  const [open, setOpen] = useState(!fold || lines <= FOLD_AT + 4);
  return (
    <div className="codeblock">
      <div className="codeblock-bar">
        <span>{label}</span>
        <button
          className="link small inline"
          onClick={() => {
            navigator.clipboard?.writeText(code).then(() => {
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1400);
            });
          }}
        >
          {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className={open ? "" : "folded"}>{code}</pre>
      {!open && (
        <button className="codeblock-more" onClick={() => setOpen(true)}>
          Show all {lines} lines
        </button>
      )}
    </div>
  );
}
