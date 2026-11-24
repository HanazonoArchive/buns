import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Search } from "lucide-react";
import { api, type Account, type AuditEntry, type AuditKind } from "../api";
import { ErrorLine, PageHead, Switch } from "../components/ui";

const KINDS: { id: "" | AuditKind; label: string; help: string }[] = [
  { id: "", label: "Everything", help: "" },
  { id: "event", label: "Actions", help: "Sign-ins, account changes, scans started, decisions, reports" },
  { id: "request", label: "Requests", help: "Every change request the API received, with status and timing" },
  { id: "system", label: "System", help: "What buns did on its own: scans finishing or failing, first-run setup" },
];

const PAGE = 200;

function stamp(iso: string) {
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function statusClass(s: number | null) {
  if (s === null) return "";
  return s >= 500 ? "st-5" : s >= 400 ? "st-4" : "st-2";
}

function Line({ e, open, onToggle }: { e: AuditEntry; open: boolean; onToggle: () => void }) {
  const who = e.actor_email || e.actor_name || "-";
  const failed = e.action.endsWith("failed") || e.action === "auth.locked" || (e.status ?? 0) >= 400;
  return (
    <li className={`log-line k-${e.kind}${failed ? " is-bad" : ""}${open ? " open" : ""}`}>
      <button className="log-row" onClick={onToggle} aria-expanded={open}>
        <span className="l-time">{stamp(e.created_at)}</span>
        <span className="l-kind">{e.kind}</span>
        <span className="l-action">{e.action}</span>
        <span className="l-who" title={e.actor_name}>
          {who}
          {e.actor_role && <span className="l-role">[{e.actor_role}]</span>}
        </span>
        <span className="l-msg">
          {e.kind === "request" ? (
            <>
              <span className="l-method">{e.method}</span> {e.path} <span className={`l-status ${statusClass(e.status)}`}>{e.status}</span>{" "}
              <span className="l-dur">{e.duration_ms}ms</span>
            </>
          ) : (
            e.message
          )}
        </span>
      </button>
      {open && (
        <pre className="log-detail">
          {JSON.stringify(
            { id: e.id, at: e.created_at, kind: e.kind, action: e.action, actor: { email: e.actor_email, name: e.actor_name, role: e.actor_role }, ip: e.ip || undefined, ...(e.kind === "request" ? { method: e.method, path: e.path, status: e.status, duration_ms: e.duration_ms } : { message: e.message }), detail: Object.keys(e.detail).length ? e.detail : undefined },
            null,
            2,
          )}
        </pre>
      )}
    </li>
  );
}

export default function Logs() {
  const [kind, setKind] = useState<"" | AuditKind>("");
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [actor, setActor] = useState("");
  const [live, setLive] = useState(true);
  const [rows, setRows] = useState<AuditEntry[] | null>(null);
  const [more, setMore] = useState(false);
  const [openId, setOpenId] = useState<number | null>(null);
  const [users, setUsers] = useState<Account[]>([]);
  const [err, setErr] = useState("");
  const filters = { kind: kind || undefined, q: query || undefined, actor: actor || undefined };
  const key = JSON.stringify(filters);
  const keyRef = useRef(key);
  keyRef.current = key;
  const olderLoaded = useRef(false);

  useEffect(() => {
    api.users().then(setUsers, () => {});
  }, []);

  // Debounce the search box.
  useEffect(() => {
    const t = window.setTimeout(() => setQuery(q.trim()), 300);
    return () => window.clearTimeout(t);
  }, [q]);

  const loadFirst = useCallback(() => {
    const asked = key;
    api.audit({ ...JSON.parse(asked), limit: PAGE }).then(
      (r) => {
        if (keyRef.current !== asked) return;
        setErr("");
        // Keep older pages already loaded; only merge what is new on top.
        setRows((prev) => {
          if (!olderLoaded.current || !prev || !r.length) return r;
          const seen = new Set(r.map((x) => x.id));
          return [...r, ...prev.filter((x) => !seen.has(x.id) && x.id < r[r.length - 1].id)];
        });
        if (!olderLoaded.current) setMore(r.length === PAGE);
      },
      (e) => setErr(e.message),
    );
  }, [key]);

  useEffect(() => {
    olderLoaded.current = false;
    setRows(null);
    loadFirst();
  }, [loadFirst]);

  useEffect(() => {
    if (!live) return;
    const t = window.setInterval(loadFirst, 4000);
    return () => window.clearInterval(t);
  }, [live, loadFirst]);

  const loadOlder = async () => {
    if (!rows?.length) return;
    olderLoaded.current = true;
    const r = await api.audit({ ...filters, before: rows[rows.length - 1].id, limit: PAGE });
    setRows([...rows, ...r]);
    setMore(r.length === PAGE);
  };

  const help = KINDS.find((k) => k.id === kind)?.help;

  return (
    <>
      <PageHead
        title="Logs"
        sub="A raw, append-only record of who did what. Only the superadmin can see this page. Passwords and request bodies are never written here."
        actions={
          <a className="btn" href={api.auditExportUrl(filters)} download>
            <Download size={16} /> Download .log
          </a>
        }
      />

      <div className="log-bar">
        <div className="seg" role="tablist" aria-label="Kind of entry">
          {KINDS.map((k) => (
            <button key={k.id} role="tab" aria-selected={kind === k.id} className={kind === k.id ? "on" : ""} onClick={() => setKind(k.id)}>
              {k.label}
            </button>
          ))}
        </div>
        <label className="log-search">
          <Search size={15} aria-hidden />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search actions, messages, paths" aria-label="Search the log" />
        </label>
        <select value={actor} onChange={(e) => setActor(e.target.value)} aria-label="Filter by user">
          <option value="">All users</option>
          {users.map((u) => (
            <option key={u.id} value={u.email}>{u.name}</option>
          ))}
        </select>
        <label className="log-live">
          <Switch checked={live} onChange={setLive} label="Follow new entries" />
          <span>{live ? "Following" : "Paused"}</span>
        </label>
      </div>
      {help && <p className="dim small log-help">{help}</p>}
      <ErrorLine msg={err} />

      <div className="log-frame">
        {!rows ? (
          <p className="log-empty">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="log-empty">No entries match. Clear the search or pick another user.</p>
        ) : (
          <ol className="log-list" aria-label="Log entries, newest first">
            {rows.map((e) => (
              <Line key={e.id} e={e} open={openId === e.id} onToggle={() => setOpenId(openId === e.id ? null : e.id)} />
            ))}
          </ol>
        )}
      </div>
      {rows && more && (
        <div className="log-more">
          <button className="btn btn-sm" onClick={loadOlder}>Load older entries</button>
        </div>
      )}
    </>
  );
}
