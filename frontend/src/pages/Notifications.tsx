import { useState } from "react";
import { Link } from "react-router-dom";
import { BellOff, CheckCheck, Settings } from "lucide-react";
import { ago, api, EVENTS, localPath, when, type Notice } from "../api";
import { DeliveryChips } from "../components/Bell";
import { Empty, ErrorLine, PageHead, Sev, Skeleton, usePoll } from "../components/ui";

const EVENT_LABEL = Object.fromEntries(EVENTS.map((e) => [e.key, e.label])) as Record<string, string>;

export default function Notifications() {
  const [onlyUnread, setOnlyUnread] = useState(false);
  const { data, error, refresh } = usePoll(() => api.notifications({ unread: onlyUnread, limit: 200 }), [onlyUnread], () => true, 6000);

  const markAll = async () => {
    await api.markRead({ all: true });
    refresh();
  };

  return (
    <>
      <PageHead
        title="Alerts"
        sub="Everything buns told someone about, and whether each channel received it."
        actions={
          <>
            <button className="btn" onClick={markAll}><CheckCheck size={16} /> Mark all read</button>
            <Link className="btn" to="/settings"><Settings size={16} /> Alert channels</Link>
          </>
        }
      />
      <div className="toolbar">
        <div className="seg" role="tablist">
          <button role="tab" aria-selected={!onlyUnread} className={!onlyUnread ? "on" : ""} onClick={() => setOnlyUnread(false)}>All</button>
          <button role="tab" aria-selected={onlyUnread} className={onlyUnread ? "on" : ""} onClick={() => setOnlyUnread(true)}>Unread</button>
        </div>
      </div>
      <ErrorLine msg={error} />
      {!data && <div className="panel"><Skeleton rows={5} /></div>}
      {data && data.length === 0 && (
        <Empty icon={BellOff} title={onlyUnread ? "No unread alerts" : "No alerts yet"}>
          Alerts are raised when analysis rates a finding critical or high, when a scan finishes or fails, when a finding is confirmed, and when a report is generated.
        </Empty>
      )}
      {data && data.length > 0 && (
        <ul className="notice-list">
          {data.map((n: Notice) => {
            const path = localPath(n.link);
            return (
              <li key={n.id} className={`notice${n.read ? "" : " unread"} edge-${n.severity || "none"}`}>
                <div className="notice-main">
                  <div className="notice-top">
                    <span className="notice-event">{EVENT_LABEL[n.event] ?? n.event}</span>
                    {n.severity && <Sev s={n.severity} size="sm" />}
                    <span className="dim small" title={when(n.created_at)}>{ago(n.created_at)}</span>
                  </div>
                  <p className="notice-title">{path ? <Link to={path}>{n.title}</Link> : n.link ? <a href={n.link} target="_blank" rel="noreferrer">{n.title}</a> : n.title}</p>
                  <p className="notice-body">{n.body}</p>
                  <DeliveryChips n={n} />
                  {n.deliveries.filter((d) => d.status === "failed").map((d, i) => (
                    <p key={i} className="deliv-error">{d.channel_name}: {d.error}</p>
                  ))}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}
