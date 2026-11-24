import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bell as BellIcon, BellRing, CheckCheck, Hash, Mail, MessageSquare, Send, Webhook } from "lucide-react";
import { ago, api, localPath, store, type ChannelKind, type Notice } from "../api";
import { useToast } from "./toast";

export const KIND_ICON: Record<ChannelKind, typeof Mail> = {
  email: Mail,
  discord: MessageSquare,
  slack: Hash,
  telegram: Send,
  webhook: Webhook,
};

export function DeliveryChips({ n }: { n: Notice }) {
  if (n.deliveries.length === 0) return <span className="deliv none">In-app only</span>;
  return (
    <span className="delivs">
      {n.deliveries.map((d, i) => {
        const Icon = KIND_ICON[d.kind] ?? Webhook;
        return (
          <span key={i} className={`deliv deliv-${d.status}`} title={d.error || `${d.channel_name}: ${d.status}`}>
            <Icon size={12} aria-hidden />
            {d.channel_name}
            <span className="sr">{d.status}</span>
          </span>
        );
      })}
    </span>
  );
}

function desktopAlert(n: Notice) {
  try {
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    const note = new Notification(n.title, { body: n.body, tag: `buns-${n.id}`, icon: "/favicon.svg" });
    const path = localPath(n.link);
    note.onclick = () => {
      window.focus();
      if (path) window.location.assign(path);
    };
  } catch {
    /* some browsers refuse notifications in this context */
  }
}

export default function Bell() {
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [items, setItems] = useState<Notice[] | null>(null);
  const [perm, setPerm] = useState<string>(() => ("Notification" in window ? Notification.permission : "unsupported"));
  const lastSeen = useRef<number>(Number(store.get("buns.lastNotice")) || -1);
  const box = useRef<HTMLDivElement>(null);
  const toast = useToast();
  const nav = useNavigate();

  // Poll for new notifications; announce the ones that arrived since last time.
  useEffect(() => {
    let timer: number;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api.notificationSummary();
        if (!alive) return;
        setUnread(s.unread);
        if (lastSeen.current < 0) {
          lastSeen.current = s.latest_id;
        } else if (s.latest_id > lastSeen.current) {
          const fresh = (await api.notifications({ unread: true, limit: 10 })).filter((n) => n.id > lastSeen.current);
          lastSeen.current = s.latest_id;
          fresh.slice(0, 3).reverse().forEach((n) => {
            const path = localPath(n.link);
            toast({
              kind: n.severity === "critical" || n.severity === "high" || n.event === "scan.failed" ? "alert" : "info",
              title: n.title,
              text: n.body,
              action: path ? { label: "Open", onClick: () => nav(path) } : undefined,
            });
            desktopAlert(n);
          });
          if (open) setItems(await api.notifications({ limit: 15 }));
        }
        store.set("buns.lastNotice", String(lastSeen.current));
      } catch {
        /* backend restarting; try again next tick */
      }
      timer = window.setTimeout(tick, 5000);
    };
    tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!open) return;
    api.notifications({ limit: 15 }).then(setItems).catch(() => setItems([]));
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const markAll = async () => {
    await api.markRead({ all: true });
    setUnread(0);
    setItems((xs) => xs?.map((x) => ({ ...x, read: true })) ?? xs);
  };

  const openItem = async (n: Notice) => {
    if (!n.read) {
      api.markRead({ ids: [n.id] }).catch(() => {});
      setUnread((u) => Math.max(0, u - 1));
    }
    setOpen(false);
    const path = localPath(n.link);
    if (path) nav(path);
    else if (n.link) window.open(n.link, "_blank");
  };

  const askPermission = async () => {
    if (!("Notification" in window)) return;
    setPerm(await Notification.requestPermission());
  };

  const Icon = unread > 0 ? BellRing : BellIcon;
  return (
    <div className="bell" ref={box}>
      <button
        className={`icon-btn bell-btn${unread ? " has-unread" : ""}`}
        aria-label={unread ? `${unread} unread notifications` : "Notifications"}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <Icon size={19} />
        {unread > 0 && <span className="bell-count">{unread > 99 ? "99+" : unread}</span>}
      </button>
      {open && (
        <div className="popover bell-pop" role="dialog" aria-label="Notifications">
          <header className="pop-head">
            <b>Notifications</b>
            {unread > 0 && (
              <button className="link small" onClick={markAll}>
                <CheckCheck size={14} aria-hidden /> Mark all read
              </button>
            )}
          </header>
          {perm === "default" && (
            <div className="pop-callout">
              <span>Get a desktop alert when something breaks, even with this tab in the background.</span>
              <button className="btn btn-sm" onClick={askPermission}>Turn on desktop alerts</button>
            </div>
          )}
          <ul className="pop-list">
            {items === null && <li className="pop-empty">Loading…</li>}
            {items?.length === 0 && <li className="pop-empty">Nothing yet. Alerts appear here when a scan finds something serious.</li>}
            {items?.map((n) => (
              <li key={n.id}>
                <button className={`pop-item${n.read ? "" : " unread"}`} onClick={() => openItem(n)}>
                  <i className={`pop-dot sev-bg-${n.severity || "none"}`} aria-hidden />
                  <span className="pop-text">
                    <span className="pop-title">{n.title}</span>
                    <span className="pop-meta">
                      {ago(n.created_at)}
                      <DeliveryChips n={n} />
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
          <footer className="pop-foot">
            <Link to="/notifications" onClick={() => setOpen(false)}>All notifications</Link>
            <Link to="/settings" onClick={() => setOpen(false)}>Alert channels</Link>
          </footer>
        </div>
      )}
    </div>
  );
}
