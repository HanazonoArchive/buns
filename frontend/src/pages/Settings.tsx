import { useState } from "react";
import { BellRing, CheckCircle2, Loader2, Pencil, Plus, Send as SendIcon, Trash2, TriangleAlert, XCircle } from "lucide-react";
import {
  ago,
  api,
  CHANNEL_LABEL,
  EVENTS,
  SEVERITIES,
  SEVERITY_LABEL,
  type Channel,
  type ChannelInput,
  type ChannelKind,
  type NotifyEvent,
  type Target,
} from "../api";
import { KIND_ICON } from "../components/Bell";
import { Modal } from "../components/Modal";
import { useToast } from "../components/toast";
import { Empty, ErrorLine, Field, PageHead, Panel, Skeleton, Switch, usePoll } from "../components/ui";

const KINDS: ChannelKind[] = ["discord", "email", "telegram", "slack", "webhook"];

const HELP: Record<ChannelKind, string> = {
  discord: "In Discord: Server Settings, Integrations, Webhooks, New Webhook, then Copy Webhook URL.",
  slack: "In Slack: create an app, turn on Incoming Webhooks, add one to a channel and copy its URL.",
  telegram: "Create a bot with @BotFather to get the token. Send your bot a message, then open https://api.telegram.org/bot<token>/getUpdates to find your chat ID.",
  webhook: "buns sends a JSON POST with event, severity, title, body, link and IDs. Use it for n8n, Zapier, or your own service.",
  email: "Sent through the SMTP server set in .env (SMTP_HOST, SMTP_USER, SMTP_PASSWORD, SMTP_FROM).",
};

const blank = (kind: ChannelKind): ChannelInput => ({
  name: "",
  kind,
  config: {},
  events: ["finding.detected", "scan.failed", "finding.confirmed"],
  min_severity: "high",
  target_id: null,
  notify_owner: kind === "email",
  enabled: true,
});

function ChannelForm({
  initial,
  editing,
  targets,
  emailReady,
  onClose,
  onSaved,
}: {
  initial: ChannelInput;
  editing: number | null;
  targets: Target[];
  emailReady: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [c, setC] = useState<ChannelInput>(initial);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof ChannelInput>(k: K, v: ChannelInput[K]) => setC({ ...c, [k]: v });
  const cfg = (k: string, v: string) => setC({ ...c, config: { ...c.config, [k]: v } });
  const toggleEvent = (e: NotifyEvent) => set("events", c.events.includes(e) ? c.events.filter((x) => x !== e) : [...c.events, e]);
  const val = (k: string) => {
    const v = c.config[k];
    return Array.isArray(v) ? v.join(", ") : v ?? "";
  };

  const save = async () => {
    setBusy(true);
    setErr("");
    try {
      const body = { ...c, name: c.name || `${CHANNEL_LABEL[c.kind]} alerts` };
      if (editing) await api.updateChannel(editing, body);
      else await api.createChannel(body);
      onSaved();
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={editing ? `Edit ${initial.name}` : "Add an alert channel"}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={busy} onClick={save}>{editing ? "Save changes" : "Add channel"}</button>
        </>
      }
    >
      <div className="form-grid">
        {!editing && (
          <div className="kind-picker" role="radiogroup" aria-label="Channel type">
            {KINDS.map((k) => {
              const Icon = KIND_ICON[k];
              return (
                <button key={k} type="button" role="radio" aria-checked={c.kind === k} className={c.kind === k ? "on" : ""} onClick={() => setC({ ...blank(k), name: c.name })}>
                  <Icon size={18} aria-hidden />
                  {CHANNEL_LABEL[k]}
                </button>
              );
            })}
          </div>
        )}
        <p className="help-line">{HELP[c.kind]}</p>
        {c.kind === "email" && !emailReady && (
          <p className="callout warn">
            <TriangleAlert size={16} aria-hidden />
            <span>Email is not configured on this server yet. Add the SMTP settings to <code>.env</code> and restart buns; the channel can be saved now.</span>
          </p>
        )}

        <Field label="Name"><input value={c.name} onChange={(e) => set("name", e.target.value)} placeholder={`${CHANNEL_LABEL[c.kind]} alerts`} /></Field>

        {(c.kind === "discord" || c.kind === "slack" || c.kind === "webhook") && (
          <Field label="Webhook URL" hint={editing ? "Leave as shown to keep the saved URL." : undefined}>
            <input className="mono" value={val("url")} onChange={(e) => cfg("url", e.target.value)}
              placeholder={c.kind === "discord" ? "https://discord.com/api/webhooks/…" : c.kind === "slack" ? "https://hooks.slack.com/services/…" : "https://"} />
          </Field>
        )}
        {c.kind === "telegram" && (
          <div className="form-pair">
            <Field label="Bot token" hint={editing ? "Leave as shown to keep the saved token." : undefined}>
              <input className="mono" value={val("bot_token")} onChange={(e) => cfg("bot_token", e.target.value)} placeholder="123456789:ABC…" />
            </Field>
            <Field label="Chat ID"><input className="mono" value={val("chat_id")} onChange={(e) => cfg("chat_id", e.target.value)} placeholder="123456789" /></Field>
          </div>
        )}
        {c.kind === "email" && (
          <>
            <Field label="Send to" hint="Comma-separated. Can be empty if the target owner is copied.">
              <input value={val("to")} onChange={(e) => cfg("to", e.target.value)} placeholder="team@example.com, lead@example.com" />
            </Field>
            <div className="opt-row">
              <span>
                <b>Also email the target's owner</b>
                <small>Uses the owner email set on each target, so the person responsible hears about their own system.</small>
              </span>
              <Switch checked={c.notify_owner} onChange={(v) => set("notify_owner", v)} label="Email the target owner" />
            </div>
          </>
        )}

        <fieldset className="form-group">
          <legend>When to send</legend>
          <div className="event-grid">
            {EVENTS.map((e) => (
              <label key={e.key} className={`check-card${c.events.includes(e.key) ? " on" : ""}`}>
                <input type="checkbox" checked={c.events.includes(e.key)} onChange={() => toggleEvent(e.key)} />
                <span><b>{e.label}</b><small>{e.hint}</small></span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="form-pair">
          <Field label="Only for severity" hint="Events with a severity are sent only at this level or above.">
            <select value={c.min_severity} onChange={(e) => set("min_severity", e.target.value as ChannelInput["min_severity"])}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}{s === "info" ? " (everything)" : " and above"}</option>)}
            </select>
          </Field>
          <Field label="Targets">
            <select value={c.target_id ?? ""} onChange={(e) => set("target_id", e.target.value ? Number(e.target.value) : null)}>
              <option value="">All targets</option>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </Field>
        </div>
        <ErrorLine msg={err} />
      </div>
    </Modal>
  );
}

function ChannelCard({ ch, targets, onEdit, onChanged }: { ch: Channel; targets: Target[]; onEdit: () => void; onChanged: () => void }) {
  const toast = useToast();
  const [testing, setTesting] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const Icon = KIND_ICON[ch.kind];
  const target = targets.find((t) => t.id === ch.target_id);

  const test = async () => {
    setTesting(true);
    try {
      const r = await api.testChannel(ch.id);
      toast(r.ok ? { kind: "success", title: `Test sent to ${ch.name}`, text: "Check that it arrived." } : { kind: "error", title: `${ch.name} failed`, text: r.error });
    } finally {
      setTesting(false);
      onChanged();
    }
  };

  return (
    <li className={`channel${ch.enabled ? "" : " off"}`}>
      <span className={`channel-icon k-${ch.kind}`}><Icon size={20} aria-hidden /></span>
      <div className="channel-main">
        <div className="channel-top">
          <b>{ch.name}</b>
          <span className="dim small">{CHANNEL_LABEL[ch.kind]}</span>
          {!ch.enabled && <span className="tag tag-muted">Paused</span>}
        </div>
        <p className="channel-desc small">
          {SEVERITY_LABEL[ch.min_severity]}{ch.min_severity === "info" ? "" : " and above"}, {target ? target.name : "all targets"}
          {ch.kind === "email" && (ch.notify_owner ? ", copies the target owner" : "")}
        </p>
        <div className="chips">
          {EVENTS.filter((e) => ch.events.includes(e.key)).map((e) => <span key={e.key} className="chip">{e.label}</span>)}
        </div>
        {ch.last_status && (
          <p className={`channel-status ${ch.last_status}`}>
            {ch.last_status === "sent" ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
            {ch.last_status === "sent" ? `Last delivered ${ago(ch.last_sent_at)}` : `Last attempt failed: ${ch.last_error}`}
          </p>
        )}
      </div>
      <div className="channel-actions">
        <Switch checked={ch.enabled} onChange={async (v) => { await api.updateChannel(ch.id, { enabled: v }); onChanged(); }} label={`${ch.name} enabled`} />
        <button className="btn btn-sm" onClick={test} disabled={testing}>
          {testing ? <Loader2 size={14} className="spin" /> : <SendIcon size={14} />} Send test
        </button>
        <button className="icon-btn" onClick={onEdit} aria-label={`Edit ${ch.name}`}><Pencil size={15} /></button>
        <button className="icon-btn danger" onClick={() => setConfirm(true)} aria-label={`Delete ${ch.name}`}><Trash2 size={15} /></button>
      </div>
      {confirm && (
        <Modal title={`Remove ${ch.name}?`} onClose={() => setConfirm(false)}
          footer={<><button className="btn" onClick={() => setConfirm(false)}>Keep it</button><button className="btn btn-danger" onClick={async () => { await api.deleteChannel(ch.id); setConfirm(false); onChanged(); }}>Remove channel</button></>}>
          <p>Alerts will no longer be sent to this channel. Past alerts stay in the history.</p>
        </Modal>
      )}
    </li>
  );
}

export default function SettingsPage() {
  const { data: channels, error, refresh } = usePoll(api.channels, [], () => false);
  const { data: targets } = usePoll(api.targets, [], () => false);
  const { data: summary } = usePoll(api.notificationSummary, [], () => false);
  const [form, setForm] = useState<{ initial: ChannelInput; id: number | null } | null>(null);
  const toast = useToast();

  return (
    <>
      <PageHead
        title="Alert channels"
        sub="When a scan finds something serious, the people responsible should hear about it without having to open buns."
        actions={<button className="btn btn-primary" onClick={() => setForm({ initial: blank("discord"), id: null })}><Plus size={16} /> Add channel</button>}
      />

      <section className="flow">
        <div><b>Something breaks</b><span>A scan finds a critical flaw, fails, or a finding is confirmed</span></div>
        <div><b>buns raises an alert</b><span>Shown in the bell and on the Alerts page, with a link to the evidence</span></div>
        <div><b>The owner is told</b><span>Through the channels below, filtered by severity and target</span></div>
      </section>

      <ErrorLine msg={error} />
      {!channels && <div className="panel"><Skeleton rows={3} height={26} /></div>}
      {channels && channels.length === 0 && (
        <Empty icon={BellRing} title="No channels yet" action={<button className="btn btn-primary" onClick={() => setForm({ initial: blank("discord"), id: null })}><Plus size={16} /> Add channel</button>}>
          Alerts still appear in the bell. Add Discord, email, Telegram, Slack or a webhook to reach people outside the app.
        </Empty>
      )}
      {channels && channels.length > 0 && (
        <Panel flush>
          <ul className="channel-list">
            {channels.map((ch) => (
              <ChannelCard
                key={ch.id}
                ch={ch}
                targets={targets ?? []}
                onChanged={refresh}
                onEdit={() => setForm({ initial: { ...ch }, id: ch.id })}
              />
            ))}
          </ul>
        </Panel>
      )}

      <p className="footnote">
        Alerts contain the finding title, endpoint, severity and a link to buns. Request and response evidence, payloads and credentials never leave the platform.
      </p>

      {form && (
        <ChannelForm
          initial={form.initial}
          editing={form.id}
          targets={targets ?? []}
          emailReady={!!summary?.email_configured}
          onClose={() => setForm(null)}
          onSaved={() => {
            setForm(null);
            refresh();
            toast({ kind: "success", title: form.id ? "Channel saved" : "Channel added", text: "Use Send test to check it works." });
          }}
        />
      )}
    </>
  );
}
