import { useState } from "react";
import { Link } from "react-router-dom";
import { Bell, Plus, Send } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { dateTime } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Notice, PageHeader, Section, Select, Table } from "../components/ui";

type Channel = { id: number; name: string; kind: "email" | "telegram" | "webhook"; config: Record<string, any>; has_secret: boolean;
  enabled: boolean; min_severity: string; event_types: string[]; cooldown_seconds: number; escalate_after_seconds: number | null;
  reports: "off" | "daily" | "weekly" };
type EventType = { type: string; label: string; severity: string };
type Sent = { id: number; at: string; channel: string | null; event_type: string; severity: string; title: string | null;
  lines: string[]; incident_id: string | null; status: string; attempts: number; error: string | null };

const KIND = { email: "E-mail", telegram: "Telegram", webhook: "Webhook" } as const;
const SEV = [["info", "Everything"], ["low", "Low and above"], ["medium", "Medium and above"], ["high", "High and critical"], ["critical", "Critical only"]] as [string, string][];
const STATUS_TONE: Record<string, "ok" | "warn" | "attack" | "neutral"> = { sent: "ok", pending: "warn", failed: "attack", suppressed: "neutral" };

export function AlertsPage() {
  const { can } = useAuth();
  const ch = useApi<Channel[]>("/notifications/channels");
  const types = useApi<EventType[]>("/notifications/event-types");
  const hist = useApi<Sent[]>("/notifications?limit=100", 15_000);
  const [edit, setEdit] = useState<Channel | "new" | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const admin = can("manage_settings");
  const test = async (c: Channel) => {
    setMsg(null);
    try {
      const r = await api<{ ok: boolean; error: string | null }>(`/notifications/channels/${c.id}/test`, { method: "POST" });
      setMsg({ ok: r.ok, text: r.ok ? `Test message sent to ${c.name}.` : `${c.name}: ${r.error}` });
      hist.reload();
    } catch (e: any) { setMsg({ ok: false, text: e.message }); }
  };
  return (
    <div className="space-y-5">
      <PageHeader title="Alerts"
        description="Who is told when an attack starts, a mitigation acts or fails, a BGP session or router goes down, or a link fills up."
        actions={admin && <Button variant="primary" onClick={() => setEdit("new")}><Plus size={16} /> Add channel</Button>} />
      {msg && <Notice tone={msg.ok ? "ok" : "attack"}>{msg.text}</Notice>}
      <ErrorLine error={ch.error} />
      <Section title="Channels" flush>
        <Table rows={ch.data ?? []} rowKey={(c) => String(c.id)} onRow={admin ? setEdit : undefined}
          empty="No channels yet: nobody is told about attacks. Add an e-mail address, a Telegram chat or a webhook."
          cols={[
            { key: "n", header: "Channel", render: (c) => <><div className="font-medium">{c.name} {!c.enabled && <Badge>Off</Badge>}</div>
              <div className="text-xs text-ink-3">{KIND[c.kind]}: {c.kind === "email" ? (c.config.to ?? []).join(", ") : c.kind === "telegram" ? `chat ${c.config.chat_id}` : c.config.url}</div></> },
            { key: "s", header: "Sends", render: (c) => <>{SEV.find((x) => x[0] === c.min_severity)?.[1]}
              <div className="text-xs text-ink-3">{c.event_types.length ? `${c.event_types.length} event types` : "all event types"}
                {c.reports !== "off" ? `, ${c.reports} report` : ""}</div></> },
            { key: "e", header: "Escalation", render: (c) => c.escalate_after_seconds ? `Unacknowledged attacks after ${Math.round(c.escalate_after_seconds / 60)} min` : <span className="text-ink-3">–</span> },
            { key: "a", header: "", align: "right" as const, render: (c) => admin && (
              <div onClick={(e) => e.stopPropagation()}><Button onClick={() => test(c)}><Send size={15} /> Send test</Button></div>) },
          ]} />
      </Section>
      <Section title="Recently sent" flush aside="Repeats within a channel's quiet period are recorded as suppressed">
        <Table dense rows={hist.data ?? []} rowKey={(n) => String(n.id)} empty="Nothing sent yet."
          cols={[
            { key: "t", header: "When", render: (n) => <span className="whitespace-nowrap">{dateTime(n.at)}</span> },
            { key: "w", header: "Alert", render: (n) => <><div>{n.title}</div>{n.incident_id && <Link className="text-xs text-signal hover:underline" to={`/attacks/${n.incident_id}`}>Attack</Link>}</> },
            { key: "c", header: "Channel", render: (n) => n.channel ?? "–" },
            { key: "s", header: "Result", render: (n) => <><Badge tone={STATUS_TONE[n.status] ?? "neutral"}>{n.status}</Badge>
              {n.error && <div className="mt-0.5 max-w-[40ch] text-xs text-attack">{n.error}</div>}</> },
          ]} />
      </Section>
      {edit && <ChannelDialog ch={edit === "new" ? null : edit} types={types.data ?? []} onClose={() => setEdit(null)} onSaved={ch.reload} />}
    </div>
  );
}

function ChannelDialog({ ch, types, onClose, onSaved }: { ch: Channel | null; types: EventType[]; onClose: () => void; onSaved: () => void }) {
  const c = ch?.config ?? {};
  const [f, setF] = useState({
    name: ch?.name ?? "", kind: ch?.kind ?? "email", enabled: ch?.enabled ?? true, min_severity: ch?.min_severity ?? "medium",
    secret: "", host: c.host ?? "", port: String(c.port ?? 587), security: c.security ?? "starttls", username: c.username ?? "",
    from: c.from ?? "", to: (c.to ?? []).join(", "), chat_id: c.chat_id ?? "", url: c.url ?? "", format: c.format ?? "json",
    event_types: ch?.event_types ?? [] as string[], cooldown: String(Math.round((ch?.cooldown_seconds ?? 300) / 60)),
    escalate: ch?.escalate_after_seconds ? String(Math.round(ch.escalate_after_seconds / 60)) : "", reports: ch?.reports ?? "off",
  });
  const [err, setErr] = useState<string | null>(null);
  const [sure, setSure] = useState(false);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const config = () => f.kind === "email" ? { host: f.host, port: Number(f.port), security: f.security, username: f.username || null, from: f.from,
      to: f.to.split(/[\s,;]+/).filter(Boolean) }
    : f.kind === "telegram" ? { chat_id: f.chat_id } : { url: f.url, format: f.format };
  const save = async () => {
    setErr(null);
    const common = { config: config(), enabled: f.enabled, min_severity: f.min_severity, event_types: f.event_types,
      cooldown_seconds: Number(f.cooldown) * 60, reports: f.reports, ...(f.secret ? { secret: f.secret } : {}) };
    try {
      if (ch) await api(`/notifications/channels/${ch.id}`, { method: "PATCH", body: { ...common, escalate_after_seconds: f.escalate ? Number(f.escalate) * 60 : 0 } });
      else await api("/notifications/channels", { method: "POST", body: { ...common, name: f.name, kind: f.kind,
        escalate_after_seconds: f.escalate ? Number(f.escalate) * 60 : null } });
      onSaved(); onClose();
    } catch (e: any) { setErr(e.message); }
  };
  const del = async () => {
    if (!sure) { setSure(true); return; }
    try { await api(`/notifications/channels/${ch!.id}`, { method: "DELETE" }); onSaved(); onClose(); } catch (e: any) { setErr(e.message); }
  };
  const secretLabel = { email: "SMTP password", telegram: "Bot token (from @BotFather)", webhook: "Signing key (optional)" }[f.kind as Channel["kind"]];
  return (
    <Dialog open title={ch ? `Edit ${ch.name}` : "Add an alert channel"} onClose={onClose}
      footer={<>{ch && <Button variant="danger" onClick={del}>{sure ? "Really delete" : "Delete"}</Button>}
        <Button variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save}>Save</Button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><Input value={f.name} disabled={!!ch} onChange={(e) => set("name", e.target.value)} placeholder="noc-mail" /></Field>
        <Field label="Type"><Select value={f.kind} disabled={!!ch} onChange={(v) => set("kind", v)}
          options={[["email", "E-mail"], ["telegram", "Telegram"], ["webhook", "Webhook (JSON, Slack, Mattermost, Teams)"]]} /></Field>
        {f.kind === "email" && <>
          <Field label="SMTP server"><Input value={f.host} onChange={(e) => set("host", e.target.value)} placeholder="smtp.example.net" /></Field>
          <div className="grid grid-cols-2 gap-2">
            <Field label="Port"><Input inputMode="numeric" value={f.port} onChange={(e) => set("port", e.target.value)} /></Field>
            <Field label="Security"><Select value={f.security} onChange={(v) => set("security", v)} options={[["starttls", "STARTTLS"], ["tls", "TLS"], ["none", "None"]]} /></Field>
          </div>
          <Field label="SMTP username"><Input value={f.username} onChange={(e) => set("username", e.target.value)} /></Field>
          <Field label="From"><Input value={f.from} onChange={(e) => set("from", e.target.value)} placeholder="shield@example.net" /></Field>
          <div className="sm:col-span-2"><Field label="To" hint="Comma-separated"><Input value={f.to} onChange={(e) => set("to", e.target.value)} placeholder="noc@example.net, oncall@example.net" /></Field></div>
        </>}
        {f.kind === "telegram" && <Field label="Chat id" hint="A group or user id (number) or @channelname; add the bot to the group first">
          <Input value={f.chat_id} onChange={(e) => set("chat_id", e.target.value)} placeholder="-1001234567890" /></Field>}
        {f.kind === "webhook" && <>
          <div className="sm:col-span-2"><Field label="URL"><Input value={f.url} onChange={(e) => set("url", e.target.value)} placeholder="https://hooks.example.net/…" /></Field></div>
          <Field label="Format"><Select value={f.format} onChange={(v) => set("format", v)} options={[["json", "Shield JSON"], ["slack", "Slack-compatible text"]]} /></Field>
        </>}
        <Field label={secretLabel} hint={ch?.has_secret ? "Stored encrypted. Leave empty to keep it." : "Stored encrypted; never shown again."}>
          <Input type="password" autoComplete="new-password" value={f.secret} onChange={(e) => set("secret", e.target.value)} /></Field>
        <Field label="Send"><Select value={f.min_severity} onChange={(v) => set("min_severity", v)} options={SEV} /></Field>
        <Field label="Quiet period (minutes)" hint="The same alert is not repeated within this time"><Input inputMode="numeric" value={f.cooldown} onChange={(e) => set("cooldown", e.target.value)} /></Field>
        <Field label="Escalate unacknowledged attacks after (minutes)" hint="Empty: never. For the on-call phone, e.g. 10"><Input inputMode="numeric" value={f.escalate} onChange={(e) => set("escalate", e.target.value)} /></Field>
        <Field label="Summary report"><Select value={f.reports} onChange={(v) => set("reports", v)} options={[["off", "None"], ["daily", "Daily, 08:00"], ["weekly", "Weekly, Monday 08:00"]]} /></Field>
        <div className="pt-6"><Check label="Enabled" checked={f.enabled} onChange={(v) => set("enabled", v)} /></div>
      </div>
      <div>
        <div className="mb-1 text-sm font-medium">Events <span className="font-normal text-ink-3">(none ticked: all)</span></div>
        <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2">{types.map((t) => (
          <Check key={t.type} label={t.label} checked={f.event_types.includes(t.type)}
            onChange={(v) => set("event_types", v ? [...f.event_types, t.type] : f.event_types.filter((x: string) => x !== t.type))} />))}</div>
      </div>
      {sure && <Notice tone="warn">Deleting the channel also deletes its history. Click again to confirm.</Notice>}
      <ErrorLine error={err} />
      <p className="text-xs text-ink-3"><Bell size={12} className="mr-1 inline" />Set <code>dashboard_url</code> in Settings so alerts link back to Shield.</p>
    </Dialog>
  );
}
