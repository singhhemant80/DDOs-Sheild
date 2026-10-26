import { useState, type FormEvent, type ReactNode } from "react";
import { Plus } from "lucide-react";
import { api, setTokens } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { ago, dateTime } from "../lib/format";
import { objectLabel } from "./Overview";
import { DetectionProfiles } from "./Detection";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";

// ================================================================ Users
type User = { id: string; username: string; email: string | null; full_name: string | null; role: string; is_active: boolean;
  mfa_enabled: boolean; last_login_at: string | null; locked_until: string | null };

const ROLES: [string, string][] = [["admin", "Administrator"], ["network_engineer", "Network engineer"], ["noc_operator", "NOC operator"], ["read_only", "Read-only"]];
const roleName = (r: string) => ROLES.find(([k]) => k === r)?.[1] ?? r;

export function Users() {
  const { can } = useAuth();
  const list = useApi<User[]>(can("manage_users") ? "/users" : null);
  const [edit, setEdit] = useState<User | "new" | null>(null);
  if (!can("manage_users")) return <NoAccess what="manage users" />;
  return (
    <div className="space-y-5">
      <PageHeader title="Users & roles" description="Changing someone's role, password or MFA signs them out everywhere."
        actions={<Button variant="primary" onClick={() => setEdit("new")}><Plus size={16} /> Add user</Button>} />
      <ErrorLine error={list.error} />
      <Section flush>
        <Table rows={list.data ?? []} rowKey={(u) => u.id} onRow={setEdit}
          cols={[
            { key: "u", header: "User", render: (u) => <><div className="font-medium">{u.username}</div><div className="text-xs text-ink-3">{u.full_name ?? u.email}</div></> },
            { key: "r", header: "Role", render: (u) => roleName(u.role) },
            { key: "m", header: "MFA", render: (u) => u.mfa_enabled ? <Badge tone="ok">On</Badge> : <Badge tone={u.role === "admin" ? "warn" : "neutral"}>Off</Badge> },
            { key: "s", header: "Status", render: (u) => !u.is_active ? <Lamp tone="neutral" label="Disabled" />
                : u.locked_until && Date.parse(u.locked_until) > Date.now() ? <Lamp tone="attack" label="Locked out" /> : <Lamp tone="ok" label="Active" /> },
            { key: "l", header: "Last sign-in", render: (u) => <span className="text-ink-2">{ago(u.last_login_at ? Date.parse(u.last_login_at) / 1000 : null)}</span> },
          ]} />
      </Section>
      <Section title="What each role can do">
        <Table dense rows={[
          ["View dashboards, traffic and the audit log", "✓", "✓", "✓", "✓"],
          ["Propose, approve and withdraw mitigations", "✓", "✓", "✓", ""],
          ["Emergency stop", "✓", "✓", "✓", ""],
          ["Turn automation back on", "✓", "✓", "", ""],
          ["Edit prefixes, routers, upstreams and policies", "✓", "✓", "", ""],
          ["Manage users and system settings", "✓", "", "", ""],
        ]} rowKey={(r) => r[0]} cols={[
          { key: "a", header: "Capability", render: (r) => r[0] },
          ...ROLES.map(([, n], i) => ({ key: n, header: n, render: (r: string[]) => r[i + 1] })),
        ]} />
      </Section>
      {edit && <UserDialog user={edit === "new" ? null : edit} onClose={() => setEdit(null)} onSaved={list.reload} />}
    </div>
  );
}

function UserDialog({ user, onClose, onSaved }: { user: User | null; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ username: "", full_name: user?.full_name ?? "", email: user?.email ?? "", role: user?.role ?? "read_only",
    password: "", is_active: user?.is_active ?? true, unlock: false, reset_mfa: false });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      if (user) await api(`/users/${user.id}`, { method: "PATCH", body: { full_name: f.full_name || null, email: f.email || null,
        role: f.role, is_active: f.is_active, unlock: f.unlock || undefined, reset_mfa: f.reset_mfa || undefined,
        new_password: f.password || undefined } });
      else await api("/users", { method: "POST", body: { username: f.username, password: f.password, role: f.role,
        full_name: f.full_name || null, email: f.email || null } });
      onSaved(); onClose();
    } catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog open title={user ? `Edit ${user.username}` : "Add a user"} onClose={onClose}
      footer={<><Button type="button" variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" form="usr">{user ? "Save changes" : "Add user"}</Button></>}>
      <form id="usr" onSubmit={save} className="grid gap-4 sm:grid-cols-2">
        {!user && <Field label="Username"><Input required pattern="[A-Za-z0-9_.\-]{3,64}" value={f.username} onChange={(e) => set("username", e.target.value)} /></Field>}
        <Field label="Role"><Select value={f.role} onChange={(v) => set("role", v)} options={ROLES} /></Field>
        <Field label="Full name"><Input value={f.full_name} onChange={(e) => set("full_name", e.target.value)} /></Field>
        <Field label="Email"><Input type="email" value={f.email} onChange={(e) => set("email", e.target.value)} /></Field>
        <div className="sm:col-span-2"><Field label={user ? "New password (leave blank to keep)" : "Password"}
          hint="At least 12 characters using three of: lowercase, uppercase, digits, symbols.">
          <Input type="password" autoComplete="new-password" required={!user} value={f.password} onChange={(e) => set("password", e.target.value)} /></Field></div>
        {user && <div className="space-y-2 sm:col-span-2">
          <Check label="Account active" checked={f.is_active} onChange={(v) => set("is_active", v)} />
          {user.locked_until && <Check label="Clear lockout" checked={f.unlock} onChange={(v) => set("unlock", v)} />}
          {user.mfa_enabled && <Check label="Reset MFA (they enrol again at next sign-in)" checked={f.reset_mfa} onChange={(v) => set("reset_mfa", v)} />}
        </div>}
        <div className="sm:col-span-2"><ErrorLine error={err} /></div>
      </form>
    </Dialog>
  );
}

// ================================================================ Settings & my account
type Setting = { key: string; value: unknown; description: string | null; updated_at: string };

export function SettingsPage() {
  const { can } = useAuth();
  const s = useApi<Setting[]>("/settings");
  const [err, setErr] = useState<string | null>(null);
  const get = (k: string) => s.data?.find((x) => x.key === k)?.value;
  const put = async (key: string, value: unknown) => {
    setErr(null);
    try { await api(`/settings/${key}`, { method: "PUT", body: { value } }); await s.reload(); } catch (e: any) { setErr(e.message); }
  };
  const automation = async (enabled: boolean) => {
    setErr(null);
    try { await api(`/system/automation?enabled=${enabled}&rtbh_enabled=${enabled}`, { method: "POST" }); await s.reload(); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <div className="space-y-5">
      <PageHeader title="Settings" />
      <ErrorLine error={err ?? s.error} />
      <Section title="Automatic mitigation">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="max-w-[60ch] text-sm">
            {get("automation_enabled") === true
              ? <p>Automatic mitigation is <strong>on</strong>. Policies marked automatic can act without approval.</p>
              : <p>Automatic mitigation is <strong>off</strong>. Every action needs an operator's approval.</p>}
            {get("rtbh_emergency_disable") === true && <p className="mt-1 text-warn">New blackhole announcements are blocked by an emergency stop.</p>}
            <p className="mt-1 text-ink-3">Automatic policies arrive with the mitigation engine in phase 6. The switch is recorded now.</p>
          </div>
          {can("automation_enable") && (get("automation_enabled")
            ? <Button onClick={() => automation(false)}>Turn off</Button>
            : <Button variant="primary" onClick={() => automation(true)}>Turn on and allow blackholes</Button>)}
        </div>
      </Section>
      <DetectionProfiles />
      <Section title="System" aside={can("manage_settings") ? undefined : "Read-only for your role"} flush>
        <Table rows={(s.data ?? []).filter((x) => !["automation_enabled", "rtbh_emergency_disable"].includes(x.key))} rowKey={(x) => x.key}
          cols={[
            { key: "d", header: "Setting", render: (x) => <><div className="font-medium">{x.description}</div><code className="text-xs text-ink-3">{x.key}</code></> },
            { key: "v", header: "Value", className: "w-56", render: (x) => <SettingValue s={x} editable={can("manage_settings")} onSave={(v) => put(x.key, v)} /> },
          ]} />
      </Section>
      <MyAccount />
    </div>
  );
}

function SettingValue({ s, editable, onSave }: { s: Setting; editable: boolean; onSave: (v: unknown) => void }) {
  const [v, setV] = useState(String(s.value));
  if (typeof s.value === "boolean") {
    return <Check label={s.value ? "On" : "Off"} checked={s.value} disabled={!editable} onChange={onSave} />;
  }
  if (!editable) return <span>{String(s.value)}</span>;
  return (
    <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); onSave(Number(v)); }}>
      <Input aria-label={s.key} inputMode="numeric" value={v} onChange={(e) => setV(e.target.value.replace(/\D/g, ""))} className="w-24" />
      {v !== String(s.value) && <Button>Save</Button>}
    </form>
  );
}

type SessionRow = { id: string; created_at: string; last_used_at: string | null; ip: string | null; user_agent: string | null; current: boolean; mfa_verified: boolean };

function MyAccount() {
  const { me, reloadMe } = useAuth();
  const sessions = useApi<SessionRow[]>("/auth/sessions");
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [pwMsg, setPwMsg] = useState<ReactNode>(null);
  const begin = async () => { setErr(null); try { setSetup(await api("/auth/mfa/setup", { method: "POST" })); } catch (e: any) { setErr(e.message); } };
  const finish = async () => {
    setErr(null);
    try {
      const t: any = await api("/auth/mfa/enable", { method: "POST", body: { code } });
      setTokens(t);
      setSetup(null); setCode("");
      await reloadMe();
    } catch (e: any) { setErr(e.message); }
  };
  const changePw = async (e: FormEvent) => {
    e.preventDefault();
    try { await api("/auth/password", { method: "POST", body: pw }); setPwMsg(<Notice tone="ok">Password changed. Your other sessions were signed out.</Notice>); setPw({ current_password: "", new_password: "" }); sessions.reload(); }
    catch (e: any) { setPwMsg(<Notice tone="attack">{e.message}</Notice>); }
  };
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Section title="Two-factor authentication">
        {me?.mfa_enabled ? <p className="text-sm"><Badge tone="ok">On</Badge> Sign-ins need a code from your authenticator app.</p> : !setup ? (
          <div className="space-y-3 text-sm">
            <p>Add a time-based code from an authenticator app. Administrators should always use this.</p>
            <Button variant="primary" onClick={begin}>Set up two-factor</Button>
          </div>
        ) : (
          <div className="space-y-3 text-sm">
            <p>Add this key to your authenticator app, then enter the code it shows.</p>
            <code className="block break-all rounded-[3px] bg-sunk px-3 py-2 text-[15px] tracking-wider">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code>
            <p className="text-xs text-ink-3">Or open the setup link on the device with your app: <a className="break-all text-signal" href={setup.otpauth_uri}>otpauth link</a></p>
            <div className="flex max-w-xs gap-2">
              <Input aria-label="Code" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
              <Button variant="primary" onClick={finish} disabled={code.length !== 6}>Turn on</Button>
            </div>
          </div>
        )}
        <div className="mt-3"><ErrorLine error={err} /></div>
      </Section>
      <Section title="Change password">
        <form onSubmit={changePw} className="space-y-3">
          <Field label="Current password"><Input type="password" autoComplete="current-password" required value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} /></Field>
          <Field label="New password" hint="At least 12 characters using three of: lowercase, uppercase, digits, symbols.">
            <Input type="password" autoComplete="new-password" required value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} /></Field>
          <Button>Change password</Button>
          {pwMsg}
        </form>
      </Section>
      <div className="xl:col-span-2">
        <Section title="Your sessions" flush>
          <Table dense rows={sessions.data ?? []} rowKey={(r) => r.id}
            cols={[
              { key: "w", header: "Device", render: (r) => <span className="line-clamp-1 max-w-[40ch]" title={r.user_agent ?? ""}>{r.user_agent ?? "Unknown"}</span> },
              { key: "ip", header: "Address", render: (r) => r.ip ?? "–" },
              { key: "s", header: "Signed in", render: (r) => dateTime(r.created_at) },
              { key: "c", header: "", align: "right", render: (r) => r.current ? <Badge tone="signal">This session</Badge>
                  : <Button variant="quiet" onClick={async () => { await api(`/auth/sessions/${r.id}`, { method: "DELETE" }); sessions.reload(); }}>Sign out</Button> },
            ]} />
        </Section>
      </div>
    </div>
  );
}

// ================================================================ Audit
type AuditRow = { id: number; at: string; actor_username: string; actor_ip: string | null; action: string; entity_type: string | null;
  entity_id: string | null; before: Record<string, unknown> | null; after: Record<string, unknown> | null; hash: string };

export function AuditLog() {
  const [action, setAction] = useState("");
  const [beforeId, setBeforeId] = useState<number | null>(null);
  const q = new URLSearchParams({ limit: "100" });
  if (action) q.set("action", action);
  if (beforeId) q.set("before_id", String(beforeId));
  const list = useApi<AuditRow[]>(`/audit?${q}`);
  const [verify, setVerify] = useState<{ ok: boolean; checked: number; reason: string | null; first_bad_id: number | null } | null>(null);
  const [open, setOpen] = useState<AuditRow | null>(null);
  return (
    <div className="space-y-5">
      <PageHeader title="Audit log" description="Every change and sign-in, chained by hash so any later edit to the record is detectable."
        actions={<Button onClick={async () => setVerify(await api("/audit/verify"))}>Verify the chain</Button>} />
      {verify && (verify.ok
        ? <Notice tone="ok">All {verify.checked} entries are intact.</Notice>
        : <Notice tone="attack">The audit chain is broken at entry {verify.first_bad_id}: {verify.reason}. Treat this as a security incident.</Notice>)}
      <div className="flex max-w-md gap-2">
        <Input aria-label="Filter by action" placeholder="Filter by action, e.g. prefix.update" value={action} onChange={(e) => { setAction(e.target.value); setBeforeId(null); }} />
      </div>
      <Section flush>
        <Table dense rows={list.data ?? []} rowKey={(r) => String(r.id)} onRow={setOpen}
          cols={[
            { key: "t", header: "When", render: (r) => <span className="whitespace-nowrap">{dateTime(r.at)}</span> },
            { key: "w", header: "Who", render: (r) => <>{r.actor_username} <span className="text-ink-3">{r.actor_ip}</span></> },
            { key: "a", header: "Action", render: (r) => <code className="text-[13px]">{r.action}</code> },
            { key: "o", header: "Object", render: (r) => <span className="text-ink-2" title={r.entity_id ?? ""}>{objectLabel(r.entity_type, r.entity_id)}</span> },
          ]} />
        {list.data && list.data.length === 100 && (
          <div className="border-t border-rule-soft px-4 py-2"><Button variant="quiet" onClick={() => setBeforeId(list.data![99].id)}>Older entries</Button></div>
        )}
      </Section>
      {open && <Dialog open title={`${open.action} by ${open.actor_username}`} onClose={() => setOpen(null)}
        footer={<Button onClick={() => setOpen(null)}>Close</Button>}>
        <p className="text-sm text-ink-2">{dateTime(open.at)}, entry {open.id}</p>
        <Diff before={open.before} after={open.after} />
        <p className="break-all text-xs text-ink-3">Hash {open.hash}</p>
      </Dialog>}
    </div>
  );
}

function Diff({ before, after }: { before: Record<string, unknown> | null; after: Record<string, unknown> | null }) {
  const keys = Array.from(new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})]))
    .filter((k) => !["created_at", "updated_at"].includes(k))
    .filter((k) => !before || JSON.stringify(before[k]) !== JSON.stringify(after?.[k]));
  if (!keys.length) return <p className="text-sm text-ink-3">No field changes recorded.</p>;
  return (
    <Table dense rows={keys} rowKey={(k) => k} cols={[
      { key: "k", header: "Field", render: (k) => <code className="text-[13px]">{k}</code> },
      ...(before ? [{ key: "b", header: "Before", render: (k: string) => <span className="text-ink-2">{fmtVal(before[k])}</span> }] : []),
      { key: "a", header: after ? "After" : "Value", render: (k) => fmtVal(after?.[k]) },
    ]} />
  );
}
const fmtVal = (v: unknown) => (v === null || v === undefined ? "–" : typeof v === "object" ? JSON.stringify(v) : String(v));

// ================================================================ Health
type Health = { version: string; schema_revision: string; components: Record<string, string> };
type Collector = { running: boolean; reason?: string; version?: string; started_at?: number; prefixes?: number; prefix_source?: string;
  queue_drops?: number; rejected_packets?: number; decode_errors?: number; missing_template_records?: number;
  clickhouse?: { inserted: number; dropped: number; pending: number; errors: number; last_error: string };
  exporters?: { address: string; name: string; kind: string; packets: number; records: number; last_seen: number; sampling_rate: number; sampling_source: string; stale: boolean }[] };

const COMPONENTS: [string, string, string][] = [
  ["api", "Management API", ""], ["database", "PostgreSQL", "Configuration, users, audit"],
  ["redis", "Redis", "Live feed"], ["clickhouse", "ClickHouse", "Traffic history"],
  ["collector", "Flow collector", "NetFlow, IPFIX, sFlow"], ["detector", "Detection engine", "Attack detection and incidents"],
  ["mikrotik_adapter", "MikroTik poller", "Read-only router status"], ["mitigator", "Mitigation controller", "Simulation mode: nothing is announced"],
];

export function HealthPage() {
  const h = useApi<Health>("/health/details", 10_000);
  const c = useApi<Collector>("/collector/status", 5_000);
  const tone = (s: string) => (s === "up" ? "ok" : s === "degraded" ? "warn" : s === "not_installed" || s === "idle" ? "neutral" : "attack") as any;
  const word = (s: string) => ({ up: "Running", down: "Down", degraded: "Degraded", not_installed: "Not part of this release", idle: "Nothing to do" }[s] ?? s);
  const col = c.data;
  return (
    <div className="space-y-5">
      <PageHeader title="System health" description={h.data ? `Shield ${h.data.version}, database schema ${h.data.schema_revision}` : undefined} />
      <ErrorLine error={h.error} />
      <Section flush>
        <Table rows={COMPONENTS} rowKey={(r) => r[0]} cols={[
          { key: "n", header: "Component", render: ([, n, d]) => <><div className="font-medium">{n}</div><div className="text-xs text-ink-3">{d}</div></> },
          { key: "s", header: "Status", render: ([k]) => { const s = h.data?.components[k] ?? "unknown"; return <Lamp tone={tone(s)} label={word(s)} />; } },
        ]} />
      </Section>
      <Section title="Flow collector" aside={col?.running ? `Version ${col.version}, started ${ago(col.started_at)}` : undefined}>
        {!col?.running ? <Notice tone="attack">The collector has not reported in the last 15 seconds. Check <code>systemctl status shield-collector</code>.</Notice> : (
          <div className="space-y-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3 lg:grid-cols-6">
              <Stat k="Prefixes loaded" v={`${col.prefixes} (${col.prefix_source === "api" ? "from API" : "static only"})`} />
              <Stat k="Queue drops" v={col.queue_drops} warn={!!col.queue_drops} />
              <Stat k="Rejected packets" v={col.rejected_packets} warn={!!col.rejected_packets} hint="From addresses not listed as exporters" />
              <Stat k="Malformed packets" v={col.decode_errors} warn={!!col.decode_errors} />
              <Stat k="Records without template" v={col.missing_template_records} />
              <Stat k="ClickHouse backlog" v={col.clickhouse ? `${col.clickhouse.pending} rows` : "disabled"} warn={!!col.clickhouse?.errors} />
            </dl>
            {col.clickhouse?.last_error && <Notice tone="warn">Last ClickHouse error: {col.clickhouse.last_error}</Notice>}
            <Table dense rows={col.exporters ?? []} rowKey={(e) => `${e.address}${e.kind}`} empty="No exporter has sent anything yet."
              cols={[
                { key: "a", header: "Exporter", render: (e) => <><span className="font-medium">{e.name || e.address}</span> <span className="text-ink-3">{e.address}</span></> },
                { key: "k", header: "Protocol", render: (e) => ({ netflow_v9: "NetFlow v9", ipfix: "IPFIX", sflow: "sFlow" } as Record<string, string>)[e.kind] ?? e.kind },
                { key: "s", header: "Sampling", render: (e) => e.sampling_source === "unknown"
                    ? <Badge tone="warn">Unknown: figures are estimates</Badge>
                    : <>1 in {e.sampling_rate} <span className="text-ink-3">{e.sampling_source === "override" ? "(configured)" : "(from exporter)"}</span></> },
                { key: "r", header: "Records", align: "right", render: (e) => e.records.toLocaleString() },
                { key: "l", header: "Last packet", render: (e) => e.stale ? <Lamp tone="attack" label={ago(e.last_seen)} /> : <Lamp tone="ok" label={ago(e.last_seen)} /> },
              ]} />
          </div>
        )}
      </Section>
    </div>
  );
}

function Stat({ k, v, warn, hint }: { k: string; v: ReactNode; warn?: boolean; hint?: string }) {
  return <div title={hint}><dt className="text-ink-2">{k}</dt><dd className={`text-lg font-medium ${warn ? "text-warn" : ""}`}>{v ?? "–"}</dd></div>;
}

// ================================================================ Later phases
export function NoAccess({ what }: { what: string }) {
  return <div className="space-y-4"><PageHeader title="Not available" /><Notice>Your role cannot {what}. Ask an administrator if you need access.</Notice></div>;
}

export function Upcoming({ title, phase, children }: { title: string; phase: number; children: ReactNode }) {
  return (
    <div className="space-y-5">
      <PageHeader title={title} />
      <section className="hatch rounded-[3px] border border-dashed border-rule px-6 py-10">
        <div className="max-w-[62ch] space-y-3 rounded-[3px] bg-panel p-5">
          <Badge>Arrives in phase {phase}</Badge>
          <div className="space-y-2 text-[15px]">{children}</div>
        </div>
      </section>
    </div>
  );
}
