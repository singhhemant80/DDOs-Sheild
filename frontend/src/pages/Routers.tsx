import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Check as CheckIcon, CircleAlert, KeyRound, Pencil, Plug, Plus, TriangleAlert } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { ago, bps, count, dateTime, pps } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";

// ---------------------------------------------------------------- types
export type Router = {
  id: number; name: string; model: string; role: string; mgmt_address: string; api_port: number; use_tls: boolean;
  verify_tls: boolean; api_username: string | null; access_mode: string; dry_run: boolean; enabled: boolean;
  identity: string | null; routeros_version: string | null; status: string; last_seen_at: string | null;
  has_api_password: boolean; notes: string | null; tls_fingerprint: string | null;
};
export type Finding = { level: "ok" | "warn" | "error"; code: string; message: string };
export type Peer = {
  name: string; remote_address: string; remote_as: number | null; local_as: number | null; role: string | null;
  disabled: boolean; state: string; established: boolean; uptime_seconds: number | null; prefixes_received: number | null;
  local_address: string | null; input_filter?: string | null; output_filter?: string | null;
};
export type RouterIface = {
  name: string; type: string; running: boolean; disabled: boolean; comment: string | null;
  rx_drop: number; tx_drop: number; rx_error: number; tx_error: number; link_downs: number;
  in_bps?: number; out_bps?: number; in_pps?: number; out_pps?: number;
};
export type RouterState = {
  router_id: number; polled_at: string; ok: boolean; error: string | null; consecutive_failures: number;
  identity: string | null; version: string | null; board: string | null; uptime_seconds: number | null; cpu_load: number | null;
  resources: Record<string, any>; checks: Finding[]; bgp: Peer[];
  interfaces?: RouterIface[]; addresses?: { address: string; interface: string; disabled: boolean }[];
  routes?: { dst: string; gateway: string | null; distance: number; table: string; active: boolean; blackhole: boolean;
    static: boolean; bgp: boolean; comment: string | null }[];
  traffic_flow?: { enabled: boolean; interfaces: string; sampling: boolean; sampling_interval: number | null; sampling_rate: number | null;
    active_timeout_seconds: number | null; inactive_timeout_seconds: number | null;
    targets: { address: string; port?: number; version: string; src_address: string | null; disabled: boolean }[] };
  permissions?: { username?: string; group?: string | null; policies?: string[]; write_policies?: string[]; last_error?: any };
};
export type RouterEvent = { id: number; router_id: number; router: string | null; at: string; kind: string; severity: string; message: string };
type TestResult = {
  ok: boolean; kind?: string; error?: string; presented_fingerprint?: string | null; tls?: string;
  system?: Record<string, any>; checks?: Finding[]; permissions?: RouterState["permissions"]; bgp?: Peer[]; interfaces?: number;
};
type Cert = { fingerprint: string; tls_version: string; subject?: string; issuer?: string; not_after?: string;
  self_signed?: boolean; pinned: string | null; matches_pin: boolean | null };

// ---------------------------------------------------------------- helpers
export function duration(s: number | null | undefined) {
  if (s == null) return "–";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : m ? `${m} min` : `${s} s`;
}

/** Why a router that answers is "degraded", in words. */
export function statusLabel(status: string, s?: RouterState) {
  if (status !== "degraded" || !s) return STATUS_WORD[status] ?? status;
  const down = s.bgp.filter((p) => !p.disabled && !p.established).length;
  const failed = s.checks.filter((c) => c.code.startsWith("read_")).length;
  if (down) return `Up, ${down} BGP session${down > 1 ? "s" : ""} down`;
  if (failed) return "Up, some data could not be read";
  return STATUS_WORD.degraded;
}

export function statusTone(status: string): "ok" | "warn" | "attack" | "neutral" {
  return status === "up" ? "ok" : status === "degraded" ? "warn" : status === "down" ? "attack" : "neutral";
}

const STATUS_WORD: Record<string, string> = { up: "Up", degraded: "Up, with problems", down: "Unreachable", unknown: "Not polled yet" };
const TLS_WORD: Record<string, string> = {
  pinned: "TLS, certificate pinned", ca: "TLS, certificate verified", none: "TLS, certificate not verified", plain: "No TLS",
};
const SEV_TONE: Record<string, "ok" | "warn" | "attack" | "neutral" | "signal"> = {
  info: "ok", low: "neutral", medium: "warn", high: "attack", critical: "attack",
};

function FindingList({ items }: { items: Finding[] }) {
  if (!items.length) return <p className="px-4 py-3 text-sm text-ink-3">No checks yet. They run on the first full poll.</p>;
  const order = { error: 0, warn: 1, ok: 2 };
  return (
    <ul className="divide-y divide-rule-soft">
      {[...items].sort((a, b) => order[a.level] - order[b.level]).map((f) => (
        <li key={f.code} className="flex gap-2.5 px-4 py-2 text-sm">
          {f.level === "ok" ? <CheckIcon size={16} className="mt-0.5 shrink-0 text-ok" aria-label="OK" />
            : f.level === "warn" ? <TriangleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-label="Warning" />
            : <CircleAlert size={16} className="mt-0.5 shrink-0 text-attack" aria-label="Problem" />}
          <span>{f.message}</span>
        </li>
      ))}
    </ul>
  );
}

function PeerState({ p }: { p: Peer }) {
  if (p.disabled) return <span className="text-ink-3">Disabled</span>;
  return <Lamp tone={p.established ? "ok" : "attack"} label={p.established ? `Established ${duration(p.uptime_seconds)}` : p.state} />;
}

// ---------------------------------------------------------------- list (used on Routers & upstreams)
export function RouterList() {
  const { can } = useAuth();
  const nav = useNavigate();
  const routers = useApi<Router[]>("/routers", 15_000);
  const states = useApi<RouterState[]>("/routers/states", 15_000);
  const [edit, setEdit] = useState<Router | "new" | null>(null);
  const st = (id: number) => states.data?.find((s) => s.router_id === id);
  return (
    <Section title="Edge routers" flush
      aside={can("config_network") && <Button onClick={() => setEdit("new")}><Plus size={16} /> Add router</Button>}>
      <ErrorLine error={routers.error} />
      <Table rows={routers.data ?? []} rowKey={(r) => String(r.id)} onRow={(r) => nav(`/routers/${r.id}`)}
        empty="No routers yet. Add the edge routers so Shield can read their interfaces, BGP sessions and flow export settings."
        cols={[
          { key: "n", header: "Router", render: (r) => <><div className="font-medium">{r.name}</div>
            <div className="text-xs text-ink-3">{r.model.toUpperCase()}, {r.role}{r.identity && r.identity !== r.name ? `, identity ${r.identity}` : ""}</div></> },
          { key: "a", header: "Management", render: (r) => <>{r.mgmt_address}:{r.api_port}
            <div className="text-xs text-ink-3">{!r.use_tls ? "No TLS" : r.tls_fingerprint ? "Certificate pinned" : r.verify_tls ? "CA-verified TLS" : "TLS, not verified"}</div></> },
          { key: "s", header: "Status", render: (r) => {
            const s = st(r.id);
            if (!r.enabled) return <span className="text-ink-3">Disabled</span>;
            if (!r.has_api_password) return <span className="text-ink-3">No credentials</span>;
            return <><Lamp tone={statusTone(r.status)} label={statusLabel(r.status, s)} />
              <div className="text-xs text-ink-3">{s && !s.ok ? s.error : `last read ${ago(r.last_seen_at ? Date.parse(r.last_seen_at) / 1000 : null)}`}</div></>;
          } },
          { key: "b", header: "BGP", render: (r) => {
            const peers = (st(r.id)?.bgp ?? []).filter((p) => !p.disabled);
            if (!peers.length) return <span className="text-ink-3">–</span>;
            const up = peers.filter((p) => p.established).length;
            return <Lamp tone={up === peers.length ? "ok" : up ? "warn" : "attack"} label={`${up} of ${peers.length} up`} />;
          } },
          { key: "c", header: "Checks", render: (r) => {
            const c = st(r.id)?.checks ?? [];
            const e = c.filter((x) => x.level === "error").length, w = c.filter((x) => x.level === "warn").length;
            return !c.length ? <span className="text-ink-3">–</span> : e ? <Badge tone="attack">{e} problem{e > 1 ? "s" : ""}</Badge>
              : w ? <Badge tone="warn">{w} warning{w > 1 ? "s" : ""}</Badge> : <Badge tone="ok">All good</Badge>;
          } },
          { key: "v", header: "RouterOS", render: (r) => r.routeros_version ?? <span className="text-ink-3">–</span> },
        ]} />
      {edit && <RouterDialog router={edit === "new" ? null : edit} onClose={() => setEdit(null)}
        onSaved={(r) => { routers.reload(); if (edit === "new") nav(`/routers/${r.id}`); }} />}
    </Section>
  );
}

// ---------------------------------------------------------------- add / edit
function RouterDialog({ router, onClose, onSaved }: { router: Router | null; onClose: () => void; onSaved: (r: Router) => void }) {
  const [f, setF] = useState({
    name: router?.name ?? "", model: router?.model ?? "ccr2004", role: router?.role ?? "primary",
    mgmt_address: router?.mgmt_address ?? "", api_port: String(router?.api_port ?? 8729), use_tls: router?.use_tls ?? true,
    verify_tls: router?.verify_tls ?? true, api_username: router?.api_username ?? "", api_password: "",
    tls_fingerprint: router?.tls_fingerprint ?? "", enabled: router?.enabled ?? true, notes: router?.notes ?? "",
  });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const save = async () => {
    setErr(null); setBusy(true);
    const common = { api_port: Number(f.api_port), use_tls: f.use_tls, verify_tls: f.verify_tls, role: f.role,
      api_username: f.api_username || null, enabled: f.enabled, notes: f.notes || null,
      ...(f.api_password ? { api_password: f.api_password } : {}) };
    try {
      const r = router
        ? await api<Router>(`/routers/${router.id}`, { method: "PATCH", body: { ...common, tls_fingerprint: f.tls_fingerprint } })
        : await api<Router>("/routers", { method: "POST", body: { ...common, name: f.name, model: f.model,
            mgmt_address: f.mgmt_address, tls_fingerprint: f.tls_fingerprint || null } });
      onSaved(r); onClose();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <Dialog open title={router ? `Edit ${router.name}` : "Add router"} onClose={onClose}
      footer={<><Button variant="quiet" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={save} disabled={busy}>{router ? "Save" : "Add router"}</Button></>}>
      <Notice>Shield only reads from routers in this phase. Give it a RouterOS account in a group with just
        <code className="mx-1">read,api,test</code> and allow it from the Shield server's address only.
        The templates in <code>deploy/mikrotik</code> set this up.</Notice>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><Input value={f.name} disabled={!!router} onChange={(e) => set("name", e.target.value)} /></Field>
        <Field label="Model"><Select value={f.model} disabled={!!router} onChange={(v) => set("model", v)}
          options={[["ccr2004", "CCR2004"], ["ccr2116", "CCR2116"], ["other", "Other RouterOS 7"]]} /></Field>
        <Field label="Management address" hint="Shield connects to this address"><Input value={f.mgmt_address} disabled={!!router}
          onChange={(e) => set("mgmt_address", e.target.value)} placeholder="10.255.0.1" /></Field>
        <Field label="Role"><Select value={f.role} onChange={(v) => set("role", v)}
          options={["primary", "secondary", "edge", "lab"].map((v) => [v, v[0].toUpperCase() + v.slice(1)] as [string, string])} /></Field>
        <Field label="API port" hint="api-ssl is 8729"><Input inputMode="numeric" value={f.api_port} onChange={(e) => set("api_port", e.target.value)} /></Field>
        <div className="space-y-2 pt-6">
          <Check label="Use TLS (api-ssl)" checked={f.use_tls} onChange={(v) => { set("use_tls", v); set("api_port", v ? "8729" : "8728"); }} />
          <Check label="Verify the certificate" checked={f.verify_tls} disabled={!f.use_tls} onChange={(v) => set("verify_tls", v)} />
        </div>
        <Field label="API username"><Input autoComplete="off" value={f.api_username} onChange={(e) => set("api_username", e.target.value)} placeholder="shield-ro" /></Field>
        <Field label="API password" hint={router?.has_api_password ? "Stored encrypted. Leave empty to keep it." : "Stored encrypted; never shown again."}>
          <Input type="password" autoComplete="new-password" value={f.api_password} onChange={(e) => set("api_password", e.target.value)} /></Field>
        <div className="sm:col-span-2"><Field label="Pinned certificate (SHA-256)"
          hint="Optional. With a pin, Shield accepts only this certificate, whoever signed it. Use Get certificate on the router page to read it.">
          <Input className="font-mono text-xs" value={f.tls_fingerprint} onChange={(e) => set("tls_fingerprint", e.target.value)} placeholder="AB:CD:…" /></Field></div>
        <div className="sm:col-span-2"><Check label="Poll this router" checked={f.enabled} onChange={(v) => set("enabled", v)} /></div>
      </div>
      {f.use_tls && !f.verify_tls && !f.tls_fingerprint && <Notice tone="warn">Without verification or a pin, anyone able to
        intercept the management network could capture these credentials. Pin the certificate once you have checked it.</Notice>}
      {!f.use_tls && <Notice tone="warn">The plain API sends the password unencrypted. Use api-ssl.</Notice>}
      <ErrorLine error={err} />
    </Dialog>
  );
}

// ---------------------------------------------------------------- detail
export function RouterDetail() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const router = useApi<Router>(`/routers/${id}`, 15_000);
  const state = useApi<RouterState | null>(`/routers/${id}/state`, 10_000);
  const events = useApi<RouterEvent[]>(`/routers/${id}/events?limit=50`, 15_000);
  const [editing, setEditing] = useState(false);
  const [test, setTest] = useState<TestResult | "busy" | null>(null);
  const [cert, setCert] = useState<Cert | "busy" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const r = router.data, s = state.data;

  const runTest = async () => {
    setErr(null); setTest("busy");
    try { setTest(await api<TestResult>(`/routers/${id}/test`, { method: "POST" })); } catch (e: any) { setTest(null); setErr(e.message); }
  };
  const getCert = async () => {
    setErr(null); setCert("busy");
    try { setCert(await api<Cert>(`/routers/${id}/certificate`, { method: "POST" })); } catch (e: any) { setCert(null); setErr(e.message); }
  };
  const pin = async (fp: string) => {
    setErr(null);
    try { await api(`/routers/${id}`, { method: "PATCH", body: { tls_fingerprint: fp } }); setCert(null); setTest(null); router.reload(); }
    catch (e: any) { setErr(e.message); }
  };

  if (router.error) return <ErrorLine error={router.error} />;
  if (!r) return <p className="text-ink-2">Loading…</p>;
  const ifaces = (s?.interfaces ?? []).filter((i) => i.type !== "loopback");
  return (
    <div className="space-y-5">
      <Link to="/routers" className="inline-flex items-center gap-1 text-sm text-ink-2 hover:text-ink"><ArrowLeft size={15} /> Routers & upstreams</Link>
      <PageHeader title={r.name}
        description={<>{r.model.toUpperCase()} at {r.mgmt_address}:{r.api_port}{s?.version ? <>, RouterOS {s.version}</> : null}{s?.board ? <>, {s.board}</> : null}</>}
        actions={can("config_network") && <>
          <Button onClick={runTest} disabled={test === "busy" || !r.has_api_password}><Plug size={16} /> {test === "busy" ? "Testing…" : "Test connection"}</Button>
          {r.use_tls && <Button onClick={getCert} disabled={cert === "busy"}><KeyRound size={16} /> Get certificate</Button>}
          <Button onClick={() => setEditing(true)}><Pencil size={16} /> Edit</Button>
        </>} />
      <ErrorLine error={err} />
      {!r.has_api_password && <Notice tone="warn">No API credentials are stored, so Shield cannot read this router. Edit it to add them.</Notice>}
      {s && !s.ok && <Notice tone="attack">Last attempt {ago(Date.parse(s.polled_at) / 1000)} failed: {s.error}
        {s.consecutive_failures > 1 ? ` (${s.consecutive_failures} in a row)` : ""}</Notice>}

      <div className="grid gap-px overflow-hidden rounded-[3px] border border-rule bg-rule sm:grid-cols-3 lg:grid-cols-6">
        {[
          ["Status", r.enabled ? <Lamp tone={statusTone(r.status)} label={statusLabel(r.status, s ?? undefined)} /> : "Disabled"],
          ["Last read", s ? ago(Date.parse(s.polled_at) / 1000) : "never"],
          ["Uptime", duration(s?.uptime_seconds)],
          ["CPU", s?.cpu_load != null ? `${s.cpu_load}%` : "–"],
          ["Memory", s?.resources?.memory_used_pct != null ? `${s.resources.memory_used_pct}% used` : "–"],
          ["API", s?.resources?.tls ? <>{TLS_WORD[s.resources.tls] ?? s.resources.tls}<div className="text-xs text-ink-3">{s.resources.api_latency_ms} ms</div></> : "–"],
        ].map(([k, v]) => (
          <div key={k as string} className="bg-panel px-4 py-3">
            <div className="text-xs text-ink-3">{k}</div><div className="mt-0.5 text-sm font-medium">{v}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Section title="Checks" flush aside={<span className="text-xs text-ink-3">Every minute</span>}>
          <FindingList items={s?.checks ?? []} />
        </Section>
        <Section title="Flow export" flush>
          {!s?.traffic_flow ? <p className="px-4 py-3 text-sm text-ink-3">Not read yet.</p> : (
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 px-4 py-3 text-sm">
              <dt className="text-ink-2">Traffic-flow</dt><dd>{s.traffic_flow.enabled ? "Enabled" : <span className="text-attack">Disabled</span>}</dd>
              <dt className="text-ink-2">Interfaces</dt><dd>{s.traffic_flow.interfaces || "all"}</dd>
              <dt className="text-ink-2">Sampling</dt><dd>{!s.traffic_flow.sampling ? "Off (every packet)" : s.traffic_flow.sampling_rate ? `1 in ${s.traffic_flow.sampling_rate}` : "On, rate unknown"}</dd>
              <dt className="text-ink-2">Timeouts</dt><dd>active {duration(s.traffic_flow.active_timeout_seconds)}, inactive {duration(s.traffic_flow.inactive_timeout_seconds)}</dd>
              <dt className="text-ink-2">Targets</dt><dd>{s.traffic_flow.targets.length ? s.traffic_flow.targets.map((t) => (
                <div key={t.address}>{t.address}{t.port ? `:${t.port}` : ""} {t.version.toUpperCase()}{t.src_address ? `, from ${t.src_address}` : ""}{t.disabled ? " (disabled)" : ""}</div>))
                : <span className="text-attack">None</span>}</dd>
              {s.permissions?.group && <><dt className="text-ink-2">Shield's account</dt>
                <dd>{s.permissions.username} in group {s.permissions.group}
                  {s.permissions.write_policies?.length ? <> <Badge tone="attack">can write</Badge></> : <> <Badge tone="ok">read-only</Badge></>}</dd></>}
            </dl>)}
        </Section>
      </div>

      <Section title="Interfaces" flush aside={<span className="text-xs text-ink-3">Counters every 10 s, measured</span>}>
        <Table dense rows={ifaces} rowKey={(i) => i.name} empty="Not read yet."
          cols={[
            { key: "n", header: "Interface", render: (i) => <><div className="font-medium">{i.name}</div>{i.comment && <div className="text-xs text-ink-3">{i.comment}</div>}</> },
            { key: "s", header: "Link", render: (i) => i.disabled ? <span className="text-ink-3">Disabled</span> : <Lamp tone={i.running ? "ok" : "attack"} label={i.running ? "Running" : "Down"} /> },
            { key: "in", header: "In", align: "right", render: (i) => i.in_bps == null ? <span className="text-ink-3">–</span> : <>{bps(i.in_bps)}<div className="text-xs text-ink-3">{pps(i.in_pps)}</div></> },
            { key: "out", header: "Out", align: "right", render: (i) => i.out_bps == null ? <span className="text-ink-3">–</span> : <>{bps(i.out_bps)}<div className="text-xs text-ink-3">{pps(i.out_pps)}</div></> },
            { key: "e", header: "Drops / errors", align: "right", render: (i) => {
              const d = i.rx_drop + i.tx_drop, e = i.rx_error + i.tx_error;
              return <span className={d || e ? "text-warn" : "text-ink-3"}>{count(d)} / {count(e)}</span>;
            } },
          ]} />
      </Section>

      <Section title="BGP" flush>
        <Table dense rows={s?.bgp ?? []} rowKey={(p) => p.name + p.remote_address} empty="No BGP connections on this router."
          cols={[
            { key: "n", header: "Connection", render: (p) => <><div className="font-medium">{p.name}</div><div className="text-xs text-ink-3">{p.role ?? ""}</div></> },
            { key: "r", header: "Peer", render: (p) => <>{p.remote_address}<div className="text-xs text-ink-3">AS{p.remote_as ?? "?"}</div></> },
            { key: "s", header: "State", render: (p) => <PeerState p={p} /> },
            { key: "p", header: "Prefixes received", align: "right", render: (p) => p.prefixes_received != null ? p.prefixes_received.toLocaleString() : "–" },
            { key: "f", header: "Filters", render: (p) => <span className="text-xs text-ink-2">{[p.input_filter && `in ${p.input_filter}`, p.output_filter && `out ${p.output_filter}`].filter(Boolean).join(", ") || "–"}</span> },
          ]} />
      </Section>

      <Section title="Routes for protected prefixes" flush aside={<span className="text-xs text-ink-3">Only these are read, never the full table</span>}>
        <Table dense rows={s?.routes ?? []} rowKey={(x) => `${x.dst}|${x.gateway}|${x.distance}|${x.table}`} empty="No matching routes read yet."
          cols={[
            { key: "d", header: "Destination", render: (x) => <span className="font-mono text-[13px]">{x.dst}</span> },
            { key: "g", header: "Via", render: (x) => x.blackhole ? <Badge tone="attack">Blackhole</Badge> : x.gateway ?? "–" },
            { key: "t", header: "Type", render: (x) => `${x.bgp ? "BGP" : x.static ? "Static" : "Other"}, distance ${x.distance}${x.table !== "main" ? `, table ${x.table}` : ""}` },
            { key: "a", header: "Active", render: (x) => x.active ? "Yes" : <span className="text-ink-3">No</span> },
            { key: "c", header: "Comment", render: (x) => <span className="text-ink-2">{x.comment ?? ""}</span> },
          ]} />
      </Section>

      <Section title="Events" flush>
        <EventTable rows={events.data ?? []} />
      </Section>

      {editing && <RouterDialog router={r} onClose={() => setEditing(false)} onSaved={() => { router.reload(); }} />}
      {test && test !== "busy" && <TestDialog res={test} canPin={can("config_network")} onPin={pin} onClose={() => setTest(null)} />}
      {cert && cert !== "busy" && <CertDialog cert={cert} onPin={pin} onClose={() => setCert(null)} />}
    </div>
  );
}

export function EventTable({ rows, showRouter }: { rows: RouterEvent[]; showRouter?: boolean }) {
  return (
    <Table dense rows={rows} rowKey={(e) => String(e.id)} empty="Nothing has happened yet."
      cols={[
        { key: "t", header: "When", render: (e) => <span className="whitespace-nowrap text-ink-2">{dateTime(e.at)}</span> },
        ...(showRouter ? [{ key: "r", header: "Router", render: (e: RouterEvent) => e.router ?? "–" }] : []),
        { key: "m", header: "What happened", render: (e) => <Lamp tone={SEV_TONE[e.severity] ?? "neutral"} label={e.message} /> },
      ]} />
  );
}

function PinNote() {
  return <p className="text-sm text-ink-2">Before pinning, compare this with the fingerprint the router shows for its api-ssl
    certificate: <code>/certificate print detail</code> (field <code>fingerprint</code>). If they differ, someone may be
    intercepting the connection; do not pin.</p>;
}

function TestDialog({ res, canPin, onPin, onClose }: { res: TestResult; canPin: boolean; onPin: (fp: string) => void; onClose: () => void }) {
  return (
    <Dialog open title={res.ok ? "Connected" : "Connection failed"} onClose={onClose}
      footer={<>
        {res.presented_fingerprint && canPin && <Button onClick={() => onPin(res.presented_fingerprint!)}><KeyRound size={16} /> Pin this certificate</Button>}
        <Button variant="primary" onClick={onClose}>Close</Button></>}>
      {res.ok ? <>
        <p className="text-sm">{res.system?.identity}, RouterOS {res.system?.version}, {res.interfaces} interfaces, {res.bgp?.length ?? 0} BGP connections. {TLS_WORD[res.tls ?? ""]}.</p>
        <div className="-mx-5 border-y border-rule-soft"><FindingList items={res.checks ?? []} /></div>
      </> : <>
        <Notice tone="attack">{res.error}</Notice>
        {res.presented_fingerprint && <>
          <p className="text-sm">The router presented this certificate:</p>
          <p className="break-all font-mono text-xs">{res.presented_fingerprint}</p>
          <PinNote />
        </>}
        {res.kind === "auth" && <p className="text-sm text-ink-2">Check the username and password, and that the account's allowed
          address includes the Shield server.</p>}
        {res.kind === "unreachable" && <p className="text-sm text-ink-2">Check that the api-ssl service is enabled, that its
          allowed address includes the Shield server, and that a firewall is not dropping the connection.</p>}
      </>}
    </Dialog>
  );
}

function CertDialog({ cert, onPin, onClose }: { cert: Cert; onPin: (fp: string) => void; onClose: () => void }) {
  return (
    <Dialog open title="Router certificate" onClose={onClose}
      footer={<>
        {!cert.matches_pin && <Button onClick={() => onPin(cert.fingerprint)}><KeyRound size={16} /> Pin this certificate</Button>}
        <Button variant="primary" onClick={onClose}>Close</Button></>}>
      <p className="text-sm text-ink-2">Read without sending any credentials.</p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-ink-2">SHA-256</dt><dd className="break-all font-mono text-xs">{cert.fingerprint}</dd>
        {cert.subject && <><dt className="text-ink-2">Subject</dt><dd>{cert.subject}</dd></>}
        {cert.issuer && <><dt className="text-ink-2">Issuer</dt><dd>{cert.self_signed ? "Self-signed" : cert.issuer}</dd></>}
        {cert.not_after && <><dt className="text-ink-2">Expires</dt><dd>{dateTime(cert.not_after)}</dd></>}
        <dt className="text-ink-2">Protocol</dt><dd>{cert.tls_version}</dd>
      </dl>
      {cert.matches_pin === true && <Notice tone="ok">This is the pinned certificate.</Notice>}
      {cert.matches_pin === false && <Notice tone="attack">This is not the pinned certificate ({cert.pinned}). Shield will refuse to
        connect. Pin it only if you replaced the certificate on purpose.</Notice>}
      {!cert.matches_pin && <PinNote />}
    </Dialog>
  );
}

// ---------------------------------------------------------------- topology
type Upstream = { id: number; name: string; asn: number; router_id: number | null; interface_name: string | null;
  capacity_mbps: number | null; saturation_threshold_pct: number; ddos_protected: boolean; enabled: boolean };
type IfaceRate = { agent: string; if_name?: string; router: string | null; in_bps: number; out_bps: number; in_util: number;
  provenance: string; saturated: boolean; source: string };

export function Topology() {
  const routers = useApi<Router[]>("/routers", 15_000);
  const states = useApi<RouterState[]>("/routers/states", 10_000);
  const ups = useApi<Upstream[]>("/upstreams", 30_000);
  const ifaces = useApi<{ interfaces: IfaceRate[] }>("/traffic/interfaces", 10_000);
  const nav = useNavigate();

  const layout = useMemo(() => {
    const rs = routers.data ?? [];
    const us = (ups.data ?? []).filter((u) => u.enabled);
    const W = Math.max(900, Math.max(rs.length, us.length) * 240);
    const xs = (n: number, i: number) => (W / n) * (i + 0.5);
    return {
      W, H: 470,
      ups: us.map((u, i) => ({ u, x: xs(us.length, i), y: 60 })),
      rts: rs.map((r, i) => ({ r, x: xs(rs.length, i), y: 235 })),
      shield: { x: W / 2, y: 410 },
    };
  }, [routers.data, ups.data]);

  if (routers.error) return <ErrorLine error={routers.error} />;
  const st = (id: number) => states.data?.find((s) => s.router_id === id);
  const rate = (r: Router | undefined, name: string | null) =>
    r && name ? (ifaces.data?.interfaces ?? []).find((i) => i.agent === r.mgmt_address && i.if_name === name) : undefined;
  const color = { ok: "var(--ok)", warn: "var(--warn)", attack: "var(--attack)", neutral: "var(--ink-3)" };
  const flowOk = (s?: RouterState) => s?.checks.some((c) => c.code === "flow_ok");

  return (
    <div className="space-y-5">
      <PageHeader title="Topology" description="Upstream links, edge routers and Shield, drawn from what the routers report. Select a router for detail." />
      {!layout.rts.length ? <Notice>Add edge routers and upstream providers under Routers & upstreams to see the map.</Notice> : (
        <Section flush>
          <div className="overflow-x-auto">
            <svg viewBox={`0 0 ${layout.W} ${layout.H}`} className="mx-auto block min-w-[720px]" style={{ maxWidth: layout.W }} role="img"
              aria-label="Network topology: upstream providers, edge routers and the Shield server">
              <defs>
                <pattern id="topo-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                  <line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink-3)" strokeWidth="1.5" />
                </pattern>
              </defs>
              {/* upstream -> router links */}
              {layout.ups.map(({ u, x, y }) => {
                const t = layout.rts.find((p) => p.r.id === u.router_id);
                if (!t) return null;
                const s = st(t.r.id);
                const peer = s?.bgp.find((p) => p.remote_as === u.asn && !p.disabled);
                const iface = s?.interfaces?.find((i) => i.name === u.interface_name);
                const live = rate(t.r, u.interface_name);
                const bgpTone = !peer ? "neutral" : peer.established ? "ok" : "attack";
                const util = live && live.provenance === "measured" ? live.in_util : null;
                const lineTone = live?.saturated ? "attack" : util != null && util >= 0.6 ? "warn" : bgpTone === "attack" ? "attack" : "ok";
                const unknown = !live || live.provenance !== "measured";
                const mx = (x + t.x) / 2, my = (y + 22 + t.y - 26) / 2;
                return (
                  <g key={`u${u.id}`}>
                    <line x1={x} y1={y + 22} x2={t.x} y2={t.y - 26} stroke={unknown ? "var(--ink-3)" : color[lineTone]}
                      strokeWidth={unknown ? 2 : 2 + Math.min(6, (util ?? 0) * 8)} strokeDasharray={unknown ? "5 5" : undefined} />
                    <rect x={mx - 78} y={my - 20} width={156} height={40} rx={3} fill="var(--panel)" stroke="var(--rule)" />
                    <text x={mx} y={my - 4} textAnchor="middle" fontSize="12" fill="var(--ink)">
                      {u.interface_name ?? "interface not set"}{iface && !iface.running ? " (down)" : ""}
                    </text>
                    <text x={mx} y={my + 12} textAnchor="middle" fontSize="11.5" fill="var(--ink-2)">
                      {unknown ? "no rate data" : `${bps(live!.in_bps)} in${u.capacity_mbps ? ` of ${u.capacity_mbps / 1000} G` : ""}`}
                    </text>
                    <circle cx={mx + 70} cy={my - 8} r={4} fill={color[bgpTone]}>
                      <title>{peer ? `BGP ${peer.name}: ${peer.state}` : "No BGP session to this AS seen on the router"}</title>
                    </circle>
                  </g>
                );
              })}
              {/* router -> shield links */}
              {layout.rts.map(({ r, x, y }) => {
                const s = st(r.id);
                const tone = !s ? "neutral" : !s.ok ? "attack" : flowOk(s) ? "ok" : "warn";
                return (
                  <g key={`l${r.id}`}>
                    <line x1={x} y1={y + 26} x2={layout.shield.x} y2={layout.shield.y - 22} stroke={color[tone]} strokeWidth={1.5}
                      strokeDasharray={s?.ok ? undefined : "4 4"} />
                    <text x={(x + layout.shield.x) / 2 + 6} y={(y + 26 + layout.shield.y - 22) / 2} fontSize="11" fill="var(--ink-2)">
                      {!s ? "not polled" : !s.ok ? "API unreachable" : flowOk(s) ? "API + flow export" : "API, flow export needs attention"}
                    </text>
                  </g>
                );
              })}
              {layout.ups.map(({ u, x, y }) => (
                <g key={`un${u.id}`}>
                  <rect x={x - 90} y={y - 22} width={180} height={44} rx={22} fill="var(--sunk)" stroke="var(--rule)" />
                  <text x={x} y={y - 3} textAnchor="middle" fontSize="13.5" fontWeight="600" fill="var(--ink)">{u.name}</text>
                  <text x={x} y={y + 13} textAnchor="middle" fontSize="11.5" fill="var(--ink-2)">AS{u.asn}{u.ddos_protected ? ", DDoS-protected" : ""}</text>
                </g>
              ))}
              {layout.rts.map(({ r, x, y }) => {
                const s = st(r.id);
                const tone = statusTone(r.status);
                return (
                  <g key={`r${r.id}`} className="cursor-pointer" onClick={() => nav(`/routers/${r.id}`)} role="link" tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter") nav(`/routers/${r.id}`); }} aria-label={`${r.name}, ${STATUS_WORD[r.status]}`}>
                    <rect x={x - 95} y={y - 26} width={190} height={52} rx={3} fill="var(--panel)" stroke={color[tone]} strokeWidth={2} />
                    <rect x={x - 95} y={y - 26} width={5} height={52} fill={color[tone]} />
                    <text x={x - 80} y={y - 6} fontSize="14" fontWeight="600" fill="var(--ink)">{r.name}</text>
                    <text x={x - 80} y={y + 12} fontSize="11.5" fill="var(--ink-2)">
                      {r.model.toUpperCase()}{s?.ok ? `, CPU ${s.cpu_load}%` : ""}{s?.version ? `, ${s.version.split(" ")[0]}` : ""}
                    </text>
                  </g>
                );
              })}
              <g>
                <rect x={layout.shield.x - 80} y={layout.shield.y - 22} width={160} height={44} rx={3} fill="var(--signal-soft)" stroke="var(--signal)" />
                <text x={layout.shield.x} y={layout.shield.y + 5} textAnchor="middle" fontSize="14" fontWeight="600" fill="var(--ink)">Shield</text>
              </g>
            </svg>
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-1 border-t border-rule-soft px-4 py-2 text-xs text-ink-2">
            <span>Line width: inbound load</span>
            <span>Dashed: no measured data</span>
            <Lamp tone="ok" label="BGP established" />
            <Lamp tone="attack" label="BGP down or router unreachable" />
            <Lamp tone="neutral" label="No session seen" />
          </div>
        </Section>
      )}
    </div>
  );
}
