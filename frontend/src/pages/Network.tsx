import { useEffect, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { accessToken, api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { dateTime } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";
import { duration, EventTable, RouterList, type Peer, type RouterEvent } from "./Routers";

// ================================================================ Protected prefixes
type Prefix = {
  id: number; prefix: string; description: string | null; enabled: boolean; ownership_verified: boolean;
  ownership_evidence: string | null; rtbh_allowed: boolean; steering_allowed: boolean; filtering_allowed: boolean;
  min_mitigation_prefix_len: number; authorized_at: string | null;
};
type Eligibility = {
  target: string; protected_prefix: string | null; rtbh_allowed: boolean; steering_allowed: boolean;
  filtering_allowed: boolean; within_scope_limit: boolean; customer: Record<string, string> | null; reasons: string[];
};

export function Prefixes() {
  const { can } = useAuth();
  const list = useApi<Prefix[]>("/prefixes");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Prefix | null>(null);
  return (
    <div className="space-y-5">
      <PageHeader title="Protected prefixes"
        description="Address space Shield watches. Nothing outside these prefixes can ever be mitigated, and no mitigation is allowed until ownership is verified."
        actions={can("config_network") && <Button variant="primary" onClick={() => setAdding(true)}><Plus size={16} /> Add prefix</Button>} />
      <ErrorLine error={list.error} />
      <Section flush>
        <Table rows={list.data ?? []} rowKey={(r) => String(r.id)} onRow={can("config_network") ? setEditing : undefined}
          empty="No protected prefixes yet. Add the prefixes your network announces."
          cols={[
            { key: "p", header: "Prefix", render: (r) => <><div className="font-medium">{r.prefix}</div><div className="text-xs text-ink-3">{r.description}</div></> },
            { key: "st", header: "Status", render: (r) => r.enabled ? <Lamp tone="ok" label="Monitored" /> : <Lamp tone="neutral" label="Disabled" /> },
            { key: "own", header: "Ownership", render: (r) => r.ownership_verified ? <Badge tone="ok">Verified</Badge> : <Badge tone="warn">Not verified</Badge> },
            { key: "m", header: "Allowed mitigations", render: (r) => (
              <div className="flex flex-wrap gap-1">
                {r.rtbh_allowed && <Badge tone="signal">Blackhole</Badge>}
                {r.steering_allowed && <Badge tone="signal">Upstream steering</Badge>}
                {r.filtering_allowed && <Badge tone="signal">Filtering</Badge>}
                {!r.rtbh_allowed && !r.steering_allowed && !r.filtering_allowed && <span className="text-ink-3">None</span>}
              </div>) },
            { key: "s", header: "Narrowest target", render: (r) => r.min_mitigation_prefix_len === 32 || r.min_mitigation_prefix_len === 128
                ? "Single addresses only" : <span className="text-warn">Up to /{r.min_mitigation_prefix_len}</span> },
          ]} />
      </Section>
      <EligibilityCheck />
      <PrefixDialog key={editing?.id ?? "new"} open={adding || !!editing} prefix={editing}
        onClose={() => { setAdding(false); setEditing(null); }} onSaved={list.reload} />
    </div>
  );
}

function PrefixDialog({ open, prefix, onClose, onSaved }: { open: boolean; prefix: Prefix | null; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState(() => ({
    prefix: prefix?.prefix ?? "", description: prefix?.description ?? "", enabled: prefix?.enabled ?? true,
    ownership_verified: prefix?.ownership_verified ?? false, ownership_evidence: prefix?.ownership_evidence ?? "",
    rtbh_allowed: prefix?.rtbh_allowed ?? false, steering_allowed: prefix?.steering_allowed ?? false,
    filtering_allowed: prefix?.filtering_allowed ?? false,
  }));
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const owned = f.ownership_verified && f.ownership_evidence.trim().length > 0;
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      const body = { ...f, ownership_evidence: f.ownership_evidence || null, description: f.description || null };
      if (prefix) { const { prefix: _p, ...rest } = body; await api(`/prefixes/${prefix.id}`, { method: "PATCH", body: rest }); }
      else await api("/prefixes", { method: "POST", body });
      onSaved();
      onClose();
    } catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog open={open} title={prefix ? `Edit ${prefix.prefix}` : "Add a protected prefix"} onClose={onClose}
      footer={<><Button type="button" variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" form="pfx">Save prefix</Button></>}>
      <form id="pfx" onSubmit={save} className="space-y-4">
        {!prefix && <Field label="Prefix" hint="Network address with host bits zero, e.g. 163.5.191.0/24"><Input required value={f.prefix} onChange={(e) => set("prefix", e.target.value)} /></Field>}
        <Field label="Description"><Input value={f.description} onChange={(e) => set("description", e.target.value)} /></Field>
        <Check label="Monitor this prefix" checked={f.enabled} onChange={(v) => set("enabled", v)} />
        <fieldset className="space-y-3 border-t border-rule-soft pt-3">
          <legend className="text-sm font-medium">Ownership</legend>
          <Check label="I have verified this prefix belongs to our network" checked={f.ownership_verified} onChange={(v) => set("ownership_verified", v)} />
          <Field label="Evidence" hint="IRR route object, RPKI ROA, or LOA reference. Recorded in the audit log.">
            <Input value={f.ownership_evidence} onChange={(e) => set("ownership_evidence", e.target.value)} />
          </Field>
        </fieldset>
        <fieldset className="space-y-2 border-t border-rule-soft pt-3">
          <legend className="text-sm font-medium">Allowed mitigations</legend>
          {!owned && <p className="text-xs text-ink-3">Verify ownership first to enable these.</p>}
          <Check disabled={!owned} label="Blackholing (drops all traffic to the target)" checked={f.rtbh_allowed} onChange={(v) => set("rtbh_allowed", v)} />
          <Check disabled={!owned} label="Steering via another upstream" checked={f.steering_allowed} onChange={(v) => set("steering_allowed", v)} />
          <Check disabled={!owned} label="Local filtering" checked={f.filtering_allowed} onChange={(v) => set("filtering_allowed", v)} />
        </fieldset>
        <ErrorLine error={err} />
      </form>
    </Dialog>
  );
}

function EligibilityCheck() {
  const [t, setT] = useState("");
  const [res, setRes] = useState<Eligibility | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try { setRes(await api<Eligibility>(`/prefixes/eligibility?target=${encodeURIComponent(t)}`)); }
    catch (e: any) { setRes(null); setErr(e.message); }
  };
  return (
    <Section title="Check an address" aside="What Shield would be allowed to do for a destination">
      <form onSubmit={run} className="flex max-w-xl gap-2">
        <Input aria-label="Address or prefix" placeholder="163.5.191.20" value={t} onChange={(e) => setT(e.target.value)} />
        <Button>Check</Button>
      </form>
      <div className="mt-3"><ErrorLine error={err} /></div>
      {res && (
        <div className="mt-3 space-y-2 text-sm">
          <p><span className="font-medium">{res.target}</span>{" "}
            {res.protected_prefix ? <>is inside <span className="font-medium">{res.protected_prefix}</span></> : "is not inside any protected prefix"}
            {res.customer && <> and assigned to {res.customer.customer_name ?? res.customer.customer_ref} ({res.customer.service_type})</>}.</p>
          <div className="flex flex-wrap gap-2">
            <Badge tone={res.rtbh_allowed ? "ok" : "neutral"}>Blackhole {res.rtbh_allowed ? "allowed" : "not allowed"}</Badge>
            <Badge tone={res.steering_allowed ? "ok" : "neutral"}>Steering {res.steering_allowed ? "allowed" : "not allowed"}</Badge>
            <Badge tone={res.filtering_allowed ? "ok" : "neutral"}>Filtering {res.filtering_allowed ? "allowed" : "not allowed"}</Badge>
          </div>
          {res.reasons.length > 0 && <ul className="list-disc pl-5 text-ink-2">{res.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
        </div>
      )}
    </Section>
  );
}

// ================================================================ Customer IPs
type CustomerIp = { id: number; address: string; customer_ref: string; customer_name: string | null; service_type: string;
  proxmox_node: string | null; proxmox_vmid: number | null; rtbh_opt_out: boolean; notes: string | null };

export function Customers() {
  const { can } = useAuth();
  const [q, setQ] = useState("");
  const list = useApi<CustomerIp[]>(`/customers/ips${q ? `?customer_ref=${encodeURIComponent(q)}` : ""}`);
  const [adding, setAdding] = useState(false);
  return (
    <div className="space-y-5">
      <PageHeader title="Customer IPs" description="Which customer or VM uses each address, so the impact of a mitigation is known before it happens."
        actions={can("config_network") && <Button variant="primary" onClick={() => setAdding(true)}><Plus size={16} /> Assign address</Button>} />
      <div className="max-w-sm"><Input aria-label="Filter by customer reference" placeholder="Filter by customer reference" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <ErrorLine error={list.error} />
      <Section flush>
        <Table rows={list.data ?? []} rowKey={(r) => String(r.id)} empty="No addresses assigned yet."
          cols={[
            { key: "a", header: "Address", render: (r) => <span className="font-medium">{r.address.replace(/\/(32|128)$/, "")}</span> },
            { key: "c", header: "Customer", render: (r) => <>{r.customer_name ?? "–"} <span className="text-ink-3">{r.customer_ref}</span></> },
            { key: "t", header: "Service", render: (r) => r.service_type.toUpperCase() === "VPS" ? "VPS" : r.service_type[0].toUpperCase() + r.service_type.slice(1) },
            { key: "vm", header: "Proxmox", render: (r) => r.proxmox_vmid ? `${r.proxmox_node ?? ""} VM ${r.proxmox_vmid}` : "–" },
            { key: "o", header: "Blackholing", render: (r) => r.rtbh_opt_out ? <Badge tone="warn">Opted out</Badge> : <span className="text-ink-3">Per prefix policy</span> },
          ]} />
      </Section>
      <CustomerDialog open={adding} onClose={() => setAdding(false)} onSaved={list.reload} />
    </div>
  );
}

function CustomerDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState({ address: "", customer_ref: "", customer_name: "", service_type: "vps", proxmox_node: "", proxmox_vmid: "", rtbh_opt_out: false });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api("/customers/ips", { method: "POST", body: { ...f, customer_name: f.customer_name || null,
        proxmox_node: f.proxmox_node || null, proxmox_vmid: f.proxmox_vmid ? Number(f.proxmox_vmid) : null } });
      onSaved(); onClose();
    } catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog open={open} title="Assign an address" onClose={onClose}
      footer={<><Button type="button" variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" form="cust">Assign</Button></>}>
      <form id="cust" onSubmit={save} className="grid gap-4 sm:grid-cols-2">
        <Field label="Address" hint="Must be inside a protected prefix"><Input required value={f.address} onChange={(e) => set("address", e.target.value)} /></Field>
        <Field label="Service"><Select value={f.service_type} onChange={(v) => set("service_type", v)}
          options={[["vps", "VPS"], ["dedicated", "Dedicated"], ["colo", "Colocation"], ["infra", "Infrastructure"], ["other", "Other"]]} /></Field>
        <Field label="Customer reference"><Input required value={f.customer_ref} onChange={(e) => set("customer_ref", e.target.value)} /></Field>
        <Field label="Customer name"><Input value={f.customer_name} onChange={(e) => set("customer_name", e.target.value)} /></Field>
        <Field label="Proxmox node"><Input value={f.proxmox_node} onChange={(e) => set("proxmox_node", e.target.value)} /></Field>
        <Field label="VM ID"><Input inputMode="numeric" value={f.proxmox_vmid} onChange={(e) => set("proxmox_vmid", e.target.value.replace(/\D/g, ""))} /></Field>
        <div className="sm:col-span-2"><Check label="Customer has opted out of blackholing" checked={f.rtbh_opt_out} onChange={(v) => set("rtbh_opt_out", v)} /></div>
        <div className="sm:col-span-2"><ErrorLine error={err} /></div>
      </form>
    </Dialog>
  );
}

// ================================================================ Routers & upstreams
type Router = { id: number; name: string; model: string; role: string; mgmt_address: string; api_port: number; use_tls: boolean;
  access_mode: string; dry_run: boolean; enabled: boolean; identity: string | null; routeros_version: string | null;
  status: string; last_seen_at: string | null; has_api_password: boolean };
type Policy = { enabled: boolean; communities: string[]; next_hop: string | null; min_prefix_len: number; max_prefix_len: number;
  max_routes: number; documentation_ref: string | null; verified_at: string | null };
type Upstream = { id: number; name: string; asn: number; description: string | null; router_id: number | null; interface_name: string | null;
  capacity_mbps: number | null; saturation_threshold_pct: number; ddos_protected: boolean; enabled: boolean; rtbh_policy: Policy | null };

export function Routers() {
  const { can } = useAuth();
  const routers = useApi<Router[]>("/routers");
  const ups = useApi<Upstream[]>("/upstreams");
  const [policyFor, setPolicyFor] = useState<Upstream | null>(null);
  const rname = (id: number | null) => routers.data?.find((r) => r.id === id)?.name ?? "–";
  return (
    <div className="space-y-5">
      <PageHeader title="Routers & upstreams"
        description="Edge routers and transit providers. Shield only reads from routers: nothing on a router is changed until phase 8, and then only with approval." />
      <ErrorLine error={ups.error} />
      <RouterList />
      <Section title="Upstream providers" flush>
        <Table rows={ups.data ?? []} rowKey={(r) => String(r.id)} empty="No upstreams configured."
          onRow={can("config_network") ? setPolicyFor : undefined}
          cols={[
            { key: "n", header: "Provider", render: (r) => <><div className="font-medium">{r.name} {r.ddos_protected && <Badge tone="signal">DDoS-protected</Badge>}</div><div className="text-xs text-ink-3">AS{r.asn}</div></> },
            { key: "l", header: "Link", render: (r) => <>{rname(r.router_id)} {r.interface_name}<div className="text-xs text-ink-3">{r.capacity_mbps ? `${r.capacity_mbps / 1000} Gb/s, alarm at ${r.saturation_threshold_pct}%` : "capacity not set"}</div></> },
            { key: "p", header: "Blackhole policy", render: (r) => !r.rtbh_policy ? <span className="text-ink-3">Not configured</span>
                : r.rtbh_policy.enabled ? <Badge tone="ok">Enabled: {r.rtbh_policy.communities.join(", ")}</Badge>
                : r.rtbh_policy.verified_at ? <Badge tone="signal">Verified, not enabled</Badge>
                : <Badge tone="warn">Needs verification</Badge> },
          ]} />
      </Section>
      {policyFor && <PolicyDialog up={policyFor} onClose={() => setPolicyFor(null)} onSaved={ups.reload} />}
    </div>
  );
}

function PolicyDialog({ up, onClose, onSaved }: { up: Upstream; onClose: () => void; onSaved: () => void }) {
  const p = up.rtbh_policy;
  const [f, setF] = useState({
    communities: p?.communities.join(", ") ?? "", next_hop: p?.next_hop ?? "", min_prefix_len: String(p?.min_prefix_len ?? 32),
    max_prefix_len: String(p?.max_prefix_len ?? 32), max_routes: String(p?.max_routes ?? 10), documentation_ref: p?.documentation_ref ?? "",
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: string) => setF((x) => ({ ...x, [k]: v }));
  const base = `/upstreams/${up.id}/rtbh-policy`;
  const act = async (fn: () => Promise<unknown>) => { setErr(null); try { await fn(); onSaved(); onClose(); } catch (e: any) { setErr(e.message); } };
  const save = () => act(() => api(base, { method: "PUT", body: {
    communities: f.communities.split(/[\s,]+/).filter(Boolean), next_hop: f.next_hop || null,
    min_prefix_len: Number(f.min_prefix_len), max_prefix_len: Number(f.max_prefix_len), max_routes: Number(f.max_routes),
    documentation_ref: f.documentation_ref || null } }));
  return (
    <Dialog open title={`Blackhole policy for ${up.name}`} onClose={onClose}
      footer={<>
        <Button variant="quiet" onClick={onClose}>Close</Button>
        {p && !p.verified_at && <Button onClick={() => act(() => api(`${base}/verify`, { method: "POST" }))}>Mark as verified</Button>}
        {p?.verified_at && !p.enabled && <Button onClick={() => act(() => api(`${base}/enable`, { method: "POST" }))}>Enable policy</Button>}
        {p?.enabled && <Button variant="danger" onClick={() => act(() => api(`${base}/disable`, { method: "POST" }))}>Disable policy</Button>}
        <Button variant="primary" onClick={save}>Save policy</Button>
      </>}>
      <Notice tone="warn">Take these values from {up.name}'s own blackhole documentation. Providers differ; nothing is assumed. Saving any change disables the policy until it is verified again.</Notice>
      {p?.verified_at && <p className="text-sm text-ink-2">Verified {dateTime(p.verified_at)}.</p>}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2"><Field label="Blackhole communities" hint="e.g. 174:666 or blackhole (65535:666), comma separated"><Input value={f.communities} onChange={(e) => set("communities", e.target.value)} /></Field></div>
        <Field label="Required next hop" hint="Only if the provider requires one"><Input value={f.next_hop} onChange={(e) => set("next_hop", e.target.value)} /></Field>
        <Field label="Maximum routes"><Input inputMode="numeric" value={f.max_routes} onChange={(e) => set("max_routes", e.target.value)} /></Field>
        <Field label="Shortest accepted prefix"><Input inputMode="numeric" value={f.min_prefix_len} onChange={(e) => set("min_prefix_len", e.target.value)} /></Field>
        <Field label="Longest accepted prefix"><Input inputMode="numeric" value={f.max_prefix_len} onChange={(e) => set("max_prefix_len", e.target.value)} /></Field>
        <div className="sm:col-span-2"><Field label="Provider documentation" hint="URL or ticket reference. Required before verification."><Input value={f.documentation_ref} onChange={(e) => set("documentation_ref", e.target.value)} /></Field></div>
      </div>
      <ErrorLine error={err} />
    </Dialog>
  );
}

// ================================================================ BGP
type Neighbor = { id: number; name: string; router_id: number | null; upstream_id: number | null; purpose: string; local_asn: number;
  remote_asn: number; neighbor_address: string; local_address: string | null; enabled: boolean; managed_by_shield: boolean;
  max_prefix_out: number | null; last_state: string | null; last_state_change_at: string | null; environment: string;
  remote_port: number; ebgp_multihop: number | null; has_md5_password: boolean; description: string | null };

const PURPOSE: Record<string, string> = {
  transit: "Transit", ibgp: "iBGP", rtbh_signal: "Shield to your routers (internal blackholing)",
  rtbh_upstream: "Shield to a provider's blackhole service", steering: "Steering",
};

type Session = Peer & { router_id: number | null; router: string | null; polled_at?: string; stale: boolean; in_inventory: boolean;
  neighbor_id: number | null; purpose: string | null; missing_on_router?: boolean; shield?: boolean; environment?: string;
  prefixes_sent?: number | null; uptime?: string | null };

export function Bgp() {
  const { can } = useAuth();
  const n = useApi<Neighbor[]>("/bgp/neighbors");
  const live = useApi<Session[]>("/bgp/sessions", 10_000);
  const r = useApi<Router[]>("/routers");
  const events = useApi<RouterEvent[]>("/routers/events?limit=200", 30_000);
  const st = useApi<{ speaker: string }>("/mitigation/status", 30_000);
  const [edit, setEdit] = useState<Neighbor | "new" | null>(null);
  const [filter, setFilter] = useState(false);
  const rname = (id: number | null) => id == null ? "Shield" : r.data?.find((x) => x.id === id)?.name ?? "–";
  const routerSessions = (live.data ?? []).filter((x) => !x.shield);
  const shieldSessions = (live.data ?? []).filter((x) => x.shield);
  const nb = (id: number | null) => n.data?.find((x) => x.id === id);
  const bgpEvents = (events.data ?? []).filter((e) => e.kind.startsWith("bgp_")).slice(0, 30);
  const frr = st.data?.speaker === "frr";
  return (
    <div className="space-y-5">
      <PageHeader title="BGP sessions"
        description="Your routers' sessions as they report them, and the sessions Shield's own BGP speaker uses to send blackhole routes." />
      <ErrorLine error={live.error ?? n.error} />
      <Section title="Shield's sessions" flush aside={<div className="flex gap-2">
          <Button onClick={() => setFilter(true)}>Router filter</Button>
          {can("config_network") && <Button onClick={() => setEdit("new")}><Plus size={16} /> Add session</Button>}</div>}>
        {!frr && <div className="px-4 pt-3"><Notice>The BGP speaker is set to <strong>simulated</strong>, so these sessions are not
          configured in FRR. Switch the <code>bgp_speaker</code> setting to FRR under Settings to use them.</Notice></div>}
        <Table rows={shieldSessions} rowKey={(x) => String(x.neighbor_id)} onRow={can("config_network") ? (x) => setEdit(nb(x.neighbor_id) ?? null) : undefined}
          empty="No sessions yet. Add one to a lab router to test blackholing end to end."
          cols={[
            { key: "n", header: "Session", render: (x) => <><div className="font-medium">{x.name}
              {x.environment === "production" ? <> <Badge tone="warn">Production</Badge></> : <> <Badge>Staging</Badge></>}</div>
              <div className="text-xs text-ink-3">{x.purpose ? PURPOSE[x.purpose] ?? x.purpose : ""}</div></> },
            { key: "e", header: "Peer", render: (x) => <>{x.remote_address}<div className="text-xs text-ink-3">AS{x.remote_as}</div></> },
            { key: "s", header: "State", render: (x) => x.environment === "production"
                ? <span className="text-ink-3">Not configured until phase 8</span>
                : !frr ? <span className="text-ink-3">Speaker simulated</span>
                : <Lamp tone={x.established ? "ok" : "attack"} label={x.established ? `Established ${x.uptime ?? ""}` : x.state} /> },
            { key: "p", header: "Routes sent", align: "right", render: (x) => x.prefixes_sent ?? "–" },
          ]} />
      </Section>
      <Section title="On your routers" flush>
        <Table rows={routerSessions} rowKey={(x) => `${x.router_id}|${x.remote_address}`}
          empty="No sessions read yet. Add routers with API credentials under Routers & upstreams."
          cols={[
            { key: "n", header: "Session", render: (x) => <><div className="font-medium">{x.name}</div>
              <div className="text-xs text-ink-3">{x.purpose ? PURPOSE[x.purpose] ?? x.purpose : x.role ?? ""}</div></> },
            { key: "e", header: "Between", render: (x) => <>{x.router ?? rname(x.router_id)} and {x.remote_address}<div className="text-xs text-ink-3">AS{x.remote_as ?? "?"}</div></> },
            { key: "s", header: "State", render: (x) => x.missing_on_router ? <Badge tone="warn">Not configured on the router</Badge>
                : x.disabled ? <span className="text-ink-3">Disabled</span>
                : <Lamp tone={x.established ? "ok" : "attack"} label={x.established ? `Established ${duration(x.uptime_seconds)}` : x.state} /> },
            { key: "p", header: "Prefixes received", align: "right", render: (x) => x.prefixes_received != null ? x.prefixes_received.toLocaleString() : "–" },
            { key: "i", header: "In Shield", render: (x) => x.in_inventory ? <span className="text-ink-2">Recorded</span>
                : <span className="text-ink-3" title="Configured on the router but not recorded in Shield">Not recorded</span> },
          ]} />
      </Section>
      <Section title="Recent session changes" flush><EventTable rows={bgpEvents} showRouter /></Section>
      {edit && <SessionDialog session={edit === "new" ? null : edit} onClose={() => setEdit(null)} onDone={() => { n.reload(); live.reload(); }} />}
      {filter && <FilterDialog onClose={() => setFilter(false)} />}
    </div>
  );
}

type UpstreamLite = { id: number; name: string; asn: number };

function SessionDialog({ session, onClose, onDone }: { session: Neighbor | null; onClose: () => void; onDone: () => void }) {
  const ups = useApi<UpstreamLite[]>("/upstreams");
  const [f, setF] = useState({
    name: session?.name ?? "", purpose: session?.purpose ?? "rtbh_signal", upstream_id: session?.upstream_id ? String(session.upstream_id) : "",
    local_asn: String(session?.local_asn ?? ""), remote_asn: String(session?.remote_asn ?? ""), neighbor_address: session?.neighbor_address ?? "",
    local_address: session?.local_address ?? "", remote_port: String(session?.remote_port ?? 179), ebgp_multihop: session?.ebgp_multihop ? String(session.ebgp_multihop) : "",
    max_prefix_out: String(session?.max_prefix_out ?? 50), md5_password: "", environment: session?.environment ?? "staging", enabled: session?.enabled ?? true,
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const num = (v: string) => (v ? Number(v) : null);
  const save = async () => {
    setErr(null);
    try {
      if (session) {
        await api(`/bgp/neighbors/${session.id}`, { method: "PATCH", body: {
          enabled: f.enabled, environment: f.environment, remote_port: Number(f.remote_port), ebgp_multihop: num(f.ebgp_multihop),
          max_prefix_out: Number(f.max_prefix_out), local_address: f.local_address || null,
          ...(f.md5_password ? { md5_password: f.md5_password } : {}) } });
      } else {
        const up = ups.data?.find((u) => String(u.id) === f.upstream_id);
        await api("/bgp/neighbors", { method: "POST", body: {
          name: f.name, purpose: f.purpose, upstream_id: f.purpose === "rtbh_upstream" ? Number(f.upstream_id) : null,
          local_asn: Number(f.local_asn), remote_asn: f.purpose === "rtbh_upstream" && up ? up.asn : Number(f.remote_asn),
          neighbor_address: f.neighbor_address.trim(), local_address: f.local_address.trim() || null, remote_port: Number(f.remote_port),
          ebgp_multihop: num(f.ebgp_multihop), max_prefix_out: Number(f.max_prefix_out), managed_by_shield: true,
          environment: f.environment, enabled: f.enabled, md5_password: f.md5_password || null } });
      }
      onDone(); onClose();
    } catch (e: any) { setErr(e.message); }
  };
  const del = async () => {
    try { await api(`/bgp/neighbors/${session!.id}`, { method: "DELETE" }); onDone(); onClose(); } catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog open title={session ? `Edit ${session.name}` : "Add a Shield BGP session"} onClose={onClose}
      footer={<>{session && <Button variant="danger" onClick={del}>Delete</Button>}
        <Button variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save}>Save</Button></>}>
      <Notice>Start with a lab router marked <strong>staging</strong>. Shield sends nothing but the blackhole routes you approve,
        accepts nothing from the peer, and never more than the route limit.</Notice>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><Input value={f.name} disabled={!!session} onChange={(e) => set("name", e.target.value)} placeholder="shield-to-lab-r1" /></Field>
        <Field label="Purpose"><Select value={f.purpose} disabled={!!session} onChange={(v) => set("purpose", v)}
          options={[["rtbh_signal", "Internal blackholing (your routers)"], ["rtbh_upstream", "Provider blackhole service"]]} /></Field>
        {f.purpose === "rtbh_upstream" && !session && <Field label="Provider"><Select value={f.upstream_id} onChange={(v) => set("upstream_id", v)}
          options={[["", "Choose…"], ...(ups.data ?? []).map((u) => [String(u.id), `${u.name} (AS${u.asn})`] as [string, string])]} /></Field>}
        <Field label="Peer address"><Input value={f.neighbor_address} disabled={!!session} onChange={(e) => set("neighbor_address", e.target.value)} /></Field>
        <Field label="Shield's address" hint="Source of the session (update-source)"><Input value={f.local_address} onChange={(e) => set("local_address", e.target.value)} /></Field>
        <Field label="Shield's AS"><Input inputMode="numeric" disabled={!!session} value={f.local_asn} onChange={(e) => set("local_asn", e.target.value)} /></Field>
        {f.purpose !== "rtbh_upstream" && <Field label="Peer's AS"><Input inputMode="numeric" disabled={!!session} value={f.remote_asn} onChange={(e) => set("remote_asn", e.target.value)} /></Field>}
        <Field label="Port"><Input inputMode="numeric" value={f.remote_port} onChange={(e) => set("remote_port", e.target.value)} /></Field>
        <Field label="eBGP multihop" hint="For provider route servers several hops away"><Input inputMode="numeric" value={f.ebgp_multihop} onChange={(e) => set("ebgp_multihop", e.target.value)} /></Field>
        <Field label="Route limit" hint="Shield never sends more than this"><Input inputMode="numeric" value={f.max_prefix_out} onChange={(e) => set("max_prefix_out", e.target.value)} /></Field>
        <Field label="TCP MD5 password" hint={session?.has_md5_password ? "Stored encrypted; leave empty to keep" : "Optional; letters, digits . _ -"}>
          <Input type="password" autoComplete="new-password" value={f.md5_password} onChange={(e) => set("md5_password", e.target.value)} /></Field>
        <Field label="Environment"><Select value={f.environment} onChange={(v) => set("environment", v)}
          options={[["staging", "Staging (lab)"], ["production", "Production (used from phase 8)"]]} /></Field>
        <div className="pt-6"><Check label="Enabled" checked={f.enabled} onChange={(v) => set("enabled", v)} /></div>
      </div>
      <ErrorLine error={err} />
    </Dialog>
  );
}

function FilterDialog({ onClose }: { onClose: () => void }) {
  const [fmt, setFmt] = useState("routeros");
  const [txt, setTxt] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setTxt(null); setErr(null);
    fetch(`/api/v1/bgp/receive-filter?format=${fmt}`, { headers: { Authorization: `Bearer ${accessToken()}` } })
      .then(async (r) => (r.ok ? setTxt(await r.text()) : setErr((await r.json().catch(() => ({}))).detail ?? r.statusText)))
      .catch((e) => setErr(String(e)));
  }, [fmt]);
  return (
    <Dialog open title="Router import filter for Shield's blackholes" onClose={onClose}
      footer={<><Button onClick={() => txt && navigator.clipboard?.writeText(txt)}>Copy</Button><Button variant="primary" onClick={onClose}>Close</Button></>}>
      <p className="text-sm">Put this on your router's session from Shield. It accepts only blackhole routes inside your protected
        prefixes, no broader than each allows, carrying the internal blackhole community, and rejects everything else, so
        even a misbehaving Shield cannot blackhole anything it is not authorised for.</p>
      <Select value={fmt} onChange={setFmt} options={[["routeros", "MikroTik RouterOS 7"], ["frr", "FRR"]]} />
      <ErrorLine error={err} />
      {txt && <pre className="max-h-80 overflow-auto rounded-[2px] bg-sunk p-3 text-[12px] leading-snug">{txt}</pre>}
    </Dialog>
  );
}
