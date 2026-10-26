import { useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { api } from "../lib/api";
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
type Neighbor = { id: number; name: string; router_id: number | null; purpose: string; local_asn: number; remote_asn: number;
  neighbor_address: string; enabled: boolean; managed_by_shield: boolean; max_prefix_out: number | null; last_state: string | null; last_state_change_at: string | null };

const PURPOSE: Record<string, string> = {
  transit: "Transit", ibgp: "iBGP", rtbh_signal: "Shield to router (blackhole signalling)",
  rtbh_upstream: "Dedicated upstream blackhole session", steering: "Steering",
};

type Session = Peer & { router_id: number; router: string | null; polled_at?: string; stale: boolean; in_inventory: boolean;
  neighbor_id: number | null; purpose: string | null; missing_on_router?: boolean };

export function Bgp() {
  const n = useApi<Neighbor[]>("/bgp/neighbors");
  const live = useApi<Session[]>("/bgp/sessions", 15_000);
  const r = useApi<Router[]>("/routers");
  const events = useApi<RouterEvent[]>("/routers/events?limit=200", 30_000);
  const rname = (id: number | null) => id == null ? "Shield (FRR)" : r.data?.find((x) => x.id === id)?.name ?? "–";
  const shieldSessions = (n.data ?? []).filter((x) => x.router_id == null);
  const bgpEvents = (events.data ?? []).filter((e) => e.kind.startsWith("bgp_")).slice(0, 30);
  return (
    <div className="space-y-5">
      <PageHeader title="BGP sessions"
        description="Sessions as the routers report them, every 30 seconds, matched against the sessions recorded in Shield." />
      <ErrorLine error={live.error ?? n.error} />
      <Section title="On the routers" flush>
        <Table rows={live.data ?? []} rowKey={(x) => `${x.router_id}|${x.remote_address}`}
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
      {shieldSessions.length > 0 && <Section title="Shield's own sessions" flush aside={<span className="text-xs text-ink-3">Phase 7</span>}>
        <Table rows={shieldSessions} rowKey={(x) => String(x.id)}
          cols={[
            { key: "n", header: "Session", render: (x) => <><div className="font-medium">{x.name}</div><div className="text-xs text-ink-3">{PURPOSE[x.purpose] ?? x.purpose}</div></> },
            { key: "e", header: "Peer", render: (x) => <>{x.neighbor_address}<div className="text-xs text-ink-3">AS{x.local_asn} to AS{x.remote_asn}</div></> },
            { key: "m", header: "Managed by Shield", render: (x) => x.managed_by_shield ? <Badge tone="signal">Yes, max {x.max_prefix_out} routes</Badge> : <span className="text-ink-3">No</span> },
            { key: "s", header: "State", render: () => <span className="hatch inline-block px-2 text-ink-3">Shield's BGP speaker arrives in phase 7</span> },
          ]} />
      </Section>}
      <Section title="Recent session changes" flush><EventTable rows={bgpEvents} showRouter /></Section>
    </div>
  );
}
