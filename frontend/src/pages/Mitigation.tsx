import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Check as CheckIcon, CircleAlert, Filter, FlaskConical, Pencil, Plus, Radio, ShieldBan, Shuffle, Sparkles, TriangleAlert, Undo2, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { useLive, vectorName } from "../lib/live";
import { bps, dateTime, pps } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";

// ---------------------------------------------------------------- types
export type CheckRow = { level: "block" | "warn" | "ok"; code: string; message: string };
export type FilterMatch = { dst?: string; protocol: string | null; src_port: number | null; dst_port: number | null; fragment: boolean; label?: string };
type PlanRoute = { peer: string; upstream_id: number | null; upstream: string | null; asn: number | null; prefix: string;
  communities: string[]; next_hop: string | null; no_export: boolean; description: string;
  router_id?: number | null; router?: string | null; filters?: FilterMatch[]; steering?: SteerEntry[] };
export type SteerEntry = { upstream_id: number; mode: "withhold" | "prepend" | "communities"; prepend?: number; communities?: string[]; upstream?: string };
export type Plan = { target: string; strategy: string; blocked: boolean; routes: PlanRoute[]; checks: CheckRow[];
  duration_seconds: number; simulation: boolean;
  impact: { statements: string[]; addresses: number; live: { available: boolean; reason?: string; pps?: number; bps?: number; provenance?: string | null; seen?: boolean };
    customer: Record<string, string> | null } };
export type Action = {
  id: string; group_id: string | null; state: string; strategy: string; target: string; upstream_id: number | null;
  upstream: string | null; incident_id: string | null; policy_id: number | null; automatic: boolean; dry_run: boolean;
  requested_by: string | null; approved_by: string | null; approved_at: string | null; created_at: string;
  started_at: string | null; expires_at: string | null; completed_at: string | null; extensions: number; attempts: number;
  error: string | null; rejected_reason: string | null; withdraw_reason: string | null; route: PlanRoute | null;
  router_id?: number | null; router?: string | null; provider?: string | null;
  checks: CheckRow[]; impact: Plan["impact"];
};
type FilterLedger = { id: number; action_id: string; router: string | null; comment: string; description: string; status: string;
  backend: string; packets: number | null; bytes: number | null; counted_at: string | null; verified_at: string | null; removed_at: string | null };
type Detail = Action & { group: Action[]; events: { at: string; action_id: string; from: string | null; to: string; actor: string; detail: Record<string, any> }[];
  routes: LedgerRoute[]; checks_at_approval: CheckRow[] | null; filters: FilterLedger[] };
type LedgerRoute = { id: number; action_id: string; mode: string; prefix: string; upstream: string | null; communities: string[];
  next_hop: string | null; status: string; speaker: string; announced_at: string | null; verified_at: string | null; withdrawn_at: string | null };
type Upstream = { id: number; name: string; asn: number; enabled: boolean; rtbh_policy: { enabled: boolean; verified_at: string | null; communities: string[] } | null };
type Status = { mode: string; running: boolean; counts: Record<string, number>; automation_enabled: boolean; emergency_stop: boolean;
  four_eyes_approval: boolean; require_mfa_for_mitigation: boolean; production_enabled?: boolean;
  last_interlock?: { prefix: string; session?: string; peer?: string; at?: string }[];
  controller: { ts: number; leader: boolean; speaker_routes: number | null; last_reconcile: { at?: string; ok?: boolean; error?: string; reannounced?: string[]; withdrawn?: string[] } } | null };

// ---------------------------------------------------------------- vocabulary
const STEER_EVENT_WORD: Record<string, string> = {
  active: "Steering rule added and verified on the router", announce_failed: "Adding the steering rule failed",
  withdrawn: "Steering removed: announced to this upstream again", rolled_back: "Steering rolled back",
};
const FILTER_EVENT_WORD: Record<string, string> = {
  active: "Rules added and verified on the router", announce_failed: "Adding the rules failed", withdrawn: "Rules removed",
  rolled_back: "Rules rolled back", withdrawn_failed: "Removing the rules failed",
};
export const whereOf = (a: { strategy: string; upstream: string | null; router?: string | null; provider?: string | null }) =>
  a.strategy === "scrubbing" ? `Scrubbing at ${a.provider ?? "provider"}`
    : a.strategy === "local_filter" ? `Filter on ${a.router ?? "router"}`
    : a.strategy === "steering" ? `Steer away from ${a.upstream ?? "upstream"}` : a.upstream ?? "Own edge routers";
const RULED = ["local_filter", "steering"];
const SCRUB_EVENT_WORD: Record<string, string> = {
  active: "Diversion requested and confirmed", announce_failed: "The provider refused or failed", withdrawn: "Diversion stopped",
  rolled_back: "Diversion rolled back", reconciled_reannounced: "Diversion requested again (provider had stopped it)",
};
export const ACTION_WORD: Record<string, string> = {
  proposed: "Awaiting approval", approved: "Approved", executing: "Announcing", active: "Active",
  withdrawing: "Withdrawing", withdrawn: "Withdrawn", rejected: "Rejected", failed: "Failed", rolled_back: "Rolled back",
};
export const ACTION_TONE: Record<string, "ok" | "warn" | "attack" | "neutral" | "signal"> = {
  proposed: "warn", approved: "signal", executing: "signal", active: "signal", withdrawing: "neutral",
  withdrawn: "neutral", rejected: "neutral", failed: "attack", rolled_back: "warn",
};
const EVENT_WORD: Record<string, string> = {
  proposed: "Proposed", approved: "Approved", auto_approved: "Approved by policy", executing: "Execution started",
  active: "Announced and verified", announce_failed: "Announcement failed", failed: "Failed", rolled_back: "Rolled back",
  withdraw_requested: "Withdrawal requested", withdrawn: "Withdrawn and verified", withdrawn_failed: "Withdrawal failed",
  rolled_back_failed: "Rollback failed", rejected: "Rejected", expired: "Expired without approval", extended: "Extended",
  blocked_at_execution: "Blocked just before execution", reconciled_reannounced: "Re-announced by reconciliation",
  reconciled_orphan_withdrawn: "Removed by reconciliation",
};

function idempotencyKey() {
  try { return crypto.randomUUID(); } catch {
    const b = new Uint8Array(16); crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  }
}

function errText(e: unknown) {
  if (e instanceof ApiError && e.detail && typeof e.detail === "object" && "message" in (e.detail as any)) {
    const d = e.detail as { message: string; checks?: CheckRow[] };
    const blocks = (d.checks ?? []).filter((c) => c.level === "block").map((c) => c.message);
    return [d.message, ...blocks].join(" ");
  }
  return e instanceof Error ? e.message : String(e);
}

function remaining(iso: string | null) {
  if (!iso) return "–";
  const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
  if (s <= 0) return "due now";
  return s < 3600 ? `${Math.ceil(s / 60)} min left` : `${(s / 3600).toFixed(1)} h left`;
}

/** Reload `fn` whenever a mitigation event arrives on the live stream. */
function useMitigationEvents(fn: () => void) {
  const { mitigationVersion } = useLive();
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => { if (mitigationVersion) ref.current(); }, [mitigationVersion]);
}

export function SimulationBanner() {
  const st = useApi<{ mode: string }>("/mitigation/status", 30_000);
  if (st.data?.mode === "production") {
    return (
      <Notice tone="attack">
        <span className="inline-flex items-start gap-2"><Radio size={16} className="mt-0.5 shrink-0" />
          <span><strong>Production.</strong> Approved actions are announced to your production routers and providers, but only
            over sessions that passed an acceptance run. Every route leaving Shield is checked against what was approved; anything
            else is removed and new blackholes are stopped. <Link to="/settings" className="underline">Switch off</Link> withdraws everything.</span></span>
      </Notice>
    );
  }
  if (st.data?.mode === "staging") {
    return (
      <Notice tone="signal">
        <span className="inline-flex items-start gap-2"><FlaskConical size={16} className="mt-0.5 shrink-0" />
          <span><strong>Staging.</strong> Approved actions are announced by Shield's FRR BGP speaker, only to sessions marked
            staging (lab routers). Production sessions stay unconfigured until an administrator switches production on under Settings.</span></span>
      </Notice>
    );
  }
  return (
    <Notice tone="warn">
      <span className="inline-flex items-start gap-2"><FlaskConical size={16} className="mt-0.5 shrink-0" />
        <span><strong>Simulation.</strong> Approved actions go through the whole workflow against a simulated BGP speaker.
          Nothing is announced to any router or provider. Switch the bgp_speaker setting to FRR to use staging sessions.</span></span>
    </Notice>
  );
}

export function FilterBanner({ steering = false, scrubbing = false }: { steering?: boolean; scrubbing?: boolean }) {
  const st = useApi<{ filter_backend?: string; steering_backend?: string; scrubbing_backend?: string }>("/mitigation/status", 30_000);
  if (scrubbing) {
    return st.data?.scrubbing_backend === "live"
      ? <Notice tone="signal"><span className="inline-flex items-start gap-2"><Radio size={16} className="mt-0.5 shrink-0" />
          <span><strong>Diversions are real.</strong> Shield calls the provider's API to start and stop scrubbing for the /24.</span></span></Notice>
      : <Notice tone="warn"><span className="inline-flex items-start gap-2"><FlaskConical size={16} className="mt-0.5 shrink-0" />
          <span><strong>Scrubbing simulation.</strong> No provider is called. Set scrubbing_backend to live in Settings to divert for real.</span></span></Notice>;
  }
  if (steering) {
    return st.data?.steering_backend === "routeros"
      ? <Notice tone="signal"><span className="inline-flex items-start gap-2"><Radio size={16} className="mt-0.5 shrink-0" />
          <span><strong>Steering changes what your router announces.</strong> Shield's filter account adds a rule to the BGP output
            filter towards the chosen upstream (chain shield-steer-&lt;upstream&gt;) and removes it when the action ends.</span></span></Notice>
      : <Notice tone="warn"><span className="inline-flex items-start gap-2"><FlaskConical size={16} className="mt-0.5 shrink-0" />
          <span><strong>Steering simulation.</strong> The whole workflow runs, but no router is changed. Set steering_backend to
            routeros in Settings, and add a filter account to the router, to steer for real.</span></span></Notice>;
  }
  if (st.data?.filter_backend === "routeros") {
    return <Notice tone="signal"><span className="inline-flex items-start gap-2"><Radio size={16} className="mt-0.5 shrink-0" />
      <span><strong>Filters go to your routers.</strong> Shield's filter account adds drop rules to the router's firewall raw table
        (chain shield-filter), only for the traffic shown, and removes them when the action ends.</span></span></Notice>;
  }
  return <Notice tone="warn"><span className="inline-flex items-start gap-2"><FlaskConical size={16} className="mt-0.5 shrink-0" />
    <span><strong>Filter simulation.</strong> The whole workflow runs, but no rule is added to any router. Set filter_backend to
      routeros in Settings, and add a filter account to the router, to filter for real.</span></span></Notice>;
}

function WithdrawAllDialog({ count, onClose, onDone }: { count: number; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async () => {
    setBusy(true); setErr(null);
    try { await api("/mitigation/withdraw-all", { method: "POST", body: { reason: reason.trim() || "withdraw all (rollback)" } }); onDone(); onClose(); }
    catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };
  return (
    <Dialog open title="Withdraw every blackhole?" onClose={onClose}
      footer={<><Button variant="quiet" onClick={onClose}>Cancel</Button>
        <Button variant="danger" onClick={go} disabled={busy}><Undo2 size={15} /> Withdraw all ({count})</Button></>}>
      <p>Every active blackhole is withdrawn and verified gone; everything awaiting approval or not yet announced is cancelled.</p>
      <p className="text-ink-2">Addresses under attack become reachable again, so traffic returns to them. Policies may propose new
        blackholes if attacks continue; use the emergency stop as well to prevent that.</p>
      <Field label="Reason (recorded in the audit log)"><Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="rollback" /></Field>
      <ErrorLine error={err} />
    </Dialog>
  );
}

export function CheckList({ checks }: { checks: CheckRow[] }) {
  const order = { block: 0, warn: 1, ok: 2 };
  return (
    <ul className="divide-y divide-rule-soft">
      {[...checks].sort((a, b) => order[a.level] - order[b.level]).map((c, i) => (
        <li key={c.code + i} className="flex gap-2.5 px-4 py-2 text-sm">
          {c.level === "ok" ? <CheckIcon size={16} className="mt-0.5 shrink-0 text-ok" aria-label="Passed" />
            : c.level === "warn" ? <TriangleAlert size={16} className="mt-0.5 shrink-0 text-warn" aria-label="Warning" />
            : <CircleAlert size={16} className="mt-0.5 shrink-0 text-attack" aria-label="Blocks this action" />}
          <span className={c.level === "block" ? "font-medium" : ""}>{c.message}</span>
        </li>
      ))}
    </ul>
  );
}

function PlanView({ plan }: { plan: Plan }) {
  const live = plan.impact.live;
  return (
    <div className="space-y-3">
      {plan.blocked ? <Notice tone="attack">This cannot go ahead: see the checks marked in red.</Notice> : null}
      {plan.routes.length > 0 && (
        <div>
          <div className="mb-1 text-sm font-medium">{plan.strategy === "local_filter" ? "Would add" : plan.strategy === "steering" ? "Would change" : "Would announce"}</div>
          <ul className="space-y-1 font-mono text-[12.5px]">
            {plan.routes.map((r) => <li key={r.peer} className="rounded-[2px] bg-sunk px-2 py-1">{r.description}</li>)}
          </ul>
        </div>
      )}
      {plan.impact.statements.length > 0 && (
        <div>
          <div className="mb-1 text-sm font-medium">Effect</div>
          <ul className="list-disc space-y-0.5 pl-5 text-sm">
            {plan.impact.statements.map((s) => <li key={s}>{s}</li>)}
            <li className="text-ink-2">{live.available ? (live.seen ? <>Currently {pps(live.pps)}, {bps(live.bps)} to this target ({live.provenance}).</>
              : <>No traffic to this target in the last second of flow data.</>)
              : <>Current traffic to the target is unknown: {live.reason}.</>}</li>
          </ul>
        </div>
      )}
      <div className="-mx-5 border-y border-rule-soft"><CheckList checks={plan.checks} /></div>
    </div>
  );
}

// ---------------------------------------------------------------- new mitigation
type Rtr = { id: number; name: string; enabled: boolean; has_filter_password?: boolean };

function SteerEditor({ rows, ups, onChange }: { rows: SteerEntry[]; ups: Upstream[]; onChange: (r: SteerEntry[]) => void }) {
  const set = (i: number, patch: Partial<SteerEntry>) => onChange(rows.map((r, n) => n === i ? { ...r, ...patch } : r));
  const free = ups.filter((u) => !rows.some((r) => r.upstream_id === u.id));
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="flex flex-wrap items-end gap-2 rounded-[3px] border border-rule-soft p-2">
          <Field label="Upstream"><Select value={String(r.upstream_id)} onChange={(v) => set(i, { upstream_id: Number(v) })}
            options={ups.filter((u) => u.id === r.upstream_id || free.includes(u)).map((u) => [String(u.id), `${u.name} (AS${u.asn})`] as [string, string])} /></Field>
          <Field label="Change"><Select value={r.mode} onChange={(v) => set(i, { mode: v as SteerEntry["mode"], prepend: v === "prepend" ? r.prepend ?? 3 : undefined })}
            options={[["withhold", "Stop announcing to it"], ["prepend", "Prepend (make it less preferred)"], ["communities", "Tag with its action communities"]]} /></Field>
          {r.mode === "prepend" && <Field label="Times"><Input className="w-20" inputMode="numeric" value={r.prepend ?? 3}
            onChange={(e) => set(i, { prepend: Number(e.target.value) || 1 })} /></Field>}
          {r.mode === "communities" && <Field label="Communities" hint="From the provider's documentation"><Input className="w-56"
            value={(r.communities ?? []).join(", ")} onChange={(e) => set(i, { communities: e.target.value.split(/[\s,]+/).filter(Boolean) })}
            placeholder="174:990" /></Field>}
          <Button variant="quiet" className="ml-auto" onClick={() => onChange(rows.filter((_, n) => n !== i))} aria-label="Remove"><X size={15} /></Button>
        </div>))}
      {free.length > 0 && <Button variant="quiet" onClick={() => onChange([...rows, { upstream_id: free[0].id, mode: "withhold" }])}>
        <Plus size={15} /> Add an upstream</Button>}
    </div>
  );
}

function FilterEditor({ rows, onChange }: { rows: FilterMatch[]; onChange: (r: FilterMatch[]) => void }) {
  const set = (i: number, patch: Partial<FilterMatch>) => onChange(rows.map((r, n) => n === i ? { ...r, ...patch } : r));
  const kind = (r: FilterMatch) => r.fragment ? "fragment" : r.protocol ?? "udp";
  return (
    <div className="space-y-2">
      {rows.map((r, i) => (
        <div key={i} className="flex flex-wrap items-end gap-2 rounded-[3px] border border-rule-soft p-2">
          <Field label="Drop"><Select value={kind(r)} onChange={(v) => set(i, v === "fragment"
              ? { protocol: null, fragment: true, src_port: null, dst_port: null }
              : { protocol: v, fragment: false, ...(v === "icmp" ? { src_port: null, dst_port: null } : {}) })}
            options={[["udp", "UDP"], ["tcp", "TCP"], ["icmp", "ICMP"], ["fragment", "Fragments"]]} /></Field>
          {(r.protocol === "udp" || r.protocol === "tcp") && <>
            <Field label="From port"><Input className="w-24" inputMode="numeric" value={r.src_port ?? ""}
              onChange={(e) => set(i, { src_port: e.target.value ? Number(e.target.value) : null })} placeholder="any" /></Field>
            <Field label="To port"><Input className="w-24" inputMode="numeric" value={r.dst_port ?? ""}
              onChange={(e) => set(i, { dst_port: e.target.value ? Number(e.target.value) : null })} placeholder="any" /></Field></>}
          {r.label && <span className="pb-2 text-xs text-ink-3">{r.label}</span>}
          <Button variant="quiet" className="ml-auto" onClick={() => onChange(rows.filter((_, n) => n !== i))} aria-label="Remove filter"><X size={15} /></Button>
        </div>))}
      {rows.length < 8 && <Button variant="quiet" onClick={() => onChange([...rows, { protocol: "udp", src_port: null, dst_port: null, fragment: false }])}>
        <Plus size={15} /> Add a filter</Button>}
    </div>
  );
}

export function NewMitigationDialog({ target: initial = "", incidentId, initialStrategy = "rtbh_upstream", onClose, onDone }:
  { target?: string; incidentId?: string; initialStrategy?: string; onClose: () => void; onDone: (a: Action[]) => void }) {
  const ups = useApi<Upstream[]>("/upstreams");
  const routers = useApi<Rtr[]>("/routers");
  const usable = (ups.data ?? []).filter((u) => u.enabled && u.rtbh_policy?.enabled);
  const enabledRouters = (routers.data ?? []).filter((r) => r.enabled);
  const [target, setTarget] = useState(initial);
  const [strategy, setStrategy] = useState(initialStrategy);
  const [chosen, setChosen] = useState<number[] | null>(null);
  const [chosenRouters, setChosenRouters] = useState<number[] | null>(null);
  const [filters, setFilters] = useState<FilterMatch[] | null>(null);   // null: derive from the attack
  const [steer, setSteer] = useState<SteerEntry[] | null>(null);        // null: Shield suggests
  const scrubbers = useApi<{ id: number; name: string; enabled: boolean; verified_at: string | null; method: string }[]>("/scrubbing/providers");
  const [scrubber, setScrubber] = useState<string>("");
  const [minutes, setMinutes] = useState("60");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const key = useRef(idempotencyKey());
  const keepPlan = useRef(false);
  const sel = chosen ?? usable.map((u) => u.id);
  const rsel = chosenRouters ?? enabledRouters.map((r) => r.id);
  const filtering = strategy === "local_filter";
  const steering = strategy === "steering";
  const scrubbing = strategy === "scrubbing";
  const body = () => ({ target: target.trim(), strategy, incident_id: incidentId ?? null, duration_minutes: Number(minutes) || null,
    upstream_ids: strategy === "rtbh_upstream" ? sel : null,
    router_ids: filtering ? rsel : null, filters: filtering ? filters : null,
    steering: steering && steer ? steer.map(({ upstream_id, mode, prepend, communities }) => ({ upstream_id, mode, prepend, communities })) : null,
    scrubbing_provider_id: scrubbing && scrubber ? Number(scrubber) : null });

  useEffect(() => {
    if (keepPlan.current) { keepPlan.current = false; return; }
    setPlan(null); key.current = idempotencyKey();
  }, [target, strategy, chosen, chosenRouters, filters, steer, scrubber, minutes]);

  const preview = async () => {
    setErr(null); setBusy(true);
    try {
      const p = await api<Plan>("/mitigation/preview", { method: "POST", body: body() });
      setPlan(p);
      if (filtering && filters === null && p.routes[0]?.filters?.length) {
        // Show what Shield derived from the attack, so it can be edited; keep the plan for these exact rules.
        keepPlan.current = true;
        setFilters(p.routes[0].filters);
      }
      if (steering && steer === null && p.routes.some((r) => r.steering?.length)) {
        keepPlan.current = true;
        setSteer(p.routes.flatMap((r) => r.steering ?? []));
      }
    }
    catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };
  const submit = async () => {
    setErr(null); setBusy(true);
    try {
      const r = await fetchWithKey(body(), key.current);
      onDone(r.actions); onClose();
    } catch (e) { setErr(errText(e)); } finally { setBusy(false); }
  };
  return (
    <Dialog open title={filtering ? "Filter attack traffic" : steering ? "Steer traffic between upstreams" : scrubbing ? "Divert to a scrubbing provider" : "Blackhole an address"} onClose={onClose}
      footer={<>
        <Button variant="quiet" onClick={onClose}>Cancel</Button>
        <Button onClick={preview} disabled={busy || !target.trim()}>Preview</Button>
        <Button variant="primary" onClick={submit} disabled={busy || !plan || plan.blocked}>Propose for approval</Button>
      </>}>
      {scrubbing ? <FilterBanner scrubbing /> : filtering || steering ? <FilterBanner steering={steering} /> : <SimulationBanner />}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Target" hint={steering || scrubbing ? "An address; Shield acts on the /24 (/48) holding it" : "An address (becomes /32 or /128)"}><Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="163.5.191.20" /></Field>
        <Field label="How"><Select value={strategy} onChange={setStrategy}
          options={[["rtbh_upstream", "Blackhole at the upstream providers"], ["rtbh_internal", "Blackhole at my own edge routers"],
                    ["local_filter", "Filter only the attack traffic"], ["steering", "Move the /24 away from an upstream"],
                    ["scrubbing", "Divert the /24 to a scrubbing provider"]]} /></Field>
        {strategy === "rtbh_upstream" && <div className="sm:col-span-2">
          <div className="mb-1 text-sm font-medium">Upstreams</div>
          {usable.length ? <div className="flex flex-wrap gap-x-5 gap-y-2">{usable.map((u) => (
            <Check key={u.id} label={`${u.name} (AS${u.asn})`} checked={sel.includes(u.id)}
              onChange={(v) => setChosen(v ? [...sel, u.id] : sel.filter((x) => x !== u.id))} />))}</div>
            : <p className="text-sm text-ink-2">No upstream has an enabled, verified blackhole policy. Set one up under Routers & upstreams.</p>}
        </div>}
        {filtering && <div className="space-y-3 sm:col-span-2">
          <div>
            <div className="mb-1 text-sm font-medium">Routers</div>
            {enabledRouters.length ? <div className="flex flex-wrap gap-x-5 gap-y-2">{enabledRouters.map((r) => (
              <Check key={r.id} label={r.name + (r.has_filter_password ? "" : " (no filter account)")} checked={rsel.includes(r.id)}
                onChange={(v) => setChosenRouters(v ? [...rsel, r.id] : rsel.filter((x) => x !== r.id))} />))}</div>
              : <p className="text-sm text-ink-2">No router yet. Add your edge router under Routers & upstreams.</p>}
          </div>
          <div>
            <div className="mb-1 text-sm font-medium">What to drop</div>
            {filters === null
              ? <p className="text-sm text-ink-2">{incidentId ? "Preview to see the filters Shield suggests for this attack; you can change them."
                  : "Add the traffic to drop, e.g. UDP from port 123 for an NTP reflection attack."}
                  {!incidentId && <> <Button variant="quiet" onClick={() => setFilters([{ protocol: "udp", src_port: null, dst_port: null, fragment: false }])}><Plus size={15} /> Add a filter</Button></>}</p>
              : <FilterEditor rows={filters} onChange={setFilters} />}
          </div>
        </div>}
        {scrubbing && <Field label="Provider"><Select value={scrubber} onChange={setScrubber}
          options={[["", "First verified provider"], ...(scrubbers.data ?? []).filter((x) => x.enabled).map((x) => [String(x.id), `${x.name}${x.verified_at ? "" : " (not verified)"}`] as [string, string])]} /></Field>}
        {steering && <div className="space-y-2 sm:col-span-2">
          <div className="text-sm font-medium">Upstreams to change</div>
          <p className="text-sm text-ink-2">Inbound traffic follows what you announce. Stop announcing the prefix to an upstream (traffic then
            arrives over the others), make the path through it longer, or tag it with that provider's own action communities.
            Shield never stops announcing to every upstream.</p>
          {steer === null
            ? <p className="text-sm text-ink-2">Preview to see Shield's suggestion (move onto your DDoS-protected upstream), or
                <Button variant="quiet" onClick={() => { const u = (ups.data ?? []).find((x) => x.enabled); if (u) setSteer([{ upstream_id: u.id, mode: "withhold" }]); }}>
                  <Plus size={15} /> choose yourself</Button></p>
            : <SteerEditor rows={steer} ups={(ups.data ?? []).filter((u) => u.enabled)} onChange={setSteer} />}
        </div>}
        <Field label="Duration (minutes)" hint="Extended automatically while the attack continues"><Input inputMode="numeric" value={minutes} onChange={(e) => setMinutes(e.target.value)} /></Field>
      </div>
      {plan && <PlanView plan={plan} />}
      <ErrorLine error={err} />
    </Dialog>
  );
}

function fetchWithKey(body: unknown, key: string): Promise<{ actions: Action[] }> {
  // A retried request with the same key returns the same actions instead of creating new ones.
  return api("/mitigation/actions", { method: "POST", body, headers: { "Idempotency-Key": key } });
}

// ---------------------------------------------------------------- center
type GroupRow = { key: string; actions: Action[] };
function grouped(rows: Action[]): GroupRow[] {
  const m = new Map<string, Action[]>();
  for (const a of rows) {
    const k = a.group_id ?? a.id;
    m.set(k, [...(m.get(k) ?? []), a]);
  }
  return [...m.entries()].map(([key, actions]) => ({ key, actions }));
}

function GroupState({ g }: { g: GroupRow }) {
  const states = [...new Set(g.actions.map((a) => a.state))];
  return <div className="flex flex-wrap gap-1">{states.map((s) => <Badge key={s} tone={ACTION_TONE[s]}>{ACTION_WORD[s] ?? s}</Badge>)}</div>;
}

export function MitigationCenter() {
  const { can } = useAuth();
  const nav = useNavigate();
  const live = useApi<Action[]>("/mitigation/actions?state=live", 10_000);
  const closed = useApi<Action[]>("/mitigation/actions?state=closed&limit=40", 30_000);
  const st = useApi<Status>("/mitigation/status", 10_000);
  const [creating, setCreating] = useState(false);
  const [withdrawAll, setWithdrawAll] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useMitigationEvents(() => { live.reload(); closed.reload(); st.reload(); });

  const proposed = grouped((live.data ?? []).filter((a) => a.state === "proposed"));
  const running = grouped((live.data ?? []).filter((a) => a.state !== "proposed"));
  const act = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); live.reload(); closed.reload(); } catch (e) { setErr(errText(e)); }
  };
  const s = st.data;
  const rowCols = (extra: any[]) => [
    { key: "t", header: "Target", render: (g: GroupRow) => <><div className="font-mono text-[13.5px] font-medium">{g.actions[0].target}</div>
      <div className="text-xs text-ink-3">{g.actions[0].automatic ? "Proposed by policy" : `Proposed by ${g.actions[0].requested_by ?? "–"}`}, {dateTime(g.actions[0].created_at)}</div></> },
    { key: "w", header: "Where", render: (g: GroupRow) => g.actions.map(whereOf).join(", ") },
    { key: "s", header: "State", render: (g: GroupRow) => <GroupState g={g} /> },
    ...extra,
  ];
  return (
    <div className="space-y-5">
      <PageHeader title="Mitigation center"
        description="Blackhole requests: preview exactly what would be announced, approve, watch it verified, withdraw."
        actions={<>
          {can("mitigation_withdraw") && (live.data?.length ?? 0) > 0 && <Button onClick={() => setWithdrawAll(true)}><Undo2 size={16} /> Withdraw all</Button>}
          {can("mitigation_propose") && <Button variant="primary" onClick={() => setCreating(true)}><Plus size={16} /> Blackhole an address</Button>}</>} />
      <SimulationBanner />
      {(s?.last_interlock?.length ?? 0) > 0 && (
        <Notice tone="attack"><strong>Safety interlock tripped.</strong> Shield found routes leaving that no approved action covers and removed
          them: {s!.last_interlock!.map((x) => `${x.prefix}${x.session ? ` (to ${x.session})` : ""}`).join(", ")}. New blackholes are stopped
          (emergency stop) until someone checks Shield's FRR and turns automation back on under Settings.</Notice>)}
      <ErrorLine error={err ?? live.error} />
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
        <Lamp tone={s?.running ? (s.controller?.leader ? "ok" : "warn") : "attack"}
          label={s?.running ? (s.controller?.leader ? "Controller running" : "Controller on standby") : "Controller not running"} />
        {s?.controller?.last_reconcile?.at && <Lamp tone={s.controller.last_reconcile.ok ? "ok" : "attack"}
          label={s.controller.last_reconcile.ok ? `Speaker in step (checked ${new Date(s.controller.last_reconcile.at).toLocaleTimeString()})` : `Speaker check failed: ${s.controller.last_reconcile.error}`} />}
        <Lamp tone={s?.automation_enabled ? "signal" : "neutral"} label={s?.automation_enabled ? "Policies may act without approval" : "Every action needs approval"} />
        {s?.four_eyes_approval && <Lamp tone="neutral" label="Four-eyes approval" />}
        {s?.emergency_stop && <Lamp tone="attack" label="Emergency stop: new blackholes blocked" />}
        <Link to="/mitigation/policies" className="text-signal hover:underline">Policies</Link>
      </div>

      <Section title={`Awaiting approval${proposed.length ? ` (${proposed.length})` : ""}`} flush>
        <Table rows={proposed} rowKey={(g) => g.key} onRow={(g) => nav(`/mitigation/${g.actions[0].id}`)} empty="Nothing waiting."
          cols={rowCols([
            { key: "c", header: "Checks", render: (g: GroupRow) => {
              const w = g.actions[0].checks.filter((c) => c.level === "warn").length;
              return w ? <Badge tone="warn">{w} warning{w > 1 ? "s" : ""}</Badge> : <Badge tone="ok">All passed</Badge>;
            } },
            { key: "a", header: "", align: "right" as const, render: (g: GroupRow) => can("mitigation_approve") && (
              <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                <Button onClick={() => act(() => api(`/mitigation/actions/${g.actions[0].id}/reject`, { method: "POST", body: { reason: "rejected by operator" } }))}><X size={15} /> Reject</Button>
                <Button variant="primary" onClick={() => act(() => api(`/mitigation/actions/${g.actions[0].id}/approve`, { method: "POST" }))}><CheckIcon size={15} /> Approve</Button>
              </div>) },
          ])} />
      </Section>

      <Section title="In progress and active" flush>
        <Table rows={running} rowKey={(g) => g.key} onRow={(g) => nav(`/mitigation/${g.actions[0].id}`)} empty="No blackholes are active."
          cols={rowCols([
            { key: "e", header: "Ends", render: (g: GroupRow) => g.actions[0].expires_at
              ? <>{remaining(g.actions[0].expires_at)}{g.actions[0].extensions ? <div className="text-xs text-ink-3">extended {g.actions[0].extensions}x</div> : null}</> : "–" },
            { key: "a", header: "", align: "right" as const, render: (g: GroupRow) => can("mitigation_withdraw") && g.actions.some((a) => ["active", "executing", "failed"].includes(a.state)) && (
              <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
                <Button onClick={() => act(() => api(`/mitigation/actions/${g.actions[0].id}/withdraw?whole_group=true`, { method: "POST", body: { reason: "withdrawn by operator" } }))}><Undo2 size={15} /> Withdraw</Button>
              </div>) },
          ])} />
      </Section>

      <Section title="Recently finished" flush>
        <Table dense rows={grouped(closed.data ?? [])} rowKey={(g) => g.key} onRow={(g) => nav(`/mitigation/${g.actions[0].id}`)} empty="Nothing yet."
          cols={rowCols([
            { key: "why", header: "Why", render: (g: GroupRow) => <span className="text-ink-2">{g.actions[0].withdraw_reason ?? g.actions[0].rejected_reason ?? g.actions[0].error ?? ""}</span> },
          ])} />
      </Section>
      {creating && <NewMitigationDialog onClose={() => setCreating(false)} onDone={(a) => { live.reload(); if (a[0]) nav(`/mitigation/${a[0].id}`); }} />}
      {withdrawAll && <WithdrawAllDialog count={live.data?.length ?? 0} onClose={() => setWithdrawAll(false)} onDone={() => { live.reload(); closed.reload(); }} />}
    </div>
  );
}

// ---------------------------------------------------------------- detail
export function ActionDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const d = useApi<Detail>(`/mitigation/actions/${id}`, 5_000);
  const [err, setErr] = useState<string | null>(null);
  const [extend, setExtend] = useState(false);
  useMitigationEvents(() => d.reload());
  const a = d.data;
  if (d.error) return <ErrorLine error={d.error} />;
  if (!a) return <p className="text-ink-2">Loading…</p>;
  const act = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); d.reload(); } catch (e) { setErr(errText(e)); }
  };
  const anyActive = a.group.some((x) => ["active", "executing", "failed"].includes(x.state));
  return (
    <div className="space-y-5">
      <Link to="/mitigation" className="inline-flex items-center gap-1 text-sm text-ink-2 hover:text-ink"><ArrowLeft size={15} /> Mitigation center</Link>
      <PageHeader title={a.strategy === "local_filter" ? `Filter attack traffic to ${a.target}`
        : a.strategy === "steering" ? `Steer ${a.target}` : a.strategy === "scrubbing" ? `Scrub ${a.target}` : `Blackhole ${a.target}`}
        description={<>{a.automatic ? "Proposed by a policy" : `Proposed by ${a.requested_by ?? "–"}`} {dateTime(a.created_at)}
          {a.approved_by ? `, approved by ${a.approved_by}` : a.approved_at ? ", approved by policy" : ""}
          {a.incident_id && <> for <Link className="text-signal hover:underline" to={`/attacks/${a.incident_id}`}>this attack</Link></>}.</>}
        actions={<>
          {a.state === "proposed" && can("mitigation_approve") && <>
            <Button onClick={() => act(() => api(`/mitigation/actions/${a.id}/reject`, { method: "POST", body: { reason: "rejected by operator" } }))}><X size={16} /> Reject</Button>
            <Button variant="primary" onClick={() => act(() => api(`/mitigation/actions/${a.id}/approve`, { method: "POST" }))}><CheckIcon size={16} /> Approve</Button></>}
          {a.state === "active" && can("mitigation_approve") && <Button onClick={() => setExtend(true)}>Extend</Button>}
          {anyActive && can("mitigation_withdraw") && <Button onClick={() => act(() => api(`/mitigation/actions/${a.id}/withdraw?whole_group=true`, { method: "POST", body: { reason: "withdrawn by operator" } }))}><Undo2 size={16} /> Withdraw</Button>}
        </>} />
      {a.strategy === "scrubbing" ? <FilterBanner scrubbing /> : RULED.includes(a.strategy) ? <FilterBanner steering={a.strategy === "steering"} /> : <SimulationBanner />}
      <ErrorLine error={err} />
      {RULED.includes(a.strategy) && (
        <Section title={a.strategy === "steering" ? "Steering rules on the router" : "Drop rules on the router"} flush
          aside={a.filters.some((f) => f.counted_at) ? "Counters from the router" : undefined}>
          <Table rows={a.filters} rowKey={(f) => String(f.id)} empty="Rules are created when the action runs."
            cols={[
              { key: "d", header: a.strategy === "steering" ? "Change" : "Drops", render: (f) => <><div>{f.description}</div><div className="font-mono text-xs text-ink-3">{f.comment}</div></> },
              { key: "r", header: "Router", render: (f) => f.router ?? a.router ?? "–" },
              { key: "s", header: "State", render: (f) => <Badge tone={f.status === "active" ? "signal" : f.status === "failed" ? "attack" : "neutral"}>
                {({ pending: "Being added", active: f.backend === "simulated" ? "Active (simulated)" : "Active on router", removing: "Being removed", removed: "Removed", failed: "Failed" } as Record<string, string>)[f.status] ?? f.status}</Badge> },
              ...(a.strategy === "steering" ? [] : [{ key: "p", header: "Dropped so far", align: "right" as const, render: (f: FilterLedger) => f.packets != null
                  ? <><div>{f.packets.toLocaleString()} packets</div><div className="text-xs text-ink-3">{bps((f.bytes ?? 0) * 8).replace("/s", "")} · {f.counted_at ? dateTime(f.counted_at) : ""}</div></>
                  : <span className="text-ink-3">–</span> }]),
            ]} />
        </Section>
      )}
      <Section title={a.strategy === "local_filter" ? "Routers" : a.strategy === "steering" ? "Upstreams" : a.strategy === "scrubbing" ? "Diversion" : "Routes"} flush>
        <Table rows={a.group} rowKey={(x) => x.id}
          cols={[
            { key: "w", header: "Where", render: (x) => <><div className="font-medium">{whereOf(x)}</div>
              <div className="font-mono text-xs text-ink-2">{x.route?.description}</div></> },
            { key: "s", header: "State", render: (x) => <><Badge tone={ACTION_TONE[x.state]}>{ACTION_WORD[x.state] ?? x.state}</Badge>
              {x.error && <div className="mt-1 text-xs text-attack">{x.error}</div>}</> },
            { key: "e", header: "Ends", render: (x) => x.state === "active" ? remaining(x.expires_at) : x.completed_at ? dateTime(x.completed_at) : "–" },
          ]} />
      </Section>
      <div className="grid gap-5 lg:grid-cols-2">
        <Section title="Effect">
          <ul className="list-disc space-y-1 pl-5 text-sm">{a.impact.statements?.map((s) => <li key={s}>{s}</li>)}</ul>
        </Section>
        <Section title={a.checks_at_approval ? "Checks at approval" : "Checks at proposal"} flush>
          <CheckList checks={a.checks_at_approval ?? a.checks} />
        </Section>
      </div>
      <Section title="Timeline" flush>
        <ol className="divide-y divide-rule-soft">
          {a.events.map((e, n) => (
            <li key={n} className="grid gap-x-3 px-4 py-2 text-sm sm:grid-cols-[190px_150px_1fr]">
              <span className="whitespace-nowrap text-ink-2">{dateTime(e.at)}</span>
              <span className="text-ink-2">{(() => { const x = a.group.find((y) => y.id === e.action_id); return x ? whereOf(x) : ""; })()}</span>
              <div><span className="font-medium">{(a.strategy === "local_filter" && FILTER_EVENT_WORD[e.detail.kind]) || (a.strategy === "steering" && STEER_EVENT_WORD[e.detail.kind]) || (a.strategy === "scrubbing" && SCRUB_EVENT_WORD[e.detail.kind]) || EVENT_WORD[e.detail.kind] || e.detail.kind}</span>
                {e.actor !== "controller" && <span className="text-ink-2"> by {e.actor}</span>}
                {(e.detail.reason || e.detail.error || e.detail.reasons || e.detail.until) && <p className="mt-0.5 text-ink-2">
                  {e.detail.reason ?? e.detail.error ?? (e.detail.reasons ?? []).join("; ") ?? ""}{e.detail.until ? `until ${dateTime(e.detail.until)} (${e.detail.why})` : ""}</p>}
              </div>
            </li>))}
        </ol>
      </Section>
      {extend && <ExtendDialog id={a.id} onClose={() => setExtend(false)} onDone={d.reload} />}
    </div>
  );
}

function ExtendDialog({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const [m, setM] = useState("60");
  const [err, setErr] = useState<string | null>(null);
  return (
    <Dialog open title="Extend blackhole" onClose={onClose}
      footer={<><Button variant="quiet" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={async () => {
          try { await api(`/mitigation/actions/${id}/extend`, { method: "POST", body: { minutes: Number(m) } }); onDone(); onClose(); }
          catch (e) { setErr(errText(e)); }
        }}>Extend</Button></>}>
      <Field label="Add minutes"><Input inputMode="numeric" value={m} onChange={(e) => setM(e.target.value)} /></Field>
      <ErrorLine error={err} />
    </Dialog>
  );
}

// ---------------------------------------------------------------- blackhole routes
export function BlackholeRoutes() {
  const [all, setAll] = useState(false);
  const r = useApi<{ ledger: LedgerRoute[]; speaker: { available: boolean; reason?: string; routes: { key: string; prefix: string; upstream: string | null;
    communities: string[]; next_hop: string | null; no_export: boolean; action_id: string | null }[] }; limit: number }>(`/mitigation/routes?state=${all ? "all" : "live"}`, 10_000);
  useMitigationEvents(() => r.reload());
  const nav = useNavigate();
  const ledger = r.data?.ledger ?? [];
  const speaker = r.data?.speaker;
  const live = ledger.filter((x) => x.status === "verified" || x.status === "announced");
  const drift = useMemo(() => {
    if (!speaker?.available) return null;
    const onSpeaker = new Set(speaker.routes.map((x) => x.action_id));
    const missing = live.filter((x) => !onSpeaker.has(x.action_id)).length;
    const extra = speaker.routes.filter((x) => !live.some((l) => l.action_id === x.action_id)).length;
    return { missing, extra };
  }, [speaker, live]);
  const tone = (s: string) => (s === "verified" ? "signal" : s === "withdrawn" ? "neutral" : s === "failed" ? "attack" : "warn") as any;
  return (
    <div className="space-y-5">
      <PageHeader title="Blackhole routes" description="Every blackhole route Shield has announced, and what the speaker holds right now." />
      <SimulationBanner />
      <ErrorLine error={r.error} />
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
        <span>{live.length} of {r.data?.limit ?? "–"} allowed routes in use</span>
        {drift && <Lamp tone={drift.missing || drift.extra ? "warn" : "ok"} label={drift.missing || drift.extra
          ? `Out of step: ${drift.missing} missing on the speaker, ${drift.extra} unexpected. The controller corrects this within 30 s.`
          : "Speaker matches the ledger"} />}
        {speaker && !speaker.available && <Lamp tone="attack" label={`Speaker unreachable: ${speaker.reason}`} />}
      </div>
      <Section title="Ledger" flush aside={<Check label="Include withdrawn" checked={all} onChange={setAll} />}>
        <Table dense rows={ledger} rowKey={(x) => String(x.id)} onRow={(x) => nav(`/mitigation/${x.action_id}`)} empty="No blackhole routes."
          cols={[
            { key: "p", header: "Prefix", render: (x) => <span className="font-mono text-[13px]">{x.prefix}</span> },
            { key: "u", header: "Sent to", render: (x) => x.upstream ?? "Own edge routers" },
            { key: "c", header: "Communities", render: (x) => <span className="font-mono text-xs">{x.communities.join(" ")}{x.next_hop ? ` nh ${x.next_hop}` : ""}</span> },
            { key: "s", header: "State", render: (x) => <Badge tone={tone(x.status)}>{x.status === "verified" ? "Announced, verified" : x.status.replace("_", " ")}</Badge> },
            { key: "t", header: "Since", render: (x) => <span className="text-ink-2">{dateTime(x.withdrawn_at ?? x.verified_at ?? x.announced_at ?? "") }</span> },
          ]} />
      </Section>
      <Section title="On the speaker now" flush aside={<span className="text-xs text-ink-3">Simulated speaker</span>}>
        <Table dense rows={speaker?.routes ?? []} rowKey={(x) => x.key} empty="The speaker holds no routes."
          cols={[
            { key: "p", header: "Prefix", render: (x) => <span className="font-mono text-[13px]">{x.prefix}</span> },
            { key: "u", header: "Peer", render: (x) => x.upstream ?? "–" },
            { key: "c", header: "Attributes", render: (x) => <span className="font-mono text-xs">{x.communities.join(" ")}{x.no_export ? " no-export" : ""}{x.next_hop ? ` nh ${x.next_hop}` : ""}</span> },
          ]} />
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------- policies
type Policy = { id: number; name: string; enabled: boolean; priority: number; scope: string; vectors: string[]; min_confidence: number;
  min_duration_seconds: number; pps_threshold: number | null; bps_threshold: number | null; allowed_strategies: string[];
  requires_approval: boolean; max_scope_prefix_len: number; mitigation_duration_seconds: number; min_hold_seconds: number;
  cooldown_seconds: number; max_concurrent_actions: number; version: number };

export function Policies() {
  const { can } = useAuth();
  const p = useApi<Policy[]>("/mitigation/policies");
  const [edit, setEdit] = useState<Policy | "new" | null>(null);
  return (
    <div className="space-y-5">
      <Link to="/mitigation" className="inline-flex items-center gap-1 text-sm text-ink-2 hover:text-ink"><ArrowLeft size={15} /> Mitigation center</Link>
      <PageHeader title="Mitigation policies"
        description="When a confirmed attack matches a policy, Shield proposes a blackhole for it. A policy acts without approval only if it says so and automatic mitigation is switched on."
        actions={can("config_policy") && <Button variant="primary" onClick={() => setEdit("new")}><Plus size={16} /> New policy</Button>} />
      <ErrorLine error={p.error} />
      <Section flush>
        <Table rows={p.data ?? []} rowKey={(x) => String(x.id)} onRow={can("config_policy") ? setEdit : undefined} empty="No policies. Every blackhole is proposed by a person."
          cols={[
            { key: "n", header: "Policy", render: (x) => <><div className="font-medium">{x.name}</div><div className="text-xs text-ink-3">priority {x.priority}, version {x.version}</div></> },
            { key: "s", header: "Applies to", render: (x) => <><span className="font-mono text-[13px]">{x.scope}</span>
              <div className="text-xs text-ink-3">{x.vectors.length ? x.vectors.map(vectorName).join(", ") : "any attack type"}</div></> },
            { key: "w", header: "When", render: (x) => `confidence ${Math.round(x.min_confidence * 100)}%+, confirmed for ${Math.round(x.min_duration_seconds / 60)} min` },
            { key: "a", header: "Action", render: (x) => <>{x.allowed_strategies.map((s) => ({ rtbh_upstream: "Upstream blackhole", rtbh_internal: "Internal blackhole", local_filter: "Filter on router", steering: "Steer to the protected upstream", scrubbing: "Divert to scrubbing" } as Record<string, string>)[s] ?? s).join(", ")}
              <div className="text-xs text-ink-3">{Math.round(x.mitigation_duration_seconds / 60)} min, at most {x.max_concurrent_actions} at once</div></> },
            { key: "e", header: "State", render: (x) => !x.enabled ? <span className="text-ink-3">Off</span>
              : x.requires_approval ? <Badge tone="signal">Proposes for approval</Badge> : <Badge tone="warn">Acts without approval</Badge> },
          ]} />
      </Section>
      {edit && <PolicyDialog policy={edit === "new" ? null : edit} onClose={() => setEdit(null)} onDone={p.reload} />}
    </div>
  );
}

function PolicyDialog({ policy, onClose, onDone }: { policy: Policy | null; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({
    name: policy?.name ?? "", enabled: policy?.enabled ?? false, priority: String(policy?.priority ?? 100), scope: policy?.scope ?? "",
    vectors: (policy?.vectors ?? []).join(", "), min_confidence: String(Math.round((policy?.min_confidence ?? 0.9) * 100)),
    min_duration: String(Math.round((policy?.min_duration_seconds ?? 60) / 60)), strategy: policy?.allowed_strategies[0] ?? "rtbh_upstream",
    requires_approval: policy?.requires_approval ?? true, duration: String(Math.round((policy?.mitigation_duration_seconds ?? 3600) / 60)),
    hold: String(Math.round((policy?.min_hold_seconds ?? 600) / 60)), max: String(policy?.max_concurrent_actions ?? 5),
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const save = async () => {
    setErr(null);
    const body = { name: f.name, enabled: f.enabled, priority: Number(f.priority), scope: f.scope.trim(),
      vectors: f.vectors.split(/[\s,]+/).filter(Boolean), min_confidence: Number(f.min_confidence) / 100,
      min_duration_seconds: Number(f.min_duration) * 60, allowed_strategies: [f.strategy], requires_approval: f.requires_approval,
      mitigation_duration_seconds: Number(f.duration) * 60, min_hold_seconds: Number(f.hold) * 60, max_concurrent_actions: Number(f.max) };
    try {
      await api(policy ? `/mitigation/policies/${policy.id}` : "/mitigation/policies", { method: policy ? "PUT" : "POST", body });
      onDone(); onClose();
    } catch (e) { setErr(errText(e)); }
  };
  const del = async () => {
    try { await api(`/mitigation/policies/${policy!.id}`, { method: "DELETE" }); onDone(); onClose(); } catch (e) { setErr(errText(e)); }
  };
  return (
    <Dialog open title={policy ? `Edit ${policy.name}` : "New policy"} onClose={onClose}
      footer={<>{policy && <Button variant="danger" onClick={del}>Delete</Button>}
        <Button variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save}><Pencil size={15} /> Save</Button></>}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><Input value={f.name} onChange={(e) => set("name", e.target.value)} /></Field>
        <Field label="Applies to (prefix)"><Input value={f.scope} onChange={(e) => set("scope", e.target.value)} placeholder="163.5.191.0/24" /></Field>
        <div className="sm:col-span-2"><Field label="Attack types" hint="Leave empty for any, e.g. ntp_amplification, dns_amplification">
          <Input value={f.vectors} onChange={(e) => set("vectors", e.target.value)} /></Field></div>
        <Field label="Minimum confidence (%)"><Input inputMode="numeric" value={f.min_confidence} onChange={(e) => set("min_confidence", e.target.value)} /></Field>
        <Field label="Confirmed for at least (min)"><Input inputMode="numeric" value={f.min_duration} onChange={(e) => set("min_duration", e.target.value)} /></Field>
        <Field label="Action"><Select value={f.strategy} onChange={(v) => set("strategy", v)} options={[["local_filter", "Filter the attack traffic on my routers"], ["steering", "Steer onto the DDoS-protected upstream"], ["scrubbing", "Divert to the scrubbing provider"], ["rtbh_upstream", "Upstream blackhole"], ["rtbh_internal", "Internal blackhole"]]} /></Field>
        <Field label="Duration (min)"><Input inputMode="numeric" value={f.duration} onChange={(e) => set("duration", e.target.value)} /></Field>
        <Field label="Keep at least (min)" hint="Never withdrawn automatically before this"><Input inputMode="numeric" value={f.hold} onChange={(e) => set("hold", e.target.value)} /></Field>
        <Field label="At most at once"><Input inputMode="numeric" value={f.max} onChange={(e) => set("max", e.target.value)} /></Field>
        <Field label="Priority" hint="Lower runs first"><Input inputMode="numeric" value={f.priority} onChange={(e) => set("priority", e.target.value)} /></Field>
        <div className="space-y-2 pt-6 sm:col-span-2">
          <Check label="Enabled" checked={f.enabled} onChange={(v) => set("enabled", v)} />
          <Check label="Needs a person to approve each action" checked={f.requires_approval} onChange={(v) => set("requires_approval", v)} />
        </div>
      </div>
      {!f.requires_approval && <Notice tone="warn">Without approval, matching attacks are blackholed as soon as automatic mitigation is
        switched on. Blackholing makes the address unreachable, legitimate traffic included.</Notice>}
      <ErrorLine error={err} />
    </Dialog>
  );
}

// ---------------------------------------------------------------- on the attack page
export function IncidentMitigation({ incidentId, target, eligible, filterEligible = false, steerEligible = false, scrubEligible = false, open }:
  { incidentId: string; target: string; eligible: boolean; filterEligible?: boolean; steerEligible?: boolean; scrubEligible?: boolean; open: boolean }) {
  const { can } = useAuth();
  const nav = useNavigate();
  const acts = useApi<Action[]>(`/mitigation/actions?state=all&incident_id=${incidentId}`, 10_000);
  const [creating, setCreating] = useState<string | null>(null);
  useMitigationEvents(() => acts.reload());
  const rows = grouped(acts.data ?? []);
  return (
    <div className="space-y-3 text-sm">
      {rows.length > 0 && <ul className="divide-y divide-rule-soft rounded-[3px] border border-rule-soft">
        {rows.map((g) => (
          <li key={g.key}><button className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left hover:bg-sunk" onClick={() => nav(`/mitigation/${g.actions[0].id}`)}>
            <span><ShieldBan size={14} className="mr-1.5 inline" />{g.actions.map(whereOf).join(", ")}</span>
            <GroupState g={g} /></button></li>))}
      </ul>}
      {open && can("mitigation_propose") && !rows.some((g) => g.actions.some((a) => ["proposed", "approved", "executing", "active", "withdrawing"].includes(a.state))) &&
        <div className="flex flex-wrap gap-2">
          {filterEligible && <Button variant="primary" onClick={() => setCreating("local_filter")}><Filter size={16} /> Filter the attack traffic</Button>}
          {steerEligible && <Button onClick={() => setCreating("steering")}><Shuffle size={16} /> Steer away from an upstream</Button>}
          {scrubEligible && <Button onClick={() => setCreating("scrubbing")}><Sparkles size={16} /> Divert to scrubbing</Button>}
          {eligible && <Button onClick={() => setCreating("rtbh_upstream")}><ShieldBan size={16} /> Blackhole this address</Button>}
        </div>}
      {creating && <NewMitigationDialog target={target.replace(/\/(32|128)$/, "")} incidentId={incidentId} initialStrategy={creating} onClose={() => setCreating(null)}
        onDone={(a) => { acts.reload(); if (a[0]) nav(`/mitigation/${a[0].id}`); }} />}
    </div>
  );
}
