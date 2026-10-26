import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Check as CheckIcon, CircleAlert, FlaskConical, Pencil, Plus, Radio, ShieldBan, TriangleAlert, Undo2, X } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { useLive, vectorName } from "../lib/live";
import { bps, dateTime, pps } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";

// ---------------------------------------------------------------- types
export type CheckRow = { level: "block" | "warn" | "ok"; code: string; message: string };
type PlanRoute = { peer: string; upstream_id: number | null; upstream: string | null; asn: number | null; prefix: string;
  communities: string[]; next_hop: string | null; no_export: boolean; description: string };
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
  checks: CheckRow[]; impact: Plan["impact"];
};
type Detail = Action & { group: Action[]; events: { at: string; action_id: string; from: string | null; to: string; actor: string; detail: Record<string, any> }[];
  routes: LedgerRoute[]; checks_at_approval: CheckRow[] | null };
type LedgerRoute = { id: number; action_id: string; mode: string; prefix: string; upstream: string | null; communities: string[];
  next_hop: string | null; status: string; speaker: string; announced_at: string | null; verified_at: string | null; withdrawn_at: string | null };
type Upstream = { id: number; name: string; asn: number; enabled: boolean; rtbh_policy: { enabled: boolean; verified_at: string | null; communities: string[] } | null };
type Status = { mode: string; running: boolean; counts: Record<string, number>; automation_enabled: boolean; emergency_stop: boolean;
  four_eyes_approval: boolean; require_mfa_for_mitigation: boolean; production_enabled?: boolean;
  last_interlock?: { prefix: string; session?: string; peer?: string; at?: string }[];
  controller: { ts: number; leader: boolean; speaker_routes: number | null; last_reconcile: { at?: string; ok?: boolean; error?: string; reannounced?: string[]; withdrawn?: string[] } } | null };

// ---------------------------------------------------------------- vocabulary
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
          <div className="mb-1 text-sm font-medium">Would announce</div>
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
export function NewMitigationDialog({ target: initial = "", incidentId, onClose, onDone }:
  { target?: string; incidentId?: string; onClose: () => void; onDone: (a: Action[]) => void }) {
  const ups = useApi<Upstream[]>("/upstreams");
  const usable = (ups.data ?? []).filter((u) => u.enabled && u.rtbh_policy?.enabled);
  const [target, setTarget] = useState(initial);
  const [strategy, setStrategy] = useState("rtbh_upstream");
  const [chosen, setChosen] = useState<number[] | null>(null);
  const [minutes, setMinutes] = useState("60");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const key = useRef(idempotencyKey());
  const sel = chosen ?? usable.map((u) => u.id);
  const body = () => ({ target: target.trim(), strategy, incident_id: incidentId ?? null, duration_minutes: Number(minutes) || null,
    upstream_ids: strategy === "rtbh_upstream" ? sel : null });

  useEffect(() => { setPlan(null); key.current = idempotencyKey(); }, [target, strategy, chosen, minutes]);

  const preview = async () => {
    setErr(null); setBusy(true);
    try { setPlan(await api<Plan>("/mitigation/preview", { method: "POST", body: body() })); }
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
    <Dialog open title="Blackhole an address" onClose={onClose}
      footer={<>
        <Button variant="quiet" onClick={onClose}>Cancel</Button>
        <Button onClick={preview} disabled={busy || !target.trim()}>Preview</Button>
        <Button variant="primary" onClick={submit} disabled={busy || !plan || plan.blocked}>Propose for approval</Button>
      </>}>
      <SimulationBanner />
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Target" hint="An address (becomes /32 or /128)"><Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="163.5.191.20" /></Field>
        <Field label="Where to drop it"><Select value={strategy} onChange={setStrategy}
          options={[["rtbh_upstream", "At the upstream providers"], ["rtbh_internal", "At my own edge routers"]]} /></Field>
        {strategy === "rtbh_upstream" && <div className="sm:col-span-2">
          <div className="mb-1 text-sm font-medium">Upstreams</div>
          {usable.length ? <div className="flex flex-wrap gap-x-5 gap-y-2">{usable.map((u) => (
            <Check key={u.id} label={`${u.name} (AS${u.asn})`} checked={sel.includes(u.id)}
              onChange={(v) => setChosen(v ? [...sel, u.id] : sel.filter((x) => x !== u.id))} />))}</div>
            : <p className="text-sm text-ink-2">No upstream has an enabled, verified blackhole policy. Set one up under Routers & upstreams.</p>}
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
    { key: "w", header: "Where", render: (g: GroupRow) => g.actions.map((a) => a.upstream ?? "Own edge routers").join(", ") },
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
      <PageHeader title={`Blackhole ${a.target}`}
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
      <SimulationBanner />
      <ErrorLine error={err} />
      <Section title="Routes" flush>
        <Table rows={a.group} rowKey={(x) => x.id}
          cols={[
            { key: "w", header: "Where", render: (x) => <><div className="font-medium">{x.upstream ?? "Own edge routers"}</div>
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
              <span className="text-ink-2">{a.group.find((x) => x.id === e.action_id)?.upstream ?? (a.group.length > 1 ? "" : "Own edge routers")}</span>
              <div><span className="font-medium">{EVENT_WORD[e.detail.kind] ?? e.detail.kind}</span>
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
            { key: "a", header: "Action", render: (x) => <>{x.allowed_strategies.map((s) => s === "rtbh_upstream" ? "Upstream blackhole" : "Internal blackhole").join(", ")}
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
        <Field label="Action"><Select value={f.strategy} onChange={(v) => set("strategy", v)} options={[["rtbh_upstream", "Upstream blackhole"], ["rtbh_internal", "Internal blackhole"]]} /></Field>
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
export function IncidentMitigation({ incidentId, target, eligible, open }: { incidentId: string; target: string; eligible: boolean; open: boolean }) {
  const { can } = useAuth();
  const nav = useNavigate();
  const acts = useApi<Action[]>(`/mitigation/actions?state=all&incident_id=${incidentId}`, 10_000);
  const [creating, setCreating] = useState(false);
  useMitigationEvents(() => acts.reload());
  const rows = grouped(acts.data ?? []);
  return (
    <div className="space-y-3 text-sm">
      {rows.length > 0 && <ul className="divide-y divide-rule-soft rounded-[3px] border border-rule-soft">
        {rows.map((g) => (
          <li key={g.key}><button className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left hover:bg-sunk" onClick={() => nav(`/mitigation/${g.actions[0].id}`)}>
            <span><ShieldBan size={14} className="mr-1.5 inline" />{g.actions.map((a) => a.upstream ?? "Own edge routers").join(", ")}</span>
            <GroupState g={g} /></button></li>))}
      </ul>}
      {open && eligible && can("mitigation_propose") && !rows.some((g) => g.actions.some((a) => ["proposed", "approved", "executing", "active", "withdrawing"].includes(a.state))) &&
        <Button onClick={() => setCreating(true)}><ShieldBan size={16} /> Blackhole this address</Button>}
      {creating && <NewMitigationDialog target={target.replace(/\/(32|128)$/, "")} incidentId={incidentId} onClose={() => setCreating(false)}
        onDone={(a) => { acts.reload(); if (a[0]) nav(`/mitigation/${a[0].id}`); }} />}
    </div>
  );
}
