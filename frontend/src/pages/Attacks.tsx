import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Check as CheckIcon, Flag, MessageSquarePlus } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { bps, count, dateTime, pps } from "../lib/format";
import {
  RESOLUTION_WORD, SEVERITY_TONE, STATUS_WORD, useLive, vectorName, type Incident,
} from "../lib/live";
import { LiveChart } from "../components/LiveChart";
import { Num, ProvTag } from "../components/Provenance";
import { Badge, Button, Dialog, ErrorLine, Field, Input, Lamp, Notice, PageHeader, Section, Select, Table } from "../components/ui";

// ================================================================ shared bits
const unitOf = (vector: string) => (vector === "volumetric_bps" ? "bps" : "pps");
const rate = (v: number, unit: string) => (unit === "bps" ? bps(v) : pps(v));

export function duration(sec: number) {
  if (sec < 60) return `${sec} s`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min ${sec % 60 ? `${sec % 60} s` : ""}`.trim();
  const h = Math.floor(sec / 3600);
  return `${h} h ${Math.floor((sec % 3600) / 60)} min`;
}

export function targetLabel(t: string) {
  return t.replace(/\/(32|128)$/, "");
}

export function StatusPill({ i }: { i: Pick<Incident, "status" | "resolution"> }) {
  if (i.status === "confirmed" || i.status === "mitigating" || i.status === "mitigated")
    return <Badge tone="attack">{STATUS_WORD[i.status]}</Badge>;
  if (i.status === "suspected") return <Badge tone="warn">Suspected</Badge>;
  if (i.status === "false_positive") return <Badge>False positive</Badge>;
  return <Badge tone="ok">{RESOLUTION_WORD[i.resolution ?? "ended"] ?? "Ended"}</Badge>;
}

export function Vectors({ v, max = 3 }: { v: string[]; max?: number }) {
  const shown = v.slice(0, max);
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((x) => <Badge key={x} tone={x.startsWith("volumetric") || x === "traffic_anomaly" ? "neutral" : "signal"}>{vectorName(x)}</Badge>)}
      {v.length > max && <span className="text-xs text-ink-3">+{v.length - max}</span>}
    </span>
  );
}

/** Confidence as a bar with a tick at the confirmation threshold (0.7 by default). */
export function ConfidenceBar({ v, threshold = 0.7 }: { v: number; threshold?: number }) {
  const tone = v >= threshold ? "var(--attack)" : "var(--warn)";
  return (
    <div className="flex min-w-[110px] items-center gap-2" title={`Confidence ${Math.round(v * 100)}%. Confirmation needs ${Math.round(threshold * 100)}%.`}>
      <div className="relative h-2 flex-1 rounded-[1px] bg-sunk">
        <span className="absolute inset-y-0 left-0 rounded-[1px]" style={{ width: `${v * 100}%`, background: tone }} />
        <span className="absolute inset-y-[-2px] w-px bg-ink-3" style={{ left: `${threshold * 100}%` }} aria-hidden />
      </div>
      <span className="w-9 text-right text-sm">{Math.round(v * 100)}%</span>
    </div>
  );
}

function Who({ i }: { i: Incident }) {
  return (
    <div>
      <div className="font-medium">{i.scope === "prefix" ? `${i.target} (whole prefix)` : targetLabel(i.target)}</div>
      <div className="text-xs text-ink-3">
        {i.customer ? `${i.customer.customer_name ?? i.customer.customer_ref}, ${i.customer.service_type.toUpperCase()}` : i.prefix ?? "No customer assigned"}
      </div>
    </div>
  );
}

// ================================================================ active attacks
export function ActiveAttacks() {
  const { incidents, state } = useLive();
  const nav = useNavigate();
  const prefixes = useApi<{ enabled: boolean }[]>("/prefixes", 60_000);
  const confirmed = incidents.filter((i) => i.status !== "suspected");
  const suspected = incidents.filter((i) => i.status === "suspected");
  const cols = [
    { key: "sev", header: "Severity", render: (i: Incident) => <Lamp tone={SEVERITY_TONE[i.severity]} label={i.severity[0].toUpperCase() + i.severity.slice(1)} /> },
    { key: "t", header: "Target", render: (i: Incident) => <Who i={i} /> },
    { key: "v", header: "Attack type", render: (i: Incident) => <Vectors v={i.vectors} /> },
    { key: "now", header: "Rate now", align: "right" as const, render: (i: Incident) => (
      <div><Num v={i.current?.pps} p={i.current?.provenance ?? "sampled"} fmt={pps} />
        <div className="text-xs text-ink-3">peak {pps(i.peak_pps)}</div></div>) },
    { key: "bw", header: "Bandwidth", align: "right" as const, render: (i: Incident) => <Num v={i.current?.bps} p={i.current?.provenance ?? "sampled"} fmt={bps} /> },
    { key: "c", header: "Confidence", className: "w-40", render: (i: Incident) => <ConfidenceBar v={i.current_confidence ?? i.confidence} /> },
    { key: "d", header: "For", render: (i: Incident) => <span className="whitespace-nowrap">{duration(Math.max(i.duration_seconds, Math.round(Date.now() / 1000 - Date.parse(i.first_detected_at) / 1000)))}</span> },
    { key: "a", header: "", render: (i: Incident) => i.acknowledged_at ? <span className="text-xs text-ink-3">Seen by {i.acknowledged_by}</span> : <Badge tone="warn">New</Badge> },
  ];
  const watched = prefixes.data?.filter((p) => p.enabled).length ?? 0;
  return (
    <div className="space-y-5">
      <PageHeader title="Active attacks"
        description="Confirmed attacks are sustained and attack-shaped. Suspected ones are unusual traffic that has not met the confirmation rules, and are never mitigated automatically." />
      {state !== "live" && <Notice tone="warn">The live feed is not connected, so this list may be out of date.</Notice>}
      <Section title={`Confirmed (${confirmed.length})`} flush>
        <Table rows={confirmed} rowKey={(i) => i.id} onRow={(i) => nav(`/attacks/${i.id}`)} cols={cols}
          empty={<>No confirmed attacks. Shield is watching {watched} protected prefix{watched === 1 ? "" : "es"}.</>} />
      </Section>
      <Section title={`Suspected (${suspected.length})`} aside="Watch these; they confirm automatically if they persist" flush>
        <Table rows={suspected} rowKey={(i) => i.id} onRow={(i) => nav(`/attacks/${i.id}`)} cols={cols}
          empty="Nothing unusual right now." />
      </Section>
    </div>
  );
}

// ================================================================ history
export function AttackHistory() {
  const nav = useNavigate();
  const [state, setState] = useState("all");
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const [confirmedOnly, setConfirmedOnly] = useState(true);
  const [before, setBefore] = useState<string | null>(null);
  const params = new URLSearchParams({ state, limit: "100" });
  if (sev) params.set("severity", sev);
  if (q.trim()) params.set("q", q.trim());
  if (confirmedOnly) params.set("confirmed_only", "true");
  if (before) params.set("before", before);
  const list = useApi<Incident[]>(`/attacks?${params}`);
  const reset = () => setBefore(null);
  return (
    <div className="space-y-5">
      <PageHeader title="Attack history" description="Every incident, newest first. Select one for its timeline and evidence." />
      <div className="flex flex-wrap items-center gap-2">
        <Input aria-label="Search by address or prefix" placeholder="Address or prefix" value={q}
          onChange={(e) => { setQ(e.target.value); reset(); }} className="max-w-xs" />
        <Select aria-label="State" value={state} onChange={(v) => { setState(v); reset(); }}
          options={[["all", "Open and closed"], ["closed", "Closed only"], ["open", "Open only"]]} />
        <Select aria-label="Severity" value={sev} onChange={(v) => { setSev(v); reset(); }}
          options={[["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} />
        <label className="ml-2 flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4 accent-[var(--signal)]" checked={confirmedOnly}
            onChange={(e) => { setConfirmedOnly(e.target.checked); reset(); }} />
          Confirmed attacks only
        </label>
      </div>
      <ErrorLine error={list.error} />
      <Section flush>
        <Table rows={list.data ?? []} rowKey={(i) => i.id} onRow={(i) => nav(`/attacks/${i.id}`)}
          empty={confirmedOnly ? "No confirmed attacks match. Clear \"Confirmed attacks only\" to include suspected incidents." : "No incidents match."}
          cols={[
            { key: "w", header: "Started", render: (i) => <span className="whitespace-nowrap">{dateTime(i.first_detected_at)}</span> },
            { key: "t", header: "Target", render: (i) => <Who i={i} /> },
            { key: "v", header: "Attack type", render: (i) => <Vectors v={i.vectors} /> },
            { key: "s", header: "Severity", render: (i) => <Lamp tone={SEVERITY_TONE[i.severity]} label={i.severity} /> },
            { key: "p", header: "Peak", align: "right", render: (i) => <><div>{pps(i.peak_pps)}</div><div className="text-xs text-ink-3">{bps(i.peak_bps)}</div></> },
            { key: "d", header: "Lasted", render: (i) => duration(i.duration_seconds) },
            { key: "o", header: "Outcome", render: (i) => <StatusPill i={i} /> },
          ]} />
        {list.data && list.data.length === 100 && (
          <div className="border-t border-rule-soft px-4 py-2">
            <Button variant="quiet" onClick={() => setBefore(list.data![99].first_detected_at)}>Older incidents</Button>
          </div>
        )}
      </Section>
    </div>
  );
}

// ================================================================ detail
type Detail = Incident & {
  confidence_breakdown: Record<string, number | boolean | string>;
  profile: { id: number; name: string; scope: string } | null;
  timeline: { at: string; kind: string; actor: string; detail: Record<string, any> }[];
  evidence: { observed_at: string; metric: string; value: number; threshold: number | null; provenance: string; details?: { unit?: string } }[];
  eligibility: { protected_prefix: string | null; rtbh_allowed: boolean; steering_allowed: boolean; filtering_allowed: boolean; reasons: string[] } | null;
};
type Series = { available: boolean; reason?: string; step_seconds: number; from: number; to: number;
  points: { t: number; pps: number; bps: number; udp_pps?: number; syn_pps?: number; tcp_pps?: number; icmp_pps?: number }[] };

const EVENT_WORD: Record<string, string> = {
  suspected: "Suspected", confirmed: "Confirmed as an attack", escalated: "Severity increased",
  vectors_changed: "Attack type changed", resolved: "Closed", acknowledged: "Acknowledged",
  false_positive: "Marked false positive", note: "Note", data_gap: "Traffic data stopped",
  data_resumed: "Traffic data resumed", detector_restarted: "Detector restarted",
};

const FACTORS: [string, string, string][] = [
  ["magnitude", "How far over the threshold", "Full marks at 3x the threshold or more."],
  ["specificity", "How characteristic the traffic is", "A single reflection port or SYN-only traffic is very specific; \"a lot of packets\" is not."],
  ["persistence", "How steady it has been", "Share of the last confirmation window that was over threshold."],
  ["baseline", "How unusual for this time", "Compared with this address's learned normal for this hour of the week."],
];

export function AttackDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const d = useApi<Detail>(`/attacks/${id}`, 5_000);
  const series = useApi<Series>(`/attacks/${id}/series`, 15_000);
  const [fp, setFp] = useState(false);
  const [noteOpen, setNoteOpen] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const inc = d.data;
  const open = inc && ["suspected", "confirmed", "mitigating", "mitigated"].includes(inc.status);

  const markers = useMemo(() => {
    if (!inc) return [];
    const m = [{ ts: Date.parse(inc.first_detected_at) / 1000, label: "Suspected", color: "--warn" }];
    if (inc.confirmed_at) m.push({ ts: Date.parse(inc.confirmed_at) / 1000, label: "Confirmed", color: "--attack" });
    if (inc.resolved_at) m.push({ ts: Date.parse(inc.resolved_at) / 1000, label: inc.status === "false_positive" ? "False positive" : "Ended", color: "--ok" });
    return m;
  }, [inc?.first_detected_at, inc?.confirmed_at, inc?.resolved_at, inc?.status]);

  if (d.error) return <ErrorLine error={d.error} />;
  if (!inc) return <p className="text-ink-2">Loading…</p>;
  const pts = series.data?.points ?? [];
  const b = inc.confidence_breakdown;
  const sig = inc.current?.signals ?? [];

  const act = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); await d.reload(); } catch (e: any) { setErr(e.message); }
  };

  return (
    <div className="space-y-5">
      <div className="text-sm"><Link to={open ? "/attacks" : "/history"} className="text-signal hover:underline">{open ? "Active attacks" : "Attack history"}</Link></div>
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="wide text-[28px] font-semibold leading-tight">{inc.scope === "prefix" ? inc.target : targetLabel(inc.target)}</h1>
            <StatusPill i={inc} />
            <Lamp tone={SEVERITY_TONE[inc.severity]} label={`${inc.severity[0].toUpperCase()}${inc.severity.slice(1)} severity`} />
          </div>
          <p className="mt-1 text-ink-2">
            {inc.scope === "prefix" ? "Attack spread across the whole prefix" : inc.customer
              ? <>{inc.customer.customer_name ?? inc.customer.customer_ref} ({inc.customer.customer_ref}), {inc.customer.service_type.toUpperCase()}</>
              : "No customer assigned to this address"}
            {inc.prefix && <> in {inc.prefix}</>}. Started {dateTime(inc.first_detected_at)}, {open ? "ongoing for" : "lasted"} {duration(inc.duration_seconds)}.
          </p>
        </div>
        {open && can("incident_ack") && (
          <div className="flex flex-wrap gap-2">
            {!inc.acknowledged_at && <Button variant="primary" onClick={() => act(() => api(`/attacks/${inc.id}/acknowledge`, { method: "POST" }))}><CheckIcon size={16} /> Acknowledge</Button>}
            <Button onClick={() => setNoteOpen(true)}><MessageSquarePlus size={16} /> Add note</Button>
            {(inc.status === "suspected" || inc.status === "confirmed") && <Button onClick={() => setFp(true)}><Flag size={16} /> Not an attack</Button>}
          </div>
        )}
      </header>
      <ErrorLine error={err} />
      {inc.acknowledged_at && <p className="text-sm text-ink-2">Acknowledged by {inc.acknowledged_by} at {dateTime(inc.acknowledged_at)}.</p>}

      <Section title="Traffic to the target" aside={series.data?.available === false ? undefined : "From 5 minutes before detection"}>
        {series.data?.available === false
          ? <Notice tone="warn">Stored traffic history is unavailable ({series.data.reason}).</Notice>
          : <LiveChart ts={pts.map((p) => p.t)} gapSec={(series.data?.step_seconds ?? 1) * 3} markers={markers}
              series={[
                { label: "Packets/s", color: "--signal", width: 2, fill: true, values: pts.map((p) => p.pps) },
                { label: "UDP", color: "--warn", width: 1.25, values: pts.map((p) => p.udp_pps ?? null) },
                { label: "SYN", color: "--attack", width: 1.25, values: pts.map((p) => p.syn_pps ?? null) },
              ]}
              height={240} format={pps} ariaLabel="Packet rate to the target over the incident" />}
      </Section>

      <div className="grid gap-5 xl:grid-cols-2">
        <Section title="What Shield sees" aside={inc.current?.provenance && <ProvTag p={inc.current.provenance} />}>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4">
            <Stat k="Rate now" v={<Num v={inc.current?.pps} p={open ? inc.current?.provenance ?? "sampled" : "unavailable"} fmt={pps} />} />
            <Stat k="Peak" v={pps(inc.peak_pps)} />
            <Stat k="Bandwidth peak" v={bps(inc.peak_bps)} />
            <Stat k="Sources" v={inc.current && "sources_est" in inc.current ? `≈${count((inc.current as any).sources_est)}` : "–"} />
          </dl>
          <div className="mt-4">
            <div className="mb-1.5 text-sm font-medium">Attack type</div>
            <Vectors v={inc.vectors} max={8} />
          </div>
          {sig.length > 0 && open && (
            <div className="mt-4">
              <Table dense rows={sig} rowKey={(s) => s.vector} cols={[
                { key: "v", header: "Check", render: (s) => vectorName(s.vector) },
                { key: "r", header: "Measured", align: "right", render: (s) => rate(s.value, s.unit ?? unitOf(s.vector)) },
                { key: "t", header: "Threshold", align: "right", render: (s) => <span className="text-ink-2">{rate(s.threshold, s.unit ?? unitOf(s.vector))}</span> },
                { key: "x", header: "Over by", align: "right", render: (s) => `${s.ratio}x` },
              ]} />
            </div>
          )}
        </Section>

        <Section title="Why Shield thinks this" aside={inc.profile ? <>Rules: {inc.profile.name}</> : undefined}>
          <div className="mb-3 flex items-center gap-3">
            <div className="flex-1"><ConfidenceBar v={inc.confidence} /></div>
            <span className="text-sm text-ink-2">peak confidence</span>
          </div>
          <ul className="space-y-2.5 text-sm">
            {FACTORS.map(([k, label, help]) => (
              <li key={k} className="grid grid-cols-[1fr_120px] items-center gap-3" title={help}>
                <div><div>{label}</div><div className="text-xs text-ink-3">{help}</div></div>
                <div className="h-2 rounded-[1px] bg-sunk"><div className="h-2 rounded-[1px] bg-ink-2" style={{ width: `${Number(b[k] ?? 0) * 100}%` }} /></div>
              </li>
            ))}
          </ul>
          {b.quality !== undefined && Number(b.quality) < 1 && (
            <p className="mt-3 text-sm text-warn">Confidence reduced: some flow data came from an exporter that does not report its sampling rate.</p>
          )}
          {b.baseline_known === false && <p className="mt-3 text-xs text-ink-3">No learned baseline yet for this address at this hour, so a neutral value was used.</p>}
        </Section>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Section title="Timeline" flush>
          <ol className="divide-y divide-rule-soft">
            {inc.timeline.map((e, n) => (
              <li key={n} className="grid gap-x-3 gap-y-0.5 px-4 py-2.5 text-sm sm:grid-cols-[190px_1fr]">
                <span className="whitespace-nowrap text-ink-2">{dateTime(e.at)}</span>
                <div>
                  <span className="font-medium">{EVENT_WORD[e.kind] ?? e.kind}</span>
                  {e.actor !== "detector" && <span className="text-ink-2"> by {e.actor}</span>}
                  <TimelineDetail kind={e.kind} d={e.detail} />
                </div>
              </li>
            ))}
          </ol>
        </Section>
        <Section title="Mitigation">
          {inc.eligibility?.protected_prefix ? (
            <div className="space-y-3 text-sm">
              <div className="flex flex-wrap gap-2">
                <Badge tone={inc.eligibility.rtbh_allowed ? "ok" : "neutral"}>Blackhole {inc.eligibility.rtbh_allowed ? "allowed" : "not allowed"}</Badge>
                <Badge tone={inc.eligibility.filtering_allowed ? "ok" : "neutral"}>Filtering {inc.eligibility.filtering_allowed ? "allowed" : "not allowed"}</Badge>
                <Badge tone={inc.eligibility.steering_allowed ? "ok" : "neutral"}>Steering {inc.eligibility.steering_allowed ? "allowed" : "not allowed"}</Badge>
              </div>
              {inc.eligibility.reasons.length > 0 && <ul className="list-disc pl-5 text-ink-2">{inc.eligibility.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
              <p className="text-ink-3">Proposing and approving mitigations arrives in phase 6. Only confirmed attacks will be eligible.</p>
            </div>
          ) : <p className="text-sm text-ink-2">The target is not inside a protected prefix, so no mitigation is possible.</p>}
        </Section>
      </div>

      <Section title="Evidence" aside="Recorded every 10 seconds while the incident is open" flush>
        <Table dense rows={inc.evidence.slice(-30).reverse()} rowKey={(e) => `${e.observed_at}${e.metric}`}
          cols={[
            { key: "t", header: "Time", render: (e) => dateTime(e.observed_at) },
            { key: "m", header: "Check", render: (e) => vectorName(e.metric) },
            { key: "v", header: "Measured", align: "right", render: (e) => rate(e.value, e.details?.unit ?? unitOf(e.metric)) },
            { key: "th", header: "Threshold", align: "right", render: (e) => e.threshold == null ? "–" : rate(e.threshold, e.details?.unit ?? unitOf(e.metric)) },
            { key: "p", header: "Data", render: (e) => <ProvTag p={e.provenance as any} /> },
          ]} />
      </Section>

      <FalsePositiveDialog open={fp} onClose={() => setFp(false)} onDone={d.reload} id={inc.id} />
      <NoteDialog open={noteOpen} onClose={() => setNoteOpen(false)} onDone={d.reload} id={inc.id} />
    </div>
  );
}

function TimelineDetail({ kind, d }: { kind: string; d: Record<string, any> }) {
  if (kind === "note" || kind === "false_positive") return <p className="mt-0.5 text-ink-2">{d.note}</p>;
  if (kind === "suspected" || kind === "confirmed")
    return <p className="mt-0.5 text-ink-2">{(d.vectors ?? []).map(vectorName).join(", ")} at {pps(d.pps)}, confidence {Math.round((d.confidence ?? 0) * 100)}%</p>;
  if (kind === "escalated") return <p className="mt-0.5 text-ink-2">{d.previous} to {d.severity}</p>;
  if (kind === "vectors_changed") return <p className="mt-0.5 text-ink-2">Now {(d.vectors ?? []).map(vectorName).join(", ")}</p>;
  if (kind === "resolved") return <p className="mt-0.5 text-ink-2">{RESOLUTION_WORD[d.resolution] ?? d.resolution}</p>;
  if (kind === "data_gap" || kind === "detector_restarted") return <p className="mt-0.5 text-ink-2">{d.note}</p>;
  return null;
}

function Stat({ k, v }: { k: string; v: ReactNode }) {
  return <div><dt className="text-ink-2">{k}</dt><dd className="text-lg font-medium">{v}</dd></div>;
}

function FalsePositiveDialog({ open, onClose, onDone, id }: { open: boolean; onClose: () => void; onDone: () => void; id: string }) {
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try { await api(`/attacks/${id}/false-positive`, { method: "POST", body: { note } }); onDone(); onClose(); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog open={open} title="Mark as not an attack?" onClose={onClose}
      footer={<><Button type="button" variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" form="fp">Mark as not an attack</Button></>}>
      <form id="fp" onSubmit={submit} className="space-y-3">
        <p className="text-sm">The incident closes and Shield will not report this target again for the suppression period (30 minutes by default).</p>
        <p className="text-sm text-ink-2">If this traffic is normal for the customer, raise their thresholds under Settings, Detection, so it is not flagged again.</p>
        <Field label="What was it?" hint="Recorded in the timeline and the audit log.">
          <Input required minLength={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. customer's nightly backup" />
        </Field>
        <ErrorLine error={err} />
      </form>
    </Dialog>
  );
}

function NoteDialog({ open, onClose, onDone, id }: { open: boolean; onClose: () => void; onDone: () => void; id: string }) {
  const [note, setNote] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    await api(`/attacks/${id}/notes`, { method: "POST", body: { note } });
    setNote(""); onDone(); onClose();
  };
  return (
    <Dialog open={open} title="Add a note" onClose={onClose}
      footer={<><Button type="button" variant="quiet" onClick={onClose}>Cancel</Button><Button variant="primary" form="note">Add note</Button></>}>
      <form id="note" onSubmit={submit}>
        <Field label="Note"><Input required value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      </form>
    </Dialog>
  );
}
