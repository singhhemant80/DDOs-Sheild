import { useState } from "react";
import { Link } from "react-router-dom";
import { CircleAlert, CircleCheck, CircleHelp, Download, TriangleAlert } from "lucide-react";
import { accessToken } from "../lib/api";
import { useApi } from "../lib/hooks";
import { bps, dateTime, pps } from "../lib/format";
import { vectorName } from "../lib/live";
import { Badge, Button, ErrorLine, PageHeader, Section, Select, Table } from "../components/ui";
import type { RoadmapData } from "./Roadmap";

type Summary = {
  from: string; to: string; attacks: number; false_positives: number; by_severity: Record<string, number>;
  by_vector: Record<string, number>; per_day: Record<string, number>; total_attack_minutes: number; longest_minutes: number;
  median_minutes: number; peak: { target: string; bps: number; pps: number | null; incident_id: string; at: string } | null;
  top_targets: { target: string; attacks: number; customer: string | null }[];
  top_source_networks: { asn: number; as_name: string | null; attacks: number; packets: number }[];
  mitigations: Record<string, Record<string, number>>; mitigations_total: number; mitigations_automatic: number;
};

function Stat({ k, v, sub }: { k: string; v: React.ReactNode; sub?: React.ReactNode }) {
  return <div className="bg-panel px-4 py-3"><div className="text-xs text-ink-3">{k}</div><div className="mt-0.5 text-[20px] font-semibold">{v}</div>
    {sub && <div className="text-xs text-ink-3">{sub}</div>}</div>;
}

export function ReportsPage() {
  const [days, setDays] = useState("30");
  const s = useApi<Summary>(`/reports/summary?days=${days}`);
  const d = s.data;
  const perDay = Object.entries(d?.per_day ?? {});
  const max = Math.max(1, ...perDay.map(([, n]) => n));
  const download = () => {
    fetch(`/api/v1/reports/incidents.csv?days=${days}`, { headers: { Authorization: `Bearer ${accessToken()}` } })
      .then((r) => r.blob()).then((b) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(b);
        a.download = `shield-attacks-${days}d.csv`;
        a.click();
      });
  };
  return (
    <div className="space-y-5">
      <PageHeader title="Reports" description="Attacks, their size and sources, and what Shield did, for a period."
        actions={<>
          <Select aria-label="Period" value={days} onChange={setDays}
            options={[["1", "Last 24 hours"], ["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["365", "Last year"]]} />
          <Button onClick={download}><Download size={16} /> Attacks as CSV</Button></>} />
      <ErrorLine error={s.error} />
      {d && <>
        <div className="grid gap-px overflow-hidden rounded-[3px] border border-rule bg-rule sm:grid-cols-3 lg:grid-cols-6">
          <Stat k="Attacks" v={d.attacks} sub={`${d.false_positives} false positives`} />
          <Stat k="Critical / high" v={`${d.by_severity.critical ?? 0} / ${d.by_severity.high ?? 0}`} />
          <Stat k="Time under attack" v={`${d.total_attack_minutes} min`} sub={`median ${d.median_minutes}, longest ${d.longest_minutes}`} />
          <Stat k="Largest attack" v={d.peak ? bps(d.peak.bps) : "–"} sub={d.peak ? <Link className="hover:underline" to={`/attacks/${d.peak.incident_id}`}>{d.peak.target}</Link> : undefined} />
          <Stat k="Mitigations" v={d.mitigations_total} sub={`${d.mitigations_automatic} by policy`} />
          <Stat k="Attack types" v={Object.keys(d.by_vector).length} />
        </div>
        <Section title="Attacks per day">
          {perDay.length ? <div className="flex h-32 items-end gap-1" role="img" aria-label="Attacks per day">
            {perDay.map(([day, n]) => <div key={day} className="flex-1 rounded-t-[2px] bg-attack/70" style={{ height: `${(n / max) * 100}%` }}
              title={`${day}: ${n}`} />)}
          </div> : <p className="text-sm text-ink-2">No attacks in this period.</p>}
        </Section>
        <div className="grid gap-5 lg:grid-cols-3">
          <Section title="Most attacked" flush>
            <Table dense rows={d.top_targets} rowKey={(t) => t.target} empty="–" cols={[
              { key: "t", header: "Target", render: (t) => <span className="font-mono text-[13px]">{t.target}</span> },
              { key: "c", header: "Customer", render: (t) => t.customer ?? <span className="text-ink-3">–</span> },
              { key: "n", header: "Attacks", align: "right", render: (t) => t.attacks },
            ]} />
          </Section>
          <Section title="Attack types" flush>
            <Table dense rows={Object.entries(d.by_vector)} rowKey={([v]) => v} empty="–" cols={[
              { key: "v", header: "Type", render: ([v]) => vectorName(v) },
              { key: "n", header: "Attacks", align: "right", render: ([, n]) => n },
            ]} />
          </Section>
          <Section title="Main source networks" flush>
            <Table dense rows={d.top_source_networks} rowKey={(r) => String(r.asn)} empty="No source data in this period." cols={[
              { key: "a", header: "Network", render: (r) => <>AS{r.asn} <span className="text-ink-2">{(r.as_name ?? "").slice(0, 28)}</span></> },
              { key: "n", header: "Attacks", align: "right", render: (r) => r.attacks },
            ]} />
          </Section>
        </div>
        <Section title="Mitigations" flush>
          <Table dense rows={Object.entries(d.mitigations)} rowKey={([k]) => k} empty="No mitigations in this period." cols={[
            { key: "k", header: "Method", render: ([k]) => k },
            { key: "s", header: "Outcome", render: ([, v]) => <div className="flex flex-wrap gap-1">{Object.entries(v).map(([st, n]) =>
              <Badge key={st} tone={st === "failed" || st === "rolled_back" ? "attack" : st === "active" ? "signal" : "neutral"}>{n} {st.replace("_", " ")}</Badge>)}</div> },
          ]} />
        </Section>
        <p className="text-xs text-ink-3">{dateTime(d.from)} to {dateTime(d.to)}. Confirmed attacks only; rates come from sampled flow data
          {d.peak?.pps ? ` (largest attack ${pps(d.peak.pps)})` : ""}.</p>
      </>}
    </div>
  );
}

type Check = { area: string; key: string; level: "ok" | "warn" | "problem" | "unknown"; title: string; fix: string | null };

export function ReadinessPage() {
  const h = useApi<{ ready: boolean; counts: Record<string, number>; checks: Check[] }>("/system/hardening", 60_000);
  const rm = useApi<RoadmapData>("/system/roadmap", 60_000);
  const areas = [...new Set((h.data?.checks ?? []).map((c) => c.area))];
  const order = { problem: 0, warn: 1, unknown: 2, ok: 3 };
  const icon = (l: Check["level"]) => l === "ok" ? <CircleCheck size={17} className="mt-0.5 shrink-0 text-ok" />
    : l === "warn" ? <TriangleAlert size={17} className="mt-0.5 shrink-0 text-warn" />
    : l === "problem" ? <CircleAlert size={17} className="mt-0.5 shrink-0 text-attack" /> : <CircleHelp size={17} className="mt-0.5 shrink-0 text-ink-3" />;
  const verify = (rm.data?.phases ?? []).flatMap((p) => p.verify.map((v) => ({ n: p.n, v })));
  const setup = (rm.data?.checklist ?? []).filter((c) => !c.done);
  return (
    <div className="space-y-5">
      <PageHeader title="Production readiness"
        description="Hardening checks, open setup steps and what still has to be confirmed on your own equipment before relying on Shield." />
      <ErrorLine error={h.error} />
      {h.data && <Section>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <span className="text-[17px] font-semibold">{h.data.ready ? "No blocking problems" : `${h.data.counts.problem} problem${h.data.counts.problem === 1 ? "" : "s"} to fix`}</span>
          <span className="text-sm text-ink-2">{h.data.counts.ok} ok · {h.data.counts.warn} to review · {h.data.counts.unknown} not checked</span>
        </div>
      </Section>}
      <div className="grid gap-5 lg:grid-cols-[1fr_380px]">
        <div className="space-y-5">
          {areas.map((a) => (
            <Section key={a} title={a} flush>
              <ul>{[...(h.data?.checks ?? [])].filter((c) => c.area === a).sort((x, y) => order[x.level] - order[y.level]).map((c) => (
                <li key={c.key} className="flex gap-2.5 border-b border-rule-soft px-4 py-2.5 text-sm last:border-0">
                  {icon(c.level)}<div><div className={c.level === "ok" ? "text-ink-2" : "font-medium"}>{c.title}</div>
                    {c.fix && <div className="text-xs text-ink-2">{c.fix}</div>}</div>
                </li>))}</ul>
            </Section>))}
        </div>
        <div className="space-y-5">
          <Section title="Setup steps open" flush>
            <ul>{setup.length ? setup.map((c) => (
              <li key={c.key} className="border-b border-rule-soft px-4 py-2.5 text-sm last:border-0"><div className="font-medium">{c.title}</div>
                {c.hint && <Link to={c.link} className="text-xs text-signal hover:underline">{c.hint}</Link>}</li>))
              : <li className="px-4 py-3 text-sm text-ink-2">None.</li>}</ul>
          </Section>
          <Section title="Confirm on your equipment">
            <ul className="space-y-2 text-sm">{verify.map(({ n, v }) => <li key={v}><span className="text-ink-3">Phase {n}:</span> {v}</li>)}</ul>
            <p className="mt-3 text-xs text-ink-3">Tested in the lab against simulators; try each once on a test address or prefix.</p>
          </Section>
        </div>
      </div>
    </div>
  );
}
