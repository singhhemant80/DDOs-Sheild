import { useMemo, useState } from "react";
import { LiveChart } from "../components/LiveChart";
import { Num, ProvLegend, ProvTag } from "../components/Provenance";
import { Badge, Notice, PageHeader, Section, Select, Table } from "../components/ui";
import { useApi, useLiveTraffic, type Dst } from "../lib/hooks";
import { bps, count, PROTO_PORTS, pps } from "../lib/format";
import { LiveState, TopDsts } from "./Overview";

export function LiveTraffic() {
  const [win, setWin] = useState("300");
  const live = useLiveTraffic(Number(win));
  const [pick, setPick] = useState<Dst | null>(null);
  const s = live.latest;
  const fresh = live.state === "live" && s && Date.now() / 1000 - s.ts < 6;

  const proto = useMemo(() => {
    const h = live.history;
    return {
      ts: h.map((p) => p.ts),
      series: [
        { label: "TCP", color: "--signal", values: h.map((p) => p.tcp_pps), prov: h.map((p) => p.provenance) },
        { label: "UDP", color: "--warn", values: h.map((p) => p.udp_pps), prov: h.map((p) => p.provenance) },
        { label: "ICMP", color: "--ok", values: h.map((p) => p.icmp_pps), prov: h.map((p) => p.provenance) },
        { label: "Other", color: "--ink-3", values: h.map((p) => p.other_pps), width: 1.25 },
      ],
    };
  }, [live.history]);

  return (
    <div className="space-y-5">
      <PageHeader title="Live traffic"
        description="Inbound traffic to protected prefixes, by protocol and by destination. Updated every second from flow exports."
        actions={<Select aria-label="Time window" value={win} onChange={setWin}
          options={[["60", "Last minute"], ["300", "Last 5 minutes"], ["900", "Last 15 minutes"], ["3600", "Last hour"]]} />} />

      <Section title="Inbound packets per second by protocol" aside={<ProtoKey />}>
        <LiveChart ts={proto.ts} series={proto.series} height={240} format={pps} windowSec={Number(win)}
          ariaLabel="Inbound packets per second by protocol" />
        <div className="mt-2 flex flex-wrap justify-between gap-3 text-sm">
          <LiveState state={live.state} reason={live.reason} ts={s?.ts} />
          <ProvLegend />
        </div>
      </Section>

      <Section title={`Destinations (${fresh ? s!.dst_count : 0} receiving traffic)`}
        aside="Top 50 by packet rate. Select a row for its history." flush>
        <TopDsts rows={fresh ? s!.dsts : []} onPick={setPick} />
      </Section>

      {pick && <DestinationDetail d={pick} live={fresh ? s!.dsts.find((x) => x.ip === pick.ip) ?? null : null} />}
    </div>
  );
}

function ProtoKey() {
  return (
    <span className="flex gap-3">
      {[["TCP", "var(--signal)"], ["UDP", "var(--warn)"], ["ICMP", "var(--ok)"], ["Other", "var(--ink-3)"]].map(([n, c]) => (
        <span key={n} className="inline-flex items-center gap-1"><span className="h-0.5 w-3" style={{ background: c }} />{n}</span>
      ))}
    </span>
  );
}

type Series = { available: boolean; reason?: string; step_seconds: number; note?: string;
  points: { t: number; pps: number; bps: number; udp_pps?: number; syn_pps?: number; provenance?: string }[] };

/** One destination: what the live signals say now, and the stored history. */
function DestinationDetail({ d, live }: { d: Dst; live: Dst | null }) {
  const [mins, setMins] = useState("60");
  const hist = useApi<Series>(`/traffic/destinations/${d.ip}?minutes=${mins}`, 15_000);
  const cur = live ?? d;
  const signals: [string, number][] = [
    ["SYN-only TCP", cur.syn_pps], ["ACK-only TCP", cur.ack_pps], ["RST", cur.rst_pps], ["Fragments", cur.frag_pps],
    ...Object.entries(cur.reflect ?? {}).map(([port, v]) => [`From UDP ${port} (${PROTO_PORTS[port] ?? "?"})`, v] as [string, number]),
  ];
  const pts = hist.data?.points ?? [];
  return (
    <Section title={<>History for {d.ip} <span className="font-normal text-ink-3">in {d.prefix}</span></>}
      aside={<Select aria-label="History range" value={mins} onChange={setMins}
        options={[["15", "15 minutes"], ["60", "1 hour"], ["360", "6 hours"], ["1440", "24 hours"], ["10080", "7 days"]]} />}>
      <div className="grid gap-5 lg:grid-cols-[1fr_300px]">
        <div>
          {hist.data && !hist.data.available
            ? <Notice tone="warn">History is unavailable: {hist.data.reason}. Live figures still work.</Notice>
            : <LiveChart ts={pts.map((p) => p.t)} gapSec={(hist.data?.step_seconds ?? 1) * 3}
                series={[
                  { label: "Packets/s", color: "--signal", width: 2, fill: true, values: pts.map((p) => p.pps) },
                  { label: "UDP", color: "--warn", width: 1.25, values: pts.map((p) => p.udp_pps ?? null) },
                  { label: "SYN", color: "--attack", width: 1.25, values: pts.map((p) => p.syn_pps ?? null) },
                ]}
                height={220} format={pps} windowSec={Number(mins) * 60} ariaLabel={`Packet rate history for ${d.ip}`} />}
          {hist.data?.note && <p className="mt-1 text-xs text-ink-3">{hist.data.note}</p>}
        </div>
        <div className="space-y-3 text-sm">
          <div className="flex items-baseline justify-between"><span className="text-ink-2">Now</span>
            <span className="text-lg font-medium"><Num v={cur.pps} p={live ? cur.provenance : "unavailable"} fmt={pps} /></span></div>
          <div className="flex items-baseline justify-between"><span className="text-ink-2">Bandwidth</span>
            <Num v={cur.bps} p={live ? cur.provenance : "unavailable"} fmt={bps} /></div>
          <div className="flex items-baseline justify-between"><span className="text-ink-2">Distinct sources</span>
            <span title="Linear-counting estimate">≈{count(cur.sources_est)}</span></div>
          <div className="flex items-baseline justify-between"><span className="text-ink-2">Data quality</span><ProvTag p={live ? cur.provenance : "unavailable"} /></div>
          <div className="border-t border-rule-soft pt-3">
            <div className="mb-1.5 font-medium">Attack signals</div>
            <Table dense rows={signals.filter(([, v]) => v > 0)} rowKey={([n]) => n}
              empty="No SYN-only, fragment or reflection traffic."
              cols={[
                { key: "n", header: "Signal", render: ([n]) => n },
                { key: "v", header: "Rate", align: "right", render: ([, v]) => pps(v) },
              ]} />
            <p className="mt-2 text-xs text-ink-3">Signals only describe traffic. Deciding whether it is an attack is the
              detection engine's job (<Badge>phase 4</Badge>).</p>
          </div>
        </div>
      </div>
    </Section>
  );
}

type Totals = { available: boolean; reason?: string; step_seconds: number; points: { t: number; direction: string; pps: number; bps: number; pps_max: number; provenance: string }[] };
type Top = { available: boolean; rows: { dst: string; prefix: string; pps_max: number; pps_avg: number; bps_max: number; sources_max: number; active_seconds: number }[] };

export function Analytics() {
  const [mins, setMins] = useState("1440");
  const [metric, setMetric] = useState<"pps" | "bps">("bps");
  const totals = useApi<Totals>(`/traffic/totals?minutes=${mins}`, 60_000);
  const top = useApi<Top>(`/traffic/top?minutes=${Math.min(Number(mins), 43200)}&limit=25`, 60_000);

  const chart = useMemo(() => {
    const pts = totals.data?.points ?? [];
    const tsSet = Array.from(new Set(pts.map((p) => p.t))).sort((a, b) => a - b);
    const by = (dir: string) => {
      const m = new Map(pts.filter((p) => p.direction === dir).map((p) => [p.t, p]));
      return tsSet.map((t) => { const p = m.get(t); return p ? (metric === "pps" ? p.pps : p.bps) : null; });
    };
    const prov = tsSet.map((t) => (pts.find((p) => p.t === t && p.direction === "in")?.provenance ?? "sampled") as any);
    return { ts: tsSet, series: [
      { label: "Inbound", color: "--signal", width: 2, fill: true, values: by("in"), prov },
      { label: "Outbound", color: "--outbound", width: 1.25, values: by("out") },
    ] };
  }, [totals.data, metric]);

  return (
    <div className="space-y-5">
      <PageHeader title="Traffic analytics" description="Stored history from ClickHouse: per-second detail for 7 days, per-minute rollups for longer ranges."
        actions={<>
          <Select aria-label="Metric" value={metric} onChange={(v) => setMetric(v as any)} options={[["bps", "Bits/s"], ["pps", "Packets/s"]]} />
          <Select aria-label="Range" value={mins} onChange={setMins}
            options={[["60", "1 hour"], ["360", "6 hours"], ["1440", "24 hours"], ["10080", "7 days"], ["43200", "30 days"], ["129600", "90 days"]]} />
        </>} />
      {totals.data && !totals.data.available && <Notice tone="warn">Stored history is unavailable ({totals.data.reason}). Check that ClickHouse is running.</Notice>}
      <Section title="Inbound and outbound" aside={totals.data ? `Each point averages ${fmtStep(totals.data.step_seconds)}` : undefined}>
        <LiveChart ts={chart.ts} series={chart.series} height={280} format={metric === "pps" ? pps : bps}
          gapSec={(totals.data?.step_seconds ?? 1) * 3} windowSec={Number(mins) * 60} ariaLabel="Stored traffic totals" />
      </Section>
      <Section title="Most targeted destinations" aside="Ranked by peak packet rate in the selected range" flush>
        <Table rows={top.data?.rows ?? []} rowKey={(r) => r.dst} empty="No destinations above the storage threshold in this range."
          cols={[
            { key: "d", header: "Destination", render: (r) => <><div className="font-medium">{r.dst}</div><div className="text-xs text-ink-3">{r.prefix}</div></> },
            { key: "pk", header: "Peak packets/s", align: "right", render: (r) => pps(r.pps_max) },
            { key: "av", header: "Average", align: "right", render: (r) => pps(r.pps_avg) },
            { key: "bw", header: "Peak bits/s", align: "right", render: (r) => bps(r.bps_max) },
            { key: "s", header: "Peak sources", align: "right", render: (r) => `≈${count(r.sources_max)}` },
            { key: "a", header: "Active", align: "right", render: (r) => fmtStep(r.active_seconds) },
          ]} />
      </Section>
    </div>
  );
}

function fmtStep(s: number) {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(s < 36000 ? 1 : 0)} h`;
}
