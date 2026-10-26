import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { LiveChart } from "../components/LiveChart";
import { Num, ProvLegend, ProvTag } from "../components/Provenance";
import { Badge, Notice, Section, Select, Table } from "../components/ui";
import { useApi, useLiveTraffic, type Dst } from "../lib/hooks";
import { useAttackedTargets, useLive, vectorName } from "../lib/live";
import { ago, bps, count, pct, pps } from "../lib/format";
import { InterfaceList, type Iface } from "./shared";

type Prefix = { id: number; prefix: string; enabled: boolean; rtbh_allowed: boolean; description: string | null };
type Audit = { id: number; at: string; actor_username: string; action: string; entity_type: string | null; entity_id: string | null };

export function Overview() {
  const [win, setWin] = useState("300");
  const [metric, setMetric] = useState<"pps" | "bps">("pps");
  const live = useLiveTraffic(Number(win));
  const ifaces = useApi<{ interfaces: Iface[] }>("/traffic/interfaces", 10_000);
  const prefixes = useApi<Prefix[]>("/prefixes", 60_000);
  const audit = useApi<Audit[]>("/audit?limit=8", 15_000);

  const s = live.latest;
  const fresh = live.state === "live" && s && Date.now() / 1000 - s.ts < 6;
  const inProv = fresh ? s!.in.provenance : "unavailable";
  const outProv = fresh ? s!.out.provenance : "unavailable";
  const fmt = metric === "pps" ? pps : bps;

  const chart = useMemo(() => {
    const h = live.history;
    return {
      ts: h.map((p) => p.ts),
      series: [
        { label: "Inbound", color: "--signal", width: 2, fill: true,
          values: h.map((p) => (metric === "pps" ? p.in_pps : p.in_bps)), prov: h.map((p) => p.provenance) },
        { label: "Outbound", color: "--outbound", width: 1.25,
          values: h.map((p) => (metric === "pps" ? p.out_pps : p.out_bps)) },
      ],
    };
  }, [live.history, metric]);

  const saturated = (ifaces.data?.interfaces ?? []).filter((i) => i.saturated);
  const { incidents } = useLive();
  const confirmedAttacks = incidents.filter((i) => i.status !== "suspected");
  const suspectedCount = incidents.length - confirmedAttacks.length;

  return (
    <div className="space-y-5">
      {confirmedAttacks.length > 0 && (
        <Link to="/attacks" className="block rounded-[3px] border border-attack bg-attack-soft px-4 py-3 text-attack hover:brightness-[0.98]">
          <strong>{confirmedAttacks.length} attack{confirmedAttacks.length === 1 ? "" : "s"} under way:</strong>{" "}
          {confirmedAttacks.slice(0, 3).map((i) => `${i.target.replace(/\/(32|128)$/, "")} (${vectorName(i.vectors[0] ?? "")}, ${pps(i.current?.pps ?? i.peak_pps)})`).join("; ")}
          {confirmedAttacks.length > 3 && ` and ${confirmedAttacks.length - 3} more`}. Open active attacks.
        </Link>
      )}
      {saturated.map((i) => (
        <Notice key={`${i.agent}|${i.if_index}`} tone="attack">
          <strong>{i.upstream ?? i.if_name ?? `ifIndex ${i.if_index}`} is at {pct(i.in_util)} of capacity.</strong>{" "}
          {i.advice}
        </Notice>
      ))}

      {/* Hero: the live inbound waveform with the current readout set into its top edge. */}
      <section className="min-w-0 rounded-[3px] border border-rule bg-panel">
        <div className="flex flex-wrap items-end gap-x-10 gap-y-3 px-5 pb-2 pt-4">
          <div>
            <div className="text-sm text-ink-2">Inbound to protected prefixes</div>
            <div className="wide text-[44px] font-semibold leading-none tracking-[-0.02em] text-signal">
              <Num v={s?.in.pps} p={inProv} fmt={pps} />
            </div>
            <div className="mt-1 text-lg text-ink-2"><Num v={s?.in.bps} p={inProv} fmt={bps} /></div>
          </div>
          <div className="sm:border-l sm:border-rule-soft sm:pl-6">
            <div className="text-sm text-ink-2">Outbound</div>
            <div className="text-2xl font-medium"><Num v={s?.out.pps} p={outProv} fmt={pps} /></div>
            <div className="text-ink-2"><Num v={s?.out.bps} p={outProv} fmt={bps} /></div>
          </div>
          <div className="sm:border-l sm:border-rule-soft sm:pl-6">
            <div className="text-sm text-ink-2">Destinations receiving traffic</div>
            <div className="text-2xl font-medium">{fresh ? count(s!.dst_count) : "–"}</div>
            <div className="text-ink-2">in {prefixes.data?.filter((p) => p.enabled).length ?? "–"} protected prefixes</div>
          </div>
          <div className="ml-auto flex items-center gap-2 pb-1">
            <Select aria-label="Chart metric" value={metric} onChange={(v) => setMetric(v as any)}
              options={[["pps", "Packets/s"], ["bps", "Bits/s"]]} />
            <Select aria-label="Time window" value={win} onChange={setWin}
              options={[["60", "Last minute"], ["300", "Last 5 minutes"], ["900", "Last 15 minutes"], ["3600", "Last hour"]]} />
          </div>
        </div>
        <div className="px-2">
          <LiveChart ts={chart.ts} series={chart.series} height={280} format={fmt} windowSec={Number(win)}
            ariaLabel={`Inbound and outbound ${metric} over the last ${Number(win) / 60} minutes`} />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule-soft px-5 py-2 text-sm">
          <LiveState state={live.state} reason={live.reason} ts={s?.ts} />
          <ProvLegend />
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Section title="Busiest destinations right now" aside={<Link className="text-signal hover:underline" to="/traffic">Open live traffic</Link>} flush>
          <TopDsts rows={fresh ? s!.dsts.slice(0, 8) : []} />
        </Section>
        <Section title="Upstream links" aside="Exact interface counters" flush>
          <InterfaceList rows={ifaces.data?.interfaces ?? []} />
        </Section>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Section title="Recent changes and sign-ins" aside={<Link className="text-signal hover:underline" to="/audit">Audit log</Link>} flush>
          <Table dense rows={audit.data ?? []} rowKey={(r) => String(r.id)}
            empty="No activity recorded yet."
            cols={[
              { key: "at", header: "When", render: (r) => <span className="whitespace-nowrap text-ink-2">{ago(Date.parse(r.at) / 1000)}</span> },
              { key: "who", header: "Who", render: (r) => r.actor_username },
              { key: "what", header: "What", render: (r) => <code className="text-[13px]">{r.action}</code> },
              { key: "obj", header: "Object", render: (r) => <span className="text-ink-2">{objectLabel(r.entity_type, r.entity_id)}</span> },
            ]} />
        </Section>
        <Section title="Protection status" flush>
          <ul className="divide-y divide-rule-soft text-sm">
            <li className="flex justify-between px-4 py-2.5"><span>Active attacks</span>
              <Link to="/attacks">{confirmedAttacks.length ? <Badge tone="attack">{confirmedAttacks.length} confirmed</Badge>
                : suspectedCount ? <Badge tone="warn">{suspectedCount} suspected</Badge> : <Badge tone="ok">None</Badge>}</Link></li>
            <li className="flex justify-between px-4 py-2.5"><span>Blackhole routes</span><Badge>0 announced</Badge></li>
            <li className="flex justify-between px-4 py-2.5"><span>BGP sessions</span><Link to="/bgp" className="text-signal hover:underline">View sessions</Link></li>
            {(prefixes.data ?? []).map((p) => (
              <li key={p.id} className="flex justify-between gap-3 px-4 py-2.5">
                <span><span className="font-medium">{p.prefix}</span> <span className="text-ink-3">{p.description}</span></span>
                {p.enabled ? (p.rtbh_allowed ? <Badge tone="ok">Blackholing authorised</Badge> : <Badge>Monitoring only</Badge>)
                  : <Badge tone="warn">Disabled</Badge>}
              </li>
            ))}
          </ul>
        </Section>
      </div>
    </div>
  );
}

export function LiveState({ state, reason, ts }: { state: string; reason: string; ts?: number }) {
  if (state === "live") return <span className="text-ink-2">Live, updated every second{ts ? ` (last ${ago(ts)})` : ""}</span>;
  if (state === "connecting") return <span className="text-ink-2">Connecting to the live feed…</span>;
  return <span className="text-warn">{reason || "Live feed unavailable"}. Hatched areas mean no data, not zero traffic.</span>;
}

export function TopDsts({ rows, onPick }: { rows: Dst[]; onPick?: (d: Dst) => void }) {
  const attacked = useAttackedTargets();
  return (
    <Table dense rows={rows} rowKey={(r) => r.ip} onRow={onPick}
      empty="No traffic to protected destinations in the last second."
      cols={[
        { key: "ip", header: "Destination", render: (r) => {
          const inc = attacked.get(r.ip);
          return (
            <div>
              <div className="font-medium">{r.ip}{" "}
                {inc && <Link to={`/attacks/${inc.id}`} onClick={(e) => e.stopPropagation()}>
                  <Badge tone={inc.status === "suspected" ? "warn" : "attack"}>{inc.status === "suspected" ? "Suspected" : "Under attack"}</Badge></Link>}
              </div>
              <div className="text-xs text-ink-3">{r.prefix}</div>
            </div>);
        } },
        { key: "pps", header: "Packets/s", align: "right", render: (r) => <Num v={r.pps} p={r.provenance} fmt={pps} /> },
        { key: "bps", header: "Bits/s", align: "right", render: (r) => <Num v={r.bps} p={r.provenance} fmt={bps} /> },
        { key: "mix", header: "Protocol mix", render: (r) => <Mix d={r} /> },
        { key: "src", header: "Sources", align: "right", render: (r) => <span title="Estimated distinct source addresses">≈{count(r.sources_est)}</span> },
        { key: "prov", header: "Data", render: (r) => <ProvTag p={r.provenance} /> },
      ]} />
  );
}

/** Proportional bar: TCP / UDP / ICMP / other, with SYN share marked inside TCP. */
export function Mix({ d }: { d: Dst }) {
  const t = d.pps || 1;
  const segs: [number, string, string][] = [
    [d.tcp_pps, "var(--signal)", "TCP"], [d.udp_pps, "var(--warn)", "UDP"],
    [d.icmp_pps, "var(--ok)", "ICMP"], [d.other_pps, "var(--ink-3)", "Other"],
  ];
  const label = segs.filter(([v]) => v > 0).map(([v, , n]) => `${n} ${pct(v / t)}`).join(", ");
  return (
    <div className="min-w-[140px]">
      <div className="flex h-2 w-full overflow-hidden rounded-[1px] bg-sunk" role="img" aria-label={label} title={label}>
        {segs.map(([v, c, n]) => v > 0 && <span key={n} style={{ width: `${(v / t) * 100}%`, background: c }} />)}
      </div>
      <div className="mt-0.5 text-xs text-ink-3">{label}</div>
    </div>
  );
}

/** Readable object reference for audit rows: UUIDs are shortened, underscores become spaces. */
export function objectLabel(type: string | null, id: string | null) {
  if (!type) return "";
  const t = type.replace(/_/g, " ");
  if (!id) return t;
  return `${t} ${/^[0-9a-f-]{36}$/.test(id) ? id.slice(0, 8) : id}`;
}
