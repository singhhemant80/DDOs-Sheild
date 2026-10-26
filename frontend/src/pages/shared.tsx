import { Num } from "../components/Provenance";
import { Table } from "../components/ui";
import { ago, bps, pct } from "../lib/format";
import type { Provenance } from "../lib/hooks";

export type Iface = {
  agent: string; if_index: number; if_name?: string; router: string | null; upstream: string | null;
  in_bps: number; out_bps: number; in_pps: number; out_pps: number; speed_bps: number; in_util: number;
  out_util: number; ts: number; source: string; provenance: Provenance; saturated: boolean; advice?: string;
};

/** Utilisation bar: fill = load, a tick marks the alarm threshold region. */
function Util({ v, prov }: { v: number; prov: Provenance }) {
  if (prov === "unavailable" || !isFinite(v)) return <div className="hatch h-2.5 w-full rounded-[1px]" />;
  const tone = v >= 0.85 ? "var(--attack)" : v >= 0.6 ? "var(--warn)" : "var(--signal)";
  return (
    <div className="relative h-2.5 w-full rounded-[1px] bg-sunk" role="img" aria-label={`${pct(v)} utilised`}>
      <span className="absolute inset-y-0 left-0 rounded-[1px]" style={{ width: `${Math.min(100, v * 100)}%`, background: tone }} />
      <span className="absolute inset-y-[-2px] left-[85%] w-px bg-ink-3" aria-hidden />
    </div>
  );
}

export function InterfaceList({ rows }: { rows: Iface[] }) {
  return (
    <Table dense rows={rows} rowKey={(r) => `${r.agent}|${r.if_index}`}
      empty={<>No interface counters yet. Configure the SNMP poller or sFlow counter export on the edge routers.</>}
      cols={[
        { key: "name", header: "Link", render: (r) => (
          <div>
            <div className="font-medium">{r.upstream ?? r.if_name ?? `ifIndex ${r.if_index}`}</div>
            <div className="text-xs text-ink-3">{r.router ?? r.agent}, {r.source === "snmp" ? "SNMP" : "sFlow"} {ago(r.ts)}</div>
          </div>) },
        { key: "in", header: "In", align: "right", render: (r) => <Num v={r.in_bps} p={r.provenance} fmt={bps} /> },
        { key: "util", header: "Load", className: "w-[34%]", render: (r) => (
          <div className="pt-1.5"><Util v={r.in_util} prov={r.provenance} />
            <div className="mt-0.5 text-xs text-ink-3">{r.provenance === "unavailable" ? "stale" : pct(r.in_util || 0)}</div></div>) },
      ]} />
  );
}
