import type { Provenance } from "../lib/hooks";

const WORD: Record<Provenance, string> = {
  measured: "Measured",
  sampled: "Sampled",
  estimated: "Estimated",
  unavailable: "No data",
};

const HELP: Record<Provenance, string> = {
  measured: "Exact interface counters (SNMP or sFlow counter samples).",
  sampled: "Scaled up from sampled flow records using the exporter's sampling rate.",
  estimated: "Some flows came from an exporter that did not report its sampling rate; treated as 1:1, so likely too low.",
  unavailable: "The source is down or the data is stale.",
};

/** The line glyph that represents each kind of data, shared with the charts. */
export function ProvSwatch({ p, color = "currentColor" }: { p: Provenance; color?: string }) {
  if (p === "unavailable") return <span className="hatch inline-block h-2.5 w-5 align-middle" aria-hidden />;
  return (
    <svg width="20" height="8" viewBox="0 0 20 8" aria-hidden className="inline-block align-middle">
      <line x1="0" y1="4" x2="20" y2="4" stroke={color}
        strokeWidth={p === "measured" ? 3 : p === "sampled" ? 1.5 : 1.75}
        strokeDasharray={p === "estimated" ? "4 3" : undefined} />
    </svg>
  );
}

export function ProvTag({ p }: { p: Provenance }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink-2" title={HELP[p]}>
      <ProvSwatch p={p} />
      {WORD[p]}
    </span>
  );
}

/** A number whose underline says how trustworthy it is. */
export function Num({ v, p, fmt, className = "" }: { v: number | null | undefined; p: Provenance; fmt: (n: number) => string; className?: string }) {
  if (p === "unavailable" || v == null) {
    return <span className={`prov-unavailable ${className}`} title={HELP.unavailable}>–</span>;
  }
  return <span className={`prov-${p} ${className}`} title={HELP[p]}>{fmt(v)}</span>;
}

export function ProvLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1">
      {(["measured", "sampled", "estimated", "unavailable"] as Provenance[]).map((p) => <ProvTag key={p} p={p} />)}
    </div>
  );
}
