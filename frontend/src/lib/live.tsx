import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { accessToken, api } from "./api";
import type { HistoryPoint, LiveState, Provenance, Snapshot } from "./hooks";

export type Incident = {
  id: string; target: string; scope: "host" | "prefix"; prefix: string | null;
  status: "suspected" | "confirmed" | "mitigating" | "mitigated" | "resolved" | "false_positive";
  severity: "info" | "low" | "medium" | "high" | "critical"; vectors: string[];
  confidence: number; current_confidence: number | null; peak_pps: number | null; peak_bps: number | null;
  peak_provenance: Provenance | null; first_detected_at: string; confirmed_at: string | null;
  resolved_at: string | null; last_hot_at: string | null; resolution: string | null;
  acknowledged_at: string | null; acknowledged_by: string | null;
  customer: { customer_ref: string; customer_name: string | null; service_type: string } | null;
  current: { pps?: number; bps?: number; provenance?: Provenance; signals?: { vector: string; value: number; threshold: number; ratio: number; unit?: string }[] };
  duration_seconds: number;
};

type IncidentEvent = {
  type: "incident"; event: string; actor?: string;
  incident: Partial<Incident> & { id: string; pps?: number; bps?: number; provenance?: Provenance; ts?: number };
};

type Ctx = {
  latest: Snapshot | null;
  history: HistoryPoint[];       // up to 1 hour
  state: LiveState;
  reason: string;
  incidents: Incident[];         // open incidents, kept current by the event stream
  lastIncidentEvent: IncidentEvent | null;
  reloadIncidents: () => void;
};

const LiveCtx = createContext<Ctx | null>(null);
const OPEN = new Set(["suspected", "confirmed", "mitigating", "mitigated"]);
const KEEP = 3600;

/** One WebSocket for the whole app: traffic every second plus incident events. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [latest, setLatest] = useState<Snapshot | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [state, setState] = useState<LiveState>("connecting");
  const [reason, setReason] = useState("");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [lastIncidentEvent, setLast] = useState<IncidentEvent | null>(null);
  const histRef = useRef<HistoryPoint[]>([]);
  const reloadTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const reloadIncidents = () => {
    api<Incident[]>("/attacks?state=open&limit=200").then(setIncidents).catch(() => undefined);
  };

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 1000;
    let timer: ReturnType<typeof setTimeout>;

    api<{ points: HistoryPoint[] }>(`/traffic/history?seconds=${KEEP}`)
      .then((h) => { histRef.current = h.points; setHistory(h.points); })
      .catch(() => undefined);
    reloadIncidents();
    const poll = setInterval(reloadIncidents, 30_000); // safety net if an event is missed

    const onIncident = (m: IncidentEvent) => {
      setLast(m);
      const inc = m.incident;
      if (m.event === "suspected" || m.event === "confirmed" || m.event === "resolved" || m.event === "false_positive") {
        // State change: fetch the full record (customer, prefix) shortly after.
        clearTimeout(reloadTimer.current);
        reloadTimer.current = setTimeout(reloadIncidents, 400);
      }
      setIncidents((cur) => {
        const i = cur.findIndex((x) => x.id === inc.id);
        if (i < 0) return cur;
        if (inc.status && !OPEN.has(inc.status)) return cur.filter((x) => x.id !== inc.id);
        const next = [...cur];
        const prev = next[i];
        next[i] = {
          ...prev,
          ...(inc.severity ? { severity: inc.severity } : {}),
          ...(inc.vectors ? { vectors: inc.vectors } : {}),
          ...(inc.status ? { status: inc.status } : {}),
          ...(inc.confidence != null ? { confidence: inc.confidence } : {}),
          ...(inc.current_confidence != null ? { current_confidence: inc.current_confidence } : {}),
          ...(inc.peak_pps != null ? { peak_pps: inc.peak_pps, peak_bps: inc.peak_bps ?? prev.peak_bps } : {}),
          ...(m.event === "acknowledged" ? { acknowledged_at: new Date().toISOString(), acknowledged_by: m.actor ?? null } : {}),
          current: inc.pps != null ? { ...prev.current, pps: inc.pps, bps: inc.bps, provenance: inc.provenance } : prev.current,
        };
        return next;
      });
    };

    const connect = () => {
      if (stopped) return;
      setState("connecting");
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/v1/ws/traffic`);
      ws.onopen = () => ws?.send(JSON.stringify({ token: accessToken() }));
      ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.type === "ready") { retry = 1000; return; }
        if (m.type === "status") { setState("no-data"); setReason(m.reason ?? ""); return; }
        if (m.type === "incident") { onIncident(m); return; }
        if (m.type !== "traffic") return;
        const s: Snapshot = m.data;
        setState("live");
        setLatest(s);
        const p: HistoryPoint = {
          ts: s.ts, in_pps: s.in.pps, in_bps: s.in.bps, out_pps: s.out.pps, out_bps: s.out.bps,
          tcp_pps: s.in.tcp_pps, udp_pps: s.in.udp_pps, icmp_pps: s.in.icmp_pps, other_pps: s.in.other_pps,
          provenance: s.in.provenance,
        };
        const h = histRef.current;
        if (h.length && h[h.length - 1].ts >= p.ts) return;
        const next = h.length >= KEEP ? [...h.slice(h.length - KEEP + 1), p] : [...h, p];
        histRef.current = next;
        setHistory(next);
      };
      ws.onclose = (ev) => {
        if (stopped) return;
        setState("offline");
        setReason(ev.code === 4401 ? "Session ended" : "Connection to the Shield API lost");
        timer = setTimeout(connect, retry);
        retry = Math.min(retry * 2, 15000);
      };
    };
    connect();
    return () => { stopped = true; clearTimeout(timer); clearInterval(poll); ws?.close(); };
  }, []);

  return (
    <LiveCtx.Provider value={{ latest, history, state, reason, incidents, lastIncidentEvent, reloadIncidents }}>
      {children}
    </LiveCtx.Provider>
  );
}

export function useLive() {
  const c = useContext(LiveCtx);
  if (!c) throw new Error("useLive outside LiveProvider");
  return c;
}

/** Traffic for a time window, from the shared connection. */
export function useLiveTraffic(windowSec = 300) {
  const { latest, history, state, reason } = useLive();
  const sliced = useMemo(() => {
    const now = latest?.ts ?? Date.now() / 1000;
    return history.filter((p) => p.ts > now - windowSec);
  }, [history, latest?.ts, windowSec]);
  return { latest, history: sliced, state, reason };
}

/** Open incidents keyed by host address, for highlighting rows elsewhere. */
export function useAttackedTargets() {
  const { incidents } = useLive();
  return useMemo(() => {
    const m = new Map<string, Incident>();
    for (const i of incidents) m.set(i.target.replace(/\/(32|128)$/, ""), i);
    return m;
  }, [incidents]);
}

// ---------------------------------------------------------------- vocabulary
export const VECTOR_NAMES: Record<string, string> = {
  udp_flood: "UDP flood", syn_flood: "SYN flood", ack_flood: "ACK flood", rst_flood: "RST flood",
  icmp_flood: "ICMP flood", fragment_flood: "Fragment flood", carpet_bombing: "Carpet bombing",
  volumetric_pps: "High packet rate", volumetric_bps: "High bandwidth", traffic_anomaly: "Unusual for this time",
  dns_amplification: "DNS reflection", ntp_amplification: "NTP reflection", ssdp_amplification: "SSDP reflection",
  cldap_amplification: "CLDAP reflection", memcached_amplification: "Memcached reflection",
  chargen_amplification: "Chargen reflection", snmp_amplification: "SNMP reflection",
  wsd_amplification: "WS-Discovery reflection", coap_amplification: "CoAP reflection",
  ard_amplification: "ARD reflection", portmap_amplification: "Portmap reflection",
  netbios_amplification: "NetBIOS reflection",
};
export const vectorName = (v: string) => VECTOR_NAMES[v] ?? v.replace(/_/g, " ");

export const STATUS_WORD: Record<string, string> = {
  suspected: "Suspected", confirmed: "Confirmed", mitigating: "Mitigating", mitigated: "Mitigated",
  resolved: "Ended", false_positive: "False positive",
};
export const RESOLUTION_WORD: Record<string, string> = {
  ended: "Attack ended", cleared_unconfirmed: "Cleared without confirmation",
  false_positive: "Marked false positive", superseded: "Superseded",
};
export const SEVERITY_TONE = { critical: "attack", high: "attack", medium: "warn", low: "neutral", info: "neutral" } as const;
