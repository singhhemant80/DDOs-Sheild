import { useCallback, useEffect, useRef, useState } from "react";
import { accessToken, api, ApiError } from "./api";

/** Fetch on mount and every `intervalMs` (0 = once). */
export function useApi<T>(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Cannot reach the Shield API");
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    setLoading(true);
    void load();
    if (!intervalMs) return;
    const t = setInterval(load, intervalMs);
    return () => clearInterval(t);
  }, [load, intervalMs]);
  return { data, error, loading, reload: load };
}

export type Rates = {
  pps: number; bps: number; tcp_pps: number; udp_pps: number; icmp_pps: number; other_pps: number;
  provenance: Provenance;
};
export type Provenance = "measured" | "sampled" | "estimated" | "unavailable";
export type Dst = {
  ip: string; prefix: string; pps: number; bps: number; flow_records: number;
  tcp_pps: number; udp_pps: number; icmp_pps: number; other_pps: number;
  syn_pps: number; ack_pps: number; rst_pps: number; frag_pps: number;
  reflect?: Record<string, number>; sources_est: number; provenance: Provenance;
};
export type Snapshot = { ts: number; in: Rates; out: Rates; dsts: Dst[]; dst_count: number };
export type HistoryPoint = {
  ts: number; in_pps: number; in_bps: number; out_pps: number; out_bps: number;
  tcp_pps: number; udp_pps: number; icmp_pps: number; other_pps: number; provenance: Provenance;
};

export type LiveState = "connecting" | "live" | "no-data" | "offline";

/**
 * Live traffic over the authenticated WebSocket, seeded with the server-side history buffer.
 * Keeps `windowSec` seconds of history. Reconnects with backoff.
 */
export function useLiveTraffic(windowSec = 300) {
  const [latest, setLatest] = useState<Snapshot | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [state, setState] = useState<LiveState>("connecting");
  const [reason, setReason] = useState<string>("");
  const histRef = useRef<HistoryPoint[]>([]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 1000;
    let timer: ReturnType<typeof setTimeout>;

    api<{ points: HistoryPoint[] }>(`/traffic/history?seconds=${windowSec}`)
      .then((h) => {
        histRef.current = h.points;
        setHistory(h.points);
      })
      .catch(() => undefined);

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
        const next = [...h, p].filter((x) => x.ts > p.ts - windowSec);
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
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [windowSec]);

  return { latest, history, state, reason };
}
