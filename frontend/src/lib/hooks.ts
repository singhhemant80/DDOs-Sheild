import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "./api";

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

export { useLiveTraffic } from "./live";
