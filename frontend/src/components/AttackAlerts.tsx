import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowDownToLine, ArrowUpFromLine, X } from "lucide-react";
import { useApi } from "../lib/hooks";
import { bps, dateTime, pps } from "../lib/format";
import { SEVERITY_TONE, useLive, vectorName, type Incident } from "../lib/live";
import { Badge, Lamp } from "./ui";

type Peer = { ip: string; asn: number | null; as_name: string | null; country: string; share: number | null;
  proto?: string; src_port?: number; dst_port?: number };
type Peers = { top: Peer[]; networks: { asn: number | null; as_name: string | null; country: string; share: number | null }[];
  count: number; max_at_once: number | null } | null;
type AlertInc = Incident & { peers: Peers };
type Side = { open: AlertInc[]; recent: AlertInc[]; recent_count: number };
type Alerts = { inbound: Side; outbound: Side; hours: number };

const ip = (t: string) => t.replace(/\/(32|128)$/, "");
const short = (n: string | null | undefined) => { const s = (n ?? "").split(",")[0].trim(); return s.length > 26 ? s.slice(0, 24) + "…" : s; };
const share = (v: number | null | undefined) => v == null ? "" : `${Math.round(v * 100)}%`;
const since = (iso: string) => {
  const s = Math.max(0, Math.round(Date.now() / 1000 - Date.parse(iso) / 1000));
  return s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
};

/** The dashboard's attack alert panel: attacks on your network and attacks sent from it, side by
 *  side, each with who is attacking (inbound) or whom your address is attacking (outbound). */
export function AttackAlerts() {
  const { lastIncidentEvent } = useLive();
  const a = useApi<Alerts>("/attacks/alerts", 10_000);
  const ev = lastIncidentEvent?.event;
  useEffect(() => {
    if (ev && ["suspected", "confirmed", "resolved", "false_positive", "escalated"].includes(ev)) a.reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastIncidentEvent]);
  const d = a.data;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <AlertBox kind="inbound" side={d?.inbound} hours={d?.hours ?? 24} loading={!d} />
      <AlertBox kind="outbound" side={d?.outbound} hours={d?.hours ?? 24} loading={!d} />
    </div>
  );
}

function AlertBox({ kind, side, hours, loading }: { kind: "inbound" | "outbound"; side?: Side; hours: number; loading: boolean }) {
  const inbound = kind === "inbound";
  const open = side?.open ?? [];
  const confirmed = open.filter((i) => i.status !== "suspected");
  const tone = confirmed.length ? (inbound ? "attack" : "warn") : open.length ? "warn" : "ok";
  const frame = confirmed.length ? (inbound ? "border-attack" : "border-warn") : "border-rule";
  const head = confirmed.length ? (inbound ? "bg-attack-soft" : "bg-warn-soft") : "bg-panel";
  return (
    <section className={`min-w-0 overflow-hidden rounded-[3px] border bg-panel ${frame}`} aria-live="polite">
      <header className={`flex items-center gap-3 border-b border-rule-soft px-4 py-3 ${head}`}>
        {inbound ? <ArrowDownToLine size={18} className={confirmed.length ? "text-attack" : "text-ink-2"} />
          : <ArrowUpFromLine size={18} className={confirmed.length ? "text-warn" : "text-ink-2"} />}
        <div className="min-w-0 flex-1">
          <h2 className="font-semibold">{inbound ? "Incoming attacks" : "Outgoing attacks"}</h2>
          <p className="text-xs text-ink-2">{inbound ? "Someone attacking your network: who and from where"
            : "One of your addresses attacking others: which IP and whom"}</p>
        </div>
        <Lamp tone={tone as any} label={loading ? "…" : confirmed.length
          ? <strong>{confirmed.length} {inbound ? "under attack" : "attacking"}</strong>
          : open.length ? `${open.length} suspected` : "None now"} />
      </header>
      {loading ? <p className="px-4 py-4 text-sm text-ink-2">Loading…</p> : (
        <div className="divide-y divide-rule-soft">
          {open.map((i) => <OpenRow key={i.id} i={i} inbound={inbound} />)}
          {!open.length && (
            <p className="px-4 py-3 text-sm text-ink-2">
              {inbound ? "No attack on your addresses right now." : "None of your addresses is sending attack traffic right now."}
            </p>
          )}
          <div className="bg-sunk/40 px-4 py-2.5">
            <div className="mb-1 text-xs font-medium text-ink-3">
              Last {hours} h: {side?.recent_count ?? 0} ended {inbound ? "attack" : "outgoing attack"}{side?.recent_count === 1 ? "" : "s"}
            </div>
            {(side?.recent ?? []).slice(0, 4).map((i) => (
              <Link key={i.id} to={`/attacks/${i.id}`} className="grid grid-cols-[auto_1fr_auto] items-baseline gap-x-3 py-0.5 text-[13px] hover:underline">
                <span className="text-ink-3">{dateTime(i.first_detected_at)}</span>
                <span className="truncate"><span className="font-medium">{ip(i.target)}</span>{" "}
                  <span className="text-ink-2">{vectorName(i.vectors[0] ?? "")}</span>
                  {i.peers?.networks?.[0]?.asn != null && <span className="text-ink-3"> · {inbound ? "from" : "to"} AS{i.peers.networks[0].asn} {short(i.peers.networks[0].as_name)}</span>}
                </span>
                <span className="text-ink-2">{pps(i.peak_pps)}</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function OpenRow({ i, inbound }: { i: AlertInc; inbound: boolean }) {
  const p = i.peers;
  return (
    <Link to={`/attacks/${i.id}`} className="block px-4 py-3 hover:bg-sunk/50">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Lamp tone={SEVERITY_TONE[i.severity]} label="" />
        <span className="font-mono text-[15px] font-semibold">{ip(i.target)}</span>
        {i.status === "suspected" ? <Badge tone="warn">Suspected</Badge> : <Badge tone={inbound ? "attack" : "warn"}>{inbound ? "Under attack" : "Attacking"}</Badge>}
        <span className="text-sm">{i.vectors.slice(0, 2).map(vectorName).join(", ")}</span>
        <span className="ml-auto text-sm text-ink-2">{pps(i.current?.pps ?? i.peak_pps)} · {bps(i.current?.bps ?? i.peak_bps)} · {since(i.first_detected_at)}</span>
      </div>
      <div className="mt-1 text-xs text-ink-3">
        {i.customer ? `${i.customer.customer_name ?? i.customer.customer_ref} (${i.customer.customer_ref})` : i.prefix ?? "No customer assigned"}
      </div>
      <div className="mt-1.5 text-[13px]">
        <span className="text-ink-2">{inbound ? "Attackers: " : "Sending to: "}</span>
        {p?.top?.length ? (
          <>
            {p.top.map((r, n) => (
              <span key={r.ip}>{n > 0 && ", "}<span className="font-mono">{r.ip}</span>
                {r.asn != null && <span className="text-ink-3"> AS{r.asn} {short(r.as_name)}</span>}
                {r.share != null && r.share >= 0.01 && <span className="text-ink-3"> {share(r.share)}</span>}</span>
            ))}
            {p.count > p.top.length && <span className="text-ink-3"> and {(p.count - p.top.length).toLocaleString()} more</span>}
            {inbound && (p.networks?.length ?? 0) > 0 && (
              <div className="text-ink-3">Main networks: {p.networks.map((x) => x.asn == null ? `${short(x.as_name)} ${share(x.share)}`
                : `AS${x.asn} ${short(x.as_name)} ${share(x.share)}`).join(" · ")}</div>
            )}
          </>
        ) : <span className="text-ink-3">being recorded (shown within 10–20 s while flow data arrives)</span>}
      </div>
    </Link>
  );
}

type Toast = { key: string; id: string; out: boolean; target: string; vectors: string[]; pps?: number; at: number };

/** Pop-up on every page when an attack is confirmed, on your network or from it. Stays for 2 minutes
 *  or until closed. */
export function AttackToasts() {
  const { lastIncidentEvent: m } = useLive();
  const [toasts, setToasts] = useState<Toast[]>([]);
  useEffect(() => {
    if (!m || m.event !== "confirmed") return;
    const inc = m.incident;
    const t: Toast = { key: `${inc.id}:${Date.now()}`, id: inc.id, out: inc.direction === "outbound", target: inc.target ?? "",
      vectors: inc.vectors ?? [], pps: inc.pps ?? inc.peak_pps ?? undefined, at: Date.now() };
    setToasts((cur) => [...cur.filter((x) => x.id !== t.id), t].slice(-4));
  }, [m]);
  useEffect(() => {
    if (!toasts.length) return;
    const timer = setInterval(() => setToasts((cur) => cur.filter((x) => Date.now() - x.at < 120_000)), 5000);
    return () => clearInterval(timer);
  }, [toasts.length]);
  if (!toasts.length) return null;
  return (
    <div className="fixed bottom-4 right-4 z-40 flex w-[min(420px,calc(100vw-2rem))] flex-col gap-2" role="alert">
      {toasts.map((t) => (
        <div key={t.key} className={`rounded-[3px] border px-4 py-3 shadow-lg ${t.out ? "border-warn bg-warn-soft text-warn" : "border-attack bg-attack-soft text-attack"}`}>
          <div className="flex items-start gap-2">
            {t.out ? <ArrowUpFromLine size={18} className="mt-0.5 shrink-0" /> : <ArrowDownToLine size={18} className="mt-0.5 shrink-0" />}
            <div className="min-w-0 flex-1">
              <div className="font-semibold">{t.out ? `Outgoing attack from your address ${ip(t.target)}` : `DDoS attack on ${ip(t.target)}`}</div>
              <div className="text-sm text-ink">{t.vectors.slice(0, 2).map(vectorName).join(", ") || "Traffic anomaly"}{t.pps ? `, ${pps(t.pps)}` : ""}</div>
              <Link to={`/attacks/${t.id}`} className="text-sm font-medium underline" onClick={() => setToasts((c) => c.filter((x) => x.key !== t.key))}>
                {t.out ? "See whom it is attacking" : "See who is attacking"}</Link>
            </div>
            <button aria-label="Close" className="text-ink-2 hover:text-ink" onClick={() => setToasts((c) => c.filter((x) => x.key !== t.key))}><X size={16} /></button>
          </div>
        </div>
      ))}
    </div>
  );
}
