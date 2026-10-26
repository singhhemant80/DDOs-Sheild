import { useState, type ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Activity, BarChart3, Bell, Cable, ClipboardList, Gauge, HeartPulse, History, LogOut, Menu, Moon, Network,
  OctagonX, Router as RouterIcon, Settings, ShieldAlert, ShieldBan, Sun, Swords, Users, Waypoints, Globe2,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { useApi } from "../lib/hooks";
import { useLive } from "../lib/live";
import { ago } from "../lib/format";
import { Button, Dialog, Lamp, Notice } from "./ui";

type Item = { to: string; label: string; icon: ReactNode; phase?: number };

// 17 pages, grouped by what the operator is doing. Items with `phase` arrive later.
export const NAV: { group: string; items: Item[] }[] = [
  { group: "Monitor", items: [
    { to: "/", label: "Overview", icon: <Gauge size={17} /> },
    { to: "/traffic", label: "Live traffic", icon: <Activity size={17} /> },
    { to: "/analytics", label: "Traffic analytics", icon: <BarChart3 size={17} /> },
    { to: "/attacks", label: "Active attacks", icon: <ShieldAlert size={17} /> },
    { to: "/history", label: "Attack history", icon: <History size={17} /> },
  ] },
  { group: "Mitigate", items: [
    { to: "/mitigation", label: "Mitigation center", icon: <Swords size={17} />, phase: 6 },
    { to: "/rtbh", label: "Blackhole routes", icon: <ShieldBan size={17} />, phase: 6 },
    { to: "/alerts", label: "Alerts", icon: <Bell size={17} />, phase: 10 },
  ] },
  { group: "Network", items: [
    { to: "/prefixes", label: "Protected prefixes", icon: <Globe2 size={17} /> },
    { to: "/customers", label: "Customer IPs", icon: <Cable size={17} /> },
    { to: "/routers", label: "Routers & upstreams", icon: <RouterIcon size={17} /> },
    { to: "/bgp", label: "BGP sessions", icon: <Waypoints size={17} /> },
    { to: "/topology", label: "Topology", icon: <Network size={17} />, phase: 5 },
  ] },
  { group: "Admin", items: [
    { to: "/users", label: "Users & roles", icon: <Users size={17} /> },
    { to: "/settings", label: "Settings", icon: <Settings size={17} /> },
    { to: "/audit", label: "Audit log", icon: <ClipboardList size={17} /> },
    { to: "/health", label: "System health", icon: <HeartPulse size={17} /> },
  ] },
];

function ThemeToggle() {
  const [, force] = useState(0);
  const cur = document.documentElement.dataset.theme
    ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  return (
    <Button variant="quiet" aria-label={`Switch to ${next} theme`} onClick={() => {
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("shield-theme", next); } catch { /* ignore */ }
      force((n) => n + 1);
    }}>
      {cur === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </Button>
  );
}

type Details = {
  automation_enabled: boolean; rtbh_emergency_disable: boolean;
  components: Record<string, string>;
};

function StatusStrip() {
  const { me, can, logout } = useAuth();
  const { data, reload } = useApi<Details>("/health/details", 10_000);
  const coll = useApi<{ running: boolean; exporters?: { last_seen: number; stale: boolean }[] }>("/collector/status", 10_000);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const c = data?.components ?? {};
  const collTone = c.collector === "up" ? "ok" : c.collector === "degraded" ? "warn" : "attack";
  const lastSeen = Math.max(0, ...(coll.data?.exporters ?? []).map((e) => e.last_seen));
  const stopped = data && !data.automation_enabled && data.rtbh_emergency_disable;

  const stop = async () => {
    setBusy(true);
    try {
      await api("/system/emergency-stop", { method: "POST" });
      setConfirm(false);
      await reload();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  const { incidents } = useLive();
  const confirmed = incidents.filter((i) => i.status !== "suspected").length;
  const suspected = incidents.length - confirmed;
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-rule bg-panel px-5 py-2 text-sm">
      <NavLink to="/attacks" className="hover:underline">
        <Lamp tone={confirmed ? "attack" : suspected ? "warn" : "ok"} label={
          confirmed ? <strong className="text-attack">{confirmed} attack{confirmed === 1 ? "" : "s"} under way{suspected ? `, ${suspected} suspected` : ""}</strong>
            : suspected ? <>{suspected} suspected, none confirmed</> : "No attacks"} />
      </NavLink>
      <Lamp tone={collTone as any} label={
        <>Flow collector {c.collector === "up" ? `receiving (${ago(lastSeen)})` : c.collector === "degraded" ? "running, no exporters sending" : "not running"}</>
      } />
      <Lamp tone={c.redis === "up" ? "ok" : "attack"} label={c.redis === "up" ? "Live feed" : "Live feed down"} />
      <Lamp tone={data?.automation_enabled ? "signal" : "neutral"}
        label={data?.automation_enabled ? "Automatic mitigation on" : "Automatic mitigation off"} />
      {data?.rtbh_emergency_disable && <Lamp tone="warn" label="New blackholes blocked" />}
      <div className="ml-auto flex items-center gap-2">
        {can("automation_stop") && (
          <Button variant="danger" onClick={() => setConfirm(true)} disabled={!!stopped}
            title={stopped ? "Already stopped" : "Stop all automatic mitigation and block new blackhole routes"}>
            <OctagonX size={16} /> {stopped ? "Stopped" : "Emergency stop"}
          </Button>
        )}
        <ThemeToggle />
        <span className="hidden text-ink-2 sm:inline">{me?.username}</span>
        <Button variant="quiet" onClick={logout} aria-label="Sign out"><LogOut size={16} /></Button>
      </div>
      <Dialog open={confirm} title="Stop automatic mitigation?" onClose={() => setConfirm(false)}
        footer={<>
          <Button variant="quiet" onClick={() => setConfirm(false)}>Cancel</Button>
          <Button variant="danger" onClick={stop} disabled={busy}><OctagonX size={16} /> Stop automation</Button>
        </>}>
        <p>Shield will stop taking any automatic action and will refuse new blackhole announcements.</p>
        <p className="text-ink-2">Routes that are already announced stay in place: withdrawing them in the middle of an
          attack could expose the network again. Withdraw them individually once traffic is under control.</p>
        <p className="text-ink-2">Only a network engineer or administrator can turn automation back on.</p>
        {err && <Notice tone="attack">{err}</Notice>}
      </Dialog>
    </div>
  );
}

export function Shell() {
  const [open, setOpen] = useState(false);
  const { incidents } = useLive();
  const confirmed = incidents.filter((i) => i.status !== "suspected").length;
  return (
    <div className="flex min-h-full">
      <nav aria-label="Main"
        className={`${open ? "block" : "hidden"} fixed inset-y-0 left-0 z-30 w-60 overflow-y-auto border-r border-rule bg-sunk md:sticky md:top-0 md:block md:h-screen`}>
        <div className="flex items-center gap-2 px-4 pb-3 pt-4">
          <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
            <path d="M16 3 5 7v8c0 7 5 12 11 14 6-2 11-7 11-14V7z" fill="var(--signal)" />
            <path d="M9 17h4l2-5 3 9 2-4h3" stroke="var(--panel)" strokeWidth="2" fill="none" />
          </svg>
          <div className="leading-tight">
            <div className="wide font-semibold">Crapplet Shield</div>
            <div className="text-xs text-ink-3">DDoS mitigation</div>
          </div>
        </div>
        {NAV.map((g) => (
          <div key={g.group} className="mt-3">
            <div className="px-4 pb-1 text-xs font-medium text-ink-3">{g.group}</div>
            <ul>
              {g.items.map((it) => (
                <li key={it.to}>
                  <NavLink to={it.to} end={it.to === "/"} onClick={() => setOpen(false)}
                    className={({ isActive }) =>
                      `mx-2 flex items-center gap-2.5 rounded-[3px] px-2.5 py-1.5 text-[14.5px] ${
                        isActive ? "bg-panel font-medium text-ink shadow-[inset_3px_0_0_var(--signal)]" : "text-ink-2 hover:text-ink"}`}>
                    {it.icon}
                    <span className="flex-1">{it.label}</span>
                    {it.phase && <span className="text-[11px] text-ink-3" title={`Arrives in phase ${it.phase}`}>P{it.phase}</span>}
                    {it.to === "/attacks" && incidents.length > 0 && (
                      <span className={`min-w-5 rounded-full px-1.5 text-center text-xs font-semibold text-white ${confirmed ? "bg-attack" : "bg-warn"}`}
                        aria-label={`${incidents.length} open`}>{incidents.length}</span>)}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      {open && <div className="fixed inset-0 z-20 bg-black/30 md:hidden" onClick={() => setOpen(false)} />}
      <div className="min-w-0 flex-1">
        <div className="sticky top-0 z-10">
          <div className="flex items-center border-b border-rule bg-panel px-3 py-1 md:hidden">
            <Button variant="quiet" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={18} /></Button>
            <span className="wide font-semibold">Crapplet Shield</span>
          </div>
          <StatusStrip />
        </div>
        <main className="mx-auto max-w-[1440px] px-5 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
