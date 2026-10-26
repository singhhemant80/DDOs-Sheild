import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import { AuthProvider, useAuth } from "./lib/auth";
import { Shell } from "./components/Shell";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Analytics, LiveTraffic } from "./pages/Traffic";
import { Bgp, Customers, Prefixes, Routers } from "./pages/Network";
import { AuditLog, HealthPage, SettingsPage, Upcoming, Users } from "./pages/Admin";

function App() {
  const { me, ready } = useAuth();
  if (!ready) return <div className="grid h-full place-items-center text-ink-2">Loading…</div>;
  if (!me) return <Login />;
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Overview />} />
        <Route path="traffic" element={<LiveTraffic />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="attacks" element={<Upcoming title="Active attacks" phase={4}>
          <p>The detection engine will list attacks here as they happen: target, attack type, confidence, rate, start time and mitigation status.</p>
          <p className="text-ink-2">It will separate suspected from confirmed attacks and learn per-destination baselines, so a busy but normal hour doesn't raise an alarm.</p>
        </Upcoming>} />
        <Route path="history" element={<Upcoming title="Attack history" phase={4}>
          <p>Every past incident with its evidence, timeline and the actions taken, searchable by target and customer.</p>
        </Upcoming>} />
        <Route path="mitigation" element={<Upcoming title="Mitigation center" phase={6}>
          <p>Proposed actions with a preview of exactly what changes and who is affected, approve and reject controls, and live verification of each action.</p>
          <p className="text-ink-2">Runs in simulation first; real announcements start in phase 8.</p>
        </Upcoming>} />
        <Route path="rtbh" element={<Upcoming title="Blackhole routes" phase={6}>
          <p>Announced blackhole routes per upstream, when each was verified, and withdrawal with hold-time and flap protection.</p>
          <p className="text-ink-2">Upstream blackhole policies can already be recorded and verified under Routers & upstreams.</p>
        </Upcoming>} />
        <Route path="alerts" element={<Upcoming title="Alerts" phase={10}>
          <p>Email, Telegram and webhook notifications for attacks, mitigation changes, BGP session loss and saturated links, with de-duplication and escalation.</p>
        </Upcoming>} />
        <Route path="topology" element={<Upcoming title="Topology" phase={5}>
          <p>A live map of edge routers, upstream links and BGP sessions, built from what the routers report once Shield can read them.</p>
        </Upcoming>} />
        <Route path="prefixes" element={<Prefixes />} />
        <Route path="customers" element={<Customers />} />
        <Route path="routers" element={<Routers />} />
        <Route path="bgp" element={<Bgp />} />
        <Route path="users" element={<Users />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="health" element={<HealthPage />} />
        <Route path="*" element={<Upcoming title="Page not found" phase={0}><p>There is no page at this address.</p></Upcoming>} />
      </Route>
    </Routes>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
