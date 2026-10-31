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
import { ActiveAttacks, AttackDetail, AttackHistory } from "./pages/Attacks";
import { Roadmap } from "./pages/Roadmap";
import { AlertsPage } from "./pages/Alerts";
import { ReadinessPage, ReportsPage } from "./pages/Reports";
import { LiveProvider } from "./lib/live";
import { RouterDetail, Topology } from "./pages/Routers";
import { ActionDetail, BlackholeRoutes, MitigationCenter, Policies } from "./pages/Mitigation";

function App() {
  const { me, ready } = useAuth();
  if (!ready) return <div className="grid h-full place-items-center text-ink-2">Loading…</div>;
  if (!me) return <Login />;
  return (
    <Routes>
      <Route element={<LiveProvider><Shell /></LiveProvider>}>
        <Route index element={<Overview />} />
        <Route path="traffic" element={<LiveTraffic />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="attacks" element={<ActiveAttacks />} />
        <Route path="attacks/:id" element={<AttackDetail />} />
        <Route path="history" element={<AttackHistory />} />
        <Route path="mitigation" element={<MitigationCenter />} />
        <Route path="mitigation/policies" element={<Policies />} />
        <Route path="mitigation/:id" element={<ActionDetail />} />
        <Route path="rtbh" element={<BlackholeRoutes />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="readiness" element={<ReadinessPage />} />
        <Route path="topology" element={<Topology />} />
        <Route path="prefixes" element={<Prefixes />} />
        <Route path="customers" element={<Customers />} />
        <Route path="routers" element={<Routers />} />
        <Route path="routers/:id" element={<RouterDetail />} />
        <Route path="bgp" element={<Bgp />} />
        <Route path="users" element={<Users />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="health" element={<HealthPage />} />
        <Route path="roadmap" element={<Roadmap />} />
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
