import { useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApi } from "../lib/hooks";
import { bps, pps } from "../lib/format";
import { Badge, Button, Check, Dialog, ErrorLine, Field, Input, Section, Table } from "../components/ui";

type Profile = {
  id: number; name: string; scope: string; enabled: boolean; is_default: boolean;
  dst_pps: number | null; dst_bps: number | null; syn_pps: number | null; tcp_flag_pps: number | null;
  udp_pps: number | null; icmp_pps: number | null; reflect_pps: number | null; frag_pps: number | null;
  prefix_pps: number | null; prefix_bps: number | null; baseline_factor: number; anomaly_min_pps: number;
  suspect_hits: number; suspect_window: number; confirm_seconds: number; confirm_confidence: number;
  release_seconds: number; suspect_timeout_seconds: number; notes: string | null;
};

const RATE_FIELDS: [keyof Profile, string, "pps" | "bps"][] = [
  ["dst_pps", "Packets per second to one address", "pps"],
  ["dst_bps", "Bits per second to one address", "bps"],
  ["udp_pps", "UDP packets per second", "pps"],
  ["syn_pps", "SYN-only TCP packets per second", "pps"],
  ["tcp_flag_pps", "ACK-only or RST packets per second", "pps"],
  ["icmp_pps", "ICMP packets per second", "pps"],
  ["reflect_pps", "Packets per second from one reflection port (DNS, NTP...)", "pps"],
  ["frag_pps", "Fragmented packets per second", "pps"],
  ["prefix_pps", "Packets per second to the whole prefix", "pps"],
  ["prefix_bps", "Bits per second to the whole prefix", "bps"],
];

export function DetectionProfiles() {
  const { can } = useAuth();
  const list = useApi<Profile[]>("/detection/profiles");
  const [edit, setEdit] = useState<Profile | "new" | null>(null);
  const editable = can("config_policy");
  return (
    <Section title="Detection thresholds"
      aside={editable ? <Button variant="quiet" onClick={() => setEdit("new")}><Plus size={16} /> Add rules for a range</Button> : "Read-only for your role"} flush>
      <div className="px-4 pt-3 text-sm text-ink-2">
        The most specific matching range wins. A customer's own packet and bit thresholds (Customer IPs) override both.
        A blank threshold turns that check off.
      </div>
      <Table rows={list.data ?? []} rowKey={(p) => String(p.id)} onRow={editable ? setEdit : undefined}
        cols={[
          { key: "n", header: "Applies to", render: (p) => <><div className="font-medium">{p.name} {p.is_default && <Badge>Default</Badge>}{!p.enabled && <Badge tone="warn">Off</Badge>}</div><div className="text-xs text-ink-3">{p.scope === "0.0.0.0/0" ? "All IPv4" : p.scope === "::/0" ? "All IPv6" : p.scope}</div></> },
          { key: "a", header: "Per address", render: (p) => <>{p.dst_pps ? pps(p.dst_pps) : "off"}<div className="text-xs text-ink-3">{p.dst_bps ? bps(p.dst_bps) : "bandwidth check off"}</div></> },
          { key: "v", header: "Attack signatures", render: (p) => <span className="text-ink-2">SYN {fmt(p.syn_pps)}, UDP {fmt(p.udp_pps)}, reflection {fmt(p.reflect_pps)}</span> },
          { key: "p", header: "Whole prefix", render: (p) => fmt(p.prefix_pps) },
          { key: "t", header: "Confirms after", render: (p) => `${p.confirm_seconds} s at ${Math.round(p.confirm_confidence * 100)}%` },
        ]} />
      {edit && <ProfileDialog p={edit === "new" ? null : edit} base={list.data?.[0]} onClose={() => setEdit(null)} onSaved={list.reload} />}
    </Section>
  );
}

const fmt = (v: number | null) => (v ? pps(v) : "off");

function ProfileDialog({ p, base, onClose, onSaved }: { p: Profile | null; base?: Profile; onClose: () => void; onSaved: () => void }) {
  const seed = p ?? (base ? { ...base, id: 0, name: "", scope: "", is_default: false, notes: null } : null);
  const [f, setF] = useState<Record<string, string | boolean>>(() => {
    const o: Record<string, string | boolean> = {};
    if (!seed) return o;
    for (const [k, v] of Object.entries(seed)) o[k] = typeof v === "boolean" ? v : v == null ? "" : String(v);
    return o;
  });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: string | boolean) => setF((x) => ({ ...x, [k]: v }));
  const num = (k: string) => (f[k] === "" ? null : Number(f[k]));
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    const body: Record<string, unknown> = { name: f.name, scope: f.scope, enabled: f.enabled, notes: f.notes || null };
    for (const [k] of RATE_FIELDS) body[k] = num(k as string);
    for (const k of ["baseline_factor", "anomaly_min_pps", "suspect_hits", "suspect_window", "confirm_seconds",
      "confirm_confidence", "release_seconds", "suspect_timeout_seconds"]) body[k] = Number(f[k]);
    try {
      if (p) await api(`/detection/profiles/${p.id}`, { method: "PUT", body });
      else await api("/detection/profiles", { method: "POST", body });
      onSaved(); onClose();
    } catch (e: any) { setErr(e.message); }
  };
  const remove = async () => {
    try { await api(`/detection/profiles/${p!.id}`, { method: "DELETE" }); onSaved(); onClose(); } catch (e: any) { setErr(e.message); }
  };
  const field = (k: string, label: string, hint?: string) => (
    <Field label={label} hint={hint}><Input inputMode="decimal" value={String(f[k] ?? "")} onChange={(e) => set(k, e.target.value.replace(/[^\d.]/g, ""))} /></Field>
  );
  return (
    <Dialog open title={p ? `Detection rules: ${p.name}` : "Add detection rules for a range"} onClose={onClose}
      footer={<>
        {p && !p.is_default && <Button variant="quiet" className="mr-auto text-attack" onClick={remove}>Delete</Button>}
        <Button type="button" variant="quiet" onClick={onClose}>Cancel</Button>
        <Button variant="primary" form="prof">Save rules</Button>
      </>}>
      <form id="prof" onSubmit={save} className="max-h-[65vh] space-y-5 overflow-y-auto pr-1">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name"><Input required value={String(f.name ?? "")} onChange={(e) => set("name", e.target.value)} /></Field>
          <Field label="Range" hint={p?.is_default ? "Default ranges cannot change" : "e.g. 163.5.191.0/24"}>
            <Input required disabled={p?.is_default} value={String(f.scope ?? "")} onChange={(e) => set("scope", e.target.value)} /></Field>
        </div>
        {!p?.is_default && <Check label="Use these rules" checked={!!f.enabled} onChange={(v) => set("enabled", v)} />}
        <fieldset className="grid gap-4 border-t border-rule-soft pt-3 sm:grid-cols-2">
          <legend className="text-sm font-medium">Thresholds (blank turns a check off)</legend>
          {RATE_FIELDS.map(([k, label, unit]) => field(k as string, label, unit === "bps" ? "bits per second, e.g. 1000000000 = 1 Gb/s" : undefined))}
        </fieldset>
        <fieldset className="grid gap-4 border-t border-rule-soft pt-3 sm:grid-cols-2">
          <legend className="text-sm font-medium">Decision rules</legend>
          {field("suspect_hits", "Suspect after this many seconds over threshold", `out of the last ${f.suspect_window || "N"} seconds`)}
          {field("suspect_window", "...within this many seconds")}
          {field("confirm_seconds", "Confirm after this many seconds", "80% of them must be over threshold")}
          {field("confirm_confidence", "Minimum confidence to confirm", "0 to 1, default 0.7")}
          {field("release_seconds", "End after this many quiet seconds")}
          {field("suspect_timeout_seconds", "Drop a suspicion after this many quiet seconds")}
          {field("baseline_factor", "Unusual if this many times above normal", "for the learned hour-of-week baseline")}
          {field("anomaly_min_pps", "...and at least this many packets per second")}
        </fieldset>
        <ErrorLine error={err} />
      </form>
    </Dialog>
  );
}
