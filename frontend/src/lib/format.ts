const UNITS = ["", "k", "M", "G", "T"];

function scaled(v: number, base = 1000): [string, string] {
  if (!isFinite(v)) return ["–", ""];
  let i = 0;
  let x = Math.abs(v);
  while (x >= base && i < UNITS.length - 1) { x /= base; i++; }
  const digits = x >= 100 || i === 0 ? 0 : x >= 10 ? 1 : 2;
  return [`${v < 0 ? "-" : ""}${x.toFixed(digits)}`, UNITS[i]];
}

export const pps = (v: number | null | undefined) => {
  if (v == null) return "–";
  const [n, u] = scaled(v);
  return `${n} ${u}pps`;
};
export const bps = (v: number | null | undefined) => {
  if (v == null) return "–";
  const [n, u] = scaled(v);
  return `${n} ${u}b/s`;
};
export const count = (v: number | null | undefined) => {
  if (v == null) return "–";
  const [n, u] = scaled(v);
  return `${n}${u}`;
};
export const pct = (v: number) => `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`;

export function ago(unix: number | null | undefined) {
  if (!unix) return "never";
  const s = Math.max(0, Math.round(Date.now() / 1000 - unix));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export const dateTime = (iso: string | number) =>
  new Date(typeof iso === "number" ? iso * 1000 : iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });

export const PROTO_PORTS: Record<string, string> = {
  "53": "DNS", "123": "NTP", "1900": "SSDP", "389": "CLDAP", "11211": "Memcached", "19": "Chargen",
  "161": "SNMP", "3702": "WS-Discovery", "5683": "CoAP", "3283": "ARD", "111": "Portmap", "137": "NetBIOS",
};
