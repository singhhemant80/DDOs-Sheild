// API client. Access token lives in memory only; the rotating refresh token is kept in
// sessionStorage so a reload keeps you signed in but closing the tab signs you out.

export type Tokens = { access_token: string; refresh_token: string; expires_in: number; mfa_verified: boolean };

const RT_KEY = "shield-rt";
let access: string | null = null;
let refreshing: Promise<boolean> | null = null;
const listeners = new Set<(signedIn: boolean) => void>();

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(typeof detail === "string" ? detail : describe(detail));
  }
}

function describe(d: unknown): string {
  if (Array.isArray(d)) return d.map((e: any) => `${(e.loc ?? []).slice(1).join(".")}: ${e.msg}`).join("; ");
  if (d && typeof d === "object") {
    return Object.entries(d as Record<string, unknown>)
      .map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(", ") : String(v)}`).join("; ");
  }
  return "Request failed";
}

function readRT(): string | null {
  try { return sessionStorage.getItem(RT_KEY); } catch { return null; }
}
function writeRT(v: string | null) {
  try { v ? sessionStorage.setItem(RT_KEY, v) : sessionStorage.removeItem(RT_KEY); } catch { /* private mode */ }
}

export function onAuthChange(f: (signedIn: boolean) => void) {
  listeners.add(f);
  return () => { listeners.delete(f); };
}

export function setTokens(t: Tokens | null) {
  access = t?.access_token ?? null;
  writeRT(t?.refresh_token ?? null);
  listeners.forEach((f) => f(!!t));
}

export function accessToken() { return access; }

export async function refresh(): Promise<boolean> {
  const rt = readRT();
  if (!rt) return false;
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const r = await fetch("/api/v1/auth/refresh", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: rt }),
        });
        if (!r.ok) { setTokens(null); return false; }
        setTokens(await r.json());
        return true;
      } catch {
        return false;
      } finally {
        setTimeout(() => (refreshing = null), 0);
      }
    })();
  }
  return refreshing;
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<T> {
  const go = () =>
    fetch(`/api/v1${path}`, {
      method: opts.method ?? "GET",
      headers: {
        ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(access ? { Authorization: `Bearer ${access}` } : {}),
        ...(opts.headers ?? {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  let r = await go();
  if (r.status === 401 && !path.startsWith("/auth/login") && (await refresh())) r = await go();
  if (r.status === 204) return undefined as T;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && !path.startsWith("/auth/")) setTokens(null);
    throw new ApiError(r.status, (data as any).detail ?? r.statusText);
  }
  return data as T;
}

// Refresh shortly before the access token expires.
setInterval(() => { if (access) void refresh(); }, 12 * 60 * 1000);
