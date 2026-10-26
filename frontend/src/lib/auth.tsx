import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, onAuthChange, refresh, setTokens, type Tokens } from "./api";

export type Me = {
  id: string; username: string; full_name: string | null; email: string | null; role: string;
  mfa_enabled: boolean; session_mfa_verified: boolean; permissions: string[];
};

type Ctx = {
  me: Me | null;
  ready: boolean;
  can: (perm: string) => boolean;
  login: (u: string, p: string, totp?: string) => Promise<"ok" | "mfa_required">;
  logout: () => Promise<void>;
  reloadMe: () => Promise<void>;
};

const AuthCtx = createContext<Ctx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  const reloadMe = useCallback(async () => {
    try { setMe(await api<Me>("/auth/me")); } catch { setMe(null); }
  }, []);

  useEffect(() => {
    (async () => {
      if (await refresh()) await reloadMe();
      setReady(true);
    })();
    return onAuthChange((signedIn) => { if (!signedIn) setMe(null); });
  }, [reloadMe]);

  const login = async (username: string, password: string, totp_code?: string) => {
    try {
      const t = await api<Tokens>("/auth/login", { method: "POST", body: { username, password, totp_code } });
      setTokens(t);
      await reloadMe();
      return "ok" as const;
    } catch (e) {
      if (e instanceof ApiError && e.detail === "mfa_required") return "mfa_required" as const;
      throw e;
    }
  };

  const logout = async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch { /* already gone */ }
    setTokens(null);
  };

  const can = (p: string) => !!me?.permissions.includes(p);
  return <AuthCtx.Provider value={{ me, ready, can, login, logout, reloadMe }}>{children}</AuthCtx.Provider>;
}

export function useAuth() {
  const c = useContext(AuthCtx);
  if (!c) throw new Error("useAuth outside provider");
  return c;
}
