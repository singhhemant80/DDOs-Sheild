import { useState, type FormEvent } from "react";
import { useAuth } from "../lib/auth";
import { Button, Field, Input, Notice } from "../components/ui";

export function Login() {
  const { login } = useAuth();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await login(u, p, needCode ? code : undefined);
      if (r === "mfa_required") setNeedCode(true);
    } catch (e: any) {
      setErr(e.status === 429 ? "Too many attempts. Wait a minute and try again."
        : needCode ? "That code didn't match. Check your authenticator app's clock and try again."
        : "Wrong username or password, or the account is locked.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-full place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-[380px] space-y-5">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="size-10" aria-hidden>
            <path d="M16 3 5 7v8c0 7 5 12 11 14 6-2 11-7 11-14V7z" fill="var(--signal)" />
            <path d="M9 17h4l2-5 3 9 2-4h3" stroke="var(--paper)" strokeWidth="2" fill="none" />
          </svg>
          <div>
            <h1 className="wide text-2xl font-semibold leading-tight">Crapplet Shield</h1>
            <p className="text-sm text-ink-2">Sign in to the operations console</p>
          </div>
        </div>
        {!needCode ? (
          <>
            <Field label="Username">
              <Input autoFocus autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} required />
            </Field>
            <Field label="Password">
              <Input type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} required />
            </Field>
          </>
        ) : (
          <Field label="Authentication code" hint="The 6-digit code from your authenticator app.">
            <Input autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6}
              value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} required />
          </Field>
        )}
        {err && <Notice tone="attack">{err}</Notice>}
        <Button variant="primary" className="w-full justify-center" disabled={busy}>
          {needCode ? "Verify and sign in" : "Sign in"}
        </Button>
        <p className="text-xs text-ink-3">Access is restricted to the management network. All sign-ins are logged.</p>
      </form>
    </div>
  );
}
