import { useEffect, useRef, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4 pb-5">
      <div className="max-w-[68ch]">
        <h1 className="wide text-[26px] font-semibold leading-tight tracking-[-0.01em]">{title}</h1>
        {description && <p className="mt-1 text-ink-2">{description}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </header>
  );
}

/** A titled region. Flat, ruled - no shadows, so dense pages stay calm. */
export function Section({ title, aside, children, className = "", flush = false }:
  { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`min-w-0 rounded-[3px] border border-rule bg-panel ${className}`}>
      {(title || aside) && (
        <div className="flex items-center justify-between gap-3 border-b border-rule-soft px-4 py-2.5">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          {aside && <div className="text-sm text-ink-2">{aside}</div>}
        </div>
      )}
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "quiet" | "danger" | "outline" };
export function Button({ variant = "outline", className = "", ...p }: BtnProps) {
  const v = {
    primary: "bg-ink text-paper hover:opacity-90",
    outline: "border border-rule bg-panel hover:bg-sunk",
    quiet: "text-ink-2 hover:text-ink hover:bg-sunk",
    danger: "bg-attack text-white hover:opacity-90",
  }[variant];
  return (
    <button
      {...p}
      className={`inline-flex h-9 items-center gap-2 rounded-[3px] px-3.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${v} ${className}`}
    />
  );
}

export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium">{label}</span>
      {children}
      {hint && !error && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
      {error && <span className="mt-1 block text-xs text-attack">{error}</span>}
    </label>
  );
}

export function Input(p: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...p}
      className={`h-9 w-full rounded-[3px] border border-rule bg-panel px-2.5 text-[15px] placeholder:text-ink-3 ${p.className ?? ""}`}
    />
  );
}

export function Select({ value, onChange, options, ...rest }:
  { value: string; onChange: (v: string) => void; options: [string, string][]; "aria-label"?: string; disabled?: boolean }) {
  return (
    <select {...rest} value={value} onChange={(e) => onChange(e.target.value)}
      className="h-9 rounded-[3px] border border-rule bg-panel px-2 text-[15px] disabled:opacity-60">
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}

export function Check({ label, checked, onChange, disabled }:
  { label: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label className={`flex items-start gap-2 text-sm ${disabled ? "opacity-50" : ""}`}>
      <input type="checkbox" className="mt-0.5 size-4 accent-[var(--signal)]" checked={checked} disabled={disabled}
        onChange={(e) => onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

type Tone = "ok" | "warn" | "attack" | "neutral" | "signal";
const toneCls: Record<Tone, string> = {
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  attack: "bg-attack-soft text-attack",
  neutral: "bg-sunk text-ink-2",
  signal: "bg-signal-soft text-signal",
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded-[2px] px-1.5 py-px text-xs font-medium ${toneCls[tone]}`}>{children}</span>;
}

/** Status lamp: a filled dot reads faster than a word on a wall display. */
export function Lamp({ tone, label }: { tone: Tone; label: ReactNode }) {
  const c = { ok: "bg-ok", warn: "bg-warn", attack: "bg-attack", neutral: "bg-ink-3", signal: "bg-signal" }[tone];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`size-2 rounded-full ${c}`} aria-hidden />
      <span>{label}</span>
    </span>
  );
}

export function Notice({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  const border = { ok: "border-ok", warn: "border-warn", attack: "border-attack", neutral: "border-rule", signal: "border-signal" }[tone];
  return <div role={tone === "attack" ? "alert" : "status"} className={`border-l-[3px] ${border} bg-panel px-3 py-2 text-sm`}>{children}</div>;
}

export type Col<T> = { key: string; header: ReactNode; render: (row: T) => ReactNode; align?: "right" | "left"; className?: string };

export function Table<T>({ cols, rows, rowKey, empty, onRow, dense }:
  { cols: Col<T>[]; rows: T[]; rowKey: (r: T) => string; empty?: ReactNode; onRow?: (r: T) => void; dense?: boolean }) {
  if (!rows.length) return <div className="hatch px-4 py-8 text-center text-ink-2">{empty ?? "Nothing here yet."}</div>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-rule text-left text-ink-2">
            {cols.map((c) => (
              <th key={c.key} scope="col" className={`whitespace-nowrap px-4 py-2 font-medium ${c.align === "right" ? "text-right" : ""}`}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)} onClick={onRow ? () => onRow(r) : undefined}
              className={`border-b border-rule-soft last:border-0 ${onRow ? "cursor-pointer hover:bg-sunk" : ""}`}>
              {cols.map((c) => (
                <td key={c.key} className={`px-4 ${dense ? "py-1.5" : "py-2.5"} align-top ${c.align === "right" ? "text-right" : ""} ${c.className ?? ""}`}>
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Dialog({ open, title, onClose, children, footer }:
  { open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} onClose={onClose}
      className="m-auto w-[min(560px,calc(100vw-32px))] rounded-[3px] border border-rule bg-panel p-0 text-ink backdrop:bg-black/40">
      <div className="border-b border-rule-soft px-5 py-3"><h2 className="text-lg font-semibold">{title}</h2></div>
      <div className="space-y-4 px-5 py-4">{children}</div>
      {footer && <div className="flex justify-end gap-2 border-t border-rule-soft px-5 py-3">{footer}</div>}
    </dialog>
  );
}

export function ErrorLine({ error }: { error: string | null }) {
  if (!error) return null;
  return <Notice tone="attack">{error}</Notice>;
}
