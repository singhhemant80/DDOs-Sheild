import { Link } from "react-router-dom";
import { CircleCheck, CircleDashed, CircleDot, TriangleAlert } from "lucide-react";
import { useApi } from "../lib/hooks";
import { Badge, ErrorLine, PageHeader, Section } from "../components/ui";

export type Phase = {
  n: number; title: string; scope: string; exit: string; release: string | null;
  status: "done" | "next" | "pending"; verify: string[]; blocked: string | null;
};
type Item = { key: string; title: string; done: boolean; hint: string | null; link: string; phase: number };
export type RoadmapData = { version: string; current: number; total: number; phases: Phase[]; checklist: Item[] };

const WORD = { done: "Done", next: "Next", pending: "Pending" } as const;
const TONE = { done: "ok", next: "signal", pending: "neutral" } as const;

/** Ten segments, filled for built phases; the next one outlined. */
export function PhaseBar({ phases, size = "md" }: { phases: Phase[]; size?: "sm" | "md" }) {
  const h = size === "sm" ? "h-1.5" : "h-2.5";
  return (
    <div className="flex gap-1" role="img" aria-label={`${phases.filter((p) => p.status === "done").length} of ${phases.length} phases done`}>
      {phases.map((p) => (
        <span key={p.n} title={`Phase ${p.n}: ${p.title} (${WORD[p.status]})`}
          className={`${h} flex-1 rounded-[2px] ${p.status === "done" ? "bg-ok" : p.status === "next" ? "border border-signal bg-signal-soft" : "bg-rule"}`} />
      ))}
    </div>
  );
}

export function Roadmap() {
  const { data, error } = useApi<RoadmapData>("/system/roadmap", 30_000);
  const phases = data?.phases ?? [];
  const done = phases.filter((p) => p.status === "done").length;
  const next = phases.find((p) => p.status === "next");
  const open = (data?.checklist ?? []).filter((c) => !c.done);
  const verify = phases.flatMap((p) => p.verify.map((v) => ({ n: p.n, v })));
  return (
    <div className="space-y-5">
      <PageHeader title="Roadmap"
        description="What is built, what comes next, and what is still to set up on this installation." />
      <ErrorLine error={error} />
      {data && (
        <Section>
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <div className="text-[17px]"><strong>{done} of {data.total}</strong> phases done
              <span className="text-ink-2"> · release v{data.version.replace(/^v/, "")}</span></div>
            {next && <div className="text-sm">Next: <strong>Phase {next.n}</strong>, {next.title}</div>}
          </div>
          <div className="mt-3"><PhaseBar phases={phases} /></div>
          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-2">
            <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-[2px] bg-ok" /> Done</span>
            <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-[2px] border border-signal bg-signal-soft" /> Next</span>
            <span className="inline-flex items-center gap-1.5"><span className="size-2.5 rounded-[2px] bg-rule" /> Pending</span>
          </div>
        </Section>
      )}

      <div className="grid gap-5 lg:grid-cols-[1fr_380px]">
        <Section title="Phases" flush>
          <ol>
            {phases.map((p) => (
              <li key={p.n} className={`flex gap-3 border-b border-rule-soft px-4 py-3 last:border-0 ${p.status === "next" ? "bg-sunk" : ""}`}>
                <span className="mt-0.5 shrink-0">
                  {p.status === "done" ? <CircleCheck size={18} className="text-ok" />
                    : p.status === "next" ? <CircleDot size={18} className="text-signal" /> : <CircleDashed size={18} className="text-ink-3" />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">Phase {p.n}. {p.title}</span>
                    <Badge tone={TONE[p.status]}>{WORD[p.status]}</Badge>
                    {p.release && <span className="text-xs text-ink-3">v{p.release}</span>}
                  </div>
                  <p className={`mt-0.5 text-sm ${p.status === "pending" ? "text-ink-3" : "text-ink-2"}`}>{p.scope}</p>
                  <p className="mt-0.5 text-xs text-ink-3">Exit criteria: {p.exit}</p>
                  {p.verify.map((v) => (
                    <p key={v} className="mt-1 inline-flex items-start gap-1.5 text-xs text-warn"><TriangleAlert size={13} className="mt-px shrink-0" /> Still to verify: {v}</p>
                  ))}
                  {p.blocked && <p className="mt-1 inline-flex items-start gap-1.5 text-xs text-warn"><TriangleAlert size={13} className="mt-px shrink-0" /> {p.blocked}</p>}
                </div>
              </li>
            ))}
          </ol>
        </Section>

        <div className="space-y-5">
          <Section title="This installation" aside={data ? `${data.checklist.length - open.length} of ${data.checklist.length} set up` : undefined} flush>
            <ul>
              {(data?.checklist ?? []).map((c) => (
                <li key={c.key} className="flex gap-2.5 border-b border-rule-soft px-4 py-2.5 last:border-0">
                  {c.done ? <CircleCheck size={17} className="mt-0.5 shrink-0 text-ok" /> : <CircleDashed size={17} className="mt-0.5 shrink-0 text-warn" />}
                  <div className="min-w-0 text-sm">
                    <div className={c.done ? "text-ink-2" : "font-medium"}>{c.title}</div>
                    {c.hint && <Link to={c.link} className="text-xs text-signal hover:underline">{c.hint}</Link>}
                  </div>
                  <span className="ml-auto shrink-0 text-[11px] text-ink-3">P{c.phase}</span>
                </li>
              ))}
            </ul>
          </Section>
          {verify.length > 0 && (
            <Section title="Hardware checks pending">
              <ul className="space-y-2 text-sm">
                {verify.map(({ n, v }) => <li key={v}><span className="text-ink-3">Phase {n}:</span> {v}</li>)}
              </ul>
              <p className="mt-3 text-xs text-ink-3">Tested in the lab; confirm on your own equipment before relying on it.</p>
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}

/** Compact version for the sidebar. */
export function RoadmapMini() {
  const { data } = useApi<RoadmapData>("/system/roadmap", 120_000);
  if (!data) return null;
  const done = data.phases.filter((p) => p.status === "done").length;
  const open = data.checklist.filter((c) => !c.done).length;
  return (
    <Link to="/roadmap" className="mx-2 mt-4 block rounded-[3px] border border-rule bg-panel px-3 py-2.5 text-xs hover:border-signal">
      <div className="mb-1.5 flex justify-between"><span className="font-medium text-ink">{done} of {data.total} phases done</span>
        <span className="text-ink-3">v{data.version.replace(/^v/, "")}</span></div>
      <PhaseBar phases={data.phases} size="sm" />
      <div className="mt-1.5 text-ink-2">{open ? `${open} setup step${open > 1 ? "s" : ""} open` : "Setup complete"}</div>
    </Link>
  );
}
