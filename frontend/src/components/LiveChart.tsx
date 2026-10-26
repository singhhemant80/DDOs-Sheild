import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { Provenance } from "../lib/hooks";

export type ChartSeries = {
  label: string;
  values: (number | null)[];
  color: string; // CSS variable name, e.g. "--signal"
  width?: number;
  /** Per-point provenance; drives solid vs dashed segments. Omit for a uniform line. */
  prov?: Provenance[];
  fill?: boolean;
};

type Props = {
  ts: number[];            // unix seconds, ascending
  series: ChartSeries[];
  height?: number;
  format: (v: number) => string;
  windowSec?: number;      // fixed x-range ending now (live charts); otherwise fit data
  gapSec?: number;         // a gap longer than this is drawn as hatched "no data"
  ariaLabel: string;
};

const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";

/**
 * Time-series chart built on uPlot. Each series with provenance is split into two traces:
 * a solid trace for sampled/measured points and a dashed trace for estimated points.
 * Spans without data are hatched rather than drawn at zero.
 */
export function LiveChart({ ts, series, height = 260, format, windowSec, gapSec = 3, ariaLabel }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const latest = useRef({ ts, series, windowSec, gapSec });
  latest.current = { ts, series, windowSec, gapSec };

  const build = () => {
    const el = host.current;
    if (!el) return;
    plot.current?.destroy();
    const { series: ss } = latest.current;
    const uSeries: uPlot.Series[] = [{}];
    for (const s of ss) {
      const stroke = css(s.color);
      uSeries.push({
        label: s.label, stroke, width: s.width ?? 1.75,
        fill: s.fill ? stroke + "1f" : undefined, points: { show: false }, spanGaps: false,
      });
      if (s.prov) {
        uSeries.push({ label: `${s.label} (estimated)`, stroke, width: s.width ?? 1.75, dash: [6, 4],
          points: { show: false }, spanGaps: false });
      }
    }
    const ink3 = css("--ink-3");
    const grid = css("--rule-soft");
    const axis: uPlot.Axis = {
      stroke: ink3, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 },
      font: "12px Archivo Variable, sans-serif",
    };
    plot.current = new uPlot({
      width: el.clientWidth, height,
      series: uSeries,
      cursor: { drag: { x: false, y: false }, points: { size: 6 } },
      legend: { show: false },
      scales: {
        x: { time: true, range: (_u, min, max) => {
          const w = latest.current.windowSec;
          if (w) { const now = Date.now() / 1000; return [now - w, now]; }
          return [min, max];
        } },
        y: { range: (_u, _min, max) => [0, max > 0 ? max * 1.12 : 1] },
      },
      axes: [
        { ...axis, space: 70 },
        { ...axis, size: 72, values: (_u, vals) => vals.map((v) => format(v)) },
      ],
      hooks: { drawClear: [(u) => drawGaps(u)] },
    }, toData(), el);
  };

  const toData = (): uPlot.AlignedData => {
    const { ts: t0, series: ss0, gapSec: g } = latest.current;
    // Insert an explicit null row inside every gap so lines break instead of bridging missing data.
    const t: number[] = [];
    const idx: number[] = [];
    for (let i = 0; i < t0.length; i++) {
      if (i > 0 && t0[i] - t0[i - 1] > g) { t.push(t0[i - 1] + 1); idx.push(-1); }
      t.push(t0[i]); idx.push(i);
    }
    const ss = ss0.map((s) => ({
      ...s,
      values: idx.map((i) => (i < 0 ? null : s.values[i])),
      prov: s.prov ? idx.map((i) => (i < 0 ? "unavailable" : s.prov![i])) : undefined,
    }));
    const cols: (number | null)[][] = [];
    for (const s of ss) {
      if (!s.prov) { cols.push(s.values); continue; }
      const solid: (number | null)[] = [];
      const dashed: (number | null)[] = [];
      for (let i = 0; i < t.length; i++) {
        const p = s.prov[i];
        const est = p === "estimated";
        const prevEst = i > 0 && s.prov[i - 1] === "estimated";
        const nextEst = i < t.length - 1 && s.prov[i + 1] === "estimated";
        // Overlap one point at each boundary so the line stays continuous.
        solid.push(!est || (prevEst !== est) || (nextEst !== est) ? s.values[i] : null);
        dashed.push(est || prevEst || nextEst ? s.values[i] : null);
        if (p === "unavailable") { solid[i] = null; dashed[i] = null; }
      }
      cols.push(solid, dashed);
    }
    return [t, ...cols] as uPlot.AlignedData;
  };

  // Hatched rectangles over spans with no data (between points further apart than gapSec,
  // and before the first / after the last point inside a live window).
  const drawGaps = (u: uPlot) => {
    const { ts: t, gapSec: g } = latest.current;
    const ctx = u.ctx;
    const { left, top, width, height: h } = u.bbox;
    const spans: [number, number][] = [];
    const xmin = u.scales.x.min!, xmax = u.scales.x.max!;
    if (!t.length) spans.push([xmin, xmax]);
    else {
      if (t[0] - xmin > g) spans.push([xmin, t[0]]);
      for (let i = 1; i < t.length; i++) if (t[i] - t[i - 1] > g) spans.push([t[i - 1], t[i]]);
      if (xmax - t[t.length - 1] > g + 1) spans.push([t[t.length - 1], xmax]);
    }
    if (!spans.length) return;
    const pat = document.createElement("canvas");
    pat.width = pat.height = 10;
    const pc = pat.getContext("2d")!;
    pc.strokeStyle = css("--hatch");
    pc.lineWidth = 2;
    pc.beginPath(); pc.moveTo(0, 10); pc.lineTo(10, 0); pc.stroke();
    ctx.save();
    ctx.fillStyle = ctx.createPattern(pat, "repeat")!;
    for (const [a, b] of spans) {
      const x0 = Math.max(left, u.valToPos(a, "x", true));
      const x1 = Math.min(left + width, u.valToPos(b, "x", true));
      if (x1 > x0) ctx.fillRect(x0, top, x1 - x0, h);
    }
    ctx.restore();
  };

  // (Re)build when series shape or theme changes; resize with the container.
  const shape = series.map((s) => `${s.label}${s.color}${!!s.prov}`).join("|");
  useEffect(() => {
    build();
    const ro = new ResizeObserver(() => {
      if (host.current) plot.current?.setSize({ width: host.current.clientWidth, height });
    });
    if (host.current) ro.observe(host.current);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const mo = new MutationObserver(build);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    mq.addEventListener("change", build);
    return () => { ro.disconnect(); mo.disconnect(); mq.removeEventListener("change", build); plot.current?.destroy(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape, height]);

  useEffect(() => { plot.current?.setData(toData(), true); });

  // Keep a live window sliding even when no new points arrive (so outages become visible).
  useEffect(() => {
    if (!windowSec) return;
    const t = setInterval(() => plot.current?.setData(toData(), true), 1000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [windowSec]);

  return <div ref={host} role="img" aria-label={ariaLabel} className="w-full" />;
}
