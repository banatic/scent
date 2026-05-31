// Timeline: events plotted on a time axis across six category tracks. Canvas-
// rendered so tens of thousands of points stay smooth. Click a point to inspect.

import { useCallback, useEffect, useRef, useState } from "react";

import { CATEGORY_META, CATEGORY_ORDER, formatTime } from "../lib/events";
import { queryEvents } from "../lib/ipc";
import type { CaptureStatus, ProcessNode, ScentEvent } from "../lib/types";

const GUTTER = 78;
const PAD_TOP = 12;
const PAD_BOTTOM = 26;

interface TimelineViewProps {
  status: CaptureStatus;
  nodesById: Map<number, ProcessNode>;
  onSelectEvent: (e: ScentEvent) => void;
}

export function TimelineView({ status, onSelectEvent }: TimelineViewProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const events = useRef<ScentEvent[]>([]);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [version, setVersion] = useState(0);

  // (Re)load events when the total grows; debounce to avoid thrashing.
  useEffect(() => {
    let active = true;
    const h = setTimeout(() => {
      queryEvents({}, 0, 50000)
        .then((p) => {
          if (!active) return;
          events.current = p.events;
          setVersion((v) => v + 1);
        })
        .catch(() => {});
    }, 300);
    return () => {
      active = false;
      clearTimeout(h);
    };
  }, [status.total_events]);

  // Track container size.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0].contentRect;
      setSize({ w: Math.floor(r.width), h: Math.floor(r.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const maxTs = Math.max(1000, status.elapsed_ms);
  const tracks = CATEGORY_ORDER;
  const plotW = Math.max(10, size.w - GUTTER - 12);
  const trackArea = Math.max(10, size.h - PAD_TOP - PAD_BOTTOM);
  const trackH = trackArea / tracks.length;

  const xOf = useCallback((ts: number) => GUTTER + (ts / maxTs) * plotW, [maxTs, plotW]);
  const yOf = useCallback(
    (catIdx: number) => PAD_TOP + catIdx * trackH + trackH / 2,
    [trackH],
  );

  // Draw.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.w === 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size.w * dpr;
    canvas.height = size.h * dpr;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.w, size.h);

    const css = getComputedStyle(canvas);
    const hairline = css.getPropertyValue("--hairline").trim() || "rgba(0,0,0,0.1)";
    const ink3 = css.getPropertyValue("--ink-3").trim() || "#888";

    // Track lanes + labels.
    ctx.font = "11px var(--font-sans, sans-serif)";
    tracks.forEach((c, i) => {
      const y = yOf(i);
      ctx.strokeStyle = hairline;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(GUTTER, y);
      ctx.lineTo(size.w - 12, y);
      ctx.stroke();
      ctx.fillStyle = ink3;
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      ctx.fillText(CATEGORY_META[c].label, 8, y);
    });

    // Time ticks.
    ctx.fillStyle = ink3;
    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    for (let i = 0; i <= 5; i++) {
      const ts = (maxTs / 5) * i;
      const x = xOf(ts);
      ctx.fillText(formatTime(ts), x, size.h - 8);
    }

    // Points.
    const catIndex: Record<string, number> = {};
    tracks.forEach((c, i) => (catIndex[c] = i));
    for (const e of events.current) {
      const ci = catIndex[e.category];
      if (ci === undefined) continue;
      const meta = CATEGORY_META[e.category];
      const color = resolveVar(css, meta.color);
      ctx.fillStyle = color;
      ctx.globalAlpha = 0.8;
      ctx.beginPath();
      ctx.arc(xOf(e.ts_ms), yOf(ci), 2.6, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  }, [size, version, maxTs, xOf, yOf, tracks]);

  const onClick = useCallback(
    (ev: React.MouseEvent<HTMLCanvasElement>) => {
      const rect = canvasRef.current!.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const ci = Math.floor((my - PAD_TOP) / trackH);
      if (ci < 0 || ci >= tracks.length) return;
      const cat = tracks[ci];
      let best: ScentEvent | null = null;
      let bestDx = 14;
      for (const e of events.current) {
        if (e.category !== cat) continue;
        const dx = Math.abs(xOf(e.ts_ms) - mx);
        if (dx < bestDx) {
          bestDx = dx;
          best = e;
        }
      }
      if (best) onSelectEvent(best);
    },
    [trackH, tracks, xOf, onSelectEvent],
  );

  return (
    <div className="timeline" ref={wrapRef}>
      {status.total_events === 0 ? (
        <div className="view-empty">No capture yet — events plot here over time.</div>
      ) : (
        <canvas ref={canvasRef} style={{ width: size.w, height: size.h }} onClick={onClick} />
      )}
    </div>
  );
}

/** Resolve a `var(--x)` color string to a concrete value via computed styles. */
function resolveVar(css: CSSStyleDeclaration, value: string): string {
  const m = value.match(/var\((--[\w-]+)\)/);
  if (m) {
    const v = css.getPropertyValue(m[1]).trim();
    if (v) return v;
  }
  return value;
}
