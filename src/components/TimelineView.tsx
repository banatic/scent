// Timeline: events on category tracks, plus a top lane of finding markers and a
// drag-to-select brush that filters the whole capture to a time window. Beaconing
// findings draw their regular connection beats as a connected line on the network
// track. Canvas-rendered for tens of thousands of points. Opaque DATA surface.

import { useCallback, useEffect, useRef, useState } from "react";

import { CATEGORY_META, CATEGORY_ORDER, formatTime } from "../lib/events";
import { SEVERITY_META } from "../lib/findings";
import { queryEvents } from "../lib/ipc";
import type { CaptureStatus, Finding, ScentEvent } from "../lib/types";

const GUTTER = 78;
const PAD_TOP = 12;
const FIND_LANE = 26; // top lane reserved for finding markers
const PAD_BOTTOM = 26;
const BRUSH_MIN_PX = 4;

interface TimelineViewProps {
  status: CaptureStatus;
  findings: Finding[];
  onSelectEvent: (e: ScentEvent) => void;
  onBrush: (range: { from: number; to: number }) => void;
}

export function TimelineView({ status, findings, onSelectEvent, onBrush }: TimelineViewProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const events = useRef<ScentEvent[]>([]);
  const eventsById = useRef<Map<number, ScentEvent>>(new Map());
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [version, setVersion] = useState(0);
  const drag = useRef<{ x0: number; x1: number } | null>(null);
  const [sel, setSel] = useState<{ x0: number; x1: number } | null>(null);

  useEffect(() => {
    let active = true;
    const h = setTimeout(() => {
      queryEvents({}, 0, 50000)
        .then((p) => {
          if (!active) return;
          events.current = p.events;
          eventsById.current = new Map(p.events.map((e) => [e.id, e]));
          setVersion((v) => v + 1);
        })
        .catch(() => {});
    }, 300);
    return () => {
      active = false;
      clearTimeout(h);
    };
  }, [status.total_events]);

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
  const trackTop = PAD_TOP + FIND_LANE;
  const trackArea = Math.max(10, size.h - trackTop - PAD_BOTTOM);
  const trackH = trackArea / tracks.length;

  const xOf = useCallback((ts: number) => GUTTER + (ts / maxTs) * plotW, [maxTs, plotW]);
  const yOf = useCallback((i: number) => trackTop + i * trackH + trackH / 2, [trackTop, trackH]);
  const tsOf = useCallback(
    (x: number) => Math.max(0, Math.min(maxTs, ((x - GUTTER) / plotW) * maxTs)),
    [maxTs, plotW],
  );

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
      ctx.fillText(formatTime(ts), xOf(ts), size.h - 8);
    }

    // Category points.
    const catIndex: Record<string, number> = {};
    tracks.forEach((c, i) => (catIndex[c] = i));
    for (const e of events.current) {
      const ci = catIndex[e.category];
      if (ci === undefined) continue;
      ctx.fillStyle = resolveVar(css, CATEGORY_META[e.category].color);
      ctx.globalAlpha = 0.8;
      ctx.beginPath();
      ctx.arc(xOf(e.ts_ms), yOf(ci), 2.6, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    // Beaconing: connect the regular beats on the network track.
    const netIdx = catIndex["network"];
    if (netIdx !== undefined) {
      for (const f of findings) {
        if (f.source.type !== "stateful" || f.source.kind !== "beaconing") continue;
        const pts = f.evidence
          .map((id) => eventsById.current.get(id))
          .filter((e): e is ScentEvent => !!e)
          .map((e) => xOf(e.ts_ms))
          .sort((a, b) => a - b);
        if (pts.length < 2) continue;
        const y = yOf(netIdx);
        ctx.strokeStyle = SEVERITY_META[f.severity].color;
        ctx.globalAlpha = 0.5;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(pts[0], y);
        for (const x of pts.slice(1)) ctx.lineTo(x, y);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }
    }

    // Finding markers in the top lane (triangles colored by severity).
    const my = PAD_TOP + FIND_LANE / 2;
    for (const f of findings) {
      const x = xOf(f.ts_ms);
      ctx.fillStyle = resolveVar(css, SEVERITY_META[f.severity].color);
      ctx.beginPath();
      ctx.moveTo(x, my + 5);
      ctx.lineTo(x - 4, my - 4);
      ctx.lineTo(x + 4, my - 4);
      ctx.closePath();
      ctx.fill();
    }

    // Brush selection overlay.
    if (sel) {
      const x = Math.min(sel.x0, sel.x1);
      const w = Math.abs(sel.x1 - sel.x0);
      ctx.fillStyle = resolveVar(css, "var(--cat-process)");
      ctx.globalAlpha = 0.14;
      ctx.fillRect(x, trackTop - 4, w, trackArea + 8);
      ctx.globalAlpha = 0.6;
      ctx.strokeStyle = resolveVar(css, "var(--cat-process)");
      ctx.lineWidth = 1;
      ctx.strokeRect(x, trackTop - 4, w, trackArea + 8);
      ctx.globalAlpha = 1;
    }
  }, [size, version, findings, maxTs, xOf, yOf, tracks, sel, trackTop, trackArea]);

  const onDown = useCallback((ev: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    drag.current = { x0: x, x1: x };
    setSel({ x0: x, x1: x });
  }, []);

  const onMove = useCallback((ev: React.MouseEvent<HTMLCanvasElement>) => {
    if (!drag.current) return;
    const rect = canvasRef.current!.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    drag.current.x1 = x;
    setSel({ x0: drag.current.x0, x1: x });
  }, []);

  const onUp = useCallback(
    (ev: React.MouseEvent<HTMLCanvasElement>) => {
      const d = drag.current;
      drag.current = null;
      const rect = canvasRef.current!.getBoundingClientRect();
      const x = ev.clientX - rect.left;
      const y = ev.clientY - rect.top;
      if (d && Math.abs(x - d.x0) > BRUSH_MIN_PX) {
        // Brush → time-window filter.
        const from = Math.round(tsOf(Math.min(d.x0, x)));
        const to = Math.round(tsOf(Math.max(d.x0, x)));
        setSel(null);
        onBrush({ from, to });
        return;
      }
      setSel(null);
      // Click → select the nearest event point on the clicked track.
      const ci = Math.floor((y - (PAD_TOP + FIND_LANE)) / trackH);
      if (ci < 0 || ci >= tracks.length) return;
      const cat = tracks[ci];
      let best: ScentEvent | null = null;
      let bestDx = 14;
      for (const e of events.current) {
        if (e.category !== cat) continue;
        const dx = Math.abs(xOf(e.ts_ms) - x);
        if (dx < bestDx) {
          bestDx = dx;
          best = e;
        }
      }
      if (best) onSelectEvent(best);
    },
    [tsOf, onBrush, trackH, tracks, xOf, onSelectEvent],
  );

  return (
    <div className="timeline" ref={wrapRef}>
      {status.total_events === 0 ? (
        <div className="view-empty">No capture yet — events plot here over time.</div>
      ) : (
        <canvas
          ref={canvasRef}
          style={{ width: size.w, height: size.h }}
          onMouseDown={onDown}
          onMouseMove={onMove}
          onMouseUp={onUp}
          onMouseLeave={() => {
            drag.current = null;
            setSel(null);
          }}
        />
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
