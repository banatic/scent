// Category panel: virtualized, filterable event log. The backend event log is
// append-only and arrival-ordered, so we page purely by `offset = loaded.length`
// — the same call fetches older history (endReached) and the live tail (poll).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { TableVirtuoso } from "react-virtuoso";
import { EyeOff, Layers, Search, X } from "lucide-react";

import { CATEGORY_META, CATEGORY_ORDER, describeEvent, formatTime, highlightOf } from "../lib/events";
import { queryEvents } from "../lib/ipc";
import type { Category, ProcessNode, ScentEvent } from "../lib/types";
import { Crosshair, Timer } from "lucide-react";

const PAGE = 500;

interface EventsTableProps {
  category: Category | null;
  onCategory: (c: Category | null) => void;
  text: string;
  onText: (t: string) => void;
  nodeFilter: number | null;
  onClearNodeFilter: () => void;
  /** Restrict to a finding's evidence event ids ("show evidence" jump). */
  evidenceIds: number[] | null;
  onClearEvidence: () => void;
  /** Timeline brush selection (capture-relative ms). */
  tsRange: { from: number; to: number } | null;
  onClearTsRange: () => void;
  nodesById: Map<number, ProcessNode>;
  liveTotal: number;
  selectedEventId: number | null;
  onSelectEvent: (e: ScentEvent) => void;
}

export function EventsTable({
  category,
  onCategory,
  text,
  onText,
  nodeFilter,
  onClearNodeFilter,
  evidenceIds,
  onClearEvidence,
  tsRange,
  onClearTsRange,
  nodesById,
  liveTotal,
  selectedEventId,
  onSelectEvent,
}: EventsTableProps) {
  const [events, setEvents] = useState<ScentEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [hideNoise, setHideNoise] = useState(false);
  const [collapse, setCollapse] = useState(false);
  const loading = useRef(false);
  // Debounced search text → only this triggers refetch (not every keystroke).
  const [debouncedText, setDebouncedText] = useState(text);

  useEffect(() => {
    const h = setTimeout(() => setDebouncedText(text), 250);
    return () => clearTimeout(h);
  }, [text]);

  const filter = useMemo(
    () => ({
      category,
      node_id: nodeFilter,
      text: debouncedText || null,
      hide_noise: hideNoise,
      collapse,
      event_ids: evidenceIds,
      ts_from: tsRange?.from ?? null,
      ts_to: tsRange?.to ?? null,
    }),
    [category, nodeFilter, debouncedText, hideNoise, collapse, evidenceIds, tsRange],
  );

  const loadFrom = useCallback(
    async (offset: number, reset: boolean) => {
      if (loading.current) return;
      loading.current = true;
      try {
        const page = await queryEvents(filter, offset, PAGE);
        setTotal(page.total);
        setEvents((prev) => (reset ? page.events : [...prev, ...page.events]));
      } catch (e) {
        console.error("query_events failed", e);
      } finally {
        loading.current = false;
      }
    },
    [filter],
  );

  // Reset + load first page whenever the filter changes.
  useEffect(() => {
    setEvents([]);
    setTotal(0);
    void loadFrom(0, true);
  }, [loadFrom]);

  // Live tail. Collapsed view re-aggregates from scratch (counts shift); the flat
  // view just appends the new tail (events are append-only & arrival-ordered).
  useEffect(() => {
    if (liveTotal === 0) return;
    if (collapse) void loadFrom(0, true);
    else if (events.length >= total) void loadFrom(events.length, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveTotal]);

  const procName = useCallback(
    (e: ScentEvent) => {
      if (e.node_id != null) {
        const n = nodesById.get(e.node_id);
        if (n) return n.name;
      }
      return String(e.pid);
    },
    [nodesById],
  );

  return (
    <div className="events">
      <div className="events__toolbar">
        <div className="chips">
          <button
            className={`chip${category === null ? " chip--on" : ""}`}
            onClick={() => onCategory(null)}
          >
            All
          </button>
          {CATEGORY_ORDER.map((c) => (
            <button
              key={c}
              className={`chip${category === c ? " chip--on" : ""}`}
              onClick={() => onCategory(category === c ? null : c)}
              style={{ "--chip-color": CATEGORY_META[c].color } as React.CSSProperties}
            >
              <span className="chip__dot" />
              {CATEGORY_META[c].label}
            </button>
          ))}
        </div>

        {nodeFilter != null && (
          <button className="chip chip--filter" onClick={onClearNodeFilter}>
            {nodesById.get(nodeFilter)?.name ?? `node ${nodeFilter}`}
            <X size={12} />
          </button>
        )}

        {evidenceIds != null && (
          <button className="chip chip--filter" onClick={onClearEvidence} title="finding evidence">
            <Crosshair size={12} />
            evidence ({evidenceIds.length})
            <X size={12} />
          </button>
        )}

        {tsRange != null && (
          <button className="chip chip--filter" onClick={onClearTsRange} title="timeline selection">
            <Timer size={12} />
            {formatTime(tsRange.from)}–{formatTime(tsRange.to)}
            <X size={12} />
          </button>
        )}

        <button
          className={`chip chip--toggle${hideNoise ? " chip--on" : ""}`}
          onClick={() => setHideNoise((v) => !v)}
          title="Hide well-known system file/module paths"
        >
          <EyeOff size={13} />
          Hide noise
        </button>
        <button
          className={`chip chip--toggle${collapse ? " chip--on" : ""}`}
          onClick={() => setCollapse((v) => !v)}
          title="Collapse identical operations into one row with a count"
        >
          <Layers size={13} />
          Collapse
        </button>

        <div className="search">
          <Search size={14} strokeWidth={1.75} />
          <input
            value={text}
            placeholder="search path / host / value"
            spellCheck={false}
            onChange={(e) => onText(e.target.value)}
          />
          {text && (
            <button className="search__clear" onClick={() => onText("")}>
              <X size={13} />
            </button>
          )}
        </div>

        <span className="events__count tnum">
          {events.length < total ? `${events.length} / ${total}` : `${total}`}
        </span>
      </div>

      <TableVirtuoso
        className="events__table scroll"
        data={events}
        endReached={() => {
          if (events.length < total) void loadFrom(events.length, false);
        }}
        fixedHeaderContent={() => (
          <tr>
            <th className="col-time">Time</th>
            <th className="col-proc">Process</th>
            <th className="col-cat">Category</th>
            <th className="col-op">Operation</th>
            <th className="col-target">Target</th>
          </tr>
        )}
        itemContent={(_i, e) => {
          const d = describeEvent(e);
          const hl = highlightOf(e);
          const meta = CATEGORY_META[e.category];
          return (
            <Row
              e={e}
              op={d.op}
              target={d.target}
              hl={hl}
              proc={procName(e)}
              metaColor={meta.color}
              metaLabel={meta.label}
              selected={selectedEventId === e.id}
              onSelect={onSelectEvent}
            />
          );
        }}
      />
    </div>
  );
}

function Row({
  e,
  op,
  target,
  hl,
  proc,
  metaColor,
  metaLabel,
  selected,
  onSelect,
}: {
  e: ScentEvent;
  op: string;
  target: string;
  hl: string | null;
  proc: string;
  metaColor: string;
  metaLabel: string;
  selected: boolean;
  onSelect: (e: ScentEvent) => void;
}) {
  return (
    <>
      <td className="col-time tnum" onClick={() => onSelect(e)}>
        {formatTime(e.ts_ms)}
      </td>
      <td className="col-proc" onClick={() => onSelect(e)}>
        <span className="proc-name">{proc}</span>
        <span className="proc-pid tnum">{e.pid}</span>
      </td>
      <td className="col-cat" onClick={() => onSelect(e)}>
        <span className="cat-tag" style={{ ["--c" as string]: metaColor }}>
          <span className="cat-tag__dot" />
          {metaLabel}
        </span>
      </td>
      <td className="col-op" onClick={() => onSelect(e)}>
        {op}
        {e.dup_count != null && e.dup_count > 1 && (
          <span className="dup tnum">×{e.dup_count}</span>
        )}
      </td>
      <td
        className={`col-target${hl ? ` hl hl--${hl}` : ""}${selected ? " is-sel" : ""}`}
        onClick={() => onSelect(e)}
        title={target}
      >
        {hl && <span className="hl-dot" />}
        {target}
      </td>
    </>
  );
}
