// Deep-mode panel: "who / how / what" for file-probe → calling-DLL attribution.
//   - flat caller-aware table (A): time / pid·tid / category / op / target / caller / ok-fail
//   - group-by-caller (C): collapse many events into one caller row; click to drill down
//   - hide known-benign (E): user-controlled noise reduction (NOT a verdict)
// Row click selects the finding → the Inspector renders its full stack chain (B).

import { useMemo, useState } from "react";
import { TableVirtuoso } from "react-virtuoso";
import { Layers, Search, ShieldCheck, X } from "lucide-react";

import { formatTime } from "../lib/events";
import type { DeepFinding, ProcessNode } from "../lib/types";

interface DeepPanelProps {
  findings: DeepFinding[];
  nodesById: Map<number, ProcessNode>;
  selectedKey: string | null;
  onSelect: (f: DeepFinding) => void;
}

export function findingKey(f: DeepFinding): string {
  return `${f.ts_ms}|${f.pid}|${f.path}`;
}

/** Strip the NT device prefix for readability (\Device\HarddiskVolume5\… → \…). */
function pretty(path: string): string {
  return path.replace(/^\\Device\\HarddiskVolume\d+/i, "");
}
function baseName(path: string): string {
  const p = path.replace(/[\\/]+$/, "");
  const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return i >= 0 ? p.slice(i + 1) : p;
}

export function DeepPanel({ findings, nodesById, selectedKey, onSelect }: DeepPanelProps) {
  const [groupBy, setGroupBy] = useState(true);
  const [hideBenign, setHideBenign] = useState(false);
  const [text, setText] = useState("");
  const [callerFilter, setCallerFilter] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = text.trim().toLowerCase();
    return findings.filter((f) => {
      if (hideBenign && f.benign) return false;
      if (callerFilter !== null && (f.caller ?? "(unresolved)") !== callerFilter) return false;
      if (q && !`${f.path} ${f.caller ?? ""}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [findings, hideBenign, callerFilter, text]);

  const groups = useMemo(() => {
    const m = new Map<
      string,
      { caller: string; benign: string | null; total: number; failed: number; targets: Set<string>; samples: string[] }
    >();
    for (const f of filtered) {
      const key = f.caller ?? "(unresolved)";
      let g = m.get(key);
      if (!g) {
        g = { caller: key, benign: f.benign, total: 0, failed: 0, targets: new Set(), samples: [] };
        m.set(key, g);
      }
      g.total += 1;
      if (f.failed) g.failed += 1;
      const t = pretty(f.path);
      if (!g.targets.has(t)) {
        g.targets.add(t);
        if (g.samples.length < 4) g.samples.push(baseName(f.path));
      }
      if (!g.benign && f.benign) g.benign = f.benign;
    }
    return [...m.values()].sort((a, b) => b.total - a.total);
  }, [filtered]);

  const procName = (f: DeepFinding) =>
    (f.node_id != null ? nodesById.get(f.node_id)?.name : undefined) ?? String(f.pid);

  if (findings.length === 0) {
    return (
      <div className="view-empty">
        No deep findings. Toggle <b>Deep</b> on before capturing to stack-walk file
        probes and attribute each to its calling DLL.
      </div>
    );
  }

  const showGroups = groupBy && callerFilter === null;

  return (
    <div className="events">
      <div className="events__toolbar">
        <button
          className={`chip chip--toggle${groupBy ? " chip--on" : ""}`}
          onClick={() => setGroupBy((v) => !v)}
          title="Collapse events by calling module"
        >
          <Layers size={13} />
          Group by caller
        </button>
        <button
          className={`chip chip--toggle${hideBenign ? " chip--on" : ""}`}
          onClick={() => setHideBenign((v) => !v)}
          title="Hide callers annotated as known-benign (noise reduction, not a verdict)"
        >
          <ShieldCheck size={13} />
          Hide known-benign
        </button>
        {callerFilter !== null && (
          <button className="chip chip--filter" onClick={() => setCallerFilter(null)}>
            {callerFilter}
            <X size={12} />
          </button>
        )}
        <div className="search">
          <Search size={14} strokeWidth={1.75} />
          <input
            value={text}
            placeholder="search target / caller"
            spellCheck={false}
            onChange={(e) => setText(e.target.value)}
          />
          {text && (
            <button className="search__clear" onClick={() => setText("")}>
              <X size={13} />
            </button>
          )}
        </div>
        <span className="events__count tnum">{filtered.length}</span>
      </div>

      {showGroups ? (
        <div className="callers scroll">
          {groups.map((g) => (
            <button key={g.caller} className="caller-row" onClick={() => setCallerFilter(g.caller)}>
              <span className="caller-row__name">
                <span className={g.caller === "(unresolved)" ? "muted" : ""}>{g.caller}</span>
                {g.benign && (
                  <span className="benign-tag" title={g.benign}>
                    <ShieldCheck size={11} />
                    benign
                  </span>
                )}
              </span>
              <span className="caller-row__stat tnum">
                {g.targets.size} target{g.targets.size === 1 ? "" : "s"}
              </span>
              <span className={`caller-row__stat tnum${g.failed ? " is-failed" : ""}`}>
                {g.failed}/{g.total} failed
              </span>
              <span className="caller-row__samples">{g.samples.join(", ")}</span>
            </button>
          ))}
        </div>
      ) : (
        <TableVirtuoso
          className="events__table scroll"
          data={filtered}
          fixedHeaderContent={() => (
            <tr>
              <th className="col-time">Time</th>
              <th className="col-proc">Process</th>
              <th className="col-cat">Caller DLL</th>
              <th className="col-op">Tier</th>
              <th className="col-target">Target</th>
            </tr>
          )}
          itemContent={(_i, f) => {
            const sel = selectedKey === findingKey(f);
            return (
              <DeepRow f={f} proc={procName(f)} selected={sel} onSelect={onSelect} />
            );
          }}
        />
      )}
    </div>
  );
}

function DeepRow({
  f,
  proc,
  selected,
  onSelect,
}: {
  f: DeepFinding;
  proc: string;
  selected: boolean;
  onSelect: (f: DeepFinding) => void;
}) {
  const click = () => onSelect(f);
  return (
    <>
      <td className="col-time tnum" onClick={click}>
        {formatTime(f.ts_ms)}
      </td>
      <td className="col-proc" onClick={click}>
        <span className="proc-name">{proc}</span>
        <span className="proc-pid tnum">
          {f.pid}·{f.tid}
        </span>
      </td>
      <td className="col-cat" onClick={click} title={f.benign ?? undefined}>
        <span className={f.caller ? "" : "muted"}>{f.caller ?? "—"}</span>
        {f.benign && (
          <span className="benign-tag">
            <ShieldCheck size={11} />
            benign
          </span>
        )}
      </td>
      <td className="col-op" onClick={click}>
        {f.tier}
      </td>
      <td
        className={`col-target${f.failed ? " hl hl--external" : ""}${selected ? " is-sel" : ""}`}
        onClick={click}
        title={f.path}
      >
        {f.failed && <span className="hl-dot" title="path not found (probe)" />}
        {pretty(f.path)}
      </td>
    </>
  );
}
