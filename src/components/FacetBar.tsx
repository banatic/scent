// The second toolbar row of the Events table: triage presets + facet controls
// contextual to the selected category. Op facets (file/registry), network
// proto/direction/port, and a subtree-scope toggle map onto the Phase 8.4
// EventFilter fields. Opaque DATA-surface chrome — no glass.

import type { NetDir, Proto } from "../lib/types";
import type { Category } from "../lib/types";
import { EMPTY_FACETS, OP_FACETS, TRIAGE_PRESETS, type Facets, type Preset } from "../lib/events";

interface FacetBarProps {
  category: Category | null;
  facets: Facets;
  onFacets: (f: Facets) => void;
  onApplyPreset: (p: Preset) => void;
  nodeFilter: number | null;
  nodeName?: string;
}

const PROTOS: Proto[] = ["tcp", "udp"];
const DIRS: NetDir[] = ["outbound", "inbound"];

export function FacetBar({
  category,
  facets,
  onFacets,
  onApplyPreset,
  nodeFilter,
  nodeName,
}: FacetBarProps) {
  const ops = category ? OP_FACETS[category] : undefined;

  const toggleOp = (id: string) => {
    const has = facets.ops.includes(id);
    onFacets({
      ...facets,
      ops: has ? facets.ops.filter((o) => o !== id) : [...facets.ops, id],
    });
  };

  const port = (which: "portMin" | "portMax", raw: string) => {
    const n = raw === "" ? null : Number(raw);
    onFacets({ ...facets, [which]: Number.isFinite(n as number) ? n : null });
  };

  return (
    <div className="facets">
      <div className="facets__group">
        <span className="facets__lead">Triage</span>
        {TRIAGE_PRESETS.map((p) => (
          <button
            key={p.id}
            className="facet-preset"
            title={p.hint}
            onClick={() => onApplyPreset(p)}
          >
            {p.label}
          </button>
        ))}
      </div>

      {ops && (
        <div className="facets__group">
          <span className="facets__div" />
          {ops.map((o) => (
            <button
              key={o.id}
              className={`facet-chip${facets.ops.includes(o.id) ? " facet-chip--on" : ""}`}
              onClick={() => toggleOp(o.id)}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}

      {category === "network" && (
        <div className="facets__group">
          <span className="facets__div" />
          {PROTOS.map((p) => (
            <button
              key={p}
              className={`facet-chip${facets.proto === p ? " facet-chip--on" : ""}`}
              onClick={() => onFacets({ ...facets, proto: facets.proto === p ? null : p })}
            >
              {p.toUpperCase()}
            </button>
          ))}
          {DIRS.map((d) => (
            <button
              key={d}
              className={`facet-chip${facets.direction === d ? " facet-chip--on" : ""}`}
              onClick={() => onFacets({ ...facets, direction: facets.direction === d ? null : d })}
            >
              {d}
            </button>
          ))}
          <span className="facet-port">
            <input
              type="number"
              min={0}
              max={65535}
              placeholder="port ≥"
              value={facets.portMin ?? ""}
              onChange={(e) => port("portMin", e.target.value)}
            />
            <span className="facet-port__dash">–</span>
            <input
              type="number"
              min={0}
              max={65535}
              placeholder="≤"
              value={facets.portMax ?? ""}
              onChange={(e) => port("portMax", e.target.value)}
            />
          </span>
        </div>
      )}

      {nodeFilter != null && (
        <div className="facets__group facets__group--end">
          <span className="facets__div" />
          <button
            className={`facet-chip${facets.includeSubtree ? " facet-chip--on" : ""}`}
            title={`Include events from descendants of ${nodeName ?? "this process"}`}
            onClick={() => onFacets({ ...facets, includeSubtree: !facets.includeSubtree })}
          >
            include subtree
          </button>
        </div>
      )}
    </div>
  );
}

/** Build the next facet state for a preset, preserving the node-scope toggle. */
export function presetFacets(p: Preset, current: Facets): Facets {
  return { ...EMPTY_FACETS, ...p.facets, includeSubtree: current.includeSubtree };
}
