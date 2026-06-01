// Causal graph: process tree (parent→child) plus, for the selected process, the
// distinct resources it touched (files / registry keys / endpoints / DNS / modules)
// as nodes with action edges. Keeping resources scoped to the selection keeps the
// graph legible instead of exploding to thousands of nodes.

import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Position,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { CATEGORY_META, CATEGORY_ORDER, describeEvent } from "../lib/events";
import { SEVERITY_META } from "../lib/findings";
import { queryEvents } from "../lib/ipc";
import type { Category, ProcessTree as ProcessTreeData, ScentEvent, Severity } from "../lib/types";

const PER_CATEGORY_CAP = 10;

// Action verb per category → typed causal edge (process → resource).
const EDGE_VERB: Record<Category, string> = {
  process: "spawned",
  file: "wrote",
  registry: "persisted",
  network: "connected",
  dns: "resolved",
  module: "loaded",
};

interface GraphViewProps {
  tree: ProcessTreeData | null;
  selectedNodeId: number | null;
  nodeSeverity: Map<number, Severity>;
  onSelectNode: (id: number) => void;
}

export function GraphView({ tree, selectedNodeId, nodeSeverity, onSelectNode }: GraphViewProps) {
  const [resources, setResources] = useState<ScentEvent[]>([]);

  // Fetch the selected process's events to derive its resource nodes.
  useEffect(() => {
    if (selectedNodeId == null) {
      setResources([]);
      return;
    }
    let active = true;
    queryEvents({ node_id: selectedNodeId }, 0, 4000)
      .then((p) => active && setResources(p.events))
      .catch(() => active && setResources([]));
    return () => {
      active = false;
    };
  }, [selectedNodeId, tree?.version]);

  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    if (!tree) return { nodes, edges };

    // Lay processes out by depth (x) and order within depth (y).
    const byParent = new Map<number, number[]>();
    for (const n of tree.nodes) {
      if (n.parent_node_id == null) continue;
      const a = byParent.get(n.parent_node_id) ?? [];
      a.push(n.node_id);
      byParent.set(n.parent_node_id, a);
    }
    const depthCount: number[] = [];
    const place = (id: number, depth: number) => {
      const n = tree.nodes.find((x) => x.node_id === id);
      if (!n) return;
      const row = depthCount[depth] ?? 0;
      depthCount[depth] = row + 1;
      const sev = nodeSeverity.get(id);
      const pcolor = sev ? SEVERITY_META[sev].color : "var(--cat-process)";
      nodes.push({
        id: `p${id}`,
        position: { x: depth * 230, y: row * 84 },
        data: { label: `${n.name}  ·  ${n.pid}` },
        style: nodeStyle(pcolor, selectedNodeId === id),
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });
      if (n.parent_node_id != null) {
        edges.push({
          id: `e-p${n.parent_node_id}-p${id}`,
          source: `p${n.parent_node_id}`,
          target: `p${id}`,
          label: EDGE_VERB.process,
          labelStyle: { fill: "var(--ink-3)", fontSize: 10 },
          labelBgStyle: { fill: "var(--surface-1)" },
          style: { stroke: "var(--cat-process)", strokeWidth: 1.5 },
        });
      }
      for (const c of byParent.get(id) ?? []) place(c, depth + 1);
    };
    if (tree.root_node_id != null) place(tree.root_node_id, 0);

    // Resource nodes for the selected process.
    if (selectedNodeId != null && resources.length) {
      const maxDepth = depthCount.length;
      const baseX = maxDepth * 230 + 120;
      const perCat = new Map<Category, Set<string>>();
      let row = 0;
      for (const c of CATEGORY_ORDER) {
        if (c === "process") continue;
        const seen = perCat.get(c) ?? new Set<string>();
        perCat.set(c, seen);
        const items = resources.filter((e) => e.category === c);
        for (const e of items) {
          const target = describeEvent(e).target || "(empty)";
          if (seen.has(target)) continue;
          seen.add(target);
          if (seen.size > PER_CATEGORY_CAP) break;
          const rid = `r${c}-${seen.size}-${selectedNodeId}`;
          nodes.push({
            id: rid,
            position: { x: baseX, y: row * 46 },
            data: { label: truncate(target, 48) },
            style: nodeStyle(CATEGORY_META[c].color, false, true),
            targetPosition: Position.Left,
          });
          edges.push({
            id: `e-sel-${rid}`,
            source: `p${selectedNodeId}`,
            target: rid,
            label: EDGE_VERB[c],
            labelStyle: { fill: "var(--ink-3)", fontSize: 10 },
            labelBgStyle: { fill: "var(--surface-1)" },
            style: { stroke: CATEGORY_META[c].color, strokeWidth: 1, opacity: 0.7 },
          });
          row += 1;
        }
      }
    }

    return { nodes, edges };
  }, [tree, selectedNodeId, resources, nodeSeverity]);

  if (!tree || tree.nodes.length === 0) {
    return <div className="view-empty">No capture yet — the causal graph appears here.</div>;
  }

  return (
    <div className="graph">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={0.1}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_e, node) => {
          if (node.id.startsWith("p")) {
            const id = Number(node.id.slice(1));
            if (!Number.isNaN(id)) onSelectNode(id);
          }
        }}
      >
        <Background color="var(--hairline)" gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
      {selectedNodeId == null && (
        <div className="graph__hint">Select a process to reveal the resources it touched.</div>
      )}
    </div>
  );
}

function nodeStyle(color: string, selected: boolean, resource = false): React.CSSProperties {
  return {
    background: "var(--surface-2)",
    color: "var(--ink-1)",
    border: `1px solid ${selected ? color : "var(--hairline-strong)"}`,
    borderLeft: `3px solid ${color}`,
    borderRadius: "8px",
    fontSize: resource ? "11px" : "12px",
    fontWeight: 500,
    padding: resource ? "4px 8px" : "6px 10px",
    width: resource ? 280 : 170,
    boxShadow: selected ? `0 0 0 2px ${color}` : "var(--shadow-panel)",
  };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `…${s.slice(s.length - n)}` : s;
}
