// Process tree panel — the Phase 1 main data view. Opaque high-contrast surface
// floating on the Mica backdrop. Rebuilds from the flat node list the backend
// returns; hierarchy is derived from node_id / parent_node_id (reuse-safe).

import { useMemo } from "react";
import { GitBranch } from "lucide-react";

import type { ProcessNode, ProcessTree as ProcessTreeData } from "../lib/types";
import { TreeNode } from "./TreeNode";

interface ProcessTreeProps {
  tree: ProcessTreeData | null;
  selectedId: number | null;
  expanded: Set<number>;
  onSelect: (id: number) => void;
  onToggle: (id: number) => void;
}

function buildChildrenMap(nodes: ProcessNode[]): Map<number, ProcessNode[]> {
  const map = new Map<number, ProcessNode[]>();
  for (const n of nodes) {
    if (n.parent_node_id == null) continue;
    const list = map.get(n.parent_node_id);
    if (list) list.push(n);
    else map.set(n.parent_node_id, [n]);
  }
  return map;
}

export function ProcessTree({
  tree,
  selectedId,
  expanded,
  onSelect,
  onToggle,
}: ProcessTreeProps) {
  const childrenMap = useMemo(
    () => buildChildrenMap(tree?.nodes ?? []),
    [tree],
  );
  const root = useMemo(() => {
    if (!tree || tree.root_node_id == null) return null;
    return tree.nodes.find((n) => n.node_id === tree.root_node_id) ?? null;
  }, [tree]);

  return (
    <section className="panel">
      <header className="panel__head">
        <GitBranch size={15} strokeWidth={1.75} />
        <h2 className="panel__title">Process Tree</h2>
        {tree && tree.nodes.length > 0 && (
          <span className="panel__count tnum">{tree.nodes.length}</span>
        )}
      </header>

      <div className="panel__body scroll">
        {root ? (
          <TreeNode
            node={root}
            childrenMap={childrenMap}
            depth={0}
            selectedId={selectedId}
            expanded={expanded}
            onSelect={onSelect}
            onToggle={onToggle}
          />
        ) : (
          <div className="empty">
            <GitBranch size={22} strokeWidth={1.5} />
            <p className="empty__title">No capture running</p>
            <p className="empty__hint">
              Select a target executable and press Capture. scent launches it
              suspended, attaches the ETW session, then resumes — so the tree
              grows from the very first action.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
