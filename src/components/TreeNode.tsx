// One process row in the tree. Opaque, high-contrast — this is a DATA surface,
// so no glass/blur here. Indentation encodes the parent/child hierarchy.

import { ChevronRight, Box } from "lucide-react";
import { motion } from "framer-motion";

import { spring } from "../lib/motion";
import { SEVERITY_META } from "../lib/findings";
import type { ProcessNode, Severity } from "../lib/types";

interface TreeNodeProps {
  node: ProcessNode;
  childrenMap: Map<number, ProcessNode[]>;
  depth: number;
  selectedId: number | null;
  expanded: Set<number>;
  /** Max severity directly attributed to a node. */
  nodeSeverity: Map<number, Severity>;
  /** Max severity anywhere in a node's subtree (hot-branch highlight). */
  branchSeverity: Map<number, Severity>;
  onSelect: (id: number) => void;
  onToggle: (id: number) => void;
}

export function TreeNode({
  node,
  childrenMap,
  depth,
  selectedId,
  expanded,
  nodeSeverity,
  branchSeverity,
  onSelect,
  onToggle,
}: TreeNodeProps) {
  const kids = childrenMap.get(node.node_id) ?? [];
  const hasKids = kids.length > 0;
  const isOpen = expanded.has(node.node_id);
  const selected = selectedId === node.node_id;
  const directSev = nodeSeverity.get(node.node_id);
  const branchSev = branchSeverity.get(node.node_id);

  return (
    <>
      <motion.div
        layout
        initial={{ opacity: 0, y: -3 }}
        animate={{ opacity: 1, y: 0 }}
        transition={spring.panel}
        className={`tnode${selected ? " tnode--selected" : ""}${branchSev ? " tnode--hot" : ""}`}
        data-hot={branchSev ? "true" : undefined}
        style={{
          paddingLeft: `calc(${depth} * var(--sp-5) + var(--sp-2))`,
          ...(branchSev ? { ["--branch" as string]: SEVERITY_META[branchSev].color } : {}),
        }}
        onClick={() => onSelect(node.node_id)}
      >
        <button
          type="button"
          className={`tnode__caret${hasKids ? "" : " tnode__caret--leaf"}`}
          onClick={(e) => {
            e.stopPropagation();
            if (hasKids) onToggle(node.node_id);
          }}
          tabIndex={-1}
        >
          {hasKids && (
            <ChevronRight
              size={13}
              strokeWidth={2}
              style={{ transform: isOpen ? "rotate(90deg)" : "none" }}
            />
          )}
        </button>

        <Box size={14} strokeWidth={1.75} className="tnode__icon" />

        <span className="tnode__name" title={node.image}>
          {node.name || "(unknown)"}
        </span>

        <span className="tnode__pid tnum">{node.pid}</span>

        <span className="tnode__spacer" />

        {directSev && (
          <span
            className="sev-score tnum"
            style={{ ["--sev" as string]: SEVERITY_META[directSev].color, ["--sev-soft" as string]: SEVERITY_META[directSev].soft }}
            title={`${SEVERITY_META[directSev].label} · suspicion ${node.suspicion}`}
          >
            {node.suspicion}
          </span>
        )}

        {node.event_count > 0 && (
          <span className="badge tnum" title="events attributed to this process">
            {node.event_count.toLocaleString()}
          </span>
        )}

        <span
          className={`dot dot--${node.status}`}
          title={
            node.status === "running"
              ? "running"
              : `exited${node.exit_code != null ? ` (code ${node.exit_code})` : ""}`
          }
        />
      </motion.div>

      {hasKids &&
        isOpen &&
        kids.map((child) => (
          <TreeNode
            key={child.node_id}
            node={child}
            childrenMap={childrenMap}
            depth={depth + 1}
            selectedId={selectedId}
            expanded={expanded}
            nodeSeverity={nodeSeverity}
            branchSeverity={branchSeverity}
            onSelect={onSelect}
            onToggle={onToggle}
          />
        ))}
    </>
  );
}
