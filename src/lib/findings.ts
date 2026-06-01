// Presentation helpers for findings + severity, shared across the verdict views.

import type { Finding, ProcessNode, Severity } from "./types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; soft: string; rank: number }
> = {
  critical: { label: "Critical", color: "var(--sev-critical)", soft: "var(--sev-critical-soft)", rank: 4 },
  high: { label: "High", color: "var(--sev-high)", soft: "var(--sev-high-soft)", rank: 3 },
  med: { label: "Medium", color: "var(--sev-med)", soft: "var(--sev-med-soft)", rank: 2 },
  low: { label: "Low", color: "var(--sev-low)", soft: "var(--sev-low-soft)", rank: 1 },
  info: { label: "Info", color: "var(--sev-info)", soft: "var(--sev-info-soft)", rank: 0 },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "med", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_META[s].rank;
}

/** Sort by severity (desc), then time (asc). */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ts_ms - b.ts_ms,
  );
}

export function sourceLabel(f: Finding): string {
  switch (f.source.type) {
    case "sigma":
      return "Sigma";
    case "stateful":
      return "Heuristic";
    case "deep":
      return "Deep";
  }
}

/** Max severity directly attributed to each node (by actor_node). */
export function directSeverityByNode(findings: Finding[]): Map<number, Severity> {
  const m = new Map<number, Severity>();
  for (const f of findings) {
    if (f.actor_node == null) continue;
    const cur = m.get(f.actor_node);
    if (!cur || severityRank(f.severity) > severityRank(cur)) m.set(f.actor_node, f.severity);
  }
  return m;
}

/** Propagate each node's severity up to its ancestors → "hot branch" highlight. */
export function branchSeverity(
  nodes: ProcessNode[],
  direct: Map<number, Severity>,
): Map<number, Severity> {
  const byId = new Map(nodes.map((n) => [n.node_id, n]));
  const out = new Map<number, Severity>();
  const bump = (id: number, s: Severity) => {
    const cur = out.get(id);
    if (!cur || severityRank(s) > severityRank(cur)) out.set(id, s);
  };
  for (const [nodeId, sev] of direct) {
    let cur: number | null = nodeId;
    let guard = 0;
    while (cur != null && guard++ < 256) {
      bump(cur, sev);
      cur = byId.get(cur)?.parent_node_id ?? null;
    }
  }
  return out;
}

/** MITRE ATT&CK technique id → reference URL (T1059.001 → …/T1059/001/). */
export function attackUrl(t: string): string {
  const id = t.replace(/^T/i, "");
  const [base, sub] = id.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/T${base}/${sub}/`
    : `https://attack.mitre.org/techniques/T${base}/`;
}
