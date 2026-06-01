// Verdict-first landing view. Findings are an accelerator, not a gate — when none
// fire, this panel says so and points at the always-available raw views. Cards are
// an opaque DATA surface (no glass), sorted by severity. Each card: a severity
// badge, the technique title, ATT&CK chips, a plain-language line, the responsible
// process, and a jump to the raw evidence rows.

import { useState } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";

import { formatTime } from "../lib/events";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  severityRank,
  sortFindings,
  sourceLabel,
} from "../lib/findings";
import type { Finding, ProcessNode, Severity } from "../lib/types";

interface FindingsPanelProps {
  findings: Finding[];
  nodesById: Map<number, ProcessNode>;
  suspicion: number;
  selectedId: number | null;
  onSelectFinding: (f: Finding) => void;
  onShowEvidence: (f: Finding) => void;
}

export function FindingsPanel({
  findings,
  nodesById,
  suspicion,
  selectedId,
  onSelectFinding,
  onShowEvidence,
}: FindingsPanelProps) {
  const [minSeverity, setMinSeverity] = useState<Severity | null>(null);

  if (findings.length === 0) {
    return (
      <div className="view-empty findings-empty">
        <ShieldCheck size={26} strokeWidth={1.5} />
        <p className="empty__title">No findings</p>
        <p className="empty__hint">
          Nothing matched a Sigma rule or invariant heuristic yet. Findings only
          accelerate triage — the raw <b>events</b>, <b>tree</b>, <b>graph</b>, and{" "}
          <b>timeline</b> stand on their own and are always available.
        </p>
      </div>
    );
  }

  const sorted = sortFindings(findings);
  const visible = minSeverity
    ? sorted.filter((f) => severityRank(f.severity) >= severityRank(minSeverity))
    : sorted;
  const tally = SEVERITY_ORDER.map((s) => ({
    sev: s,
    n: findings.filter((f) => f.severity === s).length,
  })).filter((t) => t.n > 0);

  return (
    <div className="findings">
      <div className="findings__bar">
        <ShieldAlert size={16} strokeWidth={1.9} />
        <span className="findings__score tnum" title="Σ severity weight">
          {suspicion}
        </span>
        <span className="findings__score-label">suspicion</span>
        <div className="findings__tally" role="group" aria-label="Filter by minimum severity">
          {tally.map(({ sev, n }) => (
            <SeverityPill
              key={sev}
              sev={sev}
              count={n}
              dimmed={minSeverity != null && severityRank(sev) < severityRank(minSeverity)}
              onClick={() => setMinSeverity((cur) => (cur === sev ? null : sev))}
            />
          ))}
        </div>
        <span className="events__count tnum">
          {visible.length < findings.length
            ? `${visible.length} / ${findings.length}`
            : findings.length}
        </span>
      </div>

      <div className="findings__list scroll">
        {visible.map((f) => (
          <FindingCard
            key={f.id}
            f={f}
            proc={procLabel(f, nodesById)}
            selected={selectedId === f.id}
            onSelect={onSelectFinding}
            onShowEvidence={onShowEvidence}
          />
        ))}
      </div>
    </div>
  );
}

function procLabel(f: Finding, nodesById: Map<number, ProcessNode>): string | null {
  if (f.actor_node == null) return null;
  const n = nodesById.get(f.actor_node);
  return n ? `${n.name} · ${n.pid}` : `node ${f.actor_node}`;
}

function SeverityPill({
  sev,
  count,
  dimmed,
  onClick,
}: {
  sev: Severity;
  count: number;
  dimmed: boolean;
  onClick: () => void;
}) {
  const m = SEVERITY_META[sev];
  return (
    <button
      type="button"
      className={`sev-pill tnum${dimmed ? " sev-pill--dim" : ""}`}
      style={{ ["--sev" as string]: m.color, ["--sev-soft" as string]: m.soft }}
      onClick={onClick}
      title={`Show ≥ ${m.label}`}
    >
      {count} {m.label}
    </button>
  );
}

function FindingCard({
  f,
  proc,
  selected,
  onSelect,
  onShowEvidence,
}: {
  f: Finding;
  proc: string | null;
  selected: boolean;
  onSelect: (f: Finding) => void;
  onShowEvidence: (f: Finding) => void;
}) {
  const m = SEVERITY_META[f.severity];
  return (
    <div
      className={`finding-card${selected ? " finding-card--sel" : ""}`}
      style={{ ["--sev" as string]: m.color, ["--sev-soft" as string]: m.soft }}
      onClick={() => onSelect(f)}
      role="button"
      tabIndex={0}
    >
      <span className="finding-card__bar" />
      <div className="finding-card__body">
        <div className="finding-card__head">
          <span className="sev-badge">{m.label}</span>
          <span className="finding-card__title" title={f.title}>
            {f.title}
          </span>
          <span className="finding-card__src">{sourceLabel(f)}</span>
        </div>
        {f.description && <p className="finding-card__desc">{f.description}</p>}
        {f.evidence_labels && f.evidence_labels.length > 0 && (
          <ul className="finding-card__ind">
            {f.evidence_labels.map((t) => (
              <li key={t} title={t}>
                {t}
              </li>
            ))}
          </ul>
        )}
        <div className="finding-card__meta">
          {f.technique.map((t) => (
            <span key={t} className="attack-chip">
              {t}
            </span>
          ))}
          {proc && <span className="finding-card__proc">{proc}</span>}
          <span className="finding-card__time tnum">{formatTime(f.ts_ms)}</span>
          {f.evidence.length > 0 && (
            <button
              className="finding-card__evidence"
              onClick={(e) => {
                e.stopPropagation();
                onShowEvidence(f);
              }}
            >
              {f.evidence.length} evidence →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
