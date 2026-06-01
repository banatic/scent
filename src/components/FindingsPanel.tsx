// Verdict-first landing view. Findings are an accelerator, not a gate — when none
// fire, this panel says so and points at the always-available raw views. Cards are
// an opaque DATA surface (no glass), sorted by severity. Each card: a severity
// badge, the technique title, ATT&CK chips, a plain-language line, the responsible
// process, and a jump to the raw evidence rows.

import { ShieldAlert, ShieldCheck } from "lucide-react";

import { formatTime } from "../lib/events";
import { SEVERITY_META, SEVERITY_ORDER, sortFindings, sourceLabel } from "../lib/findings";
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
        <div className="findings__tally">
          {tally.map(({ sev, n }) => (
            <SeverityPill key={sev} sev={sev} count={n} />
          ))}
        </div>
        <span className="events__count tnum">{findings.length}</span>
      </div>

      <div className="findings__list scroll">
        {sorted.map((f) => (
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

function SeverityPill({ sev, count }: { sev: Severity; count: number }) {
  const m = SEVERITY_META[sev];
  return (
    <span
      className="sev-pill tnum"
      style={{ ["--sev" as string]: m.color, ["--sev-soft" as string]: m.soft }}
    >
      {count} {m.label}
    </span>
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
