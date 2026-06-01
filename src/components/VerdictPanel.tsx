// LLM triage verdict — the optional third layer's human-facing edge. The verdict
// lives ONLY here; it never mutates Findings, so a hallucination can't overwrite
// the deterministic signals. Always offers the guarded bundle for manual use
// (copy → any model); the integrated "Run analysis" needs ANTHROPIC_API_KEY on
// the backend. Opaque DATA surface.

import { useCallback, useState } from "react";
import { Copy, Loader2, Sparkles } from "lucide-react";

import { getTriageBundle, runTriage } from "../lib/ipc";
import type { Verdict } from "../lib/types";

interface VerdictPanelProps {
  hasCapture: boolean;
}

const ASSESS_COLOR: Record<string, string> = {
  malicious: "var(--sev-critical)",
  suspicious: "var(--sev-high)",
  benign: "var(--status-running)",
  unknown: "var(--ink-3)",
};

export function VerdictPanel({ hasCapture }: VerdictPanelProps) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const copyBundle = useCallback(async () => {
    try {
      const b = await getTriageBundle();
      await navigator.clipboard.writeText(b.ready_prompt);
      setNote("Guarded prompt copied — paste into any LLM.");
    } catch {
      setNote("Could not build/copy the bundle.");
    }
  }, []);

  const run = useCallback(async () => {
    setRunning(true);
    setNote(null);
    try {
      setVerdict(await runTriage());
    } catch (e) {
      setVerdict(null);
      setNote(String(e));
    } finally {
      setRunning(false);
    }
  }, []);

  if (!hasCapture) {
    return <div className="view-empty">No capture yet — triage runs on captured telemetry.</div>;
  }

  return (
    <div className="verdict">
      <div className="verdict__bar">
        <Sparkles size={15} strokeWidth={1.9} />
        <span className="verdict__title">LLM Triage</span>
        <span className="verdict__guard">grounded in telemetry · findings stay immutable</span>
        <div className="verdict__actions">
          <button className="chip" onClick={copyBundle}>
            <Copy size={13} />
            Copy for LLM
          </button>
          <button className="btn btn--ghost" onClick={run} disabled={running}>
            {running ? <Loader2 size={14} className="spin" /> : <Sparkles size={14} />}
            Run analysis
          </button>
        </div>
      </div>

      <div className="verdict__body scroll">
        {note && <div className="verdict__note">{note}</div>}

        {!verdict && !note && (
          <p className="verdict__hint">
            scent builds a guarded, citation-ready bundle from the findings, IOCs, and
            process tree. <b>Copy for LLM</b> to run it anywhere, or <b>Run analysis</b>{" "}
            to use the backend Anthropic key. The result is advisory and appears only on
            this panel.
          </p>
        )}

        {verdict && <VerdictView v={verdict} />}
      </div>
    </div>
  );
}

function VerdictView({ v }: { v: Verdict }) {
  const color = ASSESS_COLOR[v.assessment] ?? "var(--ink-3)";
  return (
    <div className="verdict-card">
      <div className="verdict-card__head">
        <span className="assess-badge" style={{ ["--c" as string]: color }}>
          {v.assessment}
        </span>
        <span className="verdict-card__conf">confidence: {v.confidence}</span>
        <span className="verdict-card__model">{v.model}</span>
      </div>
      {v.summary && <p className="verdict-card__summary">{v.summary}</p>}

      <Section title="Key observations" items={v.key_observations} />
      <Section title="Cited indicators" items={v.cited_iocs} mono />
      <Section title="Recommended actions" items={v.recommended_actions} />
      <Section title="Uncertainties" items={v.uncertainties} />

      {v.raw && (
        <div className="verdict-sec">
          <span className="verdict-sec__title">Raw model output</span>
          <pre className="verdict-raw">{v.raw}</pre>
        </div>
      )}
    </div>
  );
}

function Section({ title, items, mono }: { title: string; items: string[]; mono?: boolean }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="verdict-sec">
      <span className="verdict-sec__title">{title}</span>
      <ul className={`verdict-sec__list${mono ? " mono" : ""}`}>
        {items.map((it, i) => (
          <li key={i}>{it}</li>
        ))}
      </ul>
    </div>
  );
}
