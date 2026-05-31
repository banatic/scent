// Export dropdown: jsonl / HTML report / CSV / Markdown. Picks a destination via
// the native dialog, then the backend writes the file(s).

import { useEffect, useRef, useState } from "react";
import { Check, Download, Loader } from "lucide-react";

import { runExport, type ExportFormat } from "../lib/ipc";

const OPTIONS: { format: ExportFormat; label: string; hint: string }[] = [
  { format: "html", label: "HTML report", hint: "self-contained .html" },
  { format: "jsonl", label: "Events JSONL", hint: "events.jsonl" },
  { format: "csv", label: "CSV per category", hint: "folder" },
  { format: "markdown", label: "Summary Markdown", hint: ".md" },
];

export function ExportMenu({ disabled }: { disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const onPick = async (format: ExportFormat) => {
    setBusy(format);
    try {
      const dest = await runExport(format);
      if (dest) {
        setDone(format);
        setTimeout(() => setDone(null), 2200);
      }
    } catch (e) {
      console.error("export failed", e);
      alert(`Export failed: ${e}`);
    } finally {
      setBusy(null);
      setOpen(false);
    }
  };

  return (
    <div className="export" ref={ref}>
      <button
        className="btn btn--ghost"
        disabled={disabled || busy !== null}
        onClick={() => setOpen((o) => !o)}
      >
        {busy ? <Loader size={14} className="spin" /> : <Download size={14} />}
        <span>Export</span>
      </button>
      {open && (
        <div className="export__menu">
          {OPTIONS.map((o) => (
            <button key={o.format} className="export__item" onClick={() => onPick(o.format)}>
              <span className="export__label">{o.label}</span>
              <span className="export__hint">{done === o.format ? <Check size={13} /> : o.hint}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
