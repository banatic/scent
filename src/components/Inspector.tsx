// Right-hand detail inspector: full fields of the selected event, deep finding,
// or process node. For a deep finding it renders the full call-stack chain (the
// "how"): syscall/loader thunks collapsed by default, the attributed caller frame
// highlighted.

import { useState } from "react";
import { ShieldCheck } from "lucide-react";

import { CATEGORY_META, dnsType, formatTime } from "../lib/events";
import type { DeepFinding, ProcessNode, ScentEvent } from "../lib/types";

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="insp__field">
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </div>
  );
}

function eventFields(e: ScentEvent): [string, React.ReactNode][] {
  switch (e.kind) {
    case "proc_create":
      return [["Child PID", e.child_pid], ["Image", e.image], ["Command line", e.cmdline]];
    case "proc_exit":
      return [["Exit code", e.exit_code ?? "—"]];
    case "file_op":
      return [["Operation", e.op], ["Path", e.path]];
    case "reg_op":
      return [["Operation", e.op.replace("_", " ")], ["Key", e.path], ["Value", e.value]];
    case "net_conn":
      return [
        ["Protocol", e.proto.toUpperCase()],
        ["Direction", e.direction],
        ["Local", e.local],
        ["Remote", `${e.remote}:${e.remote_port}`],
      ];
    case "dns":
      return [["Query", e.query], ["Type", dnsType(e.qtype)], ["Results", e.results]];
    case "image_load":
      return [["Image", e.image], ["Base", `0x${e.base.toString(16)}`]];
  }
}

function StackChain({ frames }: { frames: DeepFinding["frames"] }) {
  const [showThunks, setShowThunks] = useState(false);
  const callerIdx = frames.findIndex((f) => !f.thunk && f.module != null);
  const hidden = frames.filter((f) => f.thunk).length;

  return (
    <div className="stack">
      {frames.length === 0 && (
        <div className="muted stack__empty">
          No stack captured — attributed via thread start address.
        </div>
      )}
      {frames.map((f, i) => {
        if (!showThunks && f.thunk) return null;
        return (
          <div
            key={i}
            className={`frame${f.thunk ? " frame--thunk" : ""}${i === callerIdx ? " frame--caller" : ""}`}
          >
            <span className="frame__mod">{f.module ?? "unknown"}</span>
            <span className="frame__off tnum">
              {f.module ? `+0x${f.offset.toString(16)}` : `@0x${f.addr.toString(16)}`}
            </span>
          </div>
        );
      })}
      {hidden > 0 && (
        <button className="frame-toggle" onClick={() => setShowThunks((v) => !v)}>
          {showThunks ? "hide" : "show"} {hidden} system frame{hidden === 1 ? "" : "s"}
        </button>
      )}
    </div>
  );
}

export function Inspector({
  finding,
  event,
  node,
}: {
  finding: DeepFinding | null;
  event: ScentEvent | null;
  node: ProcessNode | null;
}) {
  if (finding) {
    return (
      <aside className="insp">
        <header className="insp__head">
          <span className="insp__title">{finding.caller ?? "unresolved caller"}</span>
          {finding.benign && (
            <span className="benign-tag" title={finding.benign}>
              <ShieldCheck size={11} />
              benign
            </span>
          )}
        </header>
        <dl className="insp__list">
          <Field label="Target" value={finding.path} mono />
          <Field
            label="Outcome"
            value={finding.failed ? "path not found (probe)" : "opened"}
          />
          <Field label="Caller (attributed)" value={finding.caller} />
          <Field label="Attribution" value={`tier: ${finding.tier}`} />
          <Field label="Thread start module" value={finding.thread_module} />
          <Field label="PID · TID" value={`${finding.pid} · ${finding.tid}`} mono />
          <Field label="Time" value={formatTime(finding.ts_ms)} mono />
        </dl>
        <div className="insp__section">
          <span className="insp__section-title">Call stack</span>
          <StackChain frames={finding.frames} />
        </div>
      </aside>
    );
  }

  if (event) {
    const meta = CATEGORY_META[event.category];
    return (
      <aside className="insp">
        <header className="insp__head">
          <span className="cat-tag" style={{ ["--c" as string]: meta.color }}>
            <span className="cat-tag__dot" />
            {meta.label}
          </span>
          <span className="insp__id tnum">#{event.id}</span>
        </header>
        <dl className="insp__list">
          <Field label="Time" value={formatTime(event.ts_ms)} mono />
          <Field label="PID" value={event.pid} mono />
          {eventFields(event).map(([k, v]) => (
            <Field key={k} label={k} value={v} mono={k !== "Operation" && k !== "Direction"} />
          ))}
        </dl>
      </aside>
    );
  }

  if (node) {
    return (
      <aside className="insp">
        <header className="insp__head">
          <span className="insp__title">{node.name}</span>
          <span className={`dot dot--${node.status}`} />
        </header>
        <dl className="insp__list">
          <Field label="PID" value={node.pid} mono />
          <Field label="Parent PID" value={node.ppid} mono />
          <Field label="Image" value={node.image} mono />
          <Field label="Command line" value={node.cmdline} mono />
          <Field label="Status" value={node.status} />
          <Field label="Started" value={formatTime(node.started_ms)} mono />
          <Field
            label="Exited"
            value={node.exited_ms != null ? formatTime(node.exited_ms) : null}
            mono
          />
          <Field label="Exit code" value={node.exit_code} mono />
          <Field label="Events" value={node.event_count} mono />
        </dl>
      </aside>
    );
  }

  return (
    <aside className="insp insp--empty">
      <p>Select a process, event, or deep finding to inspect.</p>
    </aside>
  );
}
