import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Crosshair,
  Fingerprint,
  GitBranch,
  Network,
  ShieldAlert,
  Sparkles,
  Table2,
} from "lucide-react";

import { DeepPanel, findingKey } from "./components/DeepPanel";
import { EventsTable } from "./components/EventsTable";
import { ExportMenu } from "./components/ExportMenu";
import { FindingsPanel } from "./components/FindingsPanel";
import { GraphView } from "./components/GraphView";
import { Inspector } from "./components/Inspector";
import { IocPanel } from "./components/IocPanel";
import { ProcessTree } from "./components/ProcessTree";
import { Segmented, type SegOption } from "./components/Segmented";
import { TimelineView } from "./components/TimelineView";
import { TopBar } from "./components/TopBar";
import { VerdictPanel } from "./components/VerdictPanel";
import { branchSeverity, directSeverityByNode } from "./lib/findings";
import {
  getDeepFindings,
  getFindings,
  getProcessTree,
  getStatus,
  onDelta,
  pickExecutable,
  startCapture,
  stopCapture,
} from "./lib/ipc";
import type {
  CaptureStatus,
  Category,
  DeepFinding,
  Finding,
  ProcessNode,
  ProcessTree as ProcessTreeData,
  ScentEvent,
} from "./lib/types";

// Four top-level destinations. Evidence (the raw telemetry) is one place with a
// segmented lens switch — Table / Graph / Timeline are projections of the SAME
// event stream, and Deep (caller attribution) appears as a 4th lens only when it
// has data. This restores the hierarchy the old 7 flat tabs flattened.
type Tab = "findings" | "evidence" | "ioc" | "verdict";
type EvidenceView = "table" | "graph" | "timeline" | "deep";

const EMPTY_STATUS: CaptureStatus = {
  running: false,
  root_pid: null,
  elapsed_ms: 0,
  total_events: 0,
  process_count: 0,
  live_count: 0,
  tree_version: 0,
  counts: { process: 0, file: 0, registry: 0, network: 0, dns: 0, module: 0 },
  deep_count: 0,
  findings_count: 0,
  findings_version: 0,
  suspicion: 0,
  admin_error: null,
};

function tokenizeArgs(input: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) out.push(m[1] ?? m[2]);
  return out;
}

export default function App() {
  const [status, setStatus] = useState<CaptureStatus>(EMPTY_STATUS);
  const [tree, setTree] = useState<ProcessTreeData | null>(null);
  const [targetPath, setTargetPath] = useState("");
  const [args, setArgs] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [tab, setTab] = useState<Tab>("findings");
  const [evidenceView, setEvidenceView] = useState<EvidenceView>("table");
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<ScentEvent | null>(null);
  const [selectedDeep, setSelectedDeep] = useState<DeepFinding | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [eventCategory, setEventCategory] = useState<Category | null>(null);
  const [eventText, setEventText] = useState("");
  const [deepMode, setDeepMode] = useState(false);
  const [deepFindings, setDeepFindings] = useState<DeepFinding[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidenceIds, setEvidenceIds] = useState<number[] | null>(null);
  const [tsRange, setTsRange] = useState<{ from: number; to: number } | null>(null);

  const lastTreeVersion = useRef(-1);
  const lastDeepCount = useRef(-1);
  const lastFindingsVersion = useRef(-1);

  const refreshTree = useCallback(async (version: number) => {
    lastTreeVersion.current = version;
    try {
      setTree(await getProcessTree());
    } catch (e) {
      console.error("get_process_tree failed", e);
    }
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let active = true;
    (async () => {
      const s = await getStatus();
      if (!active) return;
      setStatus(s);
      if (s.tree_version !== lastTreeVersion.current) await refreshTree(s.tree_version);
      unlisten = await onDelta((d) => {
        setStatus((prev) => ({ ...prev, ...d }));
        if (d.tree_version !== lastTreeVersion.current) void refreshTree(d.tree_version);
        if (d.deep_count !== lastDeepCount.current) {
          lastDeepCount.current = d.deep_count;
          getDeepFindings().then(setDeepFindings).catch(() => {});
        }
        if (d.findings_version !== lastFindingsVersion.current) {
          lastFindingsVersion.current = d.findings_version;
          getFindings().then(setFindings).catch(() => {});
        }
      });
    })();
    return () => {
      active = false;
      unlisten?.();
    };
  }, [refreshTree]);

  const handlePick = useCallback(async () => {
    const picked = await pickExecutable();
    if (picked) {
      setTargetPath(picked);
      setError(null);
    }
  }, []);

  const handleStart = useCallback(async () => {
    if (!targetPath) return;
    setBusy(true);
    setError(null);
    setSelectedEvent(null);
    setSelectedNodeId(null);
    setSelectedFindingId(null);
    setDeepFindings([]);
    setFindings([]);
    setEvidenceIds(null);
    setTsRange(null);
    setEvidenceView("table");
    lastDeepCount.current = -1;
    lastFindingsVersion.current = -1;
    try {
      await startCapture(targetPath, tokenizeArgs(args), deepMode);
      const s = await getStatus();
      setStatus(s);
      await refreshTree(s.tree_version);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }, [targetPath, args, deepMode, refreshTree]);

  const handleStop = useCallback(async () => {
    setBusy(true);
    try {
      await stopCapture();
      setStatus(await getStatus());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  const handleToggle = useCallback((id: number) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const expanded = useMemo(() => {
    const set = new Set<number>();
    for (const n of tree?.nodes ?? []) if (!collapsed.has(n.node_id)) set.add(n.node_id);
    return set;
  }, [tree, collapsed]);

  const nodesById = useMemo(() => {
    const m = new Map<number, ProcessNode>();
    for (const n of tree?.nodes ?? []) m.set(n.node_id, n);
    return m;
  }, [tree]);

  const nodeSeverity = useMemo(() => directSeverityByNode(findings), [findings]);
  const branchSev = useMemo(
    () => branchSeverity(tree?.nodes ?? [], nodeSeverity),
    [tree, nodeSeverity],
  );

  const selectNode = useCallback((id: number) => {
    setSelectedNodeId(id);
    setSelectedEvent(null);
    setSelectedDeep(null);
  }, []);

  const selectEvent = useCallback((e: ScentEvent) => {
    setSelectedEvent(e);
    setSelectedDeep(null);
  }, []);

  const selectDeep = useCallback((f: DeepFinding) => {
    setSelectedDeep(f);
    setSelectedEvent(null);
    setSelectedNodeId(null);
  }, []);

  const selectFinding = useCallback((f: Finding) => {
    setSelectedFindingId(f.id);
    if (f.actor_node != null) {
      setSelectedNodeId(f.actor_node);
      setSelectedEvent(null);
      setSelectedDeep(null);
    }
  }, []);

  const showEvidence = useCallback((f: Finding) => {
    setEvidenceIds(f.evidence);
    setTsRange(null);
    setEventCategory(null);
    setSelectedNodeId(null);
    setTab("evidence");
    setEvidenceView("table");
  }, []);

  const onBrush = useCallback((range: { from: number; to: number }) => {
    setTsRange(range);
    setEvidenceIds(null);
    setTab("evidence");
    setEvidenceView("table");
  }, []);

  const evidenceOptions = useMemo<SegOption<EvidenceView>[]>(() => {
    const opts: SegOption<EvidenceView>[] = [
      { id: "table", label: "Table", icon: <Table2 size={13} /> },
      { id: "graph", label: "Graph", icon: <Network size={13} /> },
      { id: "timeline", label: "Timeline", icon: <GitBranch size={13} /> },
    ];
    if (status.deep_count > 0) {
      opts.push({
        id: "deep",
        label: "Deep",
        icon: <Crosshair size={13} />,
        badge: status.deep_count,
      });
    }
    return opts;
  }, [status.deep_count]);

  // Fall back to the table lens if Deep loses its data (e.g. a fresh capture).
  const evView: EvidenceView =
    evidenceView === "deep" && status.deep_count === 0 ? "table" : evidenceView;

  const selectedNode = selectedNodeId != null ? nodesById.get(selectedNodeId) ?? null : null;
  const banner = error ?? status.admin_error;

  return (
    <div className="app">
      <TopBar
        status={status}
        targetPath={targetPath}
        args={args}
        busy={busy}
        deep={deepMode}
        onDeepChange={setDeepMode}
        onPick={handlePick}
        onArgsChange={setArgs}
        onStart={handleStart}
        onStop={handleStop}
      />

      {banner && (
        <div className="banner" role="alert">
          <AlertTriangle size={15} strokeWidth={1.9} />
          <span>{banner}</span>
        </div>
      )}

      <div className="workbench">
        <div className="rail">
          <ProcessTree
            tree={tree}
            selectedId={selectedNodeId}
            expanded={expanded}
            nodeSeverity={nodeSeverity}
            branchSeverity={branchSev}
            onSelect={selectNode}
            onToggle={handleToggle}
          />
        </div>

        <div className="center">
          <div className="tabs">
            <TabButton id="findings" tab={tab} setTab={setTab} icon={<ShieldAlert size={14} />}>
              Findings
              {status.findings_count > 0 && (
                <span className="tab__badge tnum">{status.findings_count}</span>
              )}
            </TabButton>
            <TabButton id="evidence" tab={tab} setTab={setTab} icon={<Table2 size={14} />}>
              Evidence
            </TabButton>
            <TabButton id="ioc" tab={tab} setTab={setTab} icon={<Fingerprint size={14} />}>
              IOCs
            </TabButton>
            <TabButton id="verdict" tab={tab} setTab={setTab} icon={<Sparkles size={14} />}>
              Verdict
            </TabButton>

            {tab === "evidence" && (
              <>
                <span className="tabs__div" />
                <Segmented
                  value={evView}
                  options={evidenceOptions}
                  onChange={setEvidenceView}
                  layoutId="evidence-lens"
                />
              </>
            )}

            <div className="tabs__spacer" />
            <ExportMenu disabled={status.total_events === 0} />
          </div>

          <div className="view">
            {tab === "findings" && (
              <FindingsPanel
                findings={findings}
                nodesById={nodesById}
                suspicion={status.suspicion}
                selectedId={selectedFindingId}
                onSelectFinding={selectFinding}
                onShowEvidence={showEvidence}
              />
            )}
            {tab === "evidence" && evView === "table" && (
              <EventsTable
                category={eventCategory}
                onCategory={setEventCategory}
                text={eventText}
                onText={setEventText}
                nodeFilter={selectedNodeId}
                onClearNodeFilter={() => setSelectedNodeId(null)}
                evidenceIds={evidenceIds}
                onClearEvidence={() => setEvidenceIds(null)}
                tsRange={tsRange}
                onClearTsRange={() => setTsRange(null)}
                nodesById={nodesById}
                liveTotal={status.total_events}
                selectedEventId={selectedEvent?.id ?? null}
                onSelectEvent={selectEvent}
              />
            )}
            {tab === "evidence" && evView === "graph" && (
              <GraphView
                tree={tree}
                selectedNodeId={selectedNodeId}
                nodeSeverity={nodeSeverity}
                onSelectNode={selectNode}
              />
            )}
            {tab === "evidence" && evView === "timeline" && (
              <TimelineView
                status={status}
                findings={findings}
                onSelectEvent={selectEvent}
                onBrush={onBrush}
              />
            )}
            {tab === "evidence" && evView === "deep" && (
              <DeepPanel
                findings={deepFindings}
                nodesById={nodesById}
                selectedKey={selectedDeep ? findingKey(selectedDeep) : null}
                onSelect={selectDeep}
              />
            )}
            {tab === "ioc" && <IocPanel liveTotal={status.total_events} />}
            {tab === "verdict" && <VerdictPanel hasCapture={status.total_events > 0} />}
          </div>
        </div>

        <Inspector finding={selectedDeep} event={selectedEvent} node={selectedNode} />
      </div>
    </div>
  );
}

function TabButton({
  id,
  tab,
  setTab,
  icon,
  children,
}: {
  id: Tab;
  tab: Tab;
  setTab: (t: Tab) => void;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button className={`tab${tab === id ? " tab--on" : ""}`} onClick={() => setTab(id)}>
      {icon}
      {children}
    </button>
  );
}
