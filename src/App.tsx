import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Crosshair, GitBranch, Network, Table2 } from "lucide-react";

import { DeepPanel, findingKey } from "./components/DeepPanel";
import { EventsTable } from "./components/EventsTable";
import { ExportMenu } from "./components/ExportMenu";
import { GraphView } from "./components/GraphView";
import { Inspector } from "./components/Inspector";
import { ProcessTree } from "./components/ProcessTree";
import { TimelineView } from "./components/TimelineView";
import { TopBar } from "./components/TopBar";
import {
  getDeepFindings,
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
  ProcessNode,
  ProcessTree as ProcessTreeData,
  ScentEvent,
} from "./lib/types";

type Tab = "events" | "graph" | "timeline" | "deep";

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

  const [tab, setTab] = useState<Tab>("events");
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<ScentEvent | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<DeepFinding | null>(null);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [eventCategory, setEventCategory] = useState<Category | null>(null);
  const [eventText, setEventText] = useState("");
  const [deepMode, setDeepMode] = useState(false);
  const [deepFindings, setDeepFindings] = useState<DeepFinding[]>([]);

  const lastTreeVersion = useRef(-1);
  const lastDeepCount = useRef(-1);

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
    setDeepFindings([]);
    lastDeepCount.current = -1;
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

  const selectNode = useCallback((id: number) => {
    setSelectedNodeId(id);
    setSelectedEvent(null);
    setSelectedFinding(null);
  }, []);

  const selectEvent = useCallback((e: ScentEvent) => {
    setSelectedEvent(e);
    setSelectedFinding(null);
  }, []);

  const selectFinding = useCallback((f: DeepFinding) => {
    setSelectedFinding(f);
    setSelectedEvent(null);
    setSelectedNodeId(null);
  }, []);

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
            onSelect={selectNode}
            onToggle={handleToggle}
          />
        </div>

        <div className="center">
          <div className="tabs">
            <TabButton id="events" tab={tab} setTab={setTab} icon={<Table2 size={14} />}>
              Events
            </TabButton>
            <TabButton id="graph" tab={tab} setTab={setTab} icon={<Network size={14} />}>
              Graph
            </TabButton>
            <TabButton id="timeline" tab={tab} setTab={setTab} icon={<GitBranch size={14} />}>
              Timeline
            </TabButton>
            <TabButton id="deep" tab={tab} setTab={setTab} icon={<Crosshair size={14} />}>
              Deep
              {status.deep_count > 0 && <span className="tab__badge tnum">{status.deep_count}</span>}
            </TabButton>
            <div className="tabs__spacer" />
            <ExportMenu disabled={status.total_events === 0} />
          </div>

          <div className="view">
            {tab === "events" && (
              <EventsTable
                category={eventCategory}
                onCategory={setEventCategory}
                text={eventText}
                onText={setEventText}
                nodeFilter={selectedNodeId}
                onClearNodeFilter={() => setSelectedNodeId(null)}
                nodesById={nodesById}
                liveTotal={status.total_events}
                selectedEventId={selectedEvent?.id ?? null}
                onSelectEvent={selectEvent}
              />
            )}
            {tab === "graph" && (
              <GraphView
                tree={tree}
                selectedNodeId={selectedNodeId}
                onSelectNode={selectNode}
              />
            )}
            {tab === "timeline" && (
              <TimelineView
                status={status}
                nodesById={nodesById}
                onSelectEvent={selectEvent}
              />
            )}
            {tab === "deep" && (
              <DeepPanel
                findings={deepFindings}
                nodesById={nodesById}
                selectedKey={selectedFinding ? findingKey(selectedFinding) : null}
                onSelect={selectFinding}
              />
            )}
          </div>
        </div>

        <Inspector finding={selectedFinding} event={selectedEvent} node={selectedNode} />
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
