// Mirrors the serde-serialized shapes from the Rust backend (src-tauri/src).

export type Category =
  | "process"
  | "file"
  | "registry"
  | "network"
  | "dns"
  | "module";

export type ProcStatus = "running" | "exited";
export type FileOpKind = "create" | "open" | "read" | "write" | "delete" | "rename";
export type RegOpKind = "create_key" | "set_value" | "delete_key" | "delete_value";
export type Proto = "tcp" | "udp";
export type NetDir = "outbound" | "inbound";

export interface CategoryCounts {
  process: number;
  file: number;
  registry: number;
  network: number;
  dns: number;
  module: number;
}

export interface ProcessNode {
  node_id: number;
  parent_node_id: number | null;
  pid: number;
  ppid: number;
  start_key: number;
  image: string;
  name: string;
  cmdline: string | null;
  status: ProcStatus;
  started_ms: number;
  exited_ms: number | null;
  exit_code: number | null;
  event_count: number;
  counts: CategoryCounts;
  /** Accumulated Σ severity weight of findings attributed to this node. */
  suspicion: number;
}

// ---- Findings (mirrors model.rs Finding / Severity / FindingSource) ---------
export type Severity = "info" | "low" | "med" | "high" | "critical";

export type FindingSource =
  | { type: "sigma"; rule_id: string }
  | { type: "stateful"; kind: string }
  | { type: "deep" };

export interface Finding {
  id: number;
  ts_ms: number;
  /** ATT&CK technique ids (e.g. "T1059.001"). */
  technique: string[];
  severity: Severity;
  title: string;
  description: string;
  actor_node: number | null;
  source: FindingSource;
  /** Event ids that justify the finding (drives the "show evidence" jump). */
  evidence: number[];
  /** Verbatim indicators resolved from `evidence` (loaded DLL / file / registry
   *  key / host) — names *which* indicator fired. Omitted when empty. */
  evidence_labels?: string[];
}

export interface ProcessTree {
  root_node_id: number | null;
  version: number;
  nodes: ProcessNode[];
}

// Event is a discriminated union on `kind` (serde flattens the kind fields).
interface EventBase {
  id: number;
  ts_ms: number;
  pid: number;
  node_id: number | null;
  category: Category;
  /** Number of merged occurrences in a collapsed query (absent otherwise). */
  dup_count?: number | null;
}

export type ScentEvent = EventBase &
  (
    | { kind: "proc_create"; child_pid: number; image: string; cmdline: string | null }
    | { kind: "proc_exit"; exit_code: number | null }
    | { kind: "file_op"; op: FileOpKind; path: string }
    | { kind: "reg_op"; op: RegOpKind; path: string; value: string | null }
    | {
        kind: "net_conn";
        proto: Proto;
        direction: NetDir;
        local: string;
        remote: string;
        remote_port: number;
      }
    | { kind: "dns"; query: string; qtype: number; results: string | null }
    | { kind: "image_load"; image: string; base: number }
  );

export interface CaptureStatus {
  running: boolean;
  root_pid: number | null;
  elapsed_ms: number;
  total_events: number;
  process_count: number;
  live_count: number;
  tree_version: number;
  counts: CategoryCounts;
  deep_count: number;
  findings_count: number;
  findings_version: number;
  suspicion: number;
  admin_error: string | null;
}

export interface CaptureDelta {
  running: boolean;
  elapsed_ms: number;
  total_events: number;
  process_count: number;
  live_count: number;
  tree_version: number;
  counts: CategoryCounts;
  deep_count: number;
  findings_count: number;
  findings_version: number;
  suspicion: number;
}

/** One resolved call-stack frame. */
export interface StackFrame {
  addr: number;
  module: string | null;
  offset: number;
  thunk: boolean;
}

/** Deep-mode caller attribution for a file-create probe. */
export interface DeepFinding {
  ts_ms: number;
  pid: number;
  tid: number;
  node_id: number | null;
  path: string;
  caller: string | null;
  tier: string; // "stack" | "thread" | "none"
  thread_module: string | null;
  failed: boolean;
  benign: string | null;
  frames: StackFrame[];
}

export interface EventFilter {
  category?: Category | null;
  node_id?: number | null;
  pid?: number | null;
  /** Free text; a `host:` / `path:` / `port:` prefix scopes the match to a field. */
  text?: string | null;
  hide_noise?: boolean | null;
  collapse?: boolean | null;
  /** Restrict to specific event ids (a finding's evidence). */
  event_ids?: number[] | null;
  /** Capture-relative time window (ms), inclusive — timeline brush. */
  ts_from?: number | null;
  ts_to?: number | null;
  // ---- Faceted filters (Phase 8.4) ----
  /** Per-category operation tokens: file create/open/read/write/delete/rename;
   *  registry create_key/set_value/delete_key/delete_value. */
  ops?: string[] | null;
  proto?: Proto | null;
  direction?: NetDir | null;
  port_min?: number | null;
  port_max?: number | null;
  /** Scope to these process nodes; with include_subtree, their descendants too. */
  node_ids?: number[] | null;
  include_subtree?: boolean | null;
}

export interface EventPage {
  total: number;
  offset: number;
  events: ScentEvent[];
}

export interface StartInfo {
  root_pid: number;
}

// ---- LLM triage (optional layer 3) — mirrors triage.rs ----------------------
export interface TriageBundle {
  system_prompt: string;
  context: string;
  ready_prompt: string;
}

export interface Verdict {
  assessment: string; // benign | suspicious | malicious | unknown
  confidence: string; // low | medium | high
  summary: string;
  key_observations: string[];
  cited_iocs: string[];
  recommended_actions: string[];
  uncertainties: string[];
  /** Raw model text when JSON parsing failed (nothing dropped). */
  raw?: string | null;
  model: string;
}
