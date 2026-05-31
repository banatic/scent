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
  text?: string | null;
  hide_noise?: boolean | null;
  collapse?: boolean | null;
}

export interface EventPage {
  total: number;
  offset: number;
  events: ScentEvent[];
}

export interface StartInfo {
  root_pid: number;
}
