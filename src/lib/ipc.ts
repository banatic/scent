// Thin typed wrappers over the Tauri command + event bridge. The frontend never
// streams raw events; it consumes batched deltas and pulls detail on demand.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";

export type ExportFormat = "jsonl" | "html" | "markdown" | "csv";

import type {
  CaptureDelta,
  CaptureStatus,
  DeepFinding,
  EventFilter,
  EventPage,
  ProcessTree,
  ScentEvent,
  StartInfo,
} from "./types";

export const DELTA_EVENT = "capture://delta";

export function startCapture(
  path: string,
  args: string[],
  deep: boolean,
): Promise<StartInfo> {
  return invoke<StartInfo>("start_capture", { path, args, deep });
}

export function getDeepFindings(): Promise<DeepFinding[]> {
  return invoke<DeepFinding[]>("get_deep_findings");
}

export function stopCapture(): Promise<void> {
  return invoke("stop_capture");
}

export function getStatus(): Promise<CaptureStatus> {
  return invoke<CaptureStatus>("get_status");
}

export function getProcessTree(): Promise<ProcessTree> {
  return invoke<ProcessTree>("get_process_tree");
}

export function queryEvents(
  filter: EventFilter,
  offset: number,
  limit: number,
): Promise<EventPage> {
  return invoke<EventPage>("query_events", { filter, offset, limit });
}

export function getEventDetail(id: number): Promise<ScentEvent | null> {
  return invoke<ScentEvent | null>("get_event_detail", { id });
}

export function onDelta(cb: (delta: CaptureDelta) => void): Promise<UnlistenFn> {
  return listen<CaptureDelta>(DELTA_EVENT, (e) => cb(e.payload));
}

/** Open a native file picker for the target executable. */
export async function pickExecutable(): Promise<string | null> {
  const selected = await open({
    multiple: false,
    directory: false,
    title: "Select target executable",
    filters: [{ name: "Executable", extensions: ["exe"] }],
  });
  return typeof selected === "string" ? selected : null;
}

export function exportReport(format: ExportFormat, path: string): Promise<void> {
  return invoke("export_report", { format, path });
}

const EXPORT_FILE: Record<Exclude<ExportFormat, "csv">, { name: string; ext: string }> = {
  jsonl: { name: "events.jsonl", ext: "jsonl" },
  html: { name: "scent-report.html", ext: "html" },
  markdown: { name: "scent-summary.md", ext: "md" },
};

/** Pick a destination and run the export. Returns the path written, or null if cancelled. */
export async function runExport(format: ExportFormat): Promise<string | null> {
  let dest: string | null;
  if (format === "csv") {
    const dir = await open({ directory: true, multiple: false, title: "Choose a folder for CSVs" });
    dest = typeof dir === "string" ? dir : null;
  } else {
    const f = EXPORT_FILE[format];
    dest = await save({ defaultPath: f.name, filters: [{ name: f.ext, extensions: [f.ext] }] });
  }
  if (!dest) return null;
  await exportReport(format, dest);
  return dest;
}
