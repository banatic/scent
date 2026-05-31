// Presentation helpers for events + categories, shared across views.

import type { Category, ScentEvent } from "./types";

export const CATEGORY_META: Record<
  Category,
  { label: string; color: string; short: string }
> = {
  process: { label: "Process", color: "var(--cat-process)", short: "P" },
  file: { label: "File", color: "var(--cat-file)", short: "F" },
  registry: { label: "Registry", color: "var(--cat-registry)", short: "R" },
  network: { label: "Network", color: "var(--cat-network)", short: "N" },
  dns: { label: "DNS", color: "var(--cat-dns)", short: "D" },
  module: { label: "Module", color: "var(--cat-module)", short: "M" },
};

export const CATEGORY_ORDER: Category[] = [
  "process",
  "file",
  "registry",
  "network",
  "dns",
  "module",
];

const DNS_TYPES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS",
};

export function dnsType(t: number): string {
  return DNS_TYPES[t] ?? `type ${t}`;
}

/** Compact mm:ss.mmm from capture-relative milliseconds. */
export function formatTime(ms: number): string {
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  const mil = Math.floor(ms % 1000);
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${String(mil).padStart(3, "0")}`;
}

/** A short operation verb + a target string for table/inspector rows. */
export function describeEvent(e: ScentEvent): { op: string; target: string } {
  switch (e.kind) {
    case "proc_create":
      return { op: "spawn", target: e.cmdline || e.image };
    case "proc_exit":
      return { op: "exit", target: e.exit_code == null ? "" : `code ${e.exit_code}` };
    case "file_op":
      return { op: e.op, target: e.path };
    case "reg_op":
      return {
        op: e.op.replace("_", " "),
        target: e.value ? `${e.path}  ⟶  ${e.value}` : e.path,
      };
    case "net_conn":
      return {
        op: e.direction === "outbound" ? "connect" : "accept",
        target: `${e.remote}:${e.remote_port}`,
      };
    case "dns":
      return { op: dnsType(e.qtype), target: e.query };
    case "image_load":
      return { op: "load", target: e.image };
  }
}

/** Heuristic highlights from the spec (persistence keys, external IPs, …). */
export function highlightOf(e: ScentEvent): string | null {
  if (e.kind === "reg_op") {
    const p = e.path.toLowerCase();
    if (p.includes("\\run") || p.includes("currentversion\\runonce")) {
      return "persistence";
    }
  }
  if (e.kind === "net_conn" && e.direction === "outbound") {
    if (!isPrivateIp(e.remote) && e.remote !== "0.0.0.0") return "external";
  }
  return null;
}

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")) {
    return true;
  }
  if (ip.startsWith("169.254.")) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) {
    const n = Number(m[1]);
    return n >= 16 && n <= 31;
  }
  return ip === "0.0.0.0";
}
