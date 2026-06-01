// Auto-collected indicators of compromise: domains, external IPs, dropped files,
// and registry keys, harvested from the captured events. Defanged text + CSV copy
// for handoff. Opaque DATA surface. Consistent with the exporter's view of events.

import { useEffect, useMemo, useState } from "react";
import { Copy, FileWarning, Globe, KeyRound, Wifi } from "lucide-react";

import { queryEvents } from "../lib/ipc";
import type { ScentEvent } from "../lib/types";

interface IocPanelProps {
  /** Bumps when the capture grows, to trigger a refresh. */
  liveTotal: number;
}

interface Iocs {
  domains: string[];
  ips: string[];
  files: string[];
  regkeys: string[];
}

export function IocPanel({ liveTotal }: IocPanelProps) {
  const [events, setEvents] = useState<ScentEvent[]>([]);

  useEffect(() => {
    let active = true;
    const h = setTimeout(() => {
      queryEvents({}, 0, 50000)
        .then((p) => active && setEvents(p.events))
        .catch(() => {});
    }, 250);
    return () => {
      active = false;
      clearTimeout(h);
    };
  }, [liveTotal]);

  const iocs = useMemo(() => collect(events), [events]);
  const total =
    iocs.domains.length + iocs.ips.length + iocs.files.length + iocs.regkeys.length;

  if (liveTotal === 0) {
    return <div className="view-empty">No capture yet — indicators are collected here.</div>;
  }

  return (
    <div className="ioc">
      <div className="ioc__bar">
        <span className="ioc__title">Indicators</span>
        <span className="events__count tnum">{total}</span>
        <div className="ioc__actions">
          <CopyBtn label="Copy defanged" text={() => toText(iocs)} />
          <CopyBtn label="Copy CSV" text={() => toCsv(iocs)} />
        </div>
      </div>
      <div className="ioc__grid scroll">
        <IocGroup icon={<Globe size={14} />} title="Domains" items={iocs.domains} defang />
        <IocGroup icon={<Wifi size={14} />} title="External IPs" items={iocs.ips} defang />
        <IocGroup icon={<FileWarning size={14} />} title="Dropped files" items={iocs.files} />
        <IocGroup icon={<KeyRound size={14} />} title="Registry keys" items={iocs.regkeys} />
      </div>
    </div>
  );
}

function IocGroup({
  icon,
  title,
  items,
  defang: doDefang,
}: {
  icon: React.ReactNode;
  title: string;
  items: string[];
  defang?: boolean;
}) {
  return (
    <section className="ioc-group">
      <header className="ioc-group__head">
        {icon}
        <span>{title}</span>
        <span className="ioc-group__count tnum">{items.length}</span>
      </header>
      {items.length === 0 ? (
        <p className="ioc-group__empty">none</p>
      ) : (
        <ul className="ioc-group__list">
          {items.map((v) => (
            <li key={v} className="ioc-item" title={v}>
              {doDefang ? defang(v) : v}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CopyBtn({ label, text }: { label: string; text: () => string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="chip"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text());
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
    >
      <Copy size={13} />
      {done ? "Copied" : label}
    </button>
  );
}

// ---- collection ------------------------------------------------------------

const INTERESTING_EXT = /\.(exe|dll|sys|ps1|bat|cmd|vbs|js|jse|wsf|hta|scr|lnk|dat|bin|tmp)$/i;
const DROP_DIRS = /\\(temp|tmp|appdata|programdata|downloads|public|users\\[^\\]+\\)/i;
const SYS_NOISE = /\\windows\\(system32|syswow64|winsxs|servicing|softwaredistribution)\\/i;
const PERSIST = /(\\currentversion\\run|\\services\\|\\winlogon|\\image file execution|\\policies\\explorer\\run|startup)/i;

function collect(events: ScentEvent[]): Iocs {
  const domains = new Set<string>();
  const ips = new Set<string>();
  const files = new Set<string>();
  const regkeys = new Set<string>();

  for (const e of events) {
    switch (e.kind) {
      case "dns": {
        const q = e.query.trim().toLowerCase();
        if (q && !q.endsWith(".arpa") && q.includes(".")) domains.add(q);
        break;
      }
      case "net_conn": {
        if (e.direction === "outbound" && !isPrivateIp(e.remote)) ips.add(e.remote);
        break;
      }
      case "file_op": {
        if (e.op !== "create" && e.op !== "write") break;
        const p = e.path;
        if (SYS_NOISE.test(p)) break;
        if (INTERESTING_EXT.test(p) || DROP_DIRS.test(p)) files.add(p);
        break;
      }
      case "reg_op": {
        const key = e.value ? `${e.path}\\${e.value}` : e.path;
        if (PERSIST.test(key)) regkeys.add(key);
        break;
      }
    }
  }

  const sortCap = (s: Set<string>, cap = 500) => [...s].sort().slice(0, cap);
  return {
    domains: sortCap(domains),
    ips: sortCap(ips),
    files: sortCap(files),
    regkeys: sortCap(regkeys),
  };
}

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")) return true;
  if (ip.startsWith("169.254.") || ip === "0.0.0.0") return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) {
    const n = Number(m[1]);
    return n >= 16 && n <= 31;
  }
  return false;
}

function defang(s: string): string {
  return s.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

function toText(i: Iocs): string {
  const block = (title: string, items: string[], fang: boolean) =>
    items.length ? `# ${title}\n${items.map((v) => (fang ? defang(v) : v)).join("\n")}\n` : "";
  return [
    block("Domains", i.domains, true),
    block("IPs", i.ips, true),
    block("Files", i.files, false),
    block("Registry", i.regkeys, false),
  ]
    .filter(Boolean)
    .join("\n");
}

function toCsv(i: Iocs): string {
  const esc = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  const rows = ["type,value"];
  for (const v of i.domains) rows.push(`domain,${esc(v)}`);
  for (const v of i.ips) rows.push(`ip,${esc(v)}`);
  for (const v of i.files) rows.push(`file,${esc(v)}`);
  for (const v of i.regkeys) rows.push(`regkey,${esc(v)}`);
  return rows.join("\n");
}
