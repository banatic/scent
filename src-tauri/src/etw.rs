//! ETW consumer for the six behavior categories.
//!
//! All providers share ONE real-time session (one processing thread), so the
//! callbacks run sequentially. They share an `Arc<Mutex<EtwState>>` that holds
//! the in-scope PID set and the FileObject/KeyObject -> name correlation maps.
//! Scoping happens here at the source (drop out-of-scope events before sending),
//! and high-volume events are rejected by a cheap event-id check before any
//! schema work. Only fully-resolved, in-scope `Captured` events reach the store.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crossbeam_channel::Sender;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use parking_lot::Mutex;
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_PROPERTIES,
};

use crate::model::{FileOp, NetDir, Proto, RegOp};
use crate::store::Captured;

const SESSION_NAME: &str = "scent-capture";

const GUID_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const GUID_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const GUID_REGISTRY: &str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
const GUID_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const GUID_DNS: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

// Kernel-Process keywords
const KP_PROCESS: u64 = 0x10;
const KP_IMAGE: u64 = 0x40;
// Kernel-File keywords (READ deliberately omitted — highest volume, lowest signal)
const KF_CREATE: u64 = 0x80;
const KF_WRITE: u64 = 0x200;
const KF_DELETE_PATH: u64 = 0x400;
const KF_RENAME_PATH: u64 = 0x800;

const FILE_MAP_CAP: usize = 200_000;

struct RegEntry {
    relative: String,
    base: u64,
}

/// Shared correlation + scoping state. Single ETW processing thread → the lock
/// is essentially uncontended.
pub struct EtwState {
    tracked: HashSet<u32>,
    file_names: HashMap<u64, String>, // FileObject/FileKey -> name
    reg: HashMap<u64, RegEntry>,      // KeyObject -> (relative, base)
    dns_seen: HashSet<(u32, String, u32)>,
}

impl EtwState {
    pub fn new() -> Self {
        Self {
            tracked: HashSet::new(),
            file_names: HashMap::new(),
            reg: HashMap::new(),
            dns_seen: HashSet::new(),
        }
    }

    pub fn track(&mut self, pid: u32) {
        self.tracked.insert(pid);
    }

    /// Resolve a registry KeyObject to a full path by walking base links.
    fn resolve_reg(&self, obj: u64) -> Option<String> {
        let mut segs: Vec<String> = Vec::new();
        let mut cur = obj;
        let mut depth = 0;
        while cur != 0 && depth < 32 {
            let Some(e) = self.reg.get(&cur) else { break };
            if !e.relative.is_empty() {
                segs.push(e.relative.clone());
                let abs = e.relative.starts_with("\\REGISTRY")
                    || e.relative.starts_with("\\Registry");
                if abs {
                    break;
                }
            }
            cur = e.base;
            depth += 1;
        }
        if segs.is_empty() {
            return None;
        }
        segs.reverse();
        Some(segs.join("\\"))
    }
}

impl Default for EtwState {
    fn default() -> Self {
        Self::new()
    }
}

fn ipv4(addr: u32) -> String {
    let b = addr.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

// ---- Per-provider handlers -------------------------------------------------

fn on_process(
    record: &EventRecord,
    locator: &SchemaLocator,
    state: &Arc<Mutex<EtwState>>,
    tx: &Sender<Captured>,
) {
    let id = record.event_id();
    if id != 1 && id != 2 && id != 5 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    match id {
        1 => {
            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else { return };
            let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
            {
                let mut st = state.lock();
                if !st.tracked.contains(&ppid) {
                    return;
                }
                st.tracked.insert(pid);
            }
            let image: String = parser.try_parse("ImageName").unwrap_or_default();
            let start_key: u64 = parser.try_parse("ProcessSequenceNumber").unwrap_or(0);
            let _ = tx.send(Captured::ProcCreate {
                pid,
                ppid,
                start_key,
                image,
            });
        }
        2 => {
            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else { return };
            {
                let mut st = state.lock();
                if !st.tracked.remove(&pid) {
                    return;
                }
            }
            let exit_code = parser.try_parse::<u32>("ExitCode").ok().map(|c| c as i64);
            let _ = tx.send(Captured::ProcExit { pid, exit_code });
        }
        5 => {
            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else { return };
            if !state.lock().tracked.contains(&pid) {
                return;
            }
            let image: String = parser.try_parse("ImageName").unwrap_or_default();
            let base: u64 = parser.try_parse("ImageBase").unwrap_or(0);
            let _ = tx.send(Captured::Image { pid, image, base });
        }
        _ => {}
    }
}

fn on_file(
    record: &EventRecord,
    locator: &SchemaLocator,
    state: &Arc<Mutex<EtwState>>,
    tx: &Sender<Captured>,
) {
    let id = record.event_id();
    if id != 12 && id != 16 && id != 26 && id != 27 {
        return;
    }
    let pid = record.process_id();
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);

    match id {
        12 => {
            let fobj: Option<u64> = parser.try_parse("FileObject").ok();
            let name: String = parser.try_parse("FileName").unwrap_or_default();
            // CreateOptions packs the NtCreateFile disposition in its top 8 bits.
            // FILE_SUPERSEDE(0)/FILE_CREATE(2)/FILE_OVERWRITE_IF(5) imply a write/new
            // file; FILE_OPEN(1)/FILE_OPEN_IF(3)/FILE_OVERWRITE(4) are opens.
            let create_options: u32 = parser.try_parse("CreateOptions").unwrap_or(0);
            let op = match create_options >> 24 {
                0 | 2 | 5 => FileOp::Create,
                _ => FileOp::Open,
            };
            {
                let mut st = state.lock();
                if !st.tracked.contains(&pid) {
                    return;
                }
                if let Some(fo) = fobj {
                    if st.file_names.len() < FILE_MAP_CAP {
                        st.file_names.insert(fo, name.clone());
                    }
                }
            }
            let _ = tx.send(Captured::File {
                pid,
                op,
                path: name,
            });
        }
        16 => {
            let fobj: Option<u64> = parser.try_parse("FileObject").ok();
            let fkey: Option<u64> = parser.try_parse("FileKey").ok();
            let path = {
                let st = state.lock();
                if !st.tracked.contains(&pid) {
                    return;
                }
                fobj.and_then(|o| st.file_names.get(&o).cloned())
                    .or_else(|| fkey.and_then(|k| st.file_names.get(&k).cloned()))
                    .unwrap_or_else(|| "(opened before capture)".to_string())
            };
            let _ = tx.send(Captured::File {
                pid,
                op: FileOp::Write,
                path,
            });
        }
        26 | 27 => {
            let path: String = parser.try_parse("FilePath").unwrap_or_default();
            if !state.lock().tracked.contains(&pid) {
                return;
            }
            let op = if id == 26 { FileOp::Delete } else { FileOp::Rename };
            let _ = tx.send(Captured::File { pid, op, path });
        }
        _ => {}
    }
}

fn on_registry(
    record: &EventRecord,
    locator: &SchemaLocator,
    state: &Arc<Mutex<EtwState>>,
    tx: &Sender<Captured>,
) {
    let id = record.event_id();
    // 1 CreateKey, 2 OpenKey, 3 DeleteKey, 5 SetValueKey, 6 DeleteValueKey, 13 CloseKey
    if !matches!(id, 1 | 2 | 3 | 5 | 6 | 13) {
        return;
    }
    let pid = record.process_id();
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let obj: u64 = parser.try_parse("KeyObject").unwrap_or(0);

    match id {
        1 | 2 => {
            let rel: String = parser.try_parse("RelativeName").unwrap_or_default();
            let base: u64 = parser.try_parse("BaseObject").unwrap_or(0);
            let disp: u32 = parser.try_parse("Disposition").unwrap_or(0);
            let full = {
                let mut st = state.lock();
                if !st.tracked.contains(&pid) {
                    return;
                }
                if obj != 0 {
                    st.reg.insert(
                        obj,
                        RegEntry {
                            relative: rel.clone(),
                            base,
                        },
                    );
                }
                st.resolve_reg(obj).unwrap_or(rel)
            };
            // Emit only newly-created keys (Disposition 1 == REG_CREATED_NEW_KEY).
            if id == 1 && disp == 1 {
                let _ = tx.send(Captured::Reg {
                    pid,
                    op: RegOp::CreateKey,
                    path: full,
                    value: None,
                });
            }
        }
        3 => {
            let full = {
                let st = state.lock();
                if !st.tracked.contains(&pid) {
                    return;
                }
                st.resolve_reg(obj).unwrap_or_default()
            };
            let _ = tx.send(Captured::Reg {
                pid,
                op: RegOp::DeleteKey,
                path: full,
                value: None,
            });
        }
        5 | 6 => {
            let value: String = parser.try_parse("ValueName").unwrap_or_default();
            let full = {
                let st = state.lock();
                if !st.tracked.contains(&pid) {
                    return;
                }
                st.resolve_reg(obj).unwrap_or_else(|| "(unknown key)".to_string())
            };
            let op = if id == 5 {
                RegOp::SetValue
            } else {
                RegOp::DeleteValue
            };
            let _ = tx.send(Captured::Reg {
                pid,
                op,
                path: full,
                value: Some(value),
            });
        }
        13 => {
            state.lock().reg.remove(&obj);
        }
        _ => {}
    }
}

fn on_network(
    record: &EventRecord,
    locator: &SchemaLocator,
    state: &Arc<Mutex<EtwState>>,
    tx: &Sender<Captured>,
) {
    let id = record.event_id();
    // 12 = TCP connection attempted (outbound), 15 = connection accepted (inbound)
    if id != 12 && id != 15 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let pid: u32 = parser
        .try_parse::<u32>("PID")
        .unwrap_or_else(|_| record.process_id());
    if !state.lock().tracked.contains(&pid) {
        return;
    }
    let daddr: u32 = parser.try_parse("daddr").unwrap_or(0);
    let saddr: u32 = parser.try_parse("saddr").unwrap_or(0);
    // Ports are stored in network byte order; ferrisetw parses them as native
    // u16, so swap back (e.g. 0xBB01=47873 -> 0x01BB=443).
    let dport: u16 = parser.try_parse::<u16>("dport").unwrap_or(0).swap_bytes();
    let sport: u16 = parser.try_parse::<u16>("sport").unwrap_or(0).swap_bytes();
    let direction = if id == 12 {
        NetDir::Outbound
    } else {
        NetDir::Inbound
    };
    let _ = tx.send(Captured::Net {
        pid,
        proto: Proto::Tcp,
        direction,
        local: format!("{}:{}", ipv4(saddr), sport),
        remote: ipv4(daddr),
        remote_port: dport,
    });
}

fn on_dns(
    record: &EventRecord,
    locator: &SchemaLocator,
    state: &Arc<Mutex<EtwState>>,
    tx: &Sender<Captured>,
) {
    let Ok(schema) = locator.event_schema(record) else { return };
    let parser = Parser::create(record, &schema);
    let Ok(query) = parser.try_parse::<String>("QueryName") else { return };
    if query.is_empty() {
        return;
    }
    // Only completion events carry QueryResults — using them dedups start/finish.
    let Ok(results) = parser.try_parse::<String>("QueryResults") else { return };
    let qtype: u32 = parser.try_parse("QueryType").unwrap_or(0);
    let pid = record.process_id();
    {
        let mut st = state.lock();
        if !st.tracked.contains(&pid) {
            return;
        }
        if !st.dns_seen.insert((pid, query.clone(), qtype)) {
            return;
        }
    }
    let _ = tx.send(Captured::Dns {
        pid,
        query,
        qtype,
        results: Some(results).filter(|s| !s.is_empty()),
    });
}

/// Stop a real-time session by name. Real-time ETW sessions outlive the process
/// if it's killed without cleanup, so we proactively stop a leaked one before
/// starting — otherwise it keeps the kernel buffering events and a same-named
/// `start` collides.
pub fn stop_session(name: &str) {
    #[repr(C)]
    struct Props {
        props: EVENT_TRACE_PROPERTIES,
        name: [u16; 512],
    }
    let mut p: Props = unsafe { std::mem::zeroed() };
    p.props.Wnode.BufferSize = std::mem::size_of::<Props>() as u32;
    p.props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        // Ignore the result — "not found" is the normal, expected case.
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wname.as_ptr()),
            &mut p.props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Live session statistics from ControlTrace(QUERY). `events_lost` / buffer-lost
/// counts reveal whether throughput is dropping events (vs simply delivering fewer).
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionStats {
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub realtime_buffers_lost: u32,
    pub number_of_buffers: u32,
    pub free_buffers: u32,
    pub buffers_written: u32,
    pub log_file_mode: u32,
}

/// Query a running session's stats by name (call while it's still alive).
pub fn query_session_stats(name: &str) -> Option<SessionStats> {
    #[repr(C)]
    struct Props {
        props: EVENT_TRACE_PROPERTIES,
        name: [u16; 512],
    }
    let mut p: Props = unsafe { std::mem::zeroed() };
    p.props.Wnode.BufferSize = std::mem::size_of::<Props>() as u32;
    p.props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let err = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wname.as_ptr()),
            &mut p.props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if err.0 != 0 {
        return None;
    }
    Some(SessionStats {
        events_lost: p.props.EventsLost,
        log_buffers_lost: p.props.LogBuffersLost,
        realtime_buffers_lost: p.props.RealTimeBuffersLost,
        number_of_buffers: p.props.NumberOfBuffers,
        free_buffers: p.props.FreeBuffers,
        buffers_written: p.props.BuffersWritten,
        log_file_mode: p.props.LogFileMode,
    })
}

/// Start the multi-provider real-time session. The returned `UserTrace` must be
/// kept alive (dropping it stops the trace) and stopped via `trace.stop()`.
pub fn start_session(
    tx: Sender<Captured>,
    state: Arc<Mutex<EtwState>>,
) -> Result<UserTrace, String> {
    stop_session(SESSION_NAME);

    macro_rules! cb {
        ($handler:ident) => {{
            let tx = tx.clone();
            let state = state.clone();
            move |record: &EventRecord, locator: &SchemaLocator| {
                $handler(record, locator, &state, &tx);
            }
        }};
    }

    let process = Provider::by_guid(GUID_PROCESS)
        .any(KP_PROCESS | KP_IMAGE)
        .add_callback(cb!(on_process))
        .build();
    let file = Provider::by_guid(GUID_FILE)
        .any(KF_CREATE | KF_WRITE | KF_DELETE_PATH | KF_RENAME_PATH)
        .add_callback(cb!(on_file))
        .build();
    let registry = Provider::by_guid(GUID_REGISTRY)
        .add_callback(cb!(on_registry))
        .build();
    let network = Provider::by_guid(GUID_NETWORK)
        .add_callback(cb!(on_network))
        .build();
    let dns = Provider::by_guid(GUID_DNS)
        .add_callback(cb!(on_dns))
        .build();

    UserTrace::new()
        .named(SESSION_NAME.to_string())
        .enable(process)
        .enable(file)
        .enable(registry)
        .enable(network)
        .enable(dns)
        .start_and_process()
        .map_err(|e| format!("Failed to start ETW session (administrator required?): {e:?}"))
}
