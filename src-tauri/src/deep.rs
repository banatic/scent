//! Deep mode: capture call stacks on Kernel-File **Create** events to attribute
//! the calling DLL of file probes.
//!
//! Built on ferrisetw (its real-time consumer reliably delivers Kernel-File
//! events with `StackTrace64` extended data). Stacks are enabled only on Create
//! (CREATE keyword) to avoid the full-file_op flood, with a large buffer pool.
//! Scoping is done in the callback: only events from the target subtree whose
//! path passes the `keep_path` predicate are kept (so a probe-only filter leaves
//! just the interesting events). The target's probing repeats, so even if the
//! kernel drops some system-wide events, repeated rounds capture the stack.
//!
//! (A PID-scoped raw `EVENT_FILTER_TYPE_PID` session — true ~0-loss — is tracked
//! separately as a future optimization; ferrisetw's `ByPids` writes 16-bit PIDs
//! and cannot scope.)

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{bounded, Sender};
use ferrisetw::native::ExtendedDataItem;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, UserTrace};
use ferrisetw::EventRecord;
use parking_lot::{Mutex, RwLock};

use crate::etw::{query_session_stats, stop_session, SessionStats};

const SESSION_NAME: &str = "scent-deep";
const GUID_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
/// CREATE keyword (event 12) + OP_END keyword (event 24 = OperationEnd w/ NTSTATUS).
const KF_CREATE: u64 = 0x80;
const KF_OP_END: u64 = 0x40;
const EVENT_FILE_CREATE: u16 = 12;
const EVENT_OP_END: u16 = 24;
/// STATUS_OBJECT_NAME_NOT_FOUND / STATUS_OBJECT_PATH_NOT_FOUND — a failed probe.
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_PATH_NOT_FOUND: u32 = 0xC000_003A;
/// x64 user-mode addresses are below this; kernel frames are above (skipped).
const USER_ADDR_MAX: u64 = 0x0000_8000_0000_0000;
const PENDING_CAP: usize = 100_000;

/// Create events kept by the deep callback (diagnostics).
pub static KEPT_EVENTS: AtomicUsize = AtomicUsize::new(0);

/// Predicate deciding which file paths to keep (e.g. probe paths only).
pub type PathFilter = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[derive(Clone, Debug)]
pub struct StackSample {
    pub pid: u32,
    pub tid: u32,
    pub path: String,
    /// User-mode return addresses, top frame first (for module resolution).
    pub user_addrs: Vec<u64>,
    /// The create failed because the path doesn't exist (a probe of a missing file).
    pub failed: bool,
}

/// A Create awaiting its OperationEnd (correlated by Irp) to learn success/failure.
struct Pending {
    pid: u32,
    tid: u32,
    path: String,
    user_addrs: Vec<u64>,
}

pub struct DeepSession {
    stop_tx: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl DeepSession {
    /// Start the deep session. `tracked` is the live in-scope PID set (shared with
    /// the tracker); `keep_path` selects which file paths to keep.
    pub fn start(
        tracked: Arc<RwLock<HashSet<u32>>>,
        keep_path: PathFilter,
        sink: Sender<StackSample>,
    ) -> Result<DeepSession, String> {
        let (ready_tx, ready_rx) = bounded::<Result<(), String>>(1);
        let (stop_tx, stop_rx) = bounded::<()>(1);

        // Correlate Create -> OperationEnd by Irp to learn success/failure. Single
        // ETW processing thread, so an uncontended Mutex is fine.
        let pending: Arc<Mutex<HashMap<u64, Pending>>> = Arc::new(Mutex::new(HashMap::new()));

        let worker = std::thread::spawn(move || {
            let provider = Provider::by_guid(GUID_FILE)
                .any(KF_CREATE | KF_OP_END)
                .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
                .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
                    let id = record.event_id();
                    if id != EVENT_FILE_CREATE && id != EVENT_OP_END {
                        return;
                    }
                    let Ok(schema) = locator.event_schema(record) else {
                        return;
                    };
                    let parser = Parser::create(record, &schema);

                    if id == EVENT_FILE_CREATE {
                        let pid = record.process_id();
                        if !tracked.read().contains(&pid) {
                            return;
                        }
                        let path: String = parser.try_parse("FileName").unwrap_or_default();
                        if !keep_path(&path) {
                            return;
                        }
                        let Ok(irp) = parser.try_parse::<u64>("Irp") else {
                            return;
                        };
                        let mut user_addrs = Vec::new();
                        for item in record.extended_data() {
                            if let ExtendedDataItem::StackTrace64(st) =
                                item.to_extended_data_item()
                            {
                                user_addrs.extend(
                                    st.addresses()
                                        .iter()
                                        .copied()
                                        .filter(|&a| a != 0 && a < USER_ADDR_MAX),
                                );
                            }
                        }
                        let mut map = pending.lock();
                        if map.len() < PENDING_CAP {
                            map.insert(
                                irp,
                                Pending {
                                    pid,
                                    tid: record.thread_id(),
                                    path,
                                    user_addrs,
                                },
                            );
                        }
                    } else {
                        // OperationEnd: match by Irp, learn the status, emit.
                        let Ok(irp) = parser.try_parse::<u64>("Irp") else {
                            return;
                        };
                        let Some(p) = pending.lock().remove(&irp) else {
                            return;
                        };
                        let status: u32 = parser.try_parse("Status").unwrap_or(0);
                        let failed = status == STATUS_NAME_NOT_FOUND
                            || status == STATUS_PATH_NOT_FOUND;
                        KEPT_EVENTS.fetch_add(1, Ordering::Relaxed);
                        let _ = sink.send(StackSample {
                            pid: p.pid,
                            tid: p.tid,
                            path: p.path,
                            user_addrs: p.user_addrs,
                            failed,
                        });
                    }
                })
                .build();

            let props = TraceProperties {
                buffer_size: 256, // KB per buffer
                min_buffer: 64,
                max_buffer: 320,
                flush_timer: Duration::from_secs(1),
                ..TraceProperties::default()
            };

            stop_session(SESSION_NAME); // clear any leak
            match UserTrace::new()
                .named(SESSION_NAME.to_string())
                .set_trace_properties(props)
                .enable(provider)
                .start_and_process()
            {
                Ok(trace) => {
                    let _ = ready_tx.send(Ok(()));
                    let _ = stop_rx.recv();
                    let _ = trace.stop();
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("deep ETW start failed: {e:?}")));
                }
            }
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(DeepSession {
                stop_tx,
                worker: Some(worker),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("deep control thread terminated".to_string()),
        }
    }

    pub fn stats(&self) -> Option<SessionStats> {
        query_session_stats(SESSION_NAME)
    }

    pub fn stop(mut self) {
        let _ = self.stop_tx.send(());
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
