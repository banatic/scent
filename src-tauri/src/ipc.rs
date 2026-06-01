//! Tauri command surface + capture orchestration.
//!
//! `start_capture` wires the whole pipeline in the spec-mandated order:
//! launch suspended -> seed root -> bring ETW fully online -> resume. The ETW
//! `UserTrace` is owned by a dedicated control thread (so it never needs to be
//! `Send` for managed state); start/stop are coordinated over channels.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::{bounded, unbounded, Sender};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tauri::{AppHandle, State};

use std::collections::HashSet;

use crate::deep::{self, DeepSession};
use crate::emit::run_emit_loop;
use crate::etw::{self, EtwState};
use crate::exporter;
use crate::launcher::{self, SendHandle};
use std::sync::OnceLock;

use crate::modmap;
use crate::model::{Category, Event, Finding};
use crate::peb;
use crate::sigma::{self, RuleSet};
use crate::store::{
    Capture, Captured, CaptureStatus, DeepFinding, EventFilter, EventPage, ProcessTree,
};
use crate::triage;

/// Handles needed to tear a running capture down.
pub struct CaptureControl {
    stop_tx: Sender<()>,
    running: Arc<AtomicBool>,
    process: SendHandle,
    thread: SendHandle,
    deep: Option<DeepSession>,
}

pub struct AppState {
    pub capture: Arc<RwLock<Capture>>,
    pub control: Mutex<Option<CaptureControl>>,
    /// Curated Sigma rules, loaded once on first capture and shared read-only.
    ruleset: OnceLock<Arc<RuleSet>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            capture: Arc::new(RwLock::new(Capture::new(std::process::id()))),
            control: Mutex::new(None),
            ruleset: OnceLock::new(),
        }
    }

    /// The shared ruleset, loading it (~once, lazily) on first use.
    fn ruleset(&self) -> Arc<RuleSet> {
        self.ruleset
            .get_or_init(|| Arc::new(sigma::load_default_ruleset()))
            .clone()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
pub struct StartInfo {
    pub root_pid: u32,
}

#[tauri::command]
pub fn start_capture(
    app: AppHandle,
    state: State<AppState>,
    path: String,
    args: Vec<String>,
    deep: bool,
) -> Result<StartInfo, String> {
    if state.control.lock().is_some() {
        return Err("A capture is already running.".into());
    }

    let own_pid = std::process::id();
    {
        let mut cap = state.capture.write();
        cap.reset(own_pid);
        cap.set_drive_map(launcher::dos_device_map());
    }

    // 1. Launch the target suspended — we get its PID before it runs anything.
    let launched = launcher::create_suspended(&path, &args)?;

    // 2. Seed the root node now (its ProcessStart predates our ETW session).
    state.capture.write().seed_root(
        launched.pid,
        own_pid,
        launched.create_time,
        launched.image.clone(),
        Some(launched.cmdline.clone()),
    );

    // Live subtree PID set shared with the deep session; the ingest thread keeps
    // it in sync with the tracker.
    let deep_tracked: Arc<RwLock<HashSet<u32>>> =
        Arc::new(RwLock::new(HashSet::from([launched.pid])));

    // 3. Bring ETW fully online on a control thread that owns the UserTrace.
    //    The shared EtwState is seeded with the root PID before the session
    //    starts so the very first descendant events are in scope.
    let etw_state = Arc::new(parking_lot::Mutex::new(EtwState::new()));
    etw_state.lock().track(launched.pid);

    let (raw_tx, raw_rx) = unbounded();
    let (ready_tx, ready_rx) = bounded::<Result<(), String>>(1);
    let (stop_tx, stop_rx) = bounded::<()>(1);

    let etw_state_thread = etw_state.clone();
    std::thread::spawn(move || match etw::start_session(raw_tx, etw_state_thread) {
        Ok(trace) => {
            let _ = ready_tx.send(Ok(()));
            let _ = stop_rx.recv(); // park until stop requested
            let _ = trace.stop();
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
        }
    });

    // 4. Don't resume until the session is confirmed live (capture from t=0).
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            state.capture.write().set_admin_error(e.clone());
            launcher::terminate(launched.process);
            launcher::close(launched.thread);
            launcher::close(launched.process);
            state.capture.write().stop();
            return Err(e);
        }
        Err(_) => return Err("ETW control thread terminated unexpectedly.".into()),
    }

    let running = Arc::new(AtomicBool::new(true));

    // 5. Ingest thread: drain the channel into the store in bursts (one write
    //    lock per burst) so the ETW callback never blocks on the store. After
    //    each burst, sync the deep-session scope to the live subtree.
    {
        let capture = state.capture.clone();
        let deep_tracked = deep_tracked.clone();
        let ruleset = state.ruleset();
        std::thread::spawn(move || {
            while let Ok(first) = raw_rx.recv() {
                // Drain the burst, then recover child command lines from the PEB
                // *before* taking the store lock — OpenProcess + cross-process
                // reads must not be held under the write lock (or run in a callback).
                let mut burst = vec![first];
                while let Ok(next) = raw_rx.try_recv() {
                    burst.push(next);
                }
                for c in burst.iter_mut() {
                    if let Captured::ProcCreate { pid, cmdline, .. } = c {
                        if cmdline.is_none() {
                            *cmdline = peb::read_command_line(*pid);
                        }
                    }
                }
                let live = {
                    let mut w = capture.write();
                    for c in burst {
                        // Detection (Sigma + heuristics) runs on each stored event
                        // in this same ingest thread, under the one write lock.
                        if let Some(id) = w.ingest(c) {
                            w.detect_event(id, &ruleset);
                        }
                    }
                    w.live_pids()
                };
                *deep_tracked.write() = live;
            }
        });
    }

    // 5b. Deep mode (optional): scoped stack-walk on Kernel-File Create → caller
    //     DLL attribution. Best-effort — if it fails we still run the normal capture.
    let deep_session = if deep {
        let (deep_tx, deep_rx) = unbounded::<deep::StackSample>();
        let keep_all: deep::PathFilter = Arc::new(|_p: &str| true);
        match DeepSession::start(deep_tracked.clone(), keep_all, deep_tx) {
            Ok(session) => {
                let capture = state.capture.clone();
                std::thread::spawn(move || {
                    let mut cache: std::collections::HashMap<u32, Vec<modmap::Module>> =
                        std::collections::HashMap::new();
                    while let Ok(s) = deep_rx.recv() {
                        let mut mods = cache
                            .entry(s.pid)
                            .or_insert_with(|| modmap::snapshot(s.pid))
                            .clone();
                        let mut stack_caller = modmap::caller_dll(&s.user_addrs, &mods);
                        let mut thread_module = modmap::thread_start_module(s.tid, &mods);
                        if stack_caller.is_none() && thread_module.is_none() {
                            // Modules may have loaded after the snapshot; refresh once.
                            mods = modmap::snapshot(s.pid);
                            stack_caller = modmap::caller_dll(&s.user_addrs, &mods);
                            thread_module = modmap::thread_start_module(s.tid, &mods);
                            cache.insert(s.pid, mods.clone());
                        }
                        let frames = modmap::resolve_frames(&s.user_addrs, &mods);
                        let (caller, tier) = if stack_caller.is_some() {
                            (stack_caller, "stack")
                        } else if thread_module.is_some() {
                            (thread_module.clone(), "thread")
                        } else {
                            (None, "none")
                        };
                        let benign = caller
                            .as_deref()
                            .and_then(modmap::benign_caller)
                            .map(|b| b.to_string());
                        capture.write().add_deep_finding(
                            s.pid,
                            s.tid,
                            s.path,
                            caller,
                            tier,
                            thread_module,
                            s.failed,
                            benign,
                            frames,
                        );
                    }
                });
                Some(session)
            }
            Err(e) => {
                eprintln!("[deep] disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    // 6. Emit thread: batched ~10 Hz summary deltas.
    {
        let capture = state.capture.clone();
        let running = running.clone();
        let app = app.clone();
        std::thread::spawn(move || run_emit_loop(app, capture, running));
    }

    // 7. Resume the target — full capture is now in place.
    launcher::resume(launched.thread)?;

    // 8. Best-effort root-exit watch (ETW also delivers the root ProcessStop).
    {
        let process = launched.process;
        std::thread::spawn(move || {
            let _ = launcher::wait_exit(process);
        });
    }

    *state.control.lock() = Some(CaptureControl {
        stop_tx,
        running,
        process: launched.process,
        thread: launched.thread,
        deep: deep_session,
    });

    Ok(StartInfo {
        root_pid: launched.pid,
    })
}

/// Tear down a running capture: stop the emit loop, stop the ETW session (which
/// drops the callback senders and ends the ingest thread), and close handles.
/// Safe to call when nothing is running.
pub fn stop_capture_inner(state: &AppState) {
    if let Some(ctrl) = state.control.lock().take() {
        ctrl.running.store(false, Ordering::Relaxed);
        let _ = ctrl.stop_tx.send(());
        if let Some(deep) = ctrl.deep {
            deep.stop();
        }
        launcher::close(ctrl.thread);
        launcher::close(ctrl.process);
    }
    state.capture.write().stop();
}

#[tauri::command]
pub fn stop_capture(state: State<AppState>) -> Result<(), String> {
    stop_capture_inner(&state);
    Ok(())
}

#[tauri::command]
pub fn get_status(state: State<AppState>) -> CaptureStatus {
    state.capture.read().status()
}

#[tauri::command]
pub fn get_process_tree(state: State<AppState>) -> ProcessTree {
    state.capture.read().tree()
}

#[tauri::command]
pub fn query_events(
    state: State<AppState>,
    filter: EventFilter,
    offset: u64,
    limit: u64,
) -> EventPage {
    state.capture.read().query(&filter, offset, limit)
}

#[tauri::command]
pub fn get_event_detail(state: State<AppState>, id: u64) -> Option<Event> {
    state.capture.read().event_detail(id)
}

#[tauri::command]
pub fn get_deep_findings(state: State<AppState>) -> Vec<DeepFinding> {
    state.capture.read().deep_findings().to_vec()
}

#[tauri::command]
pub fn get_findings(state: State<AppState>) -> Vec<Finding> {
    state.capture.read().findings().to_vec()
}

/// Build the deterministic LLM-triage bundle (always available; no key needed).
#[tauri::command]
pub fn get_triage_bundle(state: State<AppState>) -> triage::TriageBundle {
    triage::build_bundle(&state.capture.read())
}

/// Run the optional Anthropic triage. Builds the bundle under the read lock, then
/// releases it before the (blocking) network call. Errors clearly if no API key.
#[tauri::command]
pub fn run_triage(state: State<AppState>) -> Result<triage::Verdict, String> {
    let bundle = triage::build_bundle(&state.capture.read());
    triage::run(&bundle)
}

/// Write a report. For `jsonl`/`html`/`markdown`, `path` is the target file; for
/// `csv`, `path` is a directory into which per-category CSVs are written.
#[tauri::command]
pub fn export_report(state: State<AppState>, format: String, path: String) -> Result<(), String> {
    let cap = state.capture.read();
    let status = cap.status();
    let nodes = cap.nodes();
    let events = cap.events();
    let write = |p: &str, content: String| std::fs::write(p, content).map_err(|e| e.to_string());

    match format.as_str() {
        "jsonl" => write(&path, exporter::to_jsonl(events)),
        "html" => write(&path, exporter::to_html(&status, nodes, events)),
        "markdown" => write(&path, exporter::to_markdown(&status, nodes, events)),
        "csv" => {
            let dir = std::path::Path::new(&path);
            for (cat, name) in [
                (Category::File, "file"),
                (Category::Registry, "registry"),
                (Category::Network, "network"),
                (Category::Dns, "dns"),
                (Category::Process, "process"),
            ] {
                let file = dir.join(format!("scent_{name}.csv"));
                std::fs::write(&file, exporter::to_csv(cat, events, nodes))
                    .map_err(|e| format!("{}: {e}", file.display()))?;
            }
            Ok(())
        }
        other => Err(format!("unknown export format: {other}")),
    }
}
