//! Thread-safe event store — the single source of truth.
//!
//! ETW callbacks resolve + scope events (see `etw`) and send `Captured` messages
//! over a channel to a single ingest thread that owns the write side. Tauri
//! commands take read snapshots and page/filter via `query`. `tree_version` bumps
//! on tree changes so the frontend refetches the tree lazily.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::model::{
    basename, Category, CategoryCounts, Event, EventKind, FileOp, NetDir, Proto, ProcStatus,
    ProcessNode, RegOp,
};
use crate::tracker::Tracker;

/// Fully-resolved, already-scoped event from the ETW layer.
#[derive(Clone, Debug)]
pub enum Captured {
    ProcCreate {
        pid: u32,
        ppid: u32,
        start_key: u64,
        image: String,
        /// Recovered from the child's PEB by the ingest thread (best-effort, heavy
        /// — never read inside an ETW callback). `None` for instant-exit children.
        cmdline: Option<String>,
    },
    ProcExit {
        pid: u32,
        exit_code: Option<i64>,
    },
    File {
        pid: u32,
        op: FileOp,
        path: String,
    },
    Reg {
        pid: u32,
        op: RegOp,
        path: String,
        value: Option<String>,
    },
    Net {
        pid: u32,
        proto: Proto,
        direction: NetDir,
        local: String,
        remote: String,
        remote_port: u16,
    },
    Dns {
        pid: u32,
        query: String,
        qtype: u32,
        results: Option<String>,
    },
    Image {
        pid: u32,
        image: String,
        base: u64,
    },
}

pub struct Capture {
    pub tracker: Tracker,
    nodes: Vec<ProcessNode>,
    events: Vec<Event>,
    started_at: Option<Instant>,
    next_event_id: u64,
    tree_version: u64,
    running: bool,
    root_node_id: Option<u64>,
    root_pid: Option<u32>,
    counts: CategoryCounts,
    admin_error: Option<String>,
    /// NT device path -> DOS drive letter, for path normalization at ingest.
    drive_map: Vec<(String, String)>,
    /// Deep-mode caller attributions (populated when deep capture is on).
    deep_findings: Vec<DeepFinding>,
}

#[derive(Clone, Serialize)]
pub struct CaptureStatus {
    pub running: bool,
    pub root_pid: Option<u32>,
    pub elapsed_ms: u64,
    pub total_events: u64,
    pub process_count: u64,
    pub live_count: u64,
    pub tree_version: u64,
    pub counts: CategoryCounts,
    pub deep_count: u64,
    pub admin_error: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ProcessTree {
    pub root_node_id: Option<u64>,
    pub version: u64,
    pub nodes: Vec<ProcessNode>,
}

/// ~10 Hz summary pushed over the `capture://delta` event.
#[derive(Clone, Serialize)]
pub struct CaptureDelta {
    pub running: bool,
    pub elapsed_ms: u64,
    pub total_events: u64,
    pub process_count: u64,
    pub live_count: u64,
    pub tree_version: u64,
    pub counts: CategoryCounts,
    pub deep_count: u64,
}

/// Query parameters from the frontend (all optional, ANDed).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct EventFilter {
    pub category: Option<Category>,
    pub node_id: Option<u64>,
    pub pid: Option<u32>,
    pub text: Option<String>,
    /// Drop well-known system noise (file/module system paths).
    pub hide_noise: Option<bool>,
    /// Collapse identical (actor, op, target) into one row with a `dup_count`.
    pub collapse: Option<bool>,
}

#[derive(Clone, Serialize)]
pub struct EventPage {
    pub total: u64,
    pub offset: u64,
    pub events: Vec<Event>,
}

/// A deep-mode caller attribution for a file-create probe.
#[derive(Clone, Serialize)]
pub struct DeepFinding {
    pub ts_ms: u64,
    pub pid: u32,
    pub tid: u32,
    pub node_id: Option<u64>,
    pub path: String,
    /// Resolved caller DLL (the responsible module above syscall thunks).
    pub caller: Option<String>,
    /// How it was attributed: "stack" (tier 3), "thread" (tier 2 fallback), or "none".
    pub tier: String,
    /// Module owning the thread's start address (tier 2), for the inspector.
    pub thread_module: Option<String>,
    /// The probed path doesn't exist (a failed open — scanning behavior).
    pub failed: bool,
    /// Known-benign annotation for the caller (e.g. NVIDIA app-detection), if any.
    pub benign: Option<String>,
    /// The full resolved call stack (top frame first), for the inspector chain view.
    pub frames: Vec<crate::modmap::Frame>,
}

impl Capture {
    pub fn new(own_pid: u32) -> Self {
        Self {
            tracker: Tracker::new(own_pid),
            nodes: Vec::new(),
            events: Vec::new(),
            started_at: None,
            next_event_id: 0,
            tree_version: 0,
            running: false,
            root_node_id: None,
            root_pid: None,
            counts: CategoryCounts::default(),
            admin_error: None,
            drive_map: Vec::new(),
            deep_findings: Vec::new(),
        }
    }

    pub fn reset(&mut self, own_pid: u32) {
        *self = Capture::new(own_pid);
    }

    pub fn set_drive_map(&mut self, map: Vec<(String, String)>) {
        self.drive_map = map;
    }

    /// `\Device\HarddiskVolumeN\...` -> `C:\...`; other paths unchanged.
    fn normalize_path(&self, p: &str) -> String {
        if p.starts_with("\\Device") {
            for (dev, drive) in &self.drive_map {
                if let Some(tail) = p.strip_prefix(dev.as_str()) {
                    return format!("{drive}{tail}");
                }
            }
        }
        p.to_string()
    }

    /// `\REGISTRY\MACHINE\...` -> `HKLM\...`, `\REGISTRY\USER\...` -> `HKU\...`.
    fn normalize_reg(p: &str) -> String {
        if let Some(rest) = p.strip_prefix("\\REGISTRY\\MACHINE") {
            format!("HKLM{rest}")
        } else if let Some(rest) = p.strip_prefix("\\REGISTRY\\USER") {
            format!("HKU{rest}")
        } else {
            p.to_string()
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.started_at
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }

    /// Seed the synthesized root node (its ProcessStart predates our ETW session).
    pub fn seed_root(
        &mut self,
        pid: u32,
        ppid: u32,
        create_time: u64,
        image: String,
        cmdline: Option<String>,
    ) {
        self.started_at = Some(Instant::now());
        self.running = true;
        let node_id = self.nodes.len() as u64;
        let name = basename(&image);
        self.nodes.push(ProcessNode {
            node_id,
            parent_node_id: None,
            pid,
            ppid,
            start_key: create_time,
            image,
            name,
            cmdline,
            status: ProcStatus::Running,
            started_ms: 0,
            exited_ms: None,
            exit_code: None,
            event_count: 0,
            counts: CategoryCounts::default(),
        });
        self.tracker.add_live(pid, node_id);
        self.root_node_id = Some(node_id);
        self.root_pid = Some(pid);
        self.tree_version += 1;
    }

    fn push_event(&mut self, pid: u32, node_id: Option<u64>, kind: EventKind) {
        let category = kind.category();
        self.counts.bump(category);
        if let Some(nid) = node_id {
            let n = &mut self.nodes[nid as usize];
            n.event_count += 1;
            n.counts.bump(category);
        }
        let id = self.next_event_id;
        self.next_event_id += 1;
        let ts_ms = self.elapsed_ms();
        self.events.push(Event {
            id,
            ts_ms,
            pid,
            node_id,
            category,
            dup_count: None,
            kind,
        });
    }

    /// Apply one resolved event from the ETW layer.
    pub fn ingest(&mut self, c: Captured) {
        match c {
            Captured::ProcCreate {
                pid,
                ppid,
                start_key,
                image,
                cmdline,
            } => {
                if self.tracker.is_own(pid) {
                    return;
                }
                let Some(parent_node) = self.tracker.live_node(ppid) else {
                    return;
                };
                let image = self.normalize_path(&image);
                let ts_ms = self.elapsed_ms();
                let node_id = self.nodes.len() as u64;
                let name = basename(&image);
                self.nodes.push(ProcessNode {
                    node_id,
                    parent_node_id: Some(parent_node),
                    pid,
                    ppid,
                    start_key,
                    image: image.clone(),
                    name,
                    cmdline: cmdline.clone(),
                    status: ProcStatus::Running,
                    started_ms: ts_ms,
                    exited_ms: None,
                    exit_code: None,
                    event_count: 0,
                    counts: CategoryCounts::default(),
                });
                self.tracker.add_live(pid, node_id);
                self.push_event(
                    ppid,
                    Some(parent_node),
                    EventKind::ProcCreate {
                        child_pid: pid,
                        image,
                        cmdline,
                    },
                );
                self.tree_version += 1;
            }
            Captured::ProcExit { pid, exit_code } => {
                let Some(node_id) = self.tracker.remove_live(pid) else {
                    return;
                };
                let ts_ms = self.elapsed_ms();
                {
                    let n = &mut self.nodes[node_id as usize];
                    n.status = ProcStatus::Exited;
                    n.exited_ms = Some(ts_ms);
                    n.exit_code = exit_code;
                }
                self.push_event(pid, Some(node_id), EventKind::ProcExit { exit_code });
                self.tree_version += 1;
            }
            Captured::File { pid, op, path } => {
                let path = self.normalize_path(&path);
                let node = self.tracker.live_node(pid);
                self.push_event(pid, node, EventKind::FileOp { op, path });
            }
            Captured::Reg {
                pid,
                op,
                path,
                value,
            } => {
                let path = Self::normalize_reg(&path);
                let node = self.tracker.live_node(pid);
                self.push_event(pid, node, EventKind::RegOp { op, path, value });
            }
            Captured::Net {
                pid,
                proto,
                direction,
                local,
                remote,
                remote_port,
            } => {
                let node = self.tracker.live_node(pid);
                self.push_event(
                    pid,
                    node,
                    EventKind::NetConn {
                        proto,
                        direction,
                        local,
                        remote,
                        remote_port,
                    },
                );
            }
            Captured::Dns {
                pid,
                query,
                qtype,
                results,
            } => {
                let node = self.tracker.live_node(pid);
                self.push_event(
                    pid,
                    node,
                    EventKind::Dns {
                        query,
                        qtype,
                        results,
                    },
                );
            }
            Captured::Image { pid, image, base } => {
                let image = self.normalize_path(&image);
                let node = self.tracker.live_node(pid);
                self.push_event(pid, node, EventKind::ImageLoad { image, base });
            }
        }
    }

    pub fn set_admin_error(&mut self, msg: String) {
        self.admin_error = Some(msg);
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn status(&self) -> CaptureStatus {
        CaptureStatus {
            running: self.running,
            root_pid: self.root_pid,
            elapsed_ms: self.elapsed_ms(),
            total_events: self.next_event_id,
            process_count: self.nodes.len() as u64,
            live_count: self.tracker.live_count() as u64,
            tree_version: self.tree_version,
            counts: self.counts,
            deep_count: self.deep_findings.len() as u64,
            admin_error: self.admin_error.clone(),
        }
    }

    pub fn delta(&self) -> CaptureDelta {
        CaptureDelta {
            running: self.running,
            elapsed_ms: self.elapsed_ms(),
            total_events: self.next_event_id,
            process_count: self.nodes.len() as u64,
            live_count: self.tracker.live_count() as u64,
            tree_version: self.tree_version,
            counts: self.counts,
            deep_count: self.deep_findings.len() as u64,
        }
    }

    pub fn tree(&self) -> ProcessTree {
        ProcessTree {
            root_node_id: self.root_node_id,
            version: self.tree_version,
            nodes: self.nodes.clone(),
        }
    }

    pub fn event_detail(&self, id: u64) -> Option<Event> {
        self.events.get(id as usize).cloned()
    }

    /// All events in arrival order (for export).
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// All process nodes (for export).
    pub fn nodes(&self) -> &[ProcessNode] {
        &self.nodes
    }

    /// Currently-live tracked PIDs (for scoping the deep session).
    pub fn live_pids(&self) -> HashSet<u32> {
        self.tracker.live_pids()
    }

    /// Record a deep-mode caller attribution (stamps time + owning node).
    #[allow(clippy::too_many_arguments)]
    pub fn add_deep_finding(
        &mut self,
        pid: u32,
        tid: u32,
        path: String,
        caller: Option<String>,
        tier: &str,
        thread_module: Option<String>,
        failed: bool,
        benign: Option<String>,
        frames: Vec<crate::modmap::Frame>,
    ) {
        let ts_ms = self.elapsed_ms();
        let node_id = self.tracker.live_node(pid);
        self.deep_findings.push(DeepFinding {
            ts_ms,
            pid,
            tid,
            node_id,
            path,
            caller,
            tier: tier.to_string(),
            thread_module,
            failed,
            benign,
            frames,
        });
    }

    pub fn deep_findings(&self) -> &[DeepFinding] {
        &self.deep_findings
    }

    /// Page/filter events. Scans in arrival order; matching is ANDed.
    pub fn query(&self, filter: &EventFilter, offset: u64, limit: u64) -> EventPage {
        let text = filter
            .text
            .as_ref()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty());

        let hide_noise = filter.hide_noise.unwrap_or(false);
        let collapse = filter.collapse.unwrap_or(false);

        let matches = |e: &Event| -> bool {
            if let Some(cat) = filter.category {
                if e.category != cat {
                    return false;
                }
            }
            if let Some(nid) = filter.node_id {
                if e.node_id != Some(nid) {
                    return false;
                }
            }
            if let Some(pid) = filter.pid {
                if e.pid != pid {
                    return false;
                }
            }
            if let Some(t) = &text {
                if !e.kind.haystack().contains(t.as_str()) {
                    return false;
                }
            }
            if hide_noise && e.is_noise() {
                return false;
            }
            true
        };

        if collapse {
            // Merge identical (actor, op, target) events, preserving first-seen order.
            let mut index: HashMap<String, usize> = HashMap::new();
            let mut reps: Vec<Event> = Vec::new();
            for e in self.events.iter().filter(|e| matches(e)) {
                let key = e.dedup_key();
                if let Some(&i) = index.get(&key) {
                    reps[i].dup_count = Some(reps[i].dup_count.unwrap_or(1) + 1);
                } else {
                    index.insert(key, reps.len());
                    let mut rep = e.clone();
                    rep.dup_count = Some(1);
                    reps.push(rep);
                }
            }
            let total = reps.len() as u64;
            let events = reps
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            return EventPage {
                total,
                offset,
                events,
            };
        }

        let filtered: Vec<&Event> = self.events.iter().filter(|e| matches(e)).collect();
        let total = filtered.len() as u64;
        let events = filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        EventPage {
            total,
            offset,
            events,
        }
    }
}
