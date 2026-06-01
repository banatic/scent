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
    basename, Category, CategoryCounts, Event, EventKind, FileOp, Finding, FindingSource, NetDir,
    Proto, ProcStatus, ProcessNode, RegOp, Severity,
};
use crate::sigma::RuleSet;
use crate::sigma_fields::sigma_view;
use crate::stateful::{self, Input, InputKind};
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
    /// Triage findings (Sigma + stateful heuristics), in detection order.
    findings: Vec<Finding>,
    findings_version: u64,
    next_finding_id: u64,
    /// Capture-wide Σ severity weight.
    total_suspicion: u64,
    /// Stateful-heuristic memory (beaconing / DNS / ransom / self-delete).
    stateful: stateful::State,
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
    pub findings_count: u64,
    pub findings_version: u64,
    pub suspicion: u64,
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
    pub findings_count: u64,
    pub findings_version: u64,
    pub suspicion: u64,
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
    /// Restrict to specific event ids (a finding's evidence — "show evidence" jump).
    pub event_ids: Option<Vec<u64>>,
    /// Capture-relative time window (ms), inclusive — the timeline brush selection.
    pub ts_from: Option<u64>,
    pub ts_to: Option<u64>,

    // ---- Faceted filters (Phase 8.4) ----
    /// Per-category operation facet — file/registry op tokens (`EventKind::op_token`).
    /// Events with no op concept are excluded when this is set.
    pub ops: Option<Vec<String>>,
    /// Network facets (apply only to net events; non-net events excluded when set).
    pub proto: Option<Proto>,
    pub direction: Option<NetDir>,
    pub port_min: Option<u16>,
    pub port_max: Option<u16>,
    /// Scope to these process nodes; with `include_subtree`, their descendants too.
    pub node_ids: Option<Vec<u64>>,
    pub include_subtree: Option<bool>,
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
            findings: Vec::new(),
            findings_version: 0,
            next_finding_id: 0,
            total_suspicion: 0,
            stateful: stateful::State::default(),
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
            suspicion: 0,
        });
        self.tracker.add_live(pid, node_id);
        self.root_node_id = Some(node_id);
        self.root_pid = Some(pid);
        self.tree_version += 1;
    }

    fn push_event(&mut self, pid: u32, node_id: Option<u64>, kind: EventKind) -> u64 {
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
        id
    }

    /// Apply one resolved event from the ETW layer. Returns the id of the event it
    /// pushed (so the ingest thread can run detection on it), or `None` if dropped.
    pub fn ingest(&mut self, c: Captured) -> Option<u64> {
        match c {
            Captured::ProcCreate {
                pid,
                ppid,
                start_key,
                image,
                cmdline,
            } => {
                if self.tracker.is_own(pid) {
                    return None;
                }
                let Some(parent_node) = self.tracker.live_node(ppid) else {
                    return None;
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
                    suspicion: 0,
                });
                self.tracker.add_live(pid, node_id);
                let eid = self.push_event(
                    ppid,
                    Some(parent_node),
                    EventKind::ProcCreate {
                        child_pid: pid,
                        image,
                        cmdline,
                    },
                );
                self.tree_version += 1;
                Some(eid)
            }
            Captured::ProcExit { pid, exit_code } => {
                let Some(node_id) = self.tracker.remove_live(pid) else {
                    return None;
                };
                let ts_ms = self.elapsed_ms();
                {
                    let n = &mut self.nodes[node_id as usize];
                    n.status = ProcStatus::Exited;
                    n.exited_ms = Some(ts_ms);
                    n.exit_code = exit_code;
                }
                let eid = self.push_event(pid, Some(node_id), EventKind::ProcExit { exit_code });
                self.tree_version += 1;
                Some(eid)
            }
            Captured::File { pid, op, path } => {
                let path = self.normalize_path(&path);
                let node = self.tracker.live_node(pid);
                Some(self.push_event(pid, node, EventKind::FileOp { op, path }))
            }
            Captured::Reg {
                pid,
                op,
                path,
                value,
            } => {
                let path = Self::normalize_reg(&path);
                let node = self.tracker.live_node(pid);
                Some(self.push_event(pid, node, EventKind::RegOp { op, path, value }))
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
                Some(self.push_event(
                    pid,
                    node,
                    EventKind::NetConn {
                        proto,
                        direction,
                        local,
                        remote,
                        remote_port,
                    },
                ))
            }
            Captured::Dns {
                pid,
                query,
                qtype,
                results,
            } => {
                let node = self.tracker.live_node(pid);
                Some(self.push_event(
                    pid,
                    node,
                    EventKind::Dns {
                        query,
                        qtype,
                        results,
                    },
                ))
            }
            Captured::Image { pid, image, base } => {
                let image = self.normalize_path(&image);
                let node = self.tracker.live_node(pid);
                Some(self.push_event(pid, node, EventKind::ImageLoad { image, base }))
            }
        }
    }

    /// Run the detection layers on the event with `event_id`: Sigma rules whose
    /// category matches, then the stateful heuristics. Called by the ingest thread
    /// right after `ingest`. Collects matches under an immutable borrow, then
    /// records findings (which mutate node/capture suspicion).
    pub fn detect_event(&mut self, event_id: u64, rules: &RuleSet) {
        let Some(ev) = self.events.get(event_id as usize).cloned() else {
            return;
        };

        // --- Layer 1: Sigma -------------------------------------------------
        if !rules.is_empty() {
            if let Some((cat, fields)) = sigma_view(&ev, self) {
                let mut hits: Vec<(String, String, String, Severity, Vec<String>)> = Vec::new();
                for rule in rules.for_category(cat) {
                    if rule.eval(&fields) {
                        hits.push((
                            rule.id.clone(),
                            rule.title.clone(),
                            rule.description.clone(),
                            rule.level.severity(),
                            rule.tags.clone(),
                        ));
                    }
                }
                for (rule_id, title, description, severity, technique) in hits {
                    self.add_finding(
                        ev.ts_ms,
                        technique,
                        severity,
                        title,
                        description,
                        ev.node_id,
                        FindingSource::Sigma { rule_id },
                        vec![ev.id],
                    );
                }
            }
        }

        // --- Layer 2: stateful heuristics -----------------------------------
        // Resolve a self-delete victim (a node whose image == this delete target).
        let image_target = match &ev.kind {
            EventKind::FileOp {
                op: FileOp::Delete | FileOp::Rename,
                path,
            } => {
                let pl = path.to_lowercase();
                self.nodes
                    .iter()
                    .find(|n| n.image.to_lowercase() == pl)
                    .map(|n| n.node_id)
            }
            _ => None,
        };
        let kind = match &ev.kind {
            EventKind::NetConn {
                remote,
                remote_port,
                direction,
                ..
            } => InputKind::Net {
                remote,
                port: *remote_port,
                outbound: matches!(direction, NetDir::Outbound),
            },
            EventKind::Dns { query, .. } => InputKind::Dns { query },
            EventKind::FileOp { op, path } => InputKind::File { op: *op, path },
            _ => InputKind::Other,
        };
        let input = Input {
            event_id: ev.id,
            ts_ms: ev.ts_ms,
            node_id: ev.node_id,
            kind,
            image_target,
        };
        let pendings = self.stateful.feed(&input);
        for p in pendings {
            self.add_finding(
                ev.ts_ms,
                p.technique,
                p.severity,
                p.title,
                p.description,
                ev.node_id,
                FindingSource::Stateful { kind: p.kind.to_string() },
                p.evidence,
            );
        }
    }

    /// Record a finding, bumping the actor node's and the capture's suspicion.
    #[allow(clippy::too_many_arguments)]
    fn add_finding(
        &mut self,
        ts_ms: u64,
        technique: Vec<String>,
        severity: Severity,
        title: String,
        description: String,
        actor_node: Option<u64>,
        source: FindingSource,
        evidence: Vec<u64>,
    ) {
        let id = self.next_finding_id;
        self.next_finding_id += 1;
        let w = severity.weight();
        self.total_suspicion += w;
        if let Some(nid) = actor_node {
            if let Some(n) = self.nodes.get_mut(nid as usize) {
                n.suspicion += w;
            }
        }
        self.findings.push(Finding {
            id,
            ts_ms,
            technique,
            severity,
            title,
            description,
            actor_node,
            source,
            evidence,
        });
        self.findings_version += 1;
    }

    /// All findings (for the panel / export).
    pub fn findings(&self) -> &[Finding] {
        &self.findings
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
            findings_count: self.findings.len() as u64,
            findings_version: self.findings_version,
            suspicion: self.total_suspicion,
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
            findings_count: self.findings.len() as u64,
            findings_version: self.findings_version,
            suspicion: self.total_suspicion,
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

    /// A node by its monotonic id (== push index). For Sigma Parent* resolution.
    pub fn node(&self, id: u64) -> Option<&ProcessNode> {
        self.nodes.get(id as usize)
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

    /// Node ids reachable from `roots` (inclusive) via parent→child edges — used
    /// to scope a query to a process subtree.
    fn descendants_of(&self, roots: &[u64]) -> HashSet<u64> {
        let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
        for n in &self.nodes {
            if let Some(p) = n.parent_node_id {
                children.entry(p).or_default().push(n.node_id);
            }
        }
        let mut out: HashSet<u64> = HashSet::new();
        let mut stack: Vec<u64> = roots.to_vec();
        while let Some(id) = stack.pop() {
            if out.insert(id) {
                if let Some(kids) = children.get(&id) {
                    stack.extend(kids.iter().copied());
                }
            }
        }
        out
    }

    /// Page/filter events. Scans in arrival order; matching is ANDed.
    pub fn query(&self, filter: &EventFilter, offset: u64, limit: u64) -> EventPage {
        // Free text may be scoped to a field via a `host:` / `path:` / `port:` prefix.
        let text = filter
            .text
            .as_ref()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(parse_text_filter);

        let hide_noise = filter.hide_noise.unwrap_or(false);
        let collapse = filter.collapse.unwrap_or(false);

        // Resolve the node scope once (subtree expansion is O(nodes)).
        let scope: Option<HashSet<u64>> = filter.node_ids.as_ref().map(|ids| {
            if filter.include_subtree.unwrap_or(false) {
                self.descendants_of(ids)
            } else {
                ids.iter().copied().collect()
            }
        });

        let matches = |e: &Event| -> bool {
            if let Some(ids) = &filter.event_ids {
                if !ids.contains(&e.id) {
                    return false;
                }
            }
            if let Some(from) = filter.ts_from {
                if e.ts_ms < from {
                    return false;
                }
            }
            if let Some(to) = filter.ts_to {
                if e.ts_ms > to {
                    return false;
                }
            }
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
            if let Some(scope) = &scope {
                match e.node_id {
                    Some(nid) if scope.contains(&nid) => {}
                    _ => return false,
                }
            }
            // Per-category operation facet (file/registry op kinds).
            if let Some(ops) = &filter.ops {
                match e.kind.op_token() {
                    Some(tok) if ops.iter().any(|o| o == tok) => {}
                    _ => return false,
                }
            }
            // Network facets — only net events can satisfy them.
            if let Some(proto) = filter.proto {
                match &e.kind {
                    EventKind::NetConn { proto: p, .. } if *p == proto => {}
                    _ => return false,
                }
            }
            if let Some(dir) = filter.direction {
                match &e.kind {
                    EventKind::NetConn { direction, .. } if *direction == dir => {}
                    _ => return false,
                }
            }
            if filter.port_min.is_some() || filter.port_max.is_some() {
                match &e.kind {
                    EventKind::NetConn { remote_port, .. } => {
                        if let Some(lo) = filter.port_min {
                            if *remote_port < lo {
                                return false;
                            }
                        }
                        if let Some(hi) = filter.port_max {
                            if *remote_port > hi {
                                return false;
                            }
                        }
                    }
                    _ => return false,
                }
            }
            if let Some((field, needle)) = &text {
                match field_haystack(&e.kind, *field) {
                    Some(h) if h.contains(needle.as_str()) => {}
                    _ => return false,
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

/// Which field a free-text query targets. A `host:` / `path:` / `port:` prefix
/// scopes the match; bare text searches the whole event haystack.
#[derive(Clone, Copy)]
enum TextField {
    Any,
    Host,
    Path,
    Port,
}

fn parse_text_filter(t: &str) -> (TextField, String) {
    let lower = t.to_lowercase();
    for (pfx, field) in [
        ("host:", TextField::Host),
        ("path:", TextField::Path),
        ("port:", TextField::Port),
    ] {
        if let Some(rest) = lower.strip_prefix(pfx) {
            return (field, rest.trim().to_string());
        }
    }
    (TextField::Any, lower)
}

/// Lowercased text for a scoped field, or `None` if the event has no such field
/// (so a scoped query excludes events of the wrong shape).
fn field_haystack(kind: &EventKind, field: TextField) -> Option<String> {
    match field {
        TextField::Any => Some(kind.haystack()),
        TextField::Host => match kind {
            EventKind::NetConn { remote, local, .. } => {
                Some(format!("{remote} {local}").to_lowercase())
            }
            EventKind::Dns { query, results, .. } => {
                Some(format!("{} {}", query, results.as_deref().unwrap_or("")).to_lowercase())
            }
            _ => None,
        },
        TextField::Path => match kind {
            EventKind::FileOp { path, .. } => Some(path.to_lowercase()),
            EventKind::RegOp { path, .. } => Some(path.to_lowercase()),
            EventKind::ImageLoad { image, .. } => Some(image.to_lowercase()),
            EventKind::ProcCreate { image, .. } => Some(image.to_lowercase()),
            _ => None,
        },
        TextField::Port => match kind {
            EventKind::NetConn { remote_port, .. } => Some(remote_port.to_string()),
            _ => None,
        },
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    fn ev(id: u64, node_id: Option<u64>, kind: EventKind) -> Event {
        Event {
            id,
            ts_ms: id,
            pid: 1,
            node_id,
            category: kind.category(),
            dup_count: None,
            kind,
        }
    }

    fn fop(op: FileOp, path: &str) -> EventKind {
        EventKind::FileOp {
            op,
            path: path.into(),
        }
    }

    fn net(remote: &str, port: u16, dir: NetDir) -> EventKind {
        EventKind::NetConn {
            proto: Proto::Tcp,
            direction: dir,
            local: "10.0.0.1:1000".into(),
            remote: remote.into(),
            remote_port: port,
        }
    }

    fn node(id: u64, parent: Option<u64>) -> ProcessNode {
        ProcessNode {
            node_id: id,
            parent_node_id: parent,
            pid: id as u32,
            ppid: 0,
            start_key: 0,
            image: String::new(),
            name: String::new(),
            cmdline: None,
            status: ProcStatus::Running,
            started_ms: 0,
            exited_ms: None,
            exit_code: None,
            event_count: 0,
            counts: CategoryCounts::default(),
            suspicion: 0,
        }
    }

    fn cap_with(events: Vec<Event>) -> Capture {
        let mut c = Capture::new(0);
        c.events = events;
        c
    }

    #[test]
    fn ops_facet_filters_by_op_kind() {
        let c = cap_with(vec![
            ev(1, Some(1), fop(FileOp::Write, "a")),
            ev(2, Some(1), fop(FileOp::Read, "b")),
            ev(3, Some(1), fop(FileOp::Delete, "c")),
        ]);
        let f = EventFilter {
            ops: Some(vec!["write".into(), "delete".into()]),
            ..Default::default()
        };
        assert_eq!(c.query(&f, 0, 100).total, 2);
    }

    #[test]
    fn proto_dir_and_port_filter_network() {
        let c = cap_with(vec![
            ev(1, Some(1), net("1.1.1.1", 443, NetDir::Outbound)),
            ev(2, Some(1), net("2.2.2.2", 8080, NetDir::Outbound)),
            ev(3, Some(1), net("3.3.3.3", 9000, NetDir::Inbound)),
            ev(4, Some(1), fop(FileOp::Write, "p")),
        ]);
        // outbound tcp on a non-standard high port → only event 2.
        let f = EventFilter {
            proto: Some(Proto::Tcp),
            direction: Some(NetDir::Outbound),
            port_min: Some(1024),
            ..Default::default()
        };
        let page = c.query(&f, 0, 100);
        assert_eq!(page.total, 1);
        assert_eq!(page.events[0].id, 2);
    }

    #[test]
    fn subtree_scope_includes_descendants() {
        let mut c = Capture::new(0);
        // 1 → 2 → 3, plus unrelated 4.
        c.nodes = vec![node(1, None), node(2, Some(1)), node(3, Some(2)), node(4, None)];
        c.events = vec![
            ev(1, Some(1), fop(FileOp::Write, "a")),
            ev(2, Some(2), fop(FileOp::Write, "b")),
            ev(3, Some(3), fop(FileOp::Write, "c")),
            ev(4, Some(4), fop(FileOp::Write, "d")),
        ];
        let subtree = EventFilter {
            node_ids: Some(vec![1]),
            include_subtree: Some(true),
            ..Default::default()
        };
        assert_eq!(c.query(&subtree, 0, 100).total, 3);
        let direct = EventFilter {
            node_ids: Some(vec![1]),
            include_subtree: Some(false),
            ..Default::default()
        };
        assert_eq!(c.query(&direct, 0, 100).total, 1);
    }

    #[test]
    fn field_scoped_text_separates_host_and_path() {
        let c = cap_with(vec![
            ev(1, Some(1), fop(FileOp::Write, "C:\\evil\\host.txt")),
            ev(2, Some(1), net("host.example.com", 80, NetDir::Outbound)),
        ]);
        // host: matches only the net event, not the file path that contains "host".
        let host = EventFilter {
            text: Some("host:host".into()),
            ..Default::default()
        };
        let page = c.query(&host, 0, 100);
        assert_eq!(page.total, 1);
        assert_eq!(page.events[0].id, 2);
        // path: matches only the file event.
        let path = EventFilter {
            text: Some("path:evil".into()),
            ..Default::default()
        };
        assert_eq!(c.query(&path, 0, 100).total, 1);
    }

    #[test]
    fn port_scoped_text_matches_exact_port() {
        let c = cap_with(vec![
            ev(1, Some(1), net("a", 4444, NetDir::Outbound)),
            ev(2, Some(1), net("b", 443, NetDir::Outbound)),
        ]);
        let f = EventFilter {
            text: Some("port:4444".into()),
            ..Default::default()
        };
        assert_eq!(c.query(&f, 0, 100).total, 1);
    }
}
