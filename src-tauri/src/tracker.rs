//! Scope tracking: which processes belong to the target's subtree.
//!
//! The capture is scoped to the root process and everything descended from it.
//! Correctness under PID reuse comes from the `live` map: at any instant a PID
//! maps to at most one live node, so parent resolution by PID is exact. When a
//! process exits we drop it from `live`; a later process reusing that PID gets a
//! brand-new node rather than inheriting the old one's identity.

use std::collections::HashMap;

pub struct Tracker {
    /// scent's own PID — never tracked, so the analyzer can't observe itself.
    own_pid: u32,
    /// Currently-live in-scope processes: PID -> node_id.
    live: HashMap<u32, u64>,
}

impl Tracker {
    pub fn new(own_pid: u32) -> Self {
        Self {
            own_pid,
            live: HashMap::new(),
        }
    }

    /// Mark a process as live and in-scope.
    pub fn add_live(&mut self, pid: u32, node_id: u64) {
        self.live.insert(pid, node_id);
    }

    /// Resolve a PID to its currently-live node, if tracked.
    pub fn live_node(&self, pid: u32) -> Option<u64> {
        self.live.get(&pid).copied()
    }

    /// Remove a process from the live set (on exit), returning its node_id.
    pub fn remove_live(&mut self, pid: u32) -> Option<u64> {
        self.live.remove(&pid)
    }

    /// Whether `pid` is scent itself (always excluded from capture).
    pub fn is_own(&self, pid: u32) -> bool {
        pid == self.own_pid
    }

    /// Count of currently-live tracked processes.
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// Set of currently-live tracked PIDs (for scoping the deep session).
    pub fn live_pids(&self) -> std::collections::HashSet<u32> {
        self.live.keys().copied().collect()
    }
}
