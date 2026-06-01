//! Core data model shared across the backend and serialized to the frontend.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a tracked process node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcStatus {
    Running,
    Exited,
}

/// Behavior category. Drives counts, colors, and filtering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Process,
    File,
    Registry,
    Network,
    Dns,
    Module,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)] // Read is captured only when its keyword is enabled (off by default).
pub enum FileOp {
    /// New file created / superseded / overwrite-if (a write intent).
    Create,
    /// Existing file/handle opened (the bulk of ETW Create events — mostly reads).
    Open,
    Read,
    Write,
    Delete,
    Rename,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegOp {
    CreateKey,
    SetValue,
    DeleteKey,
    DeleteValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)] // Udp reserved for future UDP-connection capture.
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetDir {
    Outbound,
    Inbound,
}

/// Per-category event tallies (per process and global).
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct CategoryCounts {
    pub process: u64,
    pub file: u64,
    pub registry: u64,
    pub network: u64,
    pub dns: u64,
    pub module: u64,
}

impl CategoryCounts {
    pub fn bump(&mut self, c: Category) {
        match c {
            Category::Process => self.process += 1,
            Category::File => self.file += 1,
            Category::Registry => self.registry += 1,
            Category::Network => self.network += 1,
            Category::Dns => self.dns += 1,
            Category::Module => self.module += 1,
        }
    }

    #[allow(dead_code)] // used by exporter/tests
    pub fn total(&self) -> u64 {
        self.process + self.file + self.registry + self.network + self.dns + self.module
    }
}

/// Triage severity. Ordered (Info < … < Critical) so findings sort by gravity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Med,
    High,
    Critical,
}

impl Severity {
    /// Suspicion-score contribution (Crit 100 / High 40 / Med 10 / Low 2 / Info 0).
    pub fn weight(self) -> u64 {
        match self {
            Severity::Critical => 100,
            Severity::High => 40,
            Severity::Med => 10,
            Severity::Low => 2,
            Severity::Info => 0,
        }
    }
}

/// Where a finding came from. Findings are an accelerator over the raw telemetry,
/// never a gate — the events/tree/timeline stand on their own.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingSource {
    /// A curated Sigma rule matched.
    Sigma { rule_id: String },
    /// A stateful invariant heuristic fired (kind = beaconing / dns_tunnel / …).
    Stateful { kind: String },
    /// Promoted from a deep-mode caller attribution.
    Deep,
}

/// One triage finding. `evidence` holds the event ids that justify it, so the UI
/// can jump straight to the raw rows.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: u64,
    pub ts_ms: u64,
    /// ATT&CK technique ids (e.g. "T1059.001").
    pub technique: Vec<String>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    /// The responsible process node, when attributable.
    pub actor_node: Option<u64>,
    pub source: FindingSource,
    pub evidence: Vec<u64>,
    /// Verbatim indicators resolved from `evidence` (loaded DLL / file / registry
    /// key / host) so the UI names *which* indicator fired, not just the rule.
    /// Empty in the raw store; filled only when handed to the frontend.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence_labels: Vec<String>,
}

/// A node in the captured process tree. PID reuse produces a fresh node, so
/// `node_id` is stable while `pid` is not.
#[derive(Clone, Debug, Serialize)]
pub struct ProcessNode {
    pub node_id: u64,
    pub parent_node_id: Option<u64>,
    pub pid: u32,
    pub ppid: u32,
    pub start_key: u64,
    pub image: String,
    pub name: String,
    pub cmdline: Option<String>,
    pub status: ProcStatus,
    pub started_ms: u64,
    pub exited_ms: Option<u64>,
    pub exit_code: Option<i64>,
    pub event_count: u64,
    pub counts: CategoryCounts,
    /// Accumulated Σ severity weight of findings attributed to this node.
    pub suspicion: u64,
}

/// Category-tagged payload of a captured event.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    ProcCreate {
        child_pid: u32,
        image: String,
        cmdline: Option<String>,
    },
    ProcExit {
        exit_code: Option<i64>,
    },
    FileOp {
        op: FileOp,
        path: String,
    },
    RegOp {
        op: RegOp,
        path: String,
        value: Option<String>,
    },
    NetConn {
        proto: Proto,
        direction: NetDir,
        local: String,
        remote: String,
        remote_port: u16,
    },
    Dns {
        query: String,
        qtype: u32,
        results: Option<String>,
    },
    ImageLoad {
        image: String,
        base: u64,
    },
}

impl EventKind {
    pub fn category(&self) -> Category {
        match self {
            EventKind::ProcCreate { .. } | EventKind::ProcExit { .. } => Category::Process,
            EventKind::FileOp { .. } => Category::File,
            EventKind::RegOp { .. } => Category::Registry,
            EventKind::NetConn { .. } => Category::Network,
            EventKind::Dns { .. } => Category::Dns,
            EventKind::ImageLoad { .. } => Category::Module,
        }
    }

    /// Lowercased text used for free-text search/filtering.
    pub fn haystack(&self) -> String {
        match self {
            EventKind::ProcCreate { image, cmdline, .. } => {
                format!("{} {}", image, cmdline.as_deref().unwrap_or("")).to_lowercase()
            }
            EventKind::ProcExit { .. } => String::new(),
            EventKind::FileOp { path, .. } => path.to_lowercase(),
            EventKind::RegOp { path, value, .. } => {
                format!("{} {}", path, value.as_deref().unwrap_or("")).to_lowercase()
            }
            EventKind::NetConn { remote, local, .. } => format!("{remote} {local}").to_lowercase(),
            EventKind::Dns { query, results, .. } => {
                format!("{} {}", query, results.as_deref().unwrap_or("")).to_lowercase()
            }
            EventKind::ImageLoad { image, .. } => image.to_lowercase(),
        }
    }

    /// The single most relevant verbatim indicator this event carries (matched
    /// DLL / file / registry key / host:port / domain), or `None` if it has
    /// nothing to cite. Used to surface *which* indicator triggered a finding.
    pub fn indicator(&self) -> Option<String> {
        Some(match self {
            EventKind::ImageLoad { image, .. } => image.clone(),
            EventKind::FileOp { path, .. } => path.clone(),
            EventKind::RegOp { path, value, .. } => match value {
                Some(v) if !v.is_empty() => format!("{path}\\{v}"),
                _ => path.clone(),
            },
            EventKind::NetConn { remote, remote_port, .. } => format!("{remote}:{remote_port}"),
            EventKind::Dns { query, .. } => query.clone(),
            EventKind::ProcCreate { image, cmdline, .. } => match cmdline {
                Some(c) if !c.is_empty() => c.clone(),
                _ => image.clone(),
            },
            EventKind::ProcExit { .. } => return None,
        })
    }

    /// Canonical operation token for the per-category op facet (matches the
    /// frontend op ids). `None` for events with no operation concept.
    pub fn op_token(&self) -> Option<&'static str> {
        Some(match self {
            EventKind::FileOp { op, .. } => match op {
                FileOp::Create => "create",
                FileOp::Open => "open",
                FileOp::Read => "read",
                FileOp::Write => "write",
                FileOp::Delete => "delete",
                FileOp::Rename => "rename",
            },
            EventKind::RegOp { op, .. } => match op {
                RegOp::CreateKey => "create_key",
                RegOp::SetValue => "set_value",
                RegOp::DeleteKey => "delete_key",
                RegOp::DeleteValue => "delete_value",
            },
            _ => return None,
        })
    }
}

/// A single captured raw event, in arrival order.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub id: u64,
    pub ts_ms: u64,
    pub pid: u32,
    pub node_id: Option<u64>,
    pub category: Category,
    /// Number of merged occurrences when returned from a collapsed query
    /// (`None` in the raw store / non-collapsed queries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dup_count: Option<u64>,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    /// Grouping key for "collapse duplicates": same actor + same operation + same target.
    pub fn dedup_key(&self) -> String {
        let n = self.node_id.unwrap_or(u64::MAX);
        match &self.kind {
            EventKind::FileOp { op, path } => format!("F{n}|{op:?}|{}", path.to_lowercase()),
            EventKind::RegOp { op, path, value } => {
                format!("R{n}|{op:?}|{}|{}", path.to_lowercase(), value.as_deref().unwrap_or(""))
            }
            EventKind::NetConn { remote, remote_port, .. } => format!("N{n}|{remote}:{remote_port}"),
            EventKind::Dns { query, qtype, .. } => format!("D{n}|{query}|{qtype}"),
            EventKind::ImageLoad { image, .. } => format!("M{n}|{}", image.to_lowercase()),
            EventKind::ProcCreate { child_pid, .. } => format!("P{n}|{child_pid}"),
            // Exits are unique moments — never merge.
            EventKind::ProcExit { .. } => format!("X{}", self.id),
        }
    }

    /// Whether this event is well-known triage noise (system file/module paths).
    pub fn is_noise(&self) -> bool {
        match &self.kind {
            EventKind::FileOp { path, .. } => is_noise_path(path),
            EventKind::ImageLoad { image, .. } => is_noise_path(image),
            _ => false,
        }
    }
}

/// Heuristic: system loader / OS-subsystem paths that flood captures.
fn is_noise_path(p: &str) -> bool {
    let s = p.to_lowercase();
    const DIRS: &[&str] = &[
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\windows\\fonts\\",
        "\\windows\\assembly\\",
        "\\windows\\prefetch\\",
        "\\system32\\spool\\drivers\\color\\",
        "\\windows\\system32\\driverstore\\",
    ];
    if DIRS.iter().any(|d| s.contains(d)) {
        return true;
    }
    const EXT: &[&str] = &[".mui", ".nls", ".cat", ".manifest", ".icm", ".camp", ".gmmp"];
    if EXT.iter().any(|e| s.ends_with(e)) {
        return true;
    }
    s.contains("amcache")
}

/// Derive a short display name from a full image/file path (handles `\`, `/`,
/// and the NT `\Device\...` form ETW reports).
pub fn basename(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}
