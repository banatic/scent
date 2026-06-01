//! Invariant heuristics — the second detection layer, for novel combinations that
//! Sigma rules don't cover. These are *stateful*: they accumulate per-node history
//! and fire on an effect/surface pattern rather than a known signature.
//!
//!  * **beaconing**   — regular outbound connections to one endpoint (low jitter).
//!  * **dns_tunnel**  — subdomain explosion under one parent domain.
//!  * **dns_dga**     — a burst of high-entropy (algorithmically-generated) domains.
//!  * **ransom**      — a new extension / identical note name spreading across many
//!                      directories within a short window.
//!  * **self_delete** — a process deleting its own on-disk image.
//!
//! State lives inside `Capture` and is driven from the single ingest thread, so it
//! needs no locking of its own. Each detector fires at most once per logical
//! subject (endpoint / parent domain / node) to avoid finding spam.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{FileOp, Severity};

/// Per-detector tunables (kept conservative to limit false positives).
const BEACON_MIN_HITS: usize = 5;
const BEACON_MIN_INTERVAL_MS: f64 = 750.0;
const BEACON_MAX_CV: f64 = 0.25; // coefficient of variation (jitter / mean)
const BEACON_CAP: usize = 64;

const DGA_MIN_LABEL_LEN: usize = 12;
// Per-string Shannon entropy is bounded by log2(len); for a 12-char label the max
// is ~3.585, so 3.2 separates random-looking SLDs from dictionary words. A single
// long word won't fire — DGA needs DGA_MIN_DOMAINS distinct high-entropy domains.
const DGA_MIN_ENTROPY: f64 = 3.2; // bits/char
const DGA_MIN_DOMAINS: usize = 5;

const TUNNEL_MIN_SUBDOMAINS: usize = 25;

const RANSOM_WINDOW_MS: u64 = 5_000;
const RANSOM_MIN_DIRS_EXT: usize = 8;
const RANSOM_MIN_DIRS_NOTE: usize = 5;

/// A finding the detectors want recorded (the caller stamps node/time).
pub struct Pending {
    pub kind: &'static str,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub technique: Vec<String>,
    pub evidence: Vec<u64>,
}

/// One event handed to the detectors (borrows owned locals in the caller).
pub struct Input<'a> {
    pub event_id: u64,
    pub ts_ms: u64,
    pub node_id: Option<u64>,
    pub kind: InputKind<'a>,
    /// The node whose on-disk image equals this event's (delete) target, if any.
    pub image_target: Option<u64>,
}

pub enum InputKind<'a> {
    Net { remote: &'a str, port: u16, outbound: bool },
    Dns { query: &'a str },
    File { op: FileOp, path: &'a str },
    Other,
}

#[derive(Default)]
struct BeaconTrack {
    times: Vec<u64>,
    evidence: Vec<u64>,
    fired: bool,
}

#[derive(Default)]
struct DnsNode {
    /// distinct subdomains per parent domain (tunneling).
    per_parent: HashMap<String, ParentTrack>,
    /// distinct high-entropy registrable domains (DGA).
    dga_domains: HashSet<String>,
    dga_evidence: Vec<u64>,
    dga_fired: bool,
}

#[derive(Default)]
struct ParentTrack {
    subs: HashSet<String>,
    evidence: Vec<u64>,
    fired: bool,
}

#[derive(Default)]
struct RansomTrack {
    recent: VecDeque<RecentOp>,
    fired_ext: HashSet<String>,
    fired_note: HashSet<String>,
}

struct RecentOp {
    ts: u64,
    dir: String,
    ext: String,
    base: String,
    event_id: u64,
}

/// All stateful-detector memory for one capture.
#[derive(Default)]
pub struct State {
    beacon: HashMap<(u64, String), BeaconTrack>,
    dns: HashMap<u64, DnsNode>,
    ransom: HashMap<u64, RansomTrack>,
    self_deleted: HashSet<u64>,
}

impl State {
    /// Feed one event; return any findings it triggered.
    pub fn feed(&mut self, input: &Input) -> Vec<Pending> {
        let mut out = Vec::new();
        let Some(node) = input.node_id else {
            return out;
        };
        match &input.kind {
            InputKind::Net { remote, port, outbound } => {
                if *outbound {
                    self.feed_net(node, remote, *port, input, &mut out);
                }
            }
            InputKind::Dns { query } => self.feed_dns(node, query, input, &mut out),
            InputKind::File { op, path } => self.feed_file(node, *op, path, input, &mut out),
            InputKind::Other => {}
        }
        // Self-delete is keyed on the node whose image was the delete target.
        if let Some(victim) = input.image_target {
            if matches!(&input.kind, InputKind::File { op: FileOp::Delete | FileOp::Rename, .. })
                && self.self_deleted.insert(victim)
            {
                out.push(Pending {
                    kind: "self_delete",
                    severity: Severity::Med,
                    title: "Process deleted its own image".into(),
                    description:
                        "The on-disk executable of a tracked process was deleted/renamed — a common anti-forensics self-cleanup."
                            .into(),
                    technique: vec!["T1070.004".into()],
                    evidence: vec![input.event_id],
                });
            }
        }
        out
    }

    fn feed_net(&mut self, node: u64, remote: &str, port: u16, input: &Input, out: &mut Vec<Pending>) {
        if remote.starts_with("127.") || remote == "0.0.0.0" || remote.is_empty() {
            return;
        }
        let key = (node, format!("{remote}:{port}"));
        let t = self.beacon.entry(key.clone()).or_default();
        if t.fired || t.times.len() >= BEACON_CAP {
            return;
        }
        t.times.push(input.ts_ms);
        t.evidence.push(input.event_id);
        if t.times.len() < BEACON_MIN_HITS {
            return;
        }
        if let Some(cv) = coefficient_of_variation(&t.times) {
            let mean = mean_interval(&t.times);
            if mean >= BEACON_MIN_INTERVAL_MS && cv <= BEACON_MAX_CV {
                t.fired = true;
                out.push(Pending {
                    kind: "beaconing",
                    severity: Severity::High,
                    title: format!("Beaconing to {}:{}", remote, port),
                    description: format!(
                        "{} regular outbound connections to {}:{} (~{:.0} ms apart, jitter {:.0}%) — characteristic of C2 beaconing.",
                        t.times.len(),
                        remote,
                        port,
                        mean,
                        cv * 100.0
                    ),
                    technique: vec!["T1071".into(), "T1571".into()],
                    evidence: t.evidence.clone(),
                });
            }
        }
    }

    fn feed_dns(&mut self, node: u64, query: &str, input: &Input, out: &mut Vec<Pending>) {
        let q = query.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = q.split('.').filter(|l| !l.is_empty()).collect();
        if labels.len() < 2 {
            return;
        }
        let parent = labels[labels.len() - 2..].join(".");
        let sub = labels[..labels.len() - 2].join(".");
        let leftmost = labels[0];

        let d = self.dns.entry(node).or_default();

        // Tunneling: many distinct subdomains under one parent.
        if !sub.is_empty() {
            let pt = d.per_parent.entry(parent.clone()).or_default();
            if !pt.fired {
                pt.subs.insert(sub.clone());
                pt.evidence.push(input.event_id);
                if pt.subs.len() >= TUNNEL_MIN_SUBDOMAINS {
                    pt.fired = true;
                    out.push(Pending {
                        kind: "dns_tunnel",
                        severity: Severity::High,
                        title: format!("Possible DNS tunneling via *.{parent}"),
                        description: format!(
                            "{} distinct subdomains queried under {} — consistent with DNS tunneling / exfiltration.",
                            pt.subs.len(),
                            parent
                        ),
                        technique: vec!["T1071.004".into(), "T1048".into()],
                        evidence: pt.evidence.iter().rev().take(20).copied().collect(),
                    });
                }
            }
        }

        // DGA: a burst of high-entropy registrable domains.
        if !d.dga_fired
            && leftmost.len() >= DGA_MIN_LABEL_LEN
            && shannon_entropy(leftmost) >= DGA_MIN_ENTROPY
        {
            if d.dga_domains.insert(parent.clone()) {
                d.dga_evidence.push(input.event_id);
            }
            if d.dga_domains.len() >= DGA_MIN_DOMAINS {
                d.dga_fired = true;
                out.push(Pending {
                    kind: "dns_dga",
                    severity: Severity::Med,
                    title: "Algorithmically-generated domains (DGA)".into(),
                    description: format!(
                        "{} high-entropy domains queried — characteristic of malware domain-generation algorithms.",
                        d.dga_domains.len()
                    ),
                    technique: vec!["T1568.002".into()],
                    evidence: d.dga_evidence.clone(),
                });
            }
        }
    }

    fn feed_file(&mut self, node: u64, op: FileOp, path: &str, input: &Input, out: &mut Vec<Pending>) {
        if !matches!(op, FileOp::Create | FileOp::Rename) {
            return;
        }
        let (dir, base) = split_path(path);
        let ext = extension(base);
        if is_benign_mass(base, &ext) {
            return;
        }
        let base_lc = base.to_lowercase();
        let t = self.ransom.entry(node).or_default();
        t.recent.push_back(RecentOp {
            ts: input.ts_ms,
            dir: dir.to_lowercase(),
            ext: ext.clone(),
            base: base_lc.clone(),
            event_id: input.event_id,
        });
        let cutoff = input.ts_ms.saturating_sub(RANSOM_WINDOW_MS);
        while t.recent.front().is_some_and(|r| r.ts < cutoff) {
            t.recent.pop_front();
        }

        // Same NEW extension spreading across many directories.
        if !ext.is_empty() && !t.fired_ext.contains(&ext) {
            let mut dirs = HashSet::new();
            let mut ev = Vec::new();
            for r in t.recent.iter().filter(|r| r.ext == ext) {
                if dirs.insert(r.dir.clone()) {
                    ev.push(r.event_id);
                }
            }
            if dirs.len() >= RANSOM_MIN_DIRS_EXT {
                t.fired_ext.insert(ext.clone());
                out.push(Pending {
                    kind: "ransom",
                    severity: Severity::Critical,
                    title: format!("Mass file rewrite: .{ext} across {} directories", dirs.len()),
                    description: format!(
                        "A new '.{ext}' extension appeared in {} directories within {} s — characteristic of ransomware encryption.",
                        dirs.len(),
                        RANSOM_WINDOW_MS / 1000
                    ),
                    technique: vec!["T1486".into()],
                    evidence: ev,
                });
            }
        }

        // Identical note filename dropped across many directories.
        if !t.fired_note.contains(&base_lc) {
            let mut dirs = HashSet::new();
            let mut ev = Vec::new();
            for r in t.recent.iter().filter(|r| r.base == base_lc) {
                if dirs.insert(r.dir.clone()) {
                    ev.push(r.event_id);
                }
            }
            if dirs.len() >= RANSOM_MIN_DIRS_NOTE {
                t.fired_note.insert(base_lc.clone());
                out.push(Pending {
                    kind: "ransom",
                    severity: Severity::Critical,
                    title: format!("Identical file '{base}' dropped in {} directories", dirs.len()),
                    description: format!(
                        "The same filename '{base}' was written to {} directories — characteristic of a ransom note.",
                        dirs.len()
                    ),
                    technique: vec!["T1486".into()],
                    evidence: ev,
                });
            }
        }
    }
}

// ---- helpers ---------------------------------------------------------------

fn mean_interval(times: &[u64]) -> f64 {
    if times.len() < 2 {
        return 0.0;
    }
    let intervals: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    intervals.iter().sum::<f64>() / intervals.len() as f64
}

/// Coefficient of variation (stddev/mean) of inter-arrival intervals. Low = regular.
fn coefficient_of_variation(times: &[u64]) -> Option<f64> {
    if times.len() < 3 {
        return None;
    }
    let intervals: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    Some(var.sqrt() / mean)
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    if n == 0.0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Split a Windows path into (directory, filename).
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind(['\\', '/']) {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

fn extension(base: &str) -> String {
    match base.rfind('.') {
        Some(i) if i > 0 && i + 1 < base.len() => base[i + 1..].to_lowercase(),
        _ => String::new(),
    }
}

/// Filenames/extensions that legitimately appear across many directories.
fn is_benign_mass(base: &str, ext: &str) -> bool {
    const BASES: &[&str] = &["desktop.ini", "thumbs.db", ".ds_store", "index.dat"];
    const EXTS: &[&str] = &["tmp", "log", "etl", "pf", "lock", "part"];
    let b = base.to_lowercase();
    BASES.contains(&b.as_str()) || EXTS.contains(&ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(id: u64, ts: u64, node: u64, remote: &str) -> Input {
        Input {
            event_id: id,
            ts_ms: ts,
            node_id: Some(node),
            kind: InputKind::Net { remote, port: 443, outbound: true },
            image_target: None,
        }
    }

    #[test]
    fn beaconing_low_jitter_fires_high() {
        let mut s = State::default();
        let mut fired = None;
        // 6 connections ~1000ms apart, tiny jitter.
        for (i, ts) in [0u64, 1000, 2010, 2990, 4005, 5000].iter().enumerate() {
            let f = s.feed(&net(i as u64, *ts, 1, "93.184.216.34"));
            if let Some(p) = f.into_iter().next() {
                fired = Some(p);
            }
        }
        let p = fired.expect("beacon should fire");
        assert_eq!(p.kind, "beaconing");
        assert_eq!(p.severity, Severity::High);
    }

    #[test]
    fn irregular_connections_do_not_beacon() {
        let mut s = State::default();
        let mut any = false;
        for (i, ts) in [0u64, 200, 5000, 5100, 20000, 20050].iter().enumerate() {
            any |= !s.feed(&net(i as u64, *ts, 1, "93.184.216.34")).is_empty();
        }
        assert!(!any, "high-jitter traffic must not be flagged as beaconing");
    }

    #[test]
    fn dns_tunneling_fires_on_subdomain_explosion() {
        let mut s = State::default();
        let mut fired = None;
        for i in 0..TUNNEL_MIN_SUBDOMAINS {
            let q = format!("data{i}.exfil.example.com");
            let input = Input {
                event_id: i as u64,
                ts_ms: i as u64 * 10,
                node_id: Some(2),
                kind: InputKind::Dns { query: &q },
                image_target: None,
            };
            if let Some(p) = s.feed(&input).into_iter().next() {
                fired = Some(p);
            }
        }
        let p = fired.expect("tunnel should fire");
        assert_eq!(p.kind, "dns_tunnel");
        assert_eq!(p.severity, Severity::High);
    }

    #[test]
    fn dga_fires_on_high_entropy_burst() {
        let mut s = State::default();
        let domains = [
            "kq3v9xz7bt2m.com",
            "z8h4n1pwq6rd.net",
            "x7m2k9vb3qzt.org",
            "p4w8r2nz6hqk.info",
            "v9t3x7mq2bzk.biz",
        ];
        let mut fired = None;
        for (i, dom) in domains.iter().enumerate() {
            let input = Input {
                event_id: i as u64,
                ts_ms: i as u64,
                node_id: Some(3),
                kind: InputKind::Dns { query: dom },
                image_target: None,
            };
            if let Some(p) = s.feed(&input).into_iter().next() {
                fired = Some(p);
            }
        }
        let p = fired.expect("dga should fire");
        assert_eq!(p.kind, "dns_dga");
    }

    #[test]
    fn ransom_extension_spread_fires_critical() {
        let mut s = State::default();
        let mut fired = None;
        for i in 0..RANSOM_MIN_DIRS_EXT {
            let path = format!("C:\\Users\\v\\Documents\\dir{i}\\file.locky");
            let input = Input {
                event_id: i as u64,
                ts_ms: i as u64 * 100,
                node_id: Some(4),
                kind: InputKind::File { op: FileOp::Create, path: &path },
                image_target: None,
            };
            if let Some(p) = s.feed(&input).into_iter().next() {
                fired = Some(p);
            }
        }
        let p = fired.expect("ransom mass-op should fire");
        assert_eq!(p.kind, "ransom");
        assert_eq!(p.severity, Severity::Critical);
    }

    #[test]
    fn self_delete_fires_once() {
        let mut s = State::default();
        let input = Input {
            event_id: 9,
            ts_ms: 100,
            node_id: Some(5),
            kind: InputKind::File { op: FileOp::Delete, path: "C:\\Temp\\dropper.exe" },
            image_target: Some(5),
        };
        let first = s.feed(&input);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, "self_delete");
        // Same victim again → no duplicate.
        assert!(s.feed(&input).is_empty());
    }
}
