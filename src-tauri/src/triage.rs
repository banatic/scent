//! LLM triage output system (optional, layer 3's human-facing edge).
//!
//! scent never lets an LLM overwrite a Finding. Instead it builds a **guarded,
//! citation-ready bundle** from the telemetry — the deterministic part — and an
//! LLM may turn that into a narrative Verdict that lives only in its own panel.
//! The whole feature is opt-in: `build_bundle` always works (copy it into any
//! model), and `run` performs the Anthropic call only when `ANTHROPIC_API_KEY`
//! is set. Without a key, capture/detection/UI are unaffected.

use serde::{Deserialize, Serialize};

use crate::store::Capture;

/// The guardrails — the system prompt that keeps the model tethered to evidence.
const SYSTEM_PROMPT: &str = "\
You are a malware-triage analyst reviewing dynamic-analysis telemetry from the \
`scent` sandbox. Judge ONLY from the telemetry provided in the user message. \
Rules you must follow:\n\
- Do not invent processes, files, domains, IPs, registry keys, or behaviors that \
are not present in the telemetry.\n\
- When you infer or speculate beyond direct evidence, say so explicitly \
(prefix the sentence with \"Speculation:\").\n\
- Quote every indicator (domain, IP, file path, registry key) VERBATIM as it \
appears; never normalize or guess at one.\n\
- The deterministic Findings are authoritative; you contextualize them, you do \
not overrule them.\n\
- If the evidence is insufficient to decide, the assessment is \"unknown\".\n\
Respond with a single JSON object and nothing else, matching exactly:\n\
{\n\
  \"assessment\": \"benign\" | \"suspicious\" | \"malicious\" | \"unknown\",\n\
  \"confidence\": \"low\" | \"medium\" | \"high\",\n\
  \"summary\": string,                         // 1-3 sentences\n\
  \"key_observations\": string[],              // evidence-grounded bullets\n\
  \"cited_iocs\": string[],                     // indicators quoted verbatim\n\
  \"recommended_actions\": string[],\n\
  \"uncertainties\": string[]                   // what the telemetry can't show\n\
}";

const DEFAULT_MODEL: &str = "claude-sonnet-4-6";
const MAX_FINDINGS: usize = 60;
const MAX_TREE: usize = 60;
const MAX_IOCS: usize = 40;

/// The deterministic bundle handed to the model (or copied for manual analysis).
#[derive(Clone, Serialize)]
pub struct TriageBundle {
    pub system_prompt: String,
    /// Human/markdown context (findings + IOCs + tree summary).
    pub context: String,
    /// `system_prompt` + context, ready to paste into any chat model.
    pub ready_prompt: String,
}

/// The model's narrative verdict — rendered read-only in the VerdictPanel.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Verdict {
    pub assessment: String,
    pub confidence: String,
    pub summary: String,
    #[serde(default)]
    pub key_observations: Vec<String>,
    #[serde(default)]
    pub cited_iocs: Vec<String>,
    #[serde(default)]
    pub recommended_actions: Vec<String>,
    #[serde(default)]
    pub uncertainties: Vec<String>,
    /// Raw model text when JSON parsing failed (so nothing is silently dropped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Model + whether the API key was present, for the panel footer.
    pub model: String,
}

/// Build the deterministic triage context from the current capture.
pub fn build_bundle(cap: &Capture) -> TriageBundle {
    let context = build_context(cap);
    let ready_prompt = format!("{SYSTEM_PROMPT}\n\n---\nTELEMETRY:\n\n{context}");
    TriageBundle {
        system_prompt: SYSTEM_PROMPT.to_string(),
        context,
        ready_prompt,
    }
}

fn build_context(cap: &Capture) -> String {
    use std::fmt::Write;
    let st = cap.status();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "## Capture\nroot pid: {}\nduration: {} ms\nprocesses: {}\nevents: {}\nsuspicion score: {}\n",
        st.root_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        st.elapsed_ms,
        st.process_count,
        st.total_events,
        st.suspicion,
    );

    // Process tree (depth-indented, with command lines).
    let nodes = cap.nodes();
    let _ = writeln!(s, "## Process tree");
    for n in nodes.iter().take(MAX_TREE) {
        let depth = tree_depth(nodes, n);
        let _ = writeln!(
            s,
            "{}- {} (pid {}){}",
            "  ".repeat(depth),
            n.name,
            n.pid,
            n.cmdline.as_deref().map(|c| format!(" :: {c}")).unwrap_or_default(),
        );
    }
    if nodes.len() > MAX_TREE {
        let _ = writeln!(s, "  … {} more", nodes.len() - MAX_TREE);
    }

    // Findings (severity-sorted), the authoritative signals.
    let mut findings: Vec<_> = cap.findings().iter().collect();
    findings.sort_by(|a, b| (b.severity as u8).cmp(&(a.severity as u8)).then(a.ts_ms.cmp(&b.ts_ms)));
    let _ = writeln!(s, "\n## Findings ({})", findings.len());
    for f in findings.iter().take(MAX_FINDINGS) {
        let proc = f
            .actor_node
            .and_then(|id| cap.node(id))
            .map(|n| format!("{} (pid {})", n.name, n.pid))
            .unwrap_or_else(|| "-".into());
        let _ = writeln!(
            s,
            "- [{:?}] {} — {} | technique {} | actor {}{}",
            f.severity,
            f.title,
            f.description,
            if f.technique.is_empty() { "-".into() } else { f.technique.join(",") },
            proc,
            evidence_summary(cap, &f.evidence),
        );
    }
    if findings.len() > MAX_FINDINGS {
        let _ = writeln!(s, "- … {} more findings", findings.len() - MAX_FINDINGS);
    }

    // Indicators, harvested from the events (verbatim).
    let iocs = collect_iocs(cap);
    let _ = writeln!(s, "\n## Indicators");
    write_iocs(&mut s, "domains", &iocs.domains);
    write_iocs(&mut s, "external IPs", &iocs.ips);
    write_iocs(&mut s, "dropped files", &iocs.files);
    write_iocs(&mut s, "persistence registry keys", &iocs.regkeys);
    s
}

/// Resolve a finding's evidence event ids to a short, verbatim indicator list,
/// so the reader (and the LLM) sees *which* DLL/file/registry key/host actually
/// triggered it — e.g. the side-loaded `…\libwazuhshared.dll` behind a Sigma
/// image_load finding, rather than just the rule title. Returns "" when no
/// evidence resolves to a printable indicator.
fn evidence_summary(cap: &Capture, ids: &[u64]) -> String {
    use std::collections::BTreeSet;
    let events = cap.events();
    let mut seen = BTreeSet::new();
    let mut labels = Vec::new();
    for &id in ids {
        let Some(ev) = events.get(id as usize) else { continue };
        let Some(label) = ev.kind.indicator() else { continue };
        if seen.insert(label.clone()) {
            labels.push(label);
        }
        if labels.len() >= 6 {
            break;
        }
    }
    if labels.is_empty() {
        String::new()
    } else {
        format!(" | evidence: {}", labels.join("; "))
    }
}

fn write_iocs(s: &mut String, label: &str, items: &[String]) {
    use std::fmt::Write;
    if items.is_empty() {
        return;
    }
    let _ = writeln!(s, "{label}:");
    for v in items.iter().take(MAX_IOCS) {
        let _ = writeln!(s, "  {v}");
    }
    if items.len() > MAX_IOCS {
        let _ = writeln!(s, "  … {} more", items.len() - MAX_IOCS);
    }
}

fn tree_depth(nodes: &[crate::model::ProcessNode], node: &crate::model::ProcessNode) -> usize {
    let mut depth = 0;
    let mut cur = node.parent_node_id;
    let mut guard = 0;
    while let Some(id) = cur {
        depth += 1;
        guard += 1;
        if guard > 64 {
            break;
        }
        cur = nodes.get(id as usize).and_then(|p| p.parent_node_id);
    }
    depth
}

#[derive(Default)]
struct Iocs {
    domains: Vec<String>,
    ips: Vec<String>,
    files: Vec<String>,
    regkeys: Vec<String>,
}

fn collect_iocs(cap: &Capture) -> Iocs {
    use crate::model::{EventKind, FileOp, NetDir};
    use std::collections::BTreeSet;
    let (mut domains, mut ips, mut files, mut regkeys) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    for e in cap.events() {
        match &e.kind {
            EventKind::Dns { query, .. } => {
                let q = query.trim().to_lowercase();
                if q.contains('.') && !q.ends_with(".arpa") {
                    domains.insert(q);
                }
            }
            EventKind::NetConn { remote, direction, .. } => {
                if matches!(direction, NetDir::Outbound) && !is_private_ip(remote) {
                    ips.insert(remote.clone());
                }
            }
            EventKind::FileOp { op, path } => {
                if matches!(op, FileOp::Create | FileOp::Write) && is_interesting_file(path) {
                    files.insert(path.clone());
                }
            }
            EventKind::RegOp { path, value, .. } => {
                let key = match value {
                    Some(v) if !v.is_empty() => format!("{path}\\{v}"),
                    _ => path.clone(),
                };
                if is_persistence(&key) {
                    regkeys.insert(key);
                }
            }
            _ => {}
        }
    }
    Iocs {
        domains: domains.into_iter().collect(),
        ips: ips.into_iter().collect(),
        files: files.into_iter().collect(),
        regkeys: regkeys.into_iter().collect(),
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip == "0.0.0.0"
        || (ip.starts_with("172.")
            && ip
                .split('.')
                .nth(1)
                .and_then(|o| o.parse::<u32>().ok())
                .is_some_and(|n| (16..=31).contains(&n)))
}

fn is_interesting_file(p: &str) -> bool {
    let l = p.to_lowercase();
    if l.contains("\\windows\\system32\\")
        || l.contains("\\windows\\syswow64\\")
        || l.contains("\\windows\\winsxs\\")
    {
        return false;
    }
    const EXT: &[&str] = &[
        ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
        ".scr", ".lnk",
    ];
    EXT.iter().any(|e| l.ends_with(e))
        || l.contains("\\temp\\")
        || l.contains("\\appdata\\")
        || l.contains("\\programdata\\")
        || l.contains("\\downloads\\")
}

fn is_persistence(key: &str) -> bool {
    let l = key.to_lowercase();
    l.contains("\\currentversion\\run")
        || l.contains("\\services\\")
        || l.contains("\\winlogon")
        || l.contains("image file execution")
        || l.contains("\\policies\\explorer\\run")
}

/// Run the LLM triage via the Anthropic API. Requires `ANTHROPIC_API_KEY`;
/// returns a clear error otherwise (the caller then offers the manual bundle).
pub fn run(bundle: &TriageBundle) -> Result<Verdict, String> {
    let key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| "ANTHROPIC_API_KEY is not set — copy the bundle and run it in any LLM.".to_string())?;
    let model = std::env::var("ANTHROPIC_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 1500,
        "system": bundle.system_prompt,
        "messages": [{ "role": "user", "content": bundle.context }],
    });

    let resp = ureq::post("https://api.anthropic.com/v1/messages")
        .set("x-api-key", &key)
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(60))
        .send_string(&body.to_string());

    let text = match resp {
        Ok(r) => r.into_string().map_err(|e| format!("read response: {e}"))?,
        Err(ureq::Error::Status(code, r)) => {
            let detail = r.into_string().unwrap_or_default();
            return Err(format!("Anthropic API error {code}: {detail}"));
        }
        Err(e) => return Err(format!("request failed: {e}")),
    };

    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse API response: {e}"))?;
    let content = parsed
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("unexpected API response: {text}"))?;

    Ok(parse_verdict(content, &model))
}

/// Parse the model's JSON verdict; fall back to raw text so nothing is dropped.
fn parse_verdict(content: &str, model: &str) -> Verdict {
    // Models sometimes wrap JSON in prose/fences — extract the outermost object.
    let json = extract_json(content);
    if let Some(j) = json {
        if let Ok(mut v) = serde_json::from_str::<Verdict>(&j) {
            v.model = model.to_string();
            return v;
        }
    }
    Verdict {
        assessment: "unknown".into(),
        confidence: "low".into(),
        summary: "Model response was not structured JSON; raw output preserved below.".into(),
        raw: Some(content.to_string()),
        model: model.to_string(),
        ..Default::default()
    }
}

fn extract_json(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end > start {
        Some(s[start..=end].to_string())
    } else {
        None
    }
}
