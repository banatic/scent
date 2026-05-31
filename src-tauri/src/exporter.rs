//! Report exporters: events.jsonl, per-category CSV, summary Markdown, and a
//! self-contained HTML report (summary + process tree + timeline + event table,
//! no external dependencies — opens in any browser).

use crate::model::{Category, Event, EventKind, ProcessNode};
use crate::store::CaptureStatus;

/// (operation verb, target string) for tabular display, mirroring the frontend.
fn op_target(e: &Event) -> (String, String) {
    match &e.kind {
        EventKind::ProcCreate { image, cmdline, .. } => (
            "spawn".into(),
            cmdline.clone().unwrap_or_else(|| image.clone()),
        ),
        EventKind::ProcExit { exit_code } => (
            "exit".into(),
            exit_code.map(|c| format!("code {c}")).unwrap_or_default(),
        ),
        EventKind::FileOp { op, path } => (format!("{op:?}").to_lowercase(), path.clone()),
        EventKind::RegOp { op, path, value } => {
            let v = value
                .as_ref()
                .map(|v| format!("{path} -> {v}"))
                .unwrap_or_else(|| path.clone());
            (format!("{op:?}").to_lowercase(), v)
        }
        EventKind::NetConn {
            direction,
            remote,
            remote_port,
            ..
        } => (
            format!("{direction:?}").to_lowercase(),
            format!("{remote}:{remote_port}"),
        ),
        EventKind::Dns { query, .. } => ("query".into(), query.clone()),
        EventKind::ImageLoad { image, .. } => ("load".into(), image.clone()),
    }
}

fn node_name(nodes: &[ProcessNode], node_id: Option<u64>, pid: u32) -> String {
    node_id
        .and_then(|id| nodes.get(id as usize))
        .map(|n| n.name.clone())
        .unwrap_or_else(|| pid.to_string())
}

// ---- JSONL -----------------------------------------------------------------

pub fn to_jsonl(events: &[Event]) -> String {
    let mut out = String::new();
    for e in events {
        if let Ok(line) = serde_json::to_string(e) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

// ---- CSV -------------------------------------------------------------------

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// One CSV for a single category.
pub fn to_csv(category: Category, events: &[Event], nodes: &[ProcessNode]) -> String {
    let mut out = String::from("time_ms,pid,process,operation,target\n");
    for e in events.iter().filter(|e| e.category == category) {
        let (op, target) = op_target(e);
        let proc = node_name(nodes, e.node_id, e.pid);
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            e.ts_ms,
            e.pid,
            csv_field(&proc),
            csv_field(&op),
            csv_field(&target)
        ));
    }
    out
}

// ---- Markdown --------------------------------------------------------------

pub fn to_markdown(status: &CaptureStatus, nodes: &[ProcessNode], _events: &[Event]) -> String {
    let c = &status.counts;
    let mut out = String::new();
    out.push_str("# scent capture report\n\n");
    out.push_str(&format!(
        "- Root PID: {}\n- Duration: {} ms\n- Processes: {}\n- Total events: {}\n\n",
        status.root_pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
        status.elapsed_ms,
        nodes.len(),
        status.total_events
    ));
    out.push_str("## Category breakdown\n\n");
    out.push_str("| Category | Count |\n|---|---|\n");
    out.push_str(&format!(
        "| Process | {} |\n| File | {} |\n| Registry | {} |\n| Network | {} |\n| DNS | {} |\n| Module | {} |\n\n",
        c.process, c.file, c.registry, c.network, c.dns, c.module
    ));
    out.push_str("## Process tree\n\n");
    for n in nodes {
        let depth = node_depth(nodes, n);
        let indent = "  ".repeat(depth);
        out.push_str(&format!(
            "{}- **{}** (pid {}){}\n",
            indent,
            n.name,
            n.pid,
            n.cmdline
                .as_ref()
                .map(|c| format!(" — `{c}`"))
                .unwrap_or_default()
        ));
    }
    out.push('\n');
    out
}

fn node_depth(nodes: &[ProcessNode], node: &ProcessNode) -> usize {
    let mut depth = 0;
    let mut cur = node.parent_node_id;
    let mut guard = 0;
    while let Some(pid) = cur {
        depth += 1;
        guard += 1;
        if guard > 64 {
            break;
        }
        cur = nodes.get(pid as usize).and_then(|p| p.parent_node_id);
    }
    depth
}

// ---- HTML ------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const HTML_CAP: usize = 50_000;

pub fn to_html(status: &CaptureStatus, nodes: &[ProcessNode], events: &[Event]) -> String {
    let c = &status.counts;

    // Process tree as a nested list.
    let mut tree_html = String::from("<ul class=tree>");
    let mut last_depth = 0usize;
    for n in nodes {
        let d = node_depth(nodes, n);
        while last_depth < d {
            tree_html.push_str("<ul>");
            last_depth += 1;
        }
        while last_depth > d {
            tree_html.push_str("</ul>");
            last_depth -= 1;
        }
        tree_html.push_str(&format!(
            "<li><b>{}</b> <span class=pid>{}</span> <span class=meta>F{} R{} N{} D{} M{}</span></li>",
            esc(&n.name),
            n.pid,
            n.counts.file,
            n.counts.registry,
            n.counts.network,
            n.counts.dns,
            n.counts.module
        ));
    }
    while last_depth > 0 {
        tree_html.push_str("</ul>");
        last_depth -= 1;
    }
    tree_html.push_str("</ul>");

    // Event rows (capped) with category data-attr for client-side filtering.
    let mut rows = String::new();
    let shown = events.len().min(HTML_CAP);
    for e in events.iter().take(HTML_CAP) {
        let (op, target) = op_target(e);
        let proc = node_name(nodes, e.node_id, e.pid);
        let cat = format!("{:?}", e.category).to_lowercase();
        rows.push_str(&format!(
            "<tr data-c=\"{cat}\"><td>{}</td><td>{}</td><td>{}</td><td class=cat>{}</td><td>{}</td><td class=tgt>{}</td></tr>",
            fmt_ms(e.ts_ms),
            e.pid,
            esc(&proc),
            cat,
            esc(&op),
            esc(&target),
        ));
    }
    let trunc_note = if events.len() > HTML_CAP {
        format!(
            "<p class=note>Showing first {HTML_CAP} of {} events. Full data in events.jsonl.</p>",
            events.len()
        )
    } else {
        String::new()
    };

    format!(
        r#"<!doctype html><html lang=en><head><meta charset=utf-8>
<title>scent report</title>
<style>
:root{{--bg:#15171c;--s1:#1b1e24;--s2:#22262e;--ink:#e8ebef;--ink2:#aab2bd;--ink3:#7e8693;--line:rgba(255,255,255,.08);
--process:#6ea8fe;--file:#f7b955;--registry:#c08cf0;--network:#56c2a6;--dns:#e98aa8;--module:#8aa0b6}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 'Segoe UI',system-ui,sans-serif}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--ink3);margin:0 0 20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.card{{background:var(--s1);border:1px solid var(--line);border-radius:12px;padding:12px 16px;min-width:96px}}
.card .v{{font-size:20px;font-weight:600}}.card .k{{color:var(--ink3);font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
section{{background:var(--s1);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:18px}}
h2{{font-size:14px;margin:0 0 12px;color:var(--ink2)}}
.tree,.tree ul{{list-style:none;margin:0;padding-left:18px}}.tree>li,.tree ul li{{padding:2px 0}}
.pid{{color:var(--ink3);font-family:ui-monospace,Consolas,monospace;font-size:11px}}
.meta{{color:var(--ink3);font-size:11px;margin-left:8px}}
canvas{{width:100%;height:160px;display:block}}
.controls{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}}
.controls button{{background:var(--s2);border:1px solid var(--line);color:var(--ink2);border-radius:999px;padding:4px 12px;cursor:pointer;font:inherit}}
.controls button.on{{background:#2d3340;color:var(--ink)}}
.controls input{{flex:1;min-width:200px;background:var(--s2);border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:5px 10px;font:inherit}}
table{{width:100%;border-collapse:collapse;table-layout:fixed}}
th{{text-align:left;color:var(--ink3);font-size:11px;text-transform:uppercase;padding:6px 8px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--s1)}}
td{{padding:3px 8px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}}
td.cat{{color:var(--ink3)}}td.tgt{{font-family:ui-monospace,Consolas,monospace;font-size:11px}}
.tblwrap{{max-height:520px;overflow:auto}}.note{{color:var(--ink3);font-size:12px}}
</style></head><body><div class=wrap>
<h1>scent capture report</h1>
<p class=sub>root pid {root} · {dur} ms · {procs} processes · {total} events</p>
<div class=cards>
<div class=card><div class=v>{cp}</div><div class=k>Process</div></div>
<div class=card><div class=v>{cf}</div><div class=k>File</div></div>
<div class=card><div class=v>{cr}</div><div class=k>Registry</div></div>
<div class=card><div class=v>{cn}</div><div class=k>Network</div></div>
<div class=card><div class=v>{cd}</div><div class=k>DNS</div></div>
<div class=card><div class=v>{cm}</div><div class=k>Module</div></div>
</div>
<section><h2>Process tree</h2>{tree}</section>
<section><h2>Timeline</h2><canvas id=tl></canvas></section>
<section><h2>Events ({shown} shown)</h2>
<div class=controls id=ctl>
<button data-c=all class=on>All</button>
<button data-c=process>Process</button><button data-c=file>File</button>
<button data-c=registry>Registry</button><button data-c=network>Network</button>
<button data-c=dns>DNS</button><button data-c=module>Module</button>
<input id=q placeholder="search target">
</div>
{trunc}
<div class=tblwrap><table><thead><tr><th>Time</th><th>PID</th><th>Process</th><th>Category</th><th>Op</th><th>Target</th></tr></thead>
<tbody id=tb>{rows}</tbody></table></div>
</section>
</div>
<script>
const ev={events_json};
const cats={{process:'#6ea8fe',file:'#f7b955',registry:'#c08cf0',network:'#56c2a6',dns:'#e98aa8',module:'#8aa0b6'}};
const order=Object.keys(cats);
// timeline
const cv=document.getElementById('tl'),cx=cv.getContext('2d');
function draw(){{const w=cv.width=cv.clientWidth*devicePixelRatio,h=cv.height=160*devicePixelRatio;cx.clearRect(0,0,w,h);
const max=Math.max(1,{dur});const g=70*devicePixelRatio,pw=w-g-10*devicePixelRatio,th=(h-20*devicePixelRatio)/order.length;
cx.font=(11*devicePixelRatio)+'px sans-serif';order.forEach((c,i)=>{{const y=10*devicePixelRatio+i*th+th/2;cx.strokeStyle='rgba(255,255,255,.08)';cx.beginPath();cx.moveTo(g,y);cx.lineTo(w-10*devicePixelRatio,y);cx.stroke();cx.fillStyle='#7e8693';cx.fillText(c,6*devicePixelRatio,y+4*devicePixelRatio);}});
ev.forEach(e=>{{const i=order.indexOf(e.category);if(i<0)return;const x=g+(e.ts_ms/max)*pw,y=10*devicePixelRatio+i*th+th/2;cx.fillStyle=cats[e.category];cx.globalAlpha=.8;cx.beginPath();cx.arc(x,y,2.4*devicePixelRatio,0,7);cx.fill();}});cx.globalAlpha=1;}}
draw();addEventListener('resize',draw);
// filter
let fc='all',fq='';const tb=document.getElementById('tb');
function apply(){{for(const tr of tb.children){{const okc=fc==='all'||tr.dataset.c===fc;const okq=!fq||tr.lastElementChild.textContent.toLowerCase().includes(fq);tr.style.display=okc&&okq?'':'none';}}}}
document.getElementById('ctl').addEventListener('click',e=>{{if(e.target.dataset.c){{fc=e.target.dataset.c;for(const b of e.target.parentElement.querySelectorAll('button'))b.classList.toggle('on',b===e.target);apply();}}}});
document.getElementById('q').addEventListener('input',e=>{{fq=e.target.value.toLowerCase();apply();}});
</script>
</body></html>"#,
        root = status
            .root_pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".into()),
        dur = status.elapsed_ms,
        procs = nodes.len(),
        total = status.total_events,
        cp = c.process,
        cf = c.file,
        cr = c.registry,
        cn = c.network,
        cd = c.dns,
        cm = c.module,
        tree = tree_html,
        shown = shown,
        trunc = trunc_note,
        rows = rows,
        events_json = serde_json::to_string(events).unwrap_or_else(|_| "[]".into()),
    )
}

fn fmt_ms(ms: u64) -> String {
    let m = ms / 60000;
    let s = (ms % 60000) / 1000;
    let mil = ms % 1000;
    format!("{m:02}:{s:02}.{mil:03}")
}
