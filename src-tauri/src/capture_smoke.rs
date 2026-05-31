//! Headless end-to-end check of the capture engine (launcher + ETW + store).
//!
//! Requires administrator privileges (ETW kernel-process provider) and actually
//! spawns processes, so it is `#[ignore]`d by default. Run explicitly with:
//!   cargo test --lib -- --ignored --nocapture captures_cmd_subtree

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::unbounded;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::store::Capture;
use crate::{etw, launcher};

const GUID_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const GUID_REGISTRY: &str = "70eb4f03-c1de-4f73-a051-33d13d5413bd";
const GUID_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const GUID_DNS: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const GUID_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";

/// Try a property name across the common ETW value types and return a printable
/// "name=type:value" if any parse succeeds.
fn probe(parser: &Parser, name: &str) -> Option<String> {
    if let Ok(v) = parser.try_parse::<String>(name) {
        return Some(format!("{name}=str({v})"));
    }
    if let Ok(v) = parser.try_parse::<u64>(name) {
        return Some(format!("{name}=u64({v})"));
    }
    if let Ok(v) = parser.try_parse::<u32>(name) {
        return Some(format!("{name}=u32({v})"));
    }
    if let Ok(v) = parser.try_parse::<u16>(name) {
        return Some(format!("{name}=u16({v})"));
    }
    if let Ok(v) = parser.try_parse::<u8>(name) {
        return Some(format!("{name}=u8({v})"));
    }
    None
}

/// Add all descendants of `root` to the tracked set (toolhelp snapshot, BFS).
#[cfg(test)]
fn refresh_descendants(root: u32, tracked: &parking_lot::RwLock<std::collections::HashSet<u32>>) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return;
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut pairs = Vec::new();
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                pairs.push((e.th32ProcessID, e.th32ParentProcessID));
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        let mut set = tracked.write();
        set.insert(root);
        loop {
            let mut changed = false;
            for &(pid, ppid) in &pairs {
                if set.contains(&ppid) && !set.contains(&pid) {
                    set.insert(pid);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
}

/// Game comparison: launch the suspect game, deep-capture its file probes with
/// call stacks, resolve the caller DLL, and compare against the static finding
/// (no probe list on disk; mismatched node.dll 0.44.0-beta1 is the prime suspect).
#[test]
#[ignore = "launches the real game; needs admin"]
fn compare_game_probes() {
    use crossbeam_channel::unbounded;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const GAME: &str =
        "E:\\bin\\game\\(RJ01261731)드러내라! 야외노출방송 v1.0.3\\game.exe";
    let launched = launcher::create_suspended(GAME, &[]).expect("launch game");
    let root = launched.pid;
    let tracked = Arc::new(parking_lot::RwLock::new(HashSet::from([root])));

    let running = Arc::new(AtomicBool::new(true));
    {
        let tracked = tracked.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                refresh_descendants(root, &tracked);
                std::thread::sleep(Duration::from_millis(400));
            }
        });
    }

    // Keep only competitor-game probes: under \bin\ but not the game's own dir.
    let keep: crate::deep::PathFilter = Arc::new(|p: &str| {
        let l = p.to_lowercase();
        l.contains("\\bin\\") && !l.contains("rj01261731")
    });
    let (tx, rx) = unbounded();
    let session = crate::deep::DeepSession::start(tracked.clone(), keep, tx).expect("deep start");
    launcher::resume(launched.thread).expect("resume");

    std::thread::sleep(Duration::from_secs(40));

    let stats = session.stats();
    session.stop();
    running.store(false, Ordering::Relaxed);

    let mut samples = Vec::new();
    while let Ok(s) = rx.try_recv() {
        samples.push(s);
    }

    // Resolve callers (game still alive — terminate after).
    let mut modcache: HashMap<u32, Vec<crate::modmap::Module>> = HashMap::new();
    let mut by_caller: HashMap<String, usize> = HashMap::new();
    let mut distinct_paths: HashSet<String> = HashSet::new();
    let mut examples: Vec<(String, String)> = Vec::new();
    let failed = samples.iter().filter(|s| s.failed).count();
    for s in &samples {
        let mods = modcache
            .entry(s.pid)
            .or_insert_with(|| crate::modmap::snapshot(s.pid));
        let (caller, _src) = crate::modmap::attribute(&s.user_addrs, s.tid, mods);
        let caller = caller.unwrap_or_else(|| "(unresolved)".into());
        let label = match crate::modmap::benign_caller(&caller) {
            Some(b) => format!("{caller} [benign: {b}]"),
            None => caller,
        };
        *by_caller.entry(label.clone()).or_default() += 1;
        if distinct_paths.insert(s.path.clone()) && examples.len() < 24 {
            examples.push((label, crate::model::basename(&s.path)));
        }
    }

    launcher::terminate(launched.process);
    launcher::close(launched.thread);
    launcher::close(launched.process);

    println!("=== deep stats: {stats:?} ===");
    println!(
        "=== probe samples: {} | distinct paths: {} | failed: {failed} ===",
        samples.len(),
        distinct_paths.len()
    );
    println!("=== caller-DLL histogram: {by_caller:?} ===");
    println!("=== example probes (caller :: target) ===");
    for (caller, name) in &examples {
        println!("  {caller} :: {name}");
    }
}

/// Sanity: the ferrisetw deep session attaches stacks to Kernel-File Create
/// events for the target, and the module map resolves the top user frame to a
/// caller DLL (tier-3). Uses cmd as the target.
#[test]
#[ignore = "deep-session sanity; needs admin"]
fn probe_deep_session() {
    use crossbeam_channel::unbounded;
    use std::collections::HashSet;
    use std::sync::Arc;

    let launched = launcher::create_suspended(
        "C:\\Windows\\System32\\cmd.exe",
        &[
            "/c".into(),
            "type C:\\Windows\\win.ini >nul & type C:\\scent_no_such_file_zzz.dat & \
             ping -n 4 127.0.0.1 >nul"
                .into(),
        ],
    )
    .expect("create_suspended");

    let (tx, rx) = unbounded();
    let tracked = Arc::new(parking_lot::RwLock::new(HashSet::from([launched.pid])));
    let keep_all: crate::deep::PathFilter = Arc::new(|_p: &str| true);
    let session =
        crate::deep::DeepSession::start(tracked, keep_all, tx).expect("deep start");
    launcher::resume(launched.thread).expect("resume");

    // Snapshot the target's modules while it's alive.
    std::thread::sleep(Duration::from_millis(800));
    let mods = crate::modmap::snapshot(launched.pid);
    std::thread::sleep(Duration::from_secs(2));

    let stats = session.stats();
    session.stop();
    launcher::close(launched.thread);
    launcher::close(launched.process);

    let mut samples = Vec::new();
    while let Ok(s) = rx.try_recv() {
        samples.push(s);
    }
    let with_stack = samples.iter().filter(|s| !s.user_addrs.is_empty()).count();
    let failed = samples.iter().filter(|s| s.failed).count();
    let mut resolved = 0usize;
    println!("=== modules snapshotted: {} ===", mods.len());
    println!("=== deep stats: {stats:?} ===");
    println!(
        "=== samples={} with_stack={with_stack} failed_probes={failed} ===",
        samples.len()
    );
    for s in samples.iter().take(8) {
        let (caller, source) = crate::modmap::attribute(&s.user_addrs, s.tid, &mods);
        if caller.is_some() {
            resolved += 1;
        }
        let benign = caller.as_deref().and_then(crate::modmap::benign_caller);
        println!(
            "  caller={:?} via {:?}{} failed={} path={}",
            caller,
            source,
            benign.map(|b| format!(" [benign: {b}]")).unwrap_or_default(),
            s.failed,
            &s.path[..s.path.len().min(60)]
        );
    }

    assert!(!samples.is_empty(), "expected captured create samples for the target");
    assert!(with_stack > 0, "expected at least one sample with a call stack");
    assert!(resolved > 0, "expected at least one event attributed to a caller DLL");
    assert!(failed > 0, "expected the nonexistent-file probe flagged failed (OP_END)");
}

/// Stack-walk feasibility probe (tier 3): enable EVENT_ENABLE_PROPERTY_STACK_TRACE
/// on Kernel-File and confirm ETW attaches a call stack (return-address array) to
/// file-create events, which we can later resolve against the per-process module
/// map to attribute the responsible DLL.
#[test]
#[ignore = "ETW stack-walk discovery; needs admin"]
fn explore_stacks() {
    use ferrisetw::native::ExtendedDataItem;
    use ferrisetw::provider::{EventFilter, TraceFlags};
    use ferrisetw::trace::TraceProperties;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let launched = launcher::create_suspended(
        "C:\\Windows\\System32\\cmd.exe",
        &[
            "/c".into(),
            "type C:\\Windows\\win.ini >nul & type C:\\Windows\\System32\\drivers\\etc\\hosts >nul & \
             type C:\\scent_no_such_file_zzz.dat & ping -n 3 127.0.0.1 >nul"
                .into(),
        ],
    )
    .expect("create_suspended");
    let target_pid = launched.pid;
    let printed = Arc::new(AtomicUsize::new(0));
    let seen12 = Arc::new(AtomicUsize::new(0));

    let p = printed.clone();
    let s12 = seen12.clone();
    let total12 = Arc::new(AtomicUsize::new(0));
    let t12 = total12.clone();
    let file = Provider::by_guid(GUID_FILE)
        .any(0x80) // CREATE only
        .add_filter(EventFilter::ByEventIds(vec![12])) // stacks only on Create, at source
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
        .add_callback(move |record: &EventRecord, _l: &SchemaLocator| {
            if record.event_id() != 12 {
                return;
            }
            t12.fetch_add(1, Ordering::Relaxed);
            if record.process_id() != target_pid {
                return;
            }
            s12.fetch_add(1, Ordering::Relaxed);
            if p.load(Ordering::Relaxed) >= 5 {
                return;
            }
            let ext = record.extended_data();
            let mut has_stack = false;
            for item in ext {
                if let ExtendedDataItem::StackTrace64(st) = item.to_extended_data_item() {
                    has_stack = true;
                    println!("[tid {}] file-create STACK64: {:?}", record.thread_id(), st);
                }
            }
            if !has_stack {
                println!(
                    "[tid {}] event 12, ext-items={}, no stack",
                    record.thread_id(),
                    ext.len()
                );
            } else {
                p.fetch_add(1, Ordering::Relaxed);
            }
        })
        .build();

    // STEP 2 (improve): large buffer pool instead of the 3-buffer default.
    let props = TraceProperties {
        buffer_size: 128, // KB per buffer
        min_buffer: 64,
        max_buffer: 256,
        flush_timer: Duration::from_secs(1),
        ..TraceProperties::default()
    };
    let trace = UserTrace::new()
        .named("scent-explore-stacks".to_string())
        .set_trace_properties(props)
        .enable(file)
        .start_and_process()
        .expect("start trace (admin?)");
    launcher::resume(launched.thread).expect("resume");
    std::thread::sleep(Duration::from_secs(3));

    // STEP 1 (measure): read loss counters BEFORE stopping the session.
    let stats = crate::etw::query_session_stats("scent-explore-stacks");
    let _ = trace.stop();
    launcher::close(launched.thread);
    launcher::close(launched.process);

    let n = printed.load(Ordering::Relaxed);
    println!(
        "=== event-12 total(any pid): {} | for target: {} | with a captured stack: {n} ===",
        total12.load(Ordering::Relaxed),
        seen12.load(Ordering::Relaxed)
    );
    println!("=== session stats: {stats:?} ===");
    // Measurement harness, not a pass/fail gate: system-wide file volume + a 3s
    // window make per-run capture counts noisy. The session stats are the signal.
    let _ = n;
}

/// Discovery harness: subscribe to all five target providers, run a workload that
/// touches each category, and dump the FIRST occurrence of each distinct
/// (provider, event_id) with its task/opcode names and which candidate property
/// names actually parse. This nails down the real ETW schema so the production
/// parsers in `etw.rs` aren't guesswork.
#[test]
#[ignore = "ETW schema discovery; needs admin"]
fn explore_providers() {
    let (tx, rx) = unbounded::<String>();
    let seen: Arc<Mutex<HashSet<(String, u16)>>> = Arc::new(Mutex::new(HashSet::new()));

    let candidates: &[&str] = &[
        // file
        "FileObject", "FileKey", "FileName", "FilePath", "CreateOptions",
        "IssuingThreadId", "ByteOffset", "IOSize", "ExtraInformation", "ShareAccess",
        "InfoClass", "Irp", "ReturnValue",
        // registry
        "KeyObject", "KeyName", "RelativeName", "ValueName", "Status", "Disposition",
        "Type", "DataSize", "BaseObject", "CapturedDataSize", "PreviousDataType",
        // network
        "PID", "daddr", "saddr", "dport", "sport", "size", "connid", "seqnum",
        "mss", "sackopt", "tsopt", "wsopt", "rcvwin", "startime", "endtime",
        // dns
        "QueryName", "QueryType", "QueryOptions", "QueryStatus", "QueryResults",
        "ServerList", "DnsServerIpAddress",
        // process / image
        "ProcessID", "ParentProcessID", "ImageName", "ImageBase", "ImageSize",
        "ImageChecksum", "ProcessSequenceNumber", "ExitCode",
    ];

    let make_cb = |tx: crossbeam_channel::Sender<String>, seen: Arc<Mutex<HashSet<(String, u16)>>>| {
        move |record: &EventRecord, locator: &SchemaLocator| {
            let Ok(schema) = locator.event_schema(record) else { return };
            let provider = schema.provider_name();
            let id = record.event_id();
            {
                let mut s = seen.lock().unwrap();
                if !s.insert((provider.clone(), id)) {
                    return;
                }
            }
            let parser = Parser::create(record, &schema);
            let found: Vec<String> = candidates.iter().filter_map(|c| probe(&parser, c)).collect();
            let _ = tx.send(format!(
                "[{provider}] id={id} task={:?} opcode={:?}\n      {}",
                schema.task_name(),
                schema.opcode_name(),
                found.join(" | ")
            ));
        }
    };

    let file = Provider::by_guid(GUID_FILE)
        .any(0x10 | 0x40 | 0x80 | 0x200 | 0x400 | 0x800) // filename|op_end|create|write|delete|rename
        .add_callback(make_cb(tx.clone(), seen.clone()))
        .build();
    let registry = Provider::by_guid(GUID_REGISTRY)
        .add_callback(make_cb(tx.clone(), seen.clone()))
        .build();
    let network = Provider::by_guid(GUID_NETWORK)
        .add_callback(make_cb(tx.clone(), seen.clone()))
        .build();
    let dns = Provider::by_guid(GUID_DNS)
        .add_callback(make_cb(tx.clone(), seen.clone()))
        .build();
    let process = Provider::by_guid(GUID_PROCESS)
        .any(0x10 | 0x40) // process|image
        .add_callback(make_cb(tx.clone(), seen.clone()))
        .build();

    let trace = UserTrace::new()
        .named("scent-explore".to_string())
        .enable(file)
        .enable(registry)
        .enable(network)
        .enable(dns)
        .enable(process)
        .start_and_process()
        .expect("start trace (admin?)");

    // Workload that exercises every category.
    let workload = "echo hi> %TEMP%\\scent_x.txt & \
         reg add HKCU\\Software\\ScentTest /v X /t REG_SZ /d 1 /f & \
         curl -s -m 6 http://example.com -o NUL & \
         nslookup example.com & \
         reg delete HKCU\\Software\\ScentTest /f & \
         del %TEMP%\\scent_x.txt";
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", workload])
        .output();

    std::thread::sleep(Duration::from_secs(2));
    let _ = trace.stop();

    let mut lines: Vec<String> = Vec::new();
    while let Ok(s) = rx.try_recv() {
        lines.push(s);
    }
    lines.sort();
    println!("\n===== DISTINCT ETW EVENTS ({}) =====", lines.len());
    for l in lines {
        println!("{l}");
    }
    println!("===== end =====\n");
}

#[test]
#[ignore = "spawns processes + needs admin/ETW"]
fn captures_cmd_subtree() {
    use crate::etw::EtwState;

    let own = std::process::id();
    let mut cap = Capture::new(own);
    cap.set_drive_map(launcher::dos_device_map());

    // 1. Launch cmd suspended; the workload touches every category.
    let workload = "echo hi> %TEMP%\\scent_x.txt & \
         reg add HKCU\\Software\\ScentTest /v X /t REG_SZ /d 1 /f & \
         curl -s -m 6 http://example.com -o NUL & \
         nslookup example.com & \
         reg delete HKCU\\Software\\ScentTest /f & \
         del %TEMP%\\scent_x.txt";
    let launched = launcher::create_suspended(
        "C:\\Windows\\System32\\cmd.exe",
        &["/c".into(), workload.into()],
    )
    .expect("create_suspended");

    cap.seed_root(
        launched.pid,
        own,
        launched.create_time,
        launched.image.clone(),
        Some(launched.cmdline.clone()),
    );

    // 2. Bring ETW online before resuming. Seed the shared scope with the root.
    let state = Arc::new(parking_lot::Mutex::new(EtwState::new()));
    state.lock().track(launched.pid);

    let (raw_tx, raw_rx) = unbounded();
    let (ready_tx, ready_rx) = unbounded();
    let (stop_tx, stop_rx) = unbounded::<()>();
    let state_thread = state.clone();
    std::thread::spawn(move || match etw::start_session(raw_tx, state_thread) {
        Ok(trace) => {
            let _ = ready_tx.send(Ok(()));
            let _ = stop_rx.recv();
            let _ = trace.stop();
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
        }
    });
    ready_rx
        .recv()
        .expect("ready channel")
        .expect("ETW session start (run as administrator)");

    // 3. Resume — capture is now live from t=0.
    launcher::resume(launched.thread).expect("resume");

    // 4. Drain events for a few seconds.
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        while let Ok(raw) = raw_rx.try_recv() {
            cap.ingest(raw);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = stop_tx.send(());

    let tree = cap.tree();
    let status = cap.status();
    println!("\n=== captured process tree (root pid {}) ===", launched.pid);
    for n in &tree.nodes {
        println!(
            "  node {:>2} pid={:<6} {:<14} status={:?} P{} F{} R{} N{} D{} M{}",
            n.node_id,
            n.pid,
            n.name,
            n.status,
            n.counts.process,
            n.counts.file,
            n.counts.registry,
            n.counts.network,
            n.counts.dns,
            n.counts.module
        );
    }
    let c = status.counts;
    println!(
        "=== {} nodes | process={} file={} registry={} network={} dns={} module={} (total {}) ===\n",
        tree.nodes.len(),
        c.process,
        c.file,
        c.registry,
        c.network,
        c.dns,
        c.module,
        c.total()
    );

    launcher::close(launched.thread);
    launcher::close(launched.process);

    // Verify normalization + Create/Open split + collapse/hide-noise.
    use crate::model::{Category, EventKind, FileOp};
    use crate::store::EventFilter;
    let file_filter = EventFilter {
        category: Some(Category::File),
        ..Default::default()
    };
    let raw_files = cap.query(&file_filter, 0, 1_000_000);
    let mut creates = 0u64;
    let mut opens = 0u64;
    let mut device_paths = 0u64;
    for e in &raw_files.events {
        if let EventKind::FileOp { op, path } = &e.kind {
            match op {
                FileOp::Create => creates += 1,
                FileOp::Open => opens += 1,
                _ => {}
            }
            if path.starts_with("\\Device") {
                device_paths += 1;
            }
        }
    }
    let collapsed = cap.query(
        &EventFilter {
            category: Some(Category::File),
            collapse: Some(true),
            ..Default::default()
        },
        0,
        1_000_000,
    );
    let denoised = cap.query(
        &EventFilter {
            category: Some(Category::File),
            hide_noise: Some(true),
            ..Default::default()
        },
        0,
        1_000_000,
    );
    println!(
        "files: total={} create={} open={} device-unnormalized={} | collapsed={} denoised={}",
        raw_files.total, creates, opens, device_paths, collapsed.total, denoised.total
    );

    // Exercise the exporters on the captured data (Phase 4).
    let jsonl = crate::exporter::to_jsonl(cap.events());
    let html = crate::exporter::to_html(&status, cap.nodes(), cap.events());
    let md = crate::exporter::to_markdown(&status, cap.nodes(), cap.events());
    let csv = crate::exporter::to_csv(crate::model::Category::File, cap.events(), cap.nodes());
    println!(
        "exports: jsonl {} lines, html {} bytes, md {} bytes, file-csv {} lines",
        jsonl.lines().count(),
        html.len(),
        md.len(),
        csv.lines().count()
    );

    assert!(tree.nodes.len() >= 2, "expected root + children");
    assert!(c.file > 0, "expected file events");
    assert!(c.registry > 0, "expected registry events");
    assert!(c.module > 0, "expected image-load events");
    assert_eq!(jsonl.lines().count() as u64, status.total_events, "jsonl line per event");
    assert!(html.contains("scent capture report"), "html report rendered");
    assert!(html.contains("<canvas id=tl>"), "html timeline present");
    assert!(md.contains("# scent capture report"), "markdown rendered");
    assert!(csv.lines().count() >= 1, "csv has a header");
    // Most paths normalize to drive letters; a few NT-only devices (pipes,
    // shadow copies) legitimately remain in \Device form.
    assert!(
        device_paths * 2 < raw_files.total,
        "expected majority of file paths normalized off \\Device form, {device_paths}/{} remain",
        raw_files.total
    );
    assert!(collapsed.total <= raw_files.total, "collapse never grows the set");
    assert!(denoised.total <= raw_files.total, "hide-noise never grows the set");
}
