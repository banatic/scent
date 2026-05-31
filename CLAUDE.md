# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`scent` is a Windows-only dynamic behavior analyzer (Tauri 2 + React/TS frontend, Rust backend). It launches a target executable suspended, attaches ETW, then resumes it — capturing the target's whole process subtree's system behavior (process / file / registry / network / DNS / module-load) for tree/graph/timeline exploration and export. Phases 1–4 of the original design are implemented; Phase 5 (API hooking / WinDivert payloads / replay) is intentionally not built.

## Commands

All ETW capture requires an **elevated** shell (kernel providers). Dev/build work does not.

- `npm run tauri dev` — run the app (Vite + Rust build + window). **Must be elevated** to actually capture. Dev server is on **port 5173** (1420 is in a Windows reserved range on the original dev machine; bound to 127.0.0.1 to avoid an `::1` EACCES — see `vite.config.ts` / `tauri.conf.json`).
- `npm run build` — production frontend build (`tsc && vite build`); also the fastest way to catch TS errors alongside `npx tsc --noEmit`.
- `cd src-tauri && cargo check` — fast backend compile check.
- **Headless capture verification (elevated):** `cd src-tauri && cargo test --lib -- --ignored --nocapture captures_cmd_subtree` — launches `cmd.exe`, attaches ETW, and asserts the full pipeline + all exporters against real captured events. This is the primary way to verify the capture engine without driving the GUI.
- **ETW schema discovery (elevated):** `cargo test --lib -- --ignored --nocapture explore_providers` — dumps the real event ids / opcode names / parseable field names per provider on the current Windows build. Run this before changing ETW parsing; field names and event ids are version-sensitive (`src-tauri/src/capture_smoke.rs`).

Both tests are `#[ignore]`d (they spawn processes and need admin), so a normal `cargo test` skips them.

## Capture pipeline (the core invariant)

Order is mandated for capture fidelity — see `ipc::start_capture`:

1. `launcher::create_suspended` — `CreateProcessW(CREATE_SUSPENDED)`; record root PID + create-time. The root's own ProcessStart fires *before* the ETW session exists, so the root tree node is **synthesized** from launcher data, not ETW (`store::Capture::seed_root`).
2. Seed the root PID into both the store's tracker and the shared `EtwState.tracked` set, and `set_drive_map` (device→drive map) **before** the session starts.
3. Start ETW on a dedicated control thread that **owns the `UserTrace`** (so it never needs to be `Send` in Tauri-managed state); readiness is signalled back over a channel.
4. Only then `launcher::resume` — the target runs with full capture in place.

## Backend architecture (`src-tauri/src/`)

Single ETW real-time session, multiple providers, **one processing thread** (ferrisetw). The callbacks therefore run sequentially and share an `Arc<Mutex<EtwState>>` (`etw.rs`) holding the in-scope PID set and the FileObject→name / KeyObject→path correlation maps. Scoping and name correlation happen **inside the callbacks at the source** (drop out-of-scope events before sending; a cheap event-id check rejects high-volume events before any schema work). Only fully-resolved, in-scope `Captured` messages cross a `crossbeam-channel` to a **single ingest thread** that owns the store writes (one write-lock per drained burst). A separate emit thread pushes a small `CaptureDelta` summary at ~10 Hz (`emit.rs`) — events are **never** streamed individually; the frontend pulls detail via commands.

- `store.rs` — `Capture` is the single source of truth (`Vec<Event>`, `Vec<ProcessNode>`, counts). `query()` does category/pid/node/text filtering, plus `hide_noise` (system-path allowlist) and `collapse` (merge identical `(actor,op,target)` into one row with `dup_count`). Path normalization (`\Device\HarddiskVolumeN`→drive, `\REGISTRY\MACHINE`→`HKLM`) happens here at ingest, so all downstream consumers see canonical paths.
- `tracker.rs` — subtree scoping via a live `pid → node_id` map; PID-reuse-safe (nodes keyed by monotonic `node_id`, not pid).
- `model.rs` — `Event` / `EventKind` (serde-flattened tag union), `Category`, `CategoryCounts`, plus `Event::dedup_key`/`is_noise` used by collapse/hide-noise.
- `exporter.rs` — `jsonl` / per-category `csv` / `markdown` / self-contained `html` (embeds the events JSON + an inline canvas timeline). `ipc::export_report(format, path)` writes via `std::fs` (no fs-plugin capability needed).
- Tauri commands live in `ipc.rs` and are registered in `lib.rs`'s `generate_handler!` — adding a command means editing both.

### ETW gotchas (don't relearn these the hard way)

- **`FileOp::Create` vs `Open`:** ETW Kernel-File event 12 fires on every `CreateFile` (mostly opens). The Create/Open split is decided from the NtCreateFile disposition packed in the top 8 bits of `CreateOptions` (`etw.rs` `on_file`). Treating all of them as "creates" is wrong.
- **Attribution:** file/registry/dns events have no PID in payload — use `record.process_id()`. Network (`PID`) and image-load (`ProcessID`) carry it in payload. `daddr`/`saddr` are little-endian u32.
- **Session leak / self-healing:** a real-time ETW session outlives the process if it's killed without cleanup, keeps the kernel buffering system-wide events (slows the whole machine), and a same-named restart collides. `etw::start_session` proactively stops any pre-existing `scent-capture` session, and `lib.rs`'s `on_window_event(Destroyed)` calls `ipc::stop_capture_inner`. If things feel slow, check `logman query -ets | findstr scent` and `logman stop scent-capture -ets`.

## Frontend architecture (`src/`)

State lives in `App.tsx`: it listens to `capture://delta` and refetches the process tree only when `tree_version` changes (lazy). The event log is **append-only and arrival-ordered**, so `EventsTable` pages purely by `offset = loaded.length` — the same call fetches history (endReached) and the live tail (poll); under `collapse` it re-aggregates from offset 0 instead.

- `lib/types.ts` mirrors the serde shapes exactly (the `ScentEvent` discriminated union must match `EventKind`).
- `lib/events.ts` — category metadata/colors, `describeEvent`, highlight heuristics; `lib/ipc.ts` — typed command/event wrappers.
- Views: `ProcessTree`/`TreeNode`, `EventsTable` (react-virtuoso), `GraphView` (@xyflow/react), `TimelineView` (canvas), `Inspector`, `ExportMenu`.

### UI rules (Liquid Glass)

- Glass material (`backdrop-filter`, specular edge — the `.glass` class / `--glass-*` tokens) is for **chrome only** (top bar, tabs, inspector, export menu). Data surfaces (tree, event table, graph, timeline) are **opaque, high-contrast** — never put blur behind dense data.
- Saturated color is reserved for **data/category colors only** (`--cat-*`); chrome stays neutral, primary buttons are monochrome/inverted.
- **Tokens first:** define values in `src/styles/tokens.css` and reference them; never hard-code colors/blur/radius/spacing. Motion uses framer-motion springs from `lib/motion.ts` (no linear/ease). Native Mica backdrop is applied in `lib.rs` `setup` via `window-vibrancy` with `transparent: true`.
