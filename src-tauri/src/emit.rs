//! Batched delta emitter.
//!
//! ETW can deliver thousands of events per second; emitting each to the
//! frontend would melt the IPC bridge. Instead we push a small summary delta
//! ~10 times per second. The frontend uses `tree_version` in the delta to decide
//! when to lazily refetch the full tree via a command.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tauri::{AppHandle, Emitter};

use crate::store::Capture;

pub const DELTA_EVENT: &str = "capture://delta";

/// Tick at ~10 Hz while capturing, then emit one final delta after stop so the
/// UI settles on the last state.
pub fn run_emit_loop(app: AppHandle, capture: Arc<RwLock<Capture>>, running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        let delta = capture.read().delta();
        let _ = app.emit(DELTA_EVENT, delta);
    }
    let delta = capture.read().delta();
    let _ = app.emit(DELTA_EVENT, delta);
}
