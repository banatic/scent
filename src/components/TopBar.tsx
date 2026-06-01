// Top chrome bar: target selection, capture controls, and live counters.
// Glass material; neutral (no saturated color) except the recording status dot.

import { motion } from "framer-motion";
import { FolderOpen, Loader, Play, Square } from "lucide-react";

import { spring } from "../lib/motion";
import type { CaptureStatus } from "../lib/types";
import { GlassPanel } from "./GlassPanel";

function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms));
  const minutes = Math.floor(total / 60000);
  const seconds = Math.floor((total % 60000) / 1000);
  const tenths = Math.floor((total % 1000) / 100);
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${tenths}`;
}

interface TopBarProps {
  status: CaptureStatus;
  targetPath: string;
  args: string;
  busy: boolean;
  deep: boolean;
  onDeepChange: (v: boolean) => void;
  onPick: () => void;
  onArgsChange: (value: string) => void;
  onStart: () => void;
  onStop: () => void;
}

export function TopBar({
  status,
  targetPath,
  args,
  busy,
  deep,
  onDeepChange,
  onPick,
  onArgsChange,
  onStart,
  onStop,
}: TopBarProps) {
  const running = status.running;
  const fileName = targetPath ? targetPath.split(/[\\/]/).pop() : "";

  return (
    <GlassPanel className="topbar" transition={spring.panel}>
      <div className="topbar__brand">
        <span className="topbar__mark">scent</span>
      </div>

      <button
        type="button"
        className="field field--target"
        onClick={onPick}
        disabled={running || busy}
        title={targetPath || "Select target executable"}
      >
        <FolderOpen size={15} strokeWidth={1.75} />
        {targetPath ? (
          <span className="field__path">
            <span className="field__name">{fileName}</span>
            <span className="field__dir">{targetPath}</span>
          </span>
        ) : (
          <span className="field__placeholder">Select target executable…</span>
        )}
      </button>

      <input
        className="field field--args"
        placeholder="arguments"
        value={args}
        disabled={running || busy}
        spellCheck={false}
        onChange={(e) => onArgsChange(e.target.value)}
      />

      <div className="topbar__counters">
        <div
          className={`capsule${running ? " capsule--on" : ""}`}
          title={`${status.process_count.toLocaleString()} processes · ${status.live_count.toLocaleString()} live`}
        >
          <motion.span
            className="rec__dot"
            animate={running ? { opacity: [1, 0.35, 1] } : { opacity: 0.4 }}
            transition={
              running
                ? { duration: 1.4, repeat: Infinity, ease: "easeInOut" }
                : { duration: 0.2 }
            }
          />
          <span className="rec__time tnum">{formatElapsed(status.elapsed_ms)}</span>
          <span className="capsule__sep" />
          <span className="capsule__events tnum">
            {status.total_events.toLocaleString()}
            <span className="capsule__unit">events</span>
          </span>
        </div>
      </div>

      <button
        type="button"
        className={`deeptoggle${deep ? " deeptoggle--on" : ""}`}
        onClick={() => onDeepChange(!deep)}
        disabled={running || busy}
        title="Deep mode: stack-walk file probes to attribute the calling DLL (caller DLL / tier / failed). Higher overhead."
      >
        <span className="deeptoggle__track">
          <span className="deeptoggle__knob" />
        </span>
        Deep
      </button>

      <motion.button
        type="button"
        className={`btn btn--primary${running ? " btn--stop" : ""}`}
        onClick={running ? onStop : onStart}
        disabled={busy || (!running && !targetPath)}
        whileTap={{ scale: 0.97 }}
        transition={spring.snappy}
      >
        {busy ? (
          <Loader size={15} className="spin" />
        ) : running ? (
          <Square size={14} fill="currentColor" />
        ) : (
          <Play size={15} fill="currentColor" />
        )}
        <span>{running ? "Stop" : "Capture"}</span>
      </motion.button>
    </GlassPanel>
  );
}
