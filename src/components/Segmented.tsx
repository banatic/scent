// A lightweight segmented control (chrome) — used to switch between lenses of the
// same data (the Evidence table/graph/timeline/deep views). The active pill slides
// with a shared layoutId so switching reads as one moving surface, not four buttons.
// No glass/blur: it sits on an opaque data panel header.

import { motion } from "framer-motion";

import { spring } from "../lib/motion";

export interface SegOption<T extends string> {
  id: T;
  label: string;
  icon?: React.ReactNode;
  badge?: number;
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  layoutId = "seg-pill",
}: {
  value: T;
  options: SegOption<T>[];
  onChange: (id: T) => void;
  /** Unique per mounted control so multiple segmented bars don't share a pill. */
  layoutId?: string;
}) {
  return (
    <div className="seg" role="tablist">
      {options.map((o) => {
        const on = o.id === value;
        return (
          <button
            key={o.id}
            type="button"
            role="tab"
            aria-selected={on}
            className={`seg__btn${on ? " seg__btn--on" : ""}`}
            onClick={() => onChange(o.id)}
          >
            {on && (
              <motion.span
                className="seg__pill"
                layoutId={layoutId}
                transition={spring.snappy}
              />
            )}
            {o.icon}
            <span className="seg__label">{o.label}</span>
            {o.badge != null && o.badge > 0 && (
              <span className="seg__badge tnum">{o.badge}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
