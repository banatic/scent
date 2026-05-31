// Spring presets — the motion half of the token system. framer-motion only;
// linear/ease-in-out are banned by the design spec. Components reference these
// instead of inlining stiffness/damping.

import type { Transition } from "framer-motion";

export const spring = {
  // Snappy UI feedback (buttons, toggles).
  snappy: { type: "spring", stiffness: 460, damping: 34, mass: 0.9 },
  // Panels and rows morphing into place.
  panel: { type: "spring", stiffness: 320, damping: 32, mass: 1 },
  // Gentle settling for larger surfaces.
  soft: { type: "spring", stiffness: 210, damping: 26, mass: 1 },
} satisfies Record<string, Transition>;

// Standard enter for newly-discovered tree rows.
export const rowEnter = {
  initial: { opacity: 0, y: -4 },
  animate: { opacity: 1, y: 0 },
  transition: spring.panel,
};
