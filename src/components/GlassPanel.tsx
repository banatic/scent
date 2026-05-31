// The Liquid Glass material — used ONLY for floating chrome (bars, rails,
// overlays), never for data surfaces. The specular edge + layered shadows live
// in the `--shadow-glass` token; this component just composes them.

import type { HTMLMotionProps } from "framer-motion";
import { motion } from "framer-motion";

type GlassPanelProps = HTMLMotionProps<"div"> & {
  strong?: boolean;
};

export function GlassPanel({ strong, className, style, ...rest }: GlassPanelProps) {
  return (
    <motion.div
      className={`glass${strong ? " glass--strong" : ""}${className ? ` ${className}` : ""}`}
      style={style}
      {...rest}
    />
  );
}
