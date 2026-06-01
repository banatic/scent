#!/usr/bin/env python3
"""Curate SigmaHQ rules down to the subset scent's sensors can actually evaluate.

This is the permanent maintenance path. It mirrors two Rust sources and must be
kept in sync with them:

  * src-tauri/src/sigma_fields.rs  -> PROVIDED (fields scent emits per category)
  * src-tauri/src/sigma.rs         -> SUPPORTED_MODS + the condition grammar

A rule is kept only if every field/modifier/condition it uses is representable by
scent's engine, its logsource category is one we produce telemetry for, and the
product is Windows (or unspecified). Kept rules are partitioned:

  rules/stable_medium_plus/  status in {stable,test} AND level >= medium
  rules/optin/               evaluable but lower-confidence (experimental, or low)

informational-level and deprecated/unsupported rules are dropped. The run is
idempotent (output dirs are rebuilt) and writes rules/manifest.json with rule
counts, ATT&CK coverage, and a skip-reason breakdown.

Usage:
    git submodule update --init --depth 1 vendor/sigma   # first time / refresh
    python scripts/curate_sigma.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "sigma"
RULES_DIR = ROOT / "src-tauri" / "rules"
OUT_STABLE = RULES_DIR / "stable_medium_plus"
OUT_OPTIN = RULES_DIR / "optin"
MANIFEST = RULES_DIR / "manifest.json"

# Directories within vendor/sigma to scan (core detection + emerging threats).
SCAN_DIRS = ["rules", "rules-emerging-threats"]

# --- Mirrors sigma_fields.rs :: SigmaCategory::provided_fields ----------------
PROVIDED: dict[str, set[str]] = {
    "process_creation": {"Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine"},
    "registry_set": {"TargetObject", "EventType", "Image"},
    "registry_event": {"TargetObject", "EventType", "Image"},
    "registry_add": {"TargetObject", "EventType", "Image"},      # -> registry_event
    "registry_delete": {"TargetObject", "EventType", "Image"},   # -> registry_event
    "dns_query": {"QueryName", "QueryResults", "Image"},
    "dns": {"QueryName", "QueryResults", "Image"},               # -> dns_query
    "network_connection": {"DestinationIp", "DestinationPort", "Initiated", "Protocol", "Image"},
    "file_event": {"TargetFilename", "Image"},
    "file_access": {"TargetFilename", "Image"},
    "image_load": {"ImageLoaded", "Image"},
}

# --- Mirrors sigma.rs supported value modifiers ------------------------------
SUPPORTED_MODS = {
    "contains", "startswith", "endswith", "all", "re", "cidr",
    "windash", "base64", "base64offset", "i", "m", "s",
}

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def check_selection(sel, provided: set[str]) -> str | None:
    """Return a skip reason, or None if the selection is representable."""
    if isinstance(sel, dict):
        for key, _val in sel.items():
            parts = str(key).split("|")
            field, mods = parts[0], parts[1:]
            for m in mods:
                if m not in SUPPORTED_MODS:
                    return f"modifier:{m}"
            if field and field not in provided:
                return f"field:{field}"
        return None
    if isinstance(sel, list):
        if all(isinstance(i, dict) for i in sel):
            for i in sel:
                r = check_selection(i, provided)
                if r:
                    return r
            return None
        if all(isinstance(i, (str, int, float, bool)) for i in sel):
            return None  # keyword list — searches all fields, always representable
        return "mixed-list"
    # a bare scalar selection is unusual / unsupported
    return "scalar-selection"


def condition_ok(cond) -> str | None:
    """Coarse mirror of sigma.rs's condition grammar. Returns a skip reason or None."""
    if isinstance(cond, list):
        return "multi-condition"
    c = str(cond)
    if "|" in c:
        return "aggregation"  # `| count(...) by ...`
    toks = c.replace("(", " ( ").replace(")", " ) ").split()
    for i, t in enumerate(toks):
        # numeric quantifier other than `1` (e.g. `2 of selection*`)
        if t.isdigit() and t != "1":
            return "n-of-quantifier"
        if t.lower() == "of" and i > 0:
            q = toks[i - 1].lower()
            if q not in ("1", "all"):
                return "n-of-quantifier"
    return None


def classify(doc) -> tuple[str, str]:
    """Return (bucket, detail) where bucket in {stable, optin, skip}."""
    if not isinstance(doc, dict):
        return ("skip", "not-a-mapping")
    if "correlation" in doc:
        return ("skip", "correlation")

    ls = doc.get("logsource") or {}
    cat = ls.get("category")
    if cat not in PROVIDED:
        return ("skip", "category")
    product = ls.get("product")
    if product not in (None, "windows"):
        return ("skip", "product")

    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        return ("skip", "no-detection")
    if "timeframe" in det:
        return ("skip", "aggregation")
    r = condition_ok(det["condition"])
    if r:
        return ("skip", r)

    provided = PROVIDED[cat]
    for name, sel in det.items():
        if name in ("condition", "timeframe"):
            continue
        r = check_selection(sel, provided)
        if r:
            return ("skip", r)

    status = str(doc.get("status", "stable")).lower()
    if status in ("deprecated", "unsupported"):
        return ("skip", f"status:{status}")
    level_name = str(doc.get("level", "")).lower()
    if level_name not in LEVELS or level_name == "informational":
        return ("skip", "level:informational")

    if status in ("stable", "test") and LEVELS[level_name] >= LEVELS["medium"]:
        return ("stable", level_name)
    return ("optin", f"{status}/{level_name}")


def techniques(doc) -> list[str]:
    out = []
    for t in doc.get("tags", []) or []:
        t = str(t).lower()
        if t.startswith("attack.t") and t[8:9].isdigit():
            out.append("T" + t[8:].upper())
    return out


def main() -> int:
    if not VENDOR.exists():
        sys.exit(
            f"{VENDOR} not found. Run:\n"
            "  git submodule update --init --depth 1 vendor/sigma"
        )

    # Idempotent: rebuild output dirs from scratch.
    for d in (OUT_STABLE, OUT_OPTIN):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    skip_reasons: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    attack: set[str] = set()
    kept = {"stable": 0, "optin": 0}

    files = []
    for sub in SCAN_DIRS:
        base = VENDOR / sub
        if base.exists():
            files += sorted(base.rglob("*.yml"))

    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
            doc = next(iter(yaml.safe_load_all(text)))  # first document only
        except Exception:
            skip_reasons["parse-error"] += 1
            continue

        bucket, detail = classify(doc)
        if bucket == "skip":
            # Bucket fine-grained reasons under a coarse head for the summary.
            skip_reasons[detail.split(":")[0]] += 1
            continue

        out_dir = OUT_STABLE if bucket == "stable" else OUT_OPTIN
        rel = path.relative_to(VENDOR).as_posix().replace("/", "__")
        shutil.copyfile(path, out_dir / rel)
        kept[bucket] += 1
        cat = (doc.get("logsource") or {}).get("category", "?")
        by_category[cat] += 1
        by_status[str(doc.get("status", "stable")).lower()] += 1
        attack.update(techniques(doc))

    try:
        commit = subprocess.check_output(
            ["git", "-C", str(VENDOR), "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        commit = "unknown"

    manifest = {
        "generated_from": {"repo": "SigmaHQ/sigma", "commit": commit, "scanned": SCAN_DIRS},
        "counts": {
            "stable_medium_plus": kept["stable"],
            "optin": kept["optin"],
            "total_evaluable": kept["stable"] + kept["optin"],
            "scanned": len(files),
        },
        "by_category": dict(sorted(by_category.items())),
        "by_status": dict(sorted(by_status.items())),
        "attack_technique_count": len(attack),
        "attack_techniques": sorted(attack),
        "skipped": dict(sorted(skip_reasons.items(), key=lambda kv: -kv[1])),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # Console summary.
    print(f"scanned {len(files)} rules from {', '.join(SCAN_DIRS)} @ {commit[:12]}")
    print(f"  kept stable_medium_plus : {kept['stable']}")
    print(f"  kept optin              : {kept['optin']}")
    print(f"  total evaluable         : {kept['stable'] + kept['optin']}")
    print(f"  ATT&CK techniques       : {len(attack)}")
    print("  by category:")
    for c, n in sorted(by_category.items(), key=lambda kv: -kv[1]):
        print(f"    {c:<22} {n}")
    print("  skipped (by reason):")
    for r, n in sorted(skip_reasons.items(), key=lambda kv: -kv[1]):
        print(f"    {r:<22} {n}")
    print(f"manifest -> {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
