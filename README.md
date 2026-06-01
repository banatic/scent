# scent

A Windows-only dynamic behavior analyzer and malware-triage instrument (Tauri 2 +
React/TS frontend, Rust backend). scent launches a target executable **suspended**,
attaches ETW, then resumes it — capturing the target subtree's process / file /
registry / network / DNS / module-load behavior for tree, graph, and timeline
exploration, and surfacing a **verdict-first** layer on top:

1. **Sigma** — community-maintained detections for known techniques.
2. **Invariant heuristics** — a few effect/surface-based detectors for novel
   combinations rules don't cover (beaconing, DGA/tunneling, ransom mass-ops,
   self-delete, injected threads).
3. **Full telemetry (+ optional LLM)** — the always-available safety net.

Findings are an **accelerator, not a gate**: even when nothing fires, the raw
events / tree / timeline are always shown. scent is an analysis instrument, not an
autonomous blocker — containment and in-memory visibility are out of scope.

See `CLAUDE.md` for architecture and the capture-pipeline invariants.

## Build & run

ETW capture requires an **elevated** shell (kernel providers). Dev/build does not.

- `npm install` then `npm run tauri dev` — run the app (must be elevated to capture).
- `npm run build` + `npx tsc --noEmit` — frontend build / typecheck.
- `cd src-tauri && cargo check` / `cargo test --lib` — backend compile / unit tests.
- Elevated headless checks: `cargo test --lib -- --ignored --nocapture captures_cmd_subtree`
  (full pipeline) and `explore_providers` (ETW schema discovery — run before changing
  ETW parsing; field names/event ids are version-sensitive).

## Sigma ruleset

scent ships a **curated** subset of [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma):
only rules whose logsource category, fields, value modifiers, and condition syntax
are representable by scent's sensors and mini Sigma engine (`src-tauri/src/sigma.rs`).

The upstream rules are a git submodule at `vendor/sigma`; the curated copies live in
`src-tauri/rules/` and are what the app loads. To refresh after upstream changes:

```sh
git submodule update --init --depth 1 vendor/sigma   # first checkout
git submodule update --remote vendor/sigma           # pull newer rules
python scripts/curate_sigma.py                        # re-curate (idempotent)
```

`scripts/curate_sigma.py` mirrors the engine's capabilities (`sigma_fields.rs`
provided fields + `sigma.rs` supported modifiers/grammar) — **keep them in sync**.
It writes:

- `src-tauri/rules/stable_medium_plus/` — status `stable`/`test`, level ≥ medium.
- `src-tauri/rules/optin/` — evaluable but lower-confidence (experimental, or low).
- `src-tauri/rules/manifest.json` — rule counts, ATT&CK coverage, skip reasons.

The curated rules retain SigmaHQ's [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License);
`manifest.json` records the source repo and commit they were generated from.

## Optional LLM triage

The **Verdict** tab can turn the findings + IOCs + process tree into a narrative
assessment. It's strictly optional and advisory — the verdict lives only in that
panel and never mutates the deterministic Findings. Two ways to use it:

- **Copy for LLM** — copies a guarded, citation-ready prompt to paste into any model.
- **Run analysis** — calls the Anthropic API directly. Set the backend env vars:
  - `ANTHROPIC_API_KEY` (required for this path),
  - `ANTHROPIC_MODEL` (optional; defaults to `claude-sonnet-4-6`).

Without a key, everything else — capture, detection, and the whole UI — works
unchanged; only **Run analysis** is disabled.
