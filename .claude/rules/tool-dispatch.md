---
description: Quick decision guide — which RE tool to use and whether to run it directly or delegate
---

# Tool Dispatch

**BEFORE FIRST USE**: Run `python verify_install.py` from repo root. If pyghidra/Ghidra shows WARN, run `python verify_install.py --setup`.

Run all tools from repo root via `python -m <module>`. **ALWAYS pass `--types patches/<project>/kb.h`** to `decompiler.py`. For full syntax tables and caveats, read `.claude/references/tool-catalog.md`.

## Run Directly (main agent, <5s)

- `python -m retools.sigdb fingerprint $B` — compiler ID
- `python -m retools.sigdb identify $B $VA` — single function signature lookup
- `python -m retools.context assemble $B $VA --project $P` — full analysis context
- pipe through `python -m retools.context postprocess` — rename/annotate decompiler output
- `python -m retools.readmem $B $VA $TYPE` — read typed PE data
- `python -m retools.dataflow $B $VA --constants` — forward constant propagation
- `python -m retools.dataflow $B $VA --slice TARGET_VA:REG` — backward register slice
- `python -m retools.asi_patcher build spec.json` — build ASI patch DLL
- `python retools/pyghidra_backend.py status $B --project $P` — Ghidra project existence check

## Delegate to `static-analyzer`

Everything else in `retools`. Tell it WHAT you need, not HOW. D3D9-specific questions — try DX scripts first (faster).

- Decompile / callgraph / xrefs / string search / datarefs / structrefs / RTTI / throwmap / dumpinfo
- Bootstrap new binary (2-5 min) / pyghidra analyze (5-15 min) / bulk sigdb scan (1-3 min)
- dx9tracer offline analysis (summary, render-passes, shader-map, etc.)

## Live tools (main agent, attached process)

Full syntax and recipes: the `/dynamic-analysis` skill (canonical livetools reference).

- `livetools attach <name_or_pid>` — attach to running process
- `livetools attach <path> --spawn` — launch exe suspended, instrument, resume (catches init code)
- `livetools trace` / `steptrace` / `collect` — hit logging, register reads, instruction traces
- `livetools bp` / `watch` / `regs` / `stack` / `bt` — breakpoints + inspection
- `livetools mem read/write/alloc` / `scan` — memory ops
- `livetools dipcnt` / `memwatch` — D3D9 draw counters, write watchpoints
- `livetools vishook` — selective visibility override via code cave
- `livetools gamectl` — send keys/clicks to game window (no focus steal)
- `livetools modules` — loaded module list
- `livetools analyze <jsonl>` — offline trace aggregation

## DX analysis scripts (main agent, fast first-pass)

Targeted D3D9 scanners under `rtx_remix_tools/dx/scripts/` — use BEFORE retools for D3D9 questions (imports, VS/PS constants, render states, texture pipeline, transforms, FVF/vertex decls, draw classification, matrix registers, skinning, shader bytecode). Run as `python rtx_remix_tools/dx/scripts/<script> $B`. Full script table with examples: `.claude/references/tool-catalog.md`.

## dx9tracer

- Capture (main agent): `python -m graphics.directx.dx9.tracer trigger --game-dir <DIR>`
- Analysis (delegate): `python -m graphics.directx.dx9.tracer analyze <JSONL> [OPTIONS]`
