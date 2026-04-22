# Vibe Reverse Engineering — Copilot Instructions

This is a reverse engineering toolkit for PE binaries (`.exe` / `.dll`) combining static analysis (`retools`), dynamic analysis (`livetools` via Frida), and D3D9 frame tracing. Work is organized around knowledge base files (`kb.h`) that accumulate discoveries and feed back into richer decompilation.


## Read-Only Templates

These directories are **shared tooling and templates** — do not modify for game-specific work:
- `rtx_remix_tools/dx/remix-comp-proxy/` — proxy framework template (copy per-game)
- `rtx_remix_tools/dx/scripts/`, `retools/`, `livetools/`, `graphics/`, `renderdoctools/` — shared tooling

**Per-game work goes in `patches/<GameName>/`.** Copy the template there and edit the copy.

## DX9 FFP Porting

When editing `renderer.cpp`, `ffp_state.cpp`, `remix-comp-proxy.ini`, draw routing, VS constants, vertex declarations, matrix mapping, or skinning — read the **dx9-ffp-port** skill (`skills/dx9-ffp-port/SKILL.md`) before starting.

## Bootstrap

On first use, or if `kb.h` is missing or contains only minimal content, automatically run:
`python -m retools.bootstrap <binary> --project <ProjectName>`
before any further static or dynamic analysis. **Bootstrap takes 2-5 minutes** — it scans for RTTI classes, identifies CRT/library functions, and propagates labels. The output goes to `patches/<ProjectName>/kb.h` — verify this file exists and has content after bootstrap returns. All subsequent `decompiler.py` calls must use `--types patches/<ProjectName>/kb.h`. **Bootstrap speeds up all subsequent decompilation**: `--types` pre-analyzes every known function so cross-references resolve to named functions and you avoid the expensive full-binary analysis pass. Tell the user it's running and do other work while it completes.

**In parallel with bootstrap**, run `python retools/pyghidra_backend.py analyze <binary> --project patches/<ProjectName>` to create a reusable Ghidra project. This takes 5-15 minutes but makes all subsequent pyghidra decompilations near-instant. Both bootstrap and pyghidra analyze can run simultaneously.

Run `python verify_install.py` from the repo root before first use. If pyghidra/Ghidra shows as WARN, run `python verify_install.py --setup` to auto-download JDK 21 + Ghidra + pyghidra (~600MB one-time download). Common failures: missing `git lfs pull` (LFS pointer stubs instead of real binaries), missing `pip install -r requirements.txt`.

## Delegation Rule

**Never run static analysis tools (`retools`) directly in sequence.** Delegate to the `static-analyzer` agent for all offline analysis. Exceptions — run these inline (all <5s):

- `sigdb.py identify` / `fingerprint` — single-function ID or compiler detection
- `context.py assemble` / `postprocess` — context gathering and decompiler annotation (assemble now includes forward constant propagation by default; use `--no-dataflow` on large functions)
- `dataflow.py --constants` / `--slice` — single-function constant propagation or backward register trace
- `readmem.py` — single typed read from a PE file
- `asi_patcher.py build` — build step, not analysis
- `pyghidra_backend.py status` — project existence check (<1s)

If you're about to run a second `retools` command in the same turn, stop and delegate everything to a subagent.

Run all tools from the repo root using `python -m <module>` syntax (e.g. `python -m retools.search`).

## Live Tools First

The main agent owns `livetools` — always use them to verify static findings and act on leads from subagents. Use `attach <name_or_pid>` for running processes, or `attach <path> --spawn` to launch + instrument before init code runs. When a subagent returns addresses or candidates, immediately follow up with live tools (trace, breakpoint, mem read/write) rather than spawning more static analysis. Static analysis finds clues; live tools confirm and act on them. Do not wait idle for subagents — use live tools to explore independently while static analysis runs in the background.

## Dual-Backend Decompilation

The decompiler supports two backends with different strengths:

- **pyghidra (preferred)** — better MSVC type propagation, library call resolution, larger function scope detection. Requires a Ghidra project (`pyghidra_backend.py analyze` creates one). Use when `patches/<project>/ghidra/<binary>.gpr` exists.
- **r2ghidra (fallback)** — better `__thiscall` on small functions, no JVM startup. Always available.

**Auto mode**: `python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h --project patches/proj` tries pyghidra first, falls back to r2ghidra. Use `--project` alongside `--types` for auto selection.

**Dual-backend deep analysis**: For complex exploratory tasks (finding subsystems, mapping call chains), run both backends in parallel on the same functions and merge findings. r2ghidra results go to `findings_r2.md`, pyghidra to `findings.md`. Neither backend finds everything alone -- merging both gives the most complete picture.

## Engineering Standards

Every change should make the codebase better, not just make the problem go away. If a solution needs a paragraph to justify why it's not a hack, it's a hack.

**Remove:** fixes in the wrong layer, tolerance inflation, catch-all exception swallowing, excessive null-guard chains, god methods (200+ lines), leaky abstractions.

**Design for:** single responsibility (if you need "and" to describe it, split it), ownership (the component that creates the problem owns the fix), minimal public surface.

**Commit to the new code:** no legacy fallbacks, no dead code, no multiple paths to the same result, no half-migrations. Version control is the safety net — remove the old code.

## Code Comments

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey. Remove backstories, obvious narration, and debugging breadcrumbs. Keep non-obvious design decisions, tricky invariants, and API contracts (Google-style docstrings). Prefer renaming over commenting; prefer type hints over comments about expected types.

## References

Detailed guidance lives in scoped instruction files — consult these before acting:

- **Tool dispatch** (quick decision guide — which tool, run vs delegate): `.github/instructions/tool-dispatch.instructions.md`
- **Subagent workflow** (delegation, parallel work, anti-patterns): `.github/instructions/subagent-workflow.instructions.md`
- **Tool catalog** (full syntax tables and caveats): `.github/instructions/tool-catalog.instructions.md`
- **Knowledge base format** (kb.h conventions): `.github/instructions/kb-format.instructions.md`
- **FFP proxy porting** (DX9 FFP port workflow): `.github/instructions/ffp-proxy.instructions.md`
- **Static analyzer agent**: `.github/agents/static-analyzer.agent.md`
- **Web researcher agent**: `.github/agents/web-researcher.agent.md`
