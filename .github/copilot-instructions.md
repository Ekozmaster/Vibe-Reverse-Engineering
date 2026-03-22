# Vibe Reverse Engineering — Copilot Instructions

This is a reverse engineering toolkit for PE binaries (`.exe` / `.dll`) combining static analysis (`retools`), dynamic analysis (`livetools` via Frida), and D3D9 frame tracing. Work is organized around knowledge base files (`kb.h`) that accumulate discoveries and feed back into richer decompilation.


## Bootstrap

On first use, or if `kb.h` is missing or contains only minimal content, automatically run:
`python -m retools.bootstrap <binary> --project <ProjectName>`
before any further static or dynamic analysis. **Bootstrap takes 2-5 minutes** — it scans for RTTI classes, identifies CRT/library functions, and propagates labels. The output goes to `patches/<ProjectName>/kb.h` — verify this file exists and has content after bootstrap returns. All subsequent `decompiler.py` calls must use `--types patches/<ProjectName>/kb.h`. **Bootstrap speeds up all subsequent decompilation**: `--types` pre-analyzes every known function so cross-references resolve to named functions and you avoid the expensive full-binary analysis pass. Tell the user it's running and do other work while it completes.

Run `python verify_install.py` from the repo root before first use. Common failures: missing `git lfs pull` (LFS pointer stubs instead of real binaries), missing `pip install -r requirements.txt`.

## Delegation Rule

**Never run static analysis tools (`retools`) directly in sequence.** Delegate to the `static-analyzer` agent for all offline analysis. Exceptions — run these inline (all <5s):

- `sigdb.py identify` / `fingerprint` — single-function ID or compiler detection
- `context.py assemble` / `postprocess` — context gathering and decompiler annotation
- `readmem.py` — single typed read from a PE file
- `asi_patcher.py build` — build step, not analysis

If you're about to run a second `retools` command in the same turn, stop and delegate everything to a subagent.

Run all tools from the repo root using `python -m <module>` syntax (e.g. `python -m retools.search`).

## Live Tools First

The main agent owns `livetools` — always use them to verify static findings and act on leads from subagents. When a subagent returns addresses or candidates, immediately follow up with live tools (trace, breakpoint, mem read/write) rather than spawning more static analysis. Static analysis finds clues; live tools confirm and act on them. Do not wait idle for subagents — use live tools to explore independently while static analysis runs in the background.

## Engineering Standards

Every change should make the codebase better, not just make the problem go away. If a solution needs a paragraph to justify why it's not a hack, it's a hack.

**Remove:** fixes in the wrong layer, tolerance inflation, catch-all exception swallowing, excessive null-guard chains, god methods (200+ lines), leaky abstractions.

**Design for:** single responsibility (if you need "and" to describe it, split it), ownership (the component that creates the problem owns the fix), minimal public surface.

**Commit to the new code:** no legacy fallbacks, no dead code, no multiple paths to the same result, no half-migrations. Version control is the safety net — remove the old code.

## Code Comments

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey. Remove backstories, obvious narration, and debugging breadcrumbs. Keep non-obvious design decisions, tricky invariants, and API contracts (Google-style docstrings). Prefer renaming over commenting; prefer type hints over comments about expected types.

## References

Detailed guidance lives in scoped instruction files — consult these before acting:

- **Tool catalog** (all retools / livetools / dx9tracer commands and caveats): `.github/instructions/tool-catalog.instructions.md`
- **Knowledge base format** (kb.h conventions, when to update, struct/function/global notation): `.github/instructions/kb-format.instructions.md`
- **FFP proxy porting for RTX Remix** (DX9 fixed-function pipeline port workflow): `.github/instructions/ffp-proxy.instructions.md`
- **Static analyzer agent** (delegation workflow, what to tell it, output file conventions): `.github/agents/static-analyzer.agent.md`
- **Web researcher agent** (when and how to delegate web research): `.github/agents/web-researcher.agent.md`
