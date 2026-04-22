---
applyTo: "**"
---

# Subagent Workflow

Main agent: live tools, user interaction, synthesis. Heavy static analysis → `static-analyzer` subagent.

## Pre-flight

Run `python verify_install.py` before first pyghidra use. If WARN, run `python verify_install.py --setup` (one-time ~600MB).

## Bootstrap First — New Binaries

When a binary has no or sparse `patches/<project>/kb.h` (fewer than 50 `@`/`$`/`struct`/`enum` lines):

1. Spawn `static-analyzer`: `bootstrap.py <binary> --project <Name>` (2-5 min, seeds kb.h)
2. **In parallel**, spawn second `static-analyzer`: `pyghidra_backend.py analyze <binary> --project patches/<Name>` (5-15 min, reusable Ghidra project)
3. After both: all `decompiler.py` calls use `--types patches/<project>/kb.h --project patches/<project>`

**Detect needs:** `grep -cE '^[@$]|^struct |^enum ' patches/<project>/kb.h` — under 50 = bootstrap. Check `patches/<project>/ghidra/<binary>.gpr` exists for Ghidra.

## Delegation Table

| Task | Where |
|------|-------|
| Decompile / callgraph / xrefs / strings / datarefs / structrefs / RTTI / throwmap / dumpinfo | `static-analyzer` |
| Web research, API docs, specs | `web-researcher` |
| Bootstrap / pyghidra analyze / bulk sigdb scan | `static-analyzer` |
| `dataflow.py`, `readmem.py`, `sigdb identify/fingerprint`, `context.py` | Main agent (fast, <5s) |
| `livetools` (trace, bp, mem, scan) | Main agent |
| dx9tracer capture | Main agent |
| dx9tracer analysis | `static-analyzer` |

## Parallel Work

1. Spawn `static-analyzer` in background
2. **Immediately** engage user — ask to launch game, prepare livetools, discuss approach
3. Do NOT silently wait for subagents
4. When subagent returns, read `patches/<project>/findings.md` for full details
5. Follow up with livetools to verify/act on findings

Multiple `static-analyzer` instances can run in parallel for independent questions.

## Dual-Backend Deep Analysis

For complex exploratory tasks, spawn two parallel agents:
- **r2ghidra**: `--backend pdg --types kb.h` → writes `findings_r2.md`
- **pyghidra**: `pyghidra_backend.py decompile` → writes `findings.md`

Merge both for complete picture. Not needed for single-function work — use `--backend auto`.

## Anti-Patterns

- **Cascade Trap**: "One quick xref" chains into full static analysis while user waits. Second retools command = should have delegated.
- **Duplicating subagent work**: Don't grep for what you delegated.
- **Silent waiting**: Always talk to user or run livetools while subagents work.
