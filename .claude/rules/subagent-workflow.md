---
description: Subagent delegation rules — when to spawn static-analyzer vs run livetools directly, parallel work patterns
---

# Subagent Workflow

Main agent: **live tools**, **dx9tracer capture**, **user interaction**, **synthesis**. Heavy static analysis → subagents.

## Pre-flight: Ensure Ghidra Backend

Before first pyghidra use, run `python verify_install.py` — if pyghidra shows WARN, run `python verify_install.py --setup` (one-time ~600MB download).

## Bootstrap First — New Binaries

When analyzing a binary for the first time (no existing or sparsely populated `patches/<project>/kb.h`), **always bootstrap before other static analysis**:

1. Spawn `static-analyzer`: `bootstrap.py <binary> --project patches/<Name>` (`--project` is the output directory path — include the `patches/` prefix or kb.h lands outside the project tree) — seeds kb.h with RTTI, CRT/library IDs, compiler info, propagated labels. **2-5 minutes.** After bootstrap, ALL `decompiler.py` calls must use `--types patches/<project>/kb.h`.
2. **In parallel**, spawn second `static-analyzer`: `pyghidra_backend.py analyze <binary> --project patches/<Name>` — full Ghidra analysis, reusable project. **5-15 minutes.** After this, use `--project patches/<project>` so `--backend auto` prefers Ghidra.
3. Other static analysis can run in parallel but output is richer after bootstrap.

**Detect "needs bootstrap":** `grep -cE '^[@$]|^struct |^enum ' patches/<project>/kb.h` — count under 50 = bootstrap.
**Detect "needs pyghidra analyze":** Check if `patches/<project>/ghidra/<binary_stem>.gpr` exists.

## Delegation Beyond CLAUDE.md

CLAUDE.md lists allowlisted fast commands (run directly) and the general delegation rule. Additional non-obvious delegation:

| Task | Where | Notes |
|------|-------|-------|
| dx9tracer offline analysis | `static-analyzer` subagent | |
| Subsequent Ghidra decompile | `static-analyzer` subagent | Fast: JVM ~3s + decompile <1s, sub-second with a warm `ghidra_server.py` daemon |
| sigdb scan / build | `static-analyzer` subagent | scan 1-3 min, build 1-5 min |
| Dataflow: constants + backward slice (`dataflow.py`) | Main agent | fast (<5s) |
| KB updates from findings | `static-analyzer` writes kb.h, then `kb-apply` to push into Ghidra | main agent may refine |
| `index status` / `query` (SQL over index.db) | Main agent | fast (<5s); prefer over xrefs/datarefs/search/funcinfo when index.db already has the answer |
| `pyghidra_backend.py export` (seed index.db from Ghidra) | `static-analyzer` subagent | run once per analysis pass, after `kb-apply` |

## Subagent Output

Subagents write to `patches/<project>/findings.md` (appended). When a subagent returns, **read the file** for full details — the return message is just a summary.

## Parallel Work

1. Spawn `static-analyzer` **in background** for static questions
2. **Immediately** ask user to launch the game — don't wait for static results
3. While subagent works, prepare livetools or discuss approach
4. Synthesize when subagent returns

Multiple `static-analyzer` instances can run in parallel for independent questions. When results have multiple leads, spawn parallel subagents — don't serialize.

## Dual-Backend Deep Analysis

Ghidra (indexed, daemon-backed, kb-applied) is the primary backend once a project exists — prefer it plus `retools.query` over spawning two agents. Reserve the dual-agent pattern below for two specific cases: **no Ghidra project exists yet** (so there's no `index.db` or warm daemon to lean on), or **pyghidra output on a specific function looks wrong** and you need an independent r2ghidra read to cross-check it.

When one of those applies, spawn **two parallel agents**:

1. **r2ghidra**: `--backend pdg --types kb.h` → writes `findings_r2.md`
2. **pyghidra**: `pyghidra_backend.py decompile` → writes `findings.md`

r2ghidra: better `__thiscall` recovery, low-level D3D, no JVM/project dependency. pyghidra: better library call resolution, type propagation, and its output is exportable into `index.db` for future queries. Merge both for complete picture. Not needed for single-function decompilation once a Ghidra project exists — use `--backend auto` (Ghidra primary, r2ghidra fallback).

## Main Agent During Analysis

**Do not silently wait.** While static analysis runs:
- Ask user to launch game if live verification/patching needed
- Prepare livetools commands from what you already know
- Discuss the approach

## Examples

**"Analyze game.exe for the first time"**
1. Background: `bootstrap.py game.exe --project patches/MyGame`
2. Background: `pyghidra_backend.py analyze game.exe --project patches/MyGame`
3. Tell user, run `sigdb.py fingerprint` inline while waiting
4. When both return, all subsequent decompilations use `--types kb.h --project patches/MyGame`

**"Disable culling in game.exe"**
1. Spawn `static-analyzer` #1 (r2ghidra): find `SetRenderState` calls with `D3DRS_CULLMODE`, string search for "cull", xrefs --indirect to find vtable call sites. Uses `--backend pdg --types kb.h`. Writes to `findings_r2.md`.
2. Spawn `static-analyzer` #2 (pyghidra): same search strategy but decompile with `pyghidra_backend.py decompile`. Writes to `findings.md`.
3. Immediately tell the user: "Please launch the game — I'll need to attach with livetools to patch culling at runtime once I find the addresses"
4. While waiting, run `dataflow.py --constants` on any known render functions to see what cull mode constants flow in (e.g., `eax = 0x2` = D3DCULL_CW)
5. When both return, merge findings and use `livetools` to verify and patch: `mem write` to NOP the cull-enable instruction or force `D3DRS_CULLMODE` to `D3DCULL_NONE`

**"What does function 0x401000 do?"**
1. Spawn `static-analyzer`: decompile with `--types kb.h`, get callgraph --indirect, xrefs
2. Run `dataflow.py 0x401000 --constants` inline — see what constants flow through
3. Tell the user: "Static analysis is running. Want me to also trace this function live to see actual register values and call frequency?"
4. If yes, attach with `livetools trace 0x401000 --count 20 --read`

**"Find who writes to address 0x7A0000"**
1. Spawn `static-analyzer`: `datarefs.py` for static references
2. Ask user: "Is the game running? I can also set a `livetools memwatch` to catch runtime writes that static analysis might miss"
3. Combine static xrefs with live write traces for complete picture

**"Why does the game crash in d3d9.dll?"**
1. Spawn `static-analyzer`: `dumpinfo.py diagnose`, `throwmap.py match`
2. Tell the user: "Analyzing the crash dump. If you can reproduce the crash, launch the game and I'll attach to catch it live"

## Anti-Patterns

- **Cascade Trap**: Running "one quick xref" then chasing callers until you're doing full static analysis while user waits. Second retools command = should have delegated.
- **Duplicating subagent work**: Don't grep for the same thing you delegated. Trust the subagent.
- **Silent waiting**: Always talk to user or do livetools while subagents run.
