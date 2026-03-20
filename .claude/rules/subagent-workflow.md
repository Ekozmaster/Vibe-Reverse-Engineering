---
description: Subagent delegation rules — when to spawn static-analyzer vs run livetools directly, parallel work patterns, examples
---

# Subagent Workflow

The main agent orchestrates and focuses on **live tools**, **dx9tracer capture**, **user interaction**, and **synthesis**. Heavy static analysis and web research are delegated to subagents so the user isn't blocked.

## Delegation Rules

| Task | Where |
|------|-------|
| Static analysis (`retools`: decompiler, disasm, xrefs, search, structrefs, callgraph, rtti, datarefs, dumpinfo, throwmap) | `static-analyzer` subagent |
| Web research (docs, API refs, format specs, SDK docs) | `web-researcher` subagent |
| Live tools (`livetools`: attach, trace, bp, memwatch, dipcnt, mem read/write) | Main agent — directly |
| dx9tracer trigger/capture | Main agent — directly |
| dx9tracer analyze (offline JSONL analysis) | `static-analyzer` subagent |
| File editing, patch specs, builds | Main agent — directly |
| KB updates from subagent findings | `static-analyzer` writes to `kb.h`; main agent may refine |

## Subagent Output Files

Subagents write detailed findings to `patches/<project>/findings.md` (appended, not overwritten). When a subagent returns, it states the file path — **read the file** for full details including decompilation output, address tables, and suggested livetools commands. The return message is just a summary.

## Parallel Work

When both static and dynamic analysis are needed:
1. Spawn `static-analyzer` **in background** for the static questions
2. **Immediately ask the user** if the game/process is running or ask them to launch it — don't wait for static results
3. While the subagent works, prepare livetools (attach, set up traces) or discuss the approach with the user
4. Synthesize findings when the subagent returns

Multiple `static-analyzer` instances can run in parallel for independent questions (e.g., decompiling two unrelated functions, analyzing different modules).

## Main Agent Responsibilities During Analysis

**Do not silently wait for subagents.** While static analysis runs:
- Ask the user to launch the game/process if live verification or patching will be needed
- Discuss the approach, explain what the subagent is looking for
- Prepare livetools commands based on what you already know
- If the task involves runtime patching (disabling culling, skipping checks, etc.), assume live tools WILL be needed and prompt the user early

## Examples

**"Disable culling in game.exe"**
1. Spawn `static-analyzer` in background: find `SetRenderState` calls with `D3DRS_CULLMODE`, string search for "cull", xrefs to render state functions
2. Immediately tell the user: "Please launch the game — I'll need to attach with livetools to patch culling at runtime once I find the addresses"
3. When static results return, use `livetools` to verify and patch: `mem write` to NOP the cull-enable instruction or force `D3DRS_CULLMODE` to `D3DCULL_NONE`

**"What does function 0x401000 do?"**
1. Spawn `static-analyzer`: decompile with `--types kb.h`, get callgraph, xrefs
2. Tell the user: "Static analysis is running. Want me to also trace this function live to see actual register values and call frequency?"
3. If yes, attach with `livetools trace 0x401000 --count 20 --read`

**"Find who writes to address 0x7A0000"**
1. Spawn `static-analyzer`: `datarefs.py` for static references
2. Ask user: "Is the game running? I can also set a `livetools memwatch` to catch runtime writes that static analysis might miss"
3. Combine static xrefs with live write traces for complete picture

**"Why does the game crash in d3d9.dll?"**
1. Spawn `static-analyzer`: `dumpinfo.py diagnose`, `throwmap.py match`
2. Tell the user: "Analyzing the crash dump. If you can reproduce the crash, launch the game and I'll attach to catch it live"

## When NOT to Delegate

- Quick single-command lookups where you already know exactly what to run and need the result immediately — run directly
- Anything requiring a live attached process — always main agent
- Iterative debugging loops where each step depends on the last live result — main agent
