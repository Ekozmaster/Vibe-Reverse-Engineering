---
description: Subagent delegation rules — when to delegate static analysis vs run livetools directly, parallel work patterns, examples
inclusion: always
---

# Subagent Workflow

The main agent orchestrates and focuses on **live tools**, **dx9tracer capture**, **user interaction**, and **synthesis**. Heavy static analysis and web research are delegated to subagents so the user isn't blocked.

## Bootstrap First — New Binaries

When analyzing a binary for the first time (no existing or sparsely populated `patches/<project>/kb.h`), **always bootstrap before other static analysis**:

1. Spawn a `static-analyzer` subagent to run `bootstrap.py <binary> --project <Name>` — this seeds `patches/<project>/kb.h` with RTTI classes, CRT/library function IDs, compiler info, and propagated labels. **Bootstrap takes 2-5 minutes.** Tell the user it's running and do other work while it completes. The output goes to `patches/<project>/kb.h` — verify this file exists and has content after bootstrap returns. **Bootstrap speeds up all subsequent decompilation**: when `--types kb.h` is passed to the decompiler, it pre-analyzes every known function (`af` per KB entry) so cross-references resolve to named functions, callees get inlined signatures, and you avoid the expensive full-binary `aaa` analysis pass.
2. Any other static analysis subagents should run in parallel, but their decompilation output will be richer if bootstrap finishes first
3. After bootstrap, all subsequent `decompiler.py` calls **must** use `--types patches/<project>/kb.h`

**How to detect "needs bootstrap":** Check if `patches/<project>/kb.h` exists AND has real content (function signatures `@`, globals `$`, or struct definitions beyond section headers). An empty or stub KB with only comment headers counts as sparse — bootstrap it. Quick check: `grep -cE '^[@$]|^struct |^enum ' patches/<project>/kb.h` — if the count is under 50, bootstrap.

## Delegation Rules

| Task | Where |
|------|-------|
| Static analysis (`retools`: decompiler, disasm, xrefs, search, structrefs, callgraph, rtti, datarefs, dumpinfo, throwmap) | `static-analyzer` subagent |
| Web research (docs, API refs, format specs, SDK docs) | `web-researcher` subagent |
| Live tools (`livetools`: attach, trace, bp, memwatch, dipcnt, mem read/write) | Main agent — directly |
| dx9tracer trigger/capture | Main agent — directly |
| dx9tracer analyze (offline JSONL analysis) | `static-analyzer` subagent |
| Bootstrap new binary (`bootstrap.py`) | `static-analyzer` subagent -- takes 2-5 min |
| Bulk signature scan (`sigdb.py scan`) | `static-analyzer` subagent -- takes 1-3 min |
| Signature DB build (`sigdb.py build`) | `static-analyzer` subagent -- takes 1-5 min |
| Single function ID (`sigdb.py identify`, `fingerprint`) | Main agent -- fast (<5s) |
| Context assembly (`context.py assemble`) | Main agent -- fast (<5s) |
| Decompiler postprocess (`context.py postprocess`) | Main agent -- instant |
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

Multiple `static-analyzer` instances can run in parallel for independent questions (e.g., decompiling two unrelated functions, analyzing different modules). When a subagent returns findings with multiple leads (e.g., "5 candidate functions found"), spawn parallel subagents to chase independent leads simultaneously — don't serialize them or try to analyze them yourself.

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

**"Analyze game.exe for the first time"**
1. Spawn `static-analyzer` in background: `bootstrap.py game.exe --project MyGame`
2. Tell the user: "Bootstrapping the binary -- this will auto-identify RTTI classes, CRT functions, and propagated labels. Takes ~3 minutes."
3. While bootstrap runs, use `sigdb.py fingerprint` (fast) to tell the user the compiler version
4. When bootstrap returns, read the report and summarize coverage to the user
5. All subsequent decompilations use `--types patches/MyGame/kb.h` with the seeded KB

## Anti-Patterns

**The Cascade Trap.** The main agent runs "one quick xref" -> sees an interesting caller -> decompiles it -> follows another xref -> now it's doing a full static analysis session while the user waits. If you catch yourself about to run a second retools command, stop and delegate everything to a subagent.

**Duplicating subagent work.** After spawning a static-analyzer, don't also grep/search for the same thing yourself. Trust the subagent. Use the wait time for livetools or user interaction.

**Silent waiting.** Spawning a subagent and then producing no output until it returns. Always talk to the user or do livetools work while subagents run.

## When NOT to Delegate

- Allowlisted fast commands (see CLAUDE.md Delegation Rule): `sigdb identify`, `sigdb fingerprint`, `context assemble`, `context postprocess`, `readmem.py`, `asi_patcher.py build`
- Anything requiring a live attached process — always main agent
- Iterative debugging loops where each step depends on the last live result — main agent

Everything else in `retools.*` goes to a `static-analyzer` subagent. No exceptions.

## Behavioral Fallback

If your tool does not support subagent dispatch, follow these delegation rules yourself: do not run multiple retools commands in sequence. Instead, collect all static analysis questions and run them in a single comprehensive pass. Use the wait time between commands for user interaction, not more analysis.
