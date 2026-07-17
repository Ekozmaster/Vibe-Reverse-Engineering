# Vibe Reverse Engineering — Agent Instructions

LLM-friendly static and dynamic analysis toolkit for x86/x64 PE binaries (`.exe` / `.dll`), combining static analysis (`retools`), dynamic analysis (`livetools` via Frida), and D3D9 frame tracing. Work is organized around per-game knowledge base files (`kb.h`) that accumulate discoveries and feed back into richer decompilation.

This file is the canonical, harness-agnostic instruction set. Claude Code loads it via `.claude/CLAUDE.md`; Cursor, Copilot, Codex, and other agents read it directly. Deeper references live under `.claude/` and apply to every harness:

- **Tool catalog** (every retools / livetools / dx9tracer command, syntax, caveats): `.claude/references/tool-catalog.md`
- **Tool dispatch** (which tool for which question; what runs inline vs delegated): `.claude/rules/tool-dispatch.md`
- **Analysis workflow** (bootstrap ordering, Ghidra backend, index/query, parallel patterns): `.claude/rules/subagent-workflow.md`
- **Skills** (`dx9-ffp-port`, `dynamic-analysis`): `.claude/skills/` — canonical copies. Non-Claude harnesses install them with `npx skills add` (see README).

## Read-Only Templates

These directories are **shared tooling and templates**. Do not modify them for game-specific work — per-game changes go in `patches/<GameName>/`.

- `rtx_remix_tools/dx/remix-comp-proxy/` — proxy framework **template** (copied per-game)
- `rtx_remix_tools/dx/scripts/` — DX9 analysis scripts (shared tooling)
- `retools/` — static analysis toolkit (shared tooling)
- `livetools/` — Frida-based dynamic analysis (shared tooling)
- `graphics/` — DX9 tracer framework (shared tooling)

**Per-game work goes in `patches/<GameName>/`.** When starting a new game, copy `rtx_remix_tools/dx/remix-comp-proxy/` (excluding `build/`) to `patches/<GameName>/` and edit the copy. If the user says "edit remix-comp-proxy code" without specifying, ask whether they mean the template or a game copy.

Shared tooling can be modified to improve the tools themselves — just not for game-specific customization.

## Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts: knowledge base files (`kb.h`), one-off analysis scripts, ASI patch specs and builds, notes, logs, and collected trace data. Create the project subfolder on first use.

### Backups

Before modifying project files (proxy source, kb.h, proxy.ini, build scripts, ASI specs), create a timestamped backup capturing the last known-good state:

```
patches/<project>/backups/YYYY-MM-DD_HHMM_<short-description-slug>/
```

Copy ALL files being modified into the backup folder before making changes.

### Knowledge Base

Maintain `patches/<project>/kb.h` while reverse engineering a binary. Format: C types (no prefix), functions (`@` prefix), globals (`$` prefix):

```c
struct Foo { int x; float y; };
@ 0x401000 void __cdecl ProcessInput(int key);
$ 0x7C5548 Object* g_mainObject
```

Update the KB when you: identify a function's purpose, reconstruct a struct, identify a global, find magic constants (define an enum), or resolve RTTI class names. Always pass `--types patches/<project>/kb.h` to the decompiler once a KB exists.

## Working Method

- **Delegate heavy static analysis.** If your harness supports custom agents, use the `static-analyzer` agent for decompilation, xrefs, searches, and bulk scans instead of running `retools` commands in the main conversation. Only the fast (<5s) commands listed in `.claude/rules/tool-dispatch.md` run inline. If you're about to run a second retools command in the same turn, delegate.
- **Live tools confirm static findings.** When static analysis returns addresses or candidates, follow up with `livetools` (trace, breakpoint, mem read/write) rather than more static analysis. Static analysis finds clues; live tools confirm and act on them. Don't sit idle while background analysis runs.
- **Bootstrap new binaries first.** No or sparse `patches/<project>/kb.h` means run `bootstrap.py` and `pyghidra_backend.py analyze` before other static analysis — full workflow in `.claude/rules/subagent-workflow.md`.
- **DX9 FFP porting** (renderer.cpp, ffp_state, remix-comp-proxy.ini, draw routing, VS constants, vertex declarations, matrix mapping, skinning, build/deploy of a proxy patch): use the `dx9-ffp-port` skill before editing.
- **Dynamic analysis** (attach, breakpoints, tracing, runtime patching): use the `dynamic-analysis` skill as the canonical livetools reference.

## Engineering Standards

Every change should make the codebase better, not just make the problem go away. If a solution needs a paragraph to justify why it's not a hack, it's a hack.

### Remove
- **Fixes in the wrong layer**: a guard on a canvas to suppress commits that a model should own. Put the fix where the problem originates.
- **Tolerance inflation**: widening deltas or adding retries to hide flaky behavior. If the value is wrong, find out why.
- **Catch-all exception swallowing**: `try/except Exception: pass` to hide symptoms.
- **Excessive error/null handling**: adding too many error/None "if" checks. If the error is expected, handle it. If unexpected, raise it.
- **God methods**: 200+ line functions doing multiple things. Break into named steps. Focus on cognitive load. Design for fewer indentation levels.
- **Leaky abstractions**: implementation details leaking into layers/modules that should be agnostic of one another.

### Design For
- **Single responsibility**: one component, one job. If you need "and" to describe it, split it.
- **Ownership**: the component that creates the problem owns the fix.
- **Minimal public surface**: expose what consumers need, nothing more.

### Commit to the New Code
- **No legacy fallbacks**: if you replace a system, remove the old one.
- **No dead code**: commented-out blocks, unused imports, orphan functions "just in case". Version control is the safety net.
- **No multiple paths to the same result**: one way to do each thing. If two paths exist, one is wrong.
- **No half-migrations**: finish the job — update every reference, remove old APIs.

### Smell Tests
- "It works if I add a sleep" — broken data flow.
- "It works if I read from widget instead of storage" — the two are out of sync.
- "It passes alone but fails with other tests" — shared mutable state leaking.
- "I added a flag to skip this code path" — why does that path run in the first place?

## Code Comments

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey. These rules are not exhaustive — extrapolate from the principles to the context at hand.

### Remove
- **Implementation backstories**: "We do this because the other day X happened"
- **Obvious narration**: "Create the attribute", "Loop through keys", "Check if valid" — if the code says it, the comment is noise
- **Debugging breadcrumbs**: "Without this, subsequent tests may see the modifier key as still held"
- **Trial-and-error reasoning**: "We tried X but it caused Y so we do Z instead"

### Keep
- **Non-obvious design decisions**: stated as *what* and *why this design*, not *what happened to us*
- **Tricky invariants**: conditions that would be easy to accidentally break
- **API contracts**: docstrings on public methods with Args, Returns, Raises

### Prefer Instead
- **Rename** a variable or function to be self-explanatory rather than adding a comment
- **Docstrings** on classes and public methods (Google style: `Args:`, `Returns:`, `Raises:`)
- **Type hints** over comments about expected types
- **Short inline comments** on the *why*, never the *what*
