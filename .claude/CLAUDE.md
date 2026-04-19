# Vibe Reverse Engineering -- Claude Code Instructions

## Read-Only Templates

These directories are **shared tooling and templates**. Do not modify them for game-specific work — per-game changes go in `patches/<GameName>/`.

- `rtx_remix_tools/dx/remix-comp-proxy/` — proxy framework **template** (copied per-game)
- `rtx_remix_tools/dx/scripts/` — DX9 analysis scripts (shared tooling)
- `retools/` — static analysis toolkit (shared tooling)
- `livetools/` — Frida-based dynamic analysis (shared tooling)
- `graphics/` — DX9 tracer framework (shared tooling)

**Per-game work goes in `patches/<GameName>/`.** When starting a new game, use the **`/new-game <GameName>` skill** — it copies the template, stubs `kb.h` and `findings.md`, and prints the bootstrap command sequence. If the user says "edit remix-comp-proxy code" without specifying, ask whether they mean the template or a game copy.

Shared tooling can be modified to improve the tools themselves — just not for game-specific customization.

---

## Delegation Rule

**Never run static analysis tools directly.** Delegate to a `static-analyzer` subagent. Only exceptions — run these inline:
- `sigdb.py identify` / `fingerprint` (single-function ID, <5s)
- `context.py assemble` / `postprocess` (context gathering, <5s; use `--no-dataflow` on large functions)
- `dataflow.py --constants` / `--slice` (single-function analysis, <5s)
- `readmem.py` (single typed read from PE, <5s)
- `asi_patcher.py build` (build step, not analysis)
- `pyghidra_backend.py status` (project existence check, <1s)

If you're about to run a second retools command in the same turn, you should have delegated.

---

## Live Tools First

The main agent owns `livetools` — always use them to verify static findings, pursue leads from subagents, and patch at runtime. When a subagent returns addresses or candidates, **immediately follow up with live tools** (trace, breakpoint, mem read/write) rather than spawning more static analysis. Static analysis finds clues; live tools confirm and act on them. **Don't wait idle for subagents** — use live tools to explore independently while static analysis runs in the background.

---

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
- **No half-migrations**: finish the job -- update every reference, remove old APIs.

### Smell Tests
- "It works if I add a sleep" -- broken data flow.
- "It works if I read from widget instead of storage" -- the two are out of sync.
- "It passes alone but fails with other tests" -- shared mutable state leaking.
- "I added a flag to skip this code path" -- why does that path run in the first place?

## Code Comments

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey.

### Remove
- **Implementation backstories**: "We do this because the other day X happened"
- **Obvious narration**: "Create the attribute", "Loop through keys", "Check if valid" -- if the code says it, the comment is noise
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

---

## DX9 FFP Porting

When working on any of the following — invoke the **`dx9-ffp-port` skill** immediately before starting:
- Editing `renderer.cpp`, `ffp_state.cpp`, `remix-comp-proxy.ini`, or draw routing logic
- Porting a game for RTX Remix / fixed-function pipeline
- Diagnosing VS constant registers, vertex declarations, matrix mapping, skinning
- Building, deploying, or iterating on a remix-comp-proxy patch (`build.bat`, `diagnostics.log`, ImGui F4)

---

## References

- **Tool dispatch (which tool, run vs delegate)**: @.claude/rules/tool-dispatch.md
- **Full tool syntax tables and caveats**: `.claude/references/tool-catalog.md` (read on demand, not auto-loaded)
- **Subagent workflow and delegation rules**: @.claude/rules/subagent-workflow.md
- **DX9 FFP proxy porting for RTX Remix**: `.claude/skills/dx9-ffp-port/SKILL.md` (invoke `dx9-ffp-port` skill, not auto-loaded)
- **Frida-based dynamic analysis**: `/dynamic-analysis` skill
- **New game setup**: `/new-game <GameName>` skill — copies template, stubs KB + findings + addresses.json + per-game CLAUDE.md, prints bootstrap steps
- **Game analysis status**: `/game-status <GameName>` skill — KB entries, Ghidra state, findings line count, build date
- **Path-scoped FFP rules**: `.claude/rules/dx9-porting.md` — auto-loaded when editing renderer.cpp, ffp_state.*, or .ini files
- **Symbol bridge**: `patches/<GameName>/addresses.json` — confirmed addresses from static analysis; use `/trace-address <GameName> <addr>` to generate livetools commands from it
- **Tracer → ffp_state automation**: `/apply-trace-findings <GameName> <trace.jsonl>` — parses `--matrix-flow` output and patches register defaults in ffp_state.hpp
- **Per-game context**: `patches/<GameName>/CLAUDE.md` — confirmed register layout, binary info, known quirks; update as analysis progresses
