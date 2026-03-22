# Vibe Reverse Engineering -- Claude Code Instructions

## Delegation Rule

**Never run static analysis tools directly.** Delegate to a `static-analyzer` subagent. Only exceptions — run these inline:
- `sigdb.py identify` / `fingerprint` (single-function ID, <5s)
- `context.py assemble` / `postprocess` (context gathering, <5s)
- `readmem.py` (single typed read from PE, <5s)
- `asi_patcher.py build` (build step, not analysis)

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

## References

- **Tool catalog, decision guide, and caveats**: @.claude/rules/tool-catalog.md
- **Subagent workflow and delegation rules**: @.claude/rules/subagent-workflow.md
- **Project workspace and knowledge base format**: @.claude/rules/project-workspace.md
- **DX9 FFP proxy porting for RTX Remix**: @.claude/rules/dx9-ffp-port.md