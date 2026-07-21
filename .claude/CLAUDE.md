# Vibe Reverse Engineering -- Claude Code Instructions

Shared conventions (project overview, read-only templates, workspace/backup/KB rules, engineering standards, code comments) are canonical in the root file, auto-loaded here:

@../AGENTS.md

The sections below are Claude Code-specific.

---

## Delegation Rule

**Never run static analysis tools directly.** Delegate to a `static-analyzer` subagent. The only inline exceptions are the fast (<5s) commands in the "Run Directly" section of `.claude/rules/tool-dispatch.md` (auto-loaded below).

If you're about to run a second retools command in the same turn, you should have delegated.

---

## Live Tools First

The main agent owns `livetools` — always use them to verify static findings, pursue leads from subagents, and patch at runtime. When a subagent returns addresses or candidates, **immediately follow up with live tools** (trace, breakpoint, mem read/write) rather than spawning more static analysis. Static analysis finds clues; live tools confirm and act on them. **Don't wait idle for subagents** — use live tools to explore independently while static analysis runs in the background.

---

## DX9 FFP Porting

Invoke the **`dx9-ffp-port` skill** before editing `renderer.cpp`, `ffp_state.cpp`, `remix-comp-proxy.ini`, or draw routing; porting a game for RTX Remix; diagnosing VS constants, vertex declarations, matrix mapping, or skinning; or building/deploying a remix-comp-proxy patch.

---

## References

- **Tool dispatch (which tool, run vs delegate)**: @.claude/rules/tool-dispatch.md
- **Full tool syntax tables and caveats**: `.claude/references/tool-catalog.md` (read on demand, not auto-loaded)
- **Subagent workflow and delegation rules**: @.claude/rules/subagent-workflow.md
- **DX9 FFP proxy porting for RTX Remix**: `.claude/skills/dx9-ffp-port/SKILL.md` (invoke `dx9-ffp-port` skill, not auto-loaded)
- **Frida-based dynamic analysis**: `/dynamic-analysis` skill
