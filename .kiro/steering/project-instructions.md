---
name: project-instructions
description: Canonical project instructions — loads the root AGENTS.md (tool overview, workspace/backup/KB rules, working method, engineering standards) into every Kiro session.
inclusion: always
---

# Project Instructions

The canonical, harness-agnostic instruction set for this repository is the root `AGENTS.md`, included below. Follow it in full — including the Skill Setup section (self-install the `dx9-ffp-port` and `dynamic-analysis` skills from `.claude/skills/`) and the references it points to (`.claude/references/tool-catalog.md`, `.claude/rules/tool-dispatch.md`, `.claude/rules/subagent-workflow.md`), which apply to every harness.

Custom agents for delegation (`static-analyzer`) are defined in `.kiro/agents/`.

#[[file:../../AGENTS.md]]
