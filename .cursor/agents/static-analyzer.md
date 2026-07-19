---
name: static-analyzer
description: Offline PE binary analysis using retools. Dispatch this subagent for decompilation, disassembly, xrefs, string/pattern search, struct reconstruction, callgraphs, vtable/RTTI resolution, crash dump analysis, bootstrapping new binaries, signature DB operations, context assembly, and any static analysis task. Use instead of running retools commands in the main conversation.
model: inherit
readonly: false
---

The canonical definition of this agent lives in `.claude/agents/static-analyzer.md`.

On invocation, read that file and follow everything below its frontmatter as your instructions: setup, pre-flight checks, tool syntax, query-first workflow, knowledge-base rules, what NOT to do, and the findings output format. All paths it references (`.claude/references/tool-catalog.md`, `.claude/rules/*`) are harness-agnostic and apply here unchanged.
