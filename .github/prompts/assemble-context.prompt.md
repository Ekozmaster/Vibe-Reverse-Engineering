---
name: 'Assemble Context'
description: 'Gather full analysis context for a function — decompilation, callgraph, xrefs, signature ID, and KB entries'
argument-hint: '<binary> <hex_address> --project <ProjectName>'
tools: ['search/codebase']
---

# Assemble Context

Run the context assembly pipeline for a function:

    python -m retools.context assemble ${input}

This gathers:
- Decompilation with KB types applied
- Upstream callers (callgraph --up 2)
- Downstream callees (callgraph --down 1)
- Cross-references to the function
- Signature database lookup
- Related KB entries

Review the assembled context and summarize what the function does, its role in the call hierarchy, and any KB entries that inform its behavior.
