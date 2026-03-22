---
name: 'Identify Function'
description: 'Identify a function using the signature database — checks compiler library signatures, FLIRT, and byte-pattern matching'
argument-hint: '<binary> <hex_address>'
tools: ['search/codebase']
---

# Identify Function

Run signature identification:

    python -m retools.sigdb identify ${input}

If the function is identified, report:
- Library name and function name
- Confidence level and match tier
- Whether this changes the KB — if so, suggest adding `@ 0xADDR <signature>` to the project's `patches/<project>/kb.h`

If not identified, suggest next steps:
- Decompile with `python -m retools.decompiler <binary> <addr> --types patches/<project>/kb.h`
- Check for RTTI with `python -m retools.rtti <binary> vtable <nearby_vtable_addr>`
- Search for related strings with `python -m retools.search <binary> strings --xrefs`
