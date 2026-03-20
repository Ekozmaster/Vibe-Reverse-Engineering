---
description: Project workspace conventions (patches/ directory) and knowledge base format for accumulating RE discoveries
---

# Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts:
- Knowledge base files (`kb.h`)
- One-off analysis scripts
- ASI patch specs and builds
- Notes, logs, collected trace data

Create the project subfolder on first use.

# Knowledge Base

When reverse engineering a binary, maintain a knowledge base file (`.h`) that accumulates discoveries. Store in `patches/<project>/kb.h`.

**Format:**
```c
// C type definitions (structs, enums, typedefs) -- no prefix
struct Foo { int x; float y; };
enum Mode { MODE_A=0, MODE_B=1 };
typedef unsigned int Flags;

// Function signatures at addresses -- @ prefix
@ 0x401000 void __cdecl ProcessInput(int key);
@ 0x402000 float __thiscall Object_GetValue(Object* this);

// Global variables at addresses -- $ prefix
$ 0x7C5548 Object* g_mainObject
$ 0x7C554C Flags g_renderFlags
```

**When to update the KB:**
- When you identify a function's purpose, add `@ 0xADDR` with a descriptive name and signature
- When you reconstruct a struct (e.g., from `structrefs.py --aggregate`), add the struct definition
- When you identify a global variable via `datarefs.py`, add `$ 0xADDR` with its name and type
- When you identify magic constants, define an enum with named values
- When `rtti.py` reveals a class name, use it in struct/function names
