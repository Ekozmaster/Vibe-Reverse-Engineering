# Vibe Reverse Engineering -- Claude Code Instructions

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

## Tool Catalog

All tools work on PE binaries (`.exe` and `.dll`). `$B` = path to binary, `$VA` = hex address, `$D` = path to minidump `.dmp` file. Check tools help command for more info on usage.
Always consult this catalog before making any move to take the best decision on what to use with best bang for your buck.

IMPORTANT: Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

### Static Analysis (`retools/`) -- offline, on-disk PE files

| Tool | Purpose | Example |
|------|---------|---------|
| `disasm.py $B $VA` | Disassemble N instructions at VA | `disasm.py binary.exe 0x401000 -n 50` |
| `decompiler.py $B $VA` | **Ghidra-quality C decompilation** (r2ghidra, auto-configured) | `python -m retools.decompiler binary.exe 0x401000` |
| `decompiler.py $B $VA --types` | Decompile with knowledge base (structs, func sigs, globals) | `python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h` |
| `funcinfo.py $B $VA` | Find function start/end, rets, calling convention, callees | `funcinfo.py binary.exe 0x401000` |
| `cfg.py $B $VA` | Control flow graph (basic blocks + edges, text or mermaid) | `cfg.py binary.exe 0x401000 --format mermaid` |
| `callgraph.py $B $VA` | Caller/callee tree (multi-level, --up/--down N) | `callgraph.py binary.exe 0x401000 --up 3` |
| `xrefs.py $B $VA` | Find all calls/jumps TO an address | `xrefs.py binary.exe 0x401000 -t call` |
| `datarefs.py $B $VA` | Find instructions that reference a global address | `datarefs.py binary.exe 0x7A0000 --imm` |
| `structrefs.py $B $OFF` | Find all `[reg+offset]` accesses (struct field usage) | `structrefs.py binary.exe 0x54 --base esi` |
| `structrefs.py $B --aggregate` | Reconstruct C struct from all field accesses in a function | `structrefs.py binary.exe --aggregate --fn 0x401000 --base esi` |
| `vtable.py $B dump $VA` | Dump C++ vtable slots with instruction preview | `vtable.py binary.exe dump 0x6A0000` |
| `vtable.py $B calls $OFF` | Find all indirect `call [reg+offset]` (vtable call sites) | `vtable.py binary.exe calls 0xB0` |
| `rtti.py $B vtable $VA` | Resolve C++ class name + inheritance chain from vtable (MSVC RTTI) | `rtti.py binary.dll vtable 0x6A0000` |
| `rtti.py $B throwinfo $RVA` | Resolve exception type from `_ThrowInfo` (MSVC RTTI) | `rtti.py binary.dll throwinfo 0x5040CF8` |
| `search.py $B strings` | Extract strings with keyword filter | `search.py binary.exe strings -f render,draw` |
| `search.py $B strings --xrefs` | Find strings AND code locations that reference them | `search.py binary.exe strings -f "error" --xrefs` |
| `search.py $B pattern` | Find exact byte pattern | `search.py binary.exe pattern "D9 56 54 D8 1D"` |
| `search.py $B imports` | List PE imports, filter by DLL | `search.py binary.exe imports -d kernel32` |
| `search.py $B exports` | List PE exports, filter by keyword | `search.py binary.dll exports -f Create` |
| `search.py $B insn` | Find instructions by mnemonic/operand pattern | `search.py binary.dll insn "mov *,0x10000"` |
| `search.py $B insn --near` | Find instructions near another pattern | `search.py binary.dll insn "mov *,0x10000" --near "cmp *,0x10000" --range 0x400` |
| `readmem.py $B $VA $TYPE` | Read typed data (float, uint32, ptr, bytes...) | `readmem.py binary.exe 0x401000 float` |
| `asi_patcher.py build` | Generate .asi DLL patch from JSON spec | `asi_patcher.py build spec.json --vcvarsall ...` |

### Minidump Analysis (`retools/dumpinfo.py`) -- crash dump files

| Tool | Purpose | Example |
|------|---------|---------|
| `dumpinfo.py $D info` | Crash dump overview: modules, exception summary | `dumpinfo.py crash.dmp info` |
| `dumpinfo.py $D threads` | All threads with registers resolved to module+offset | `dumpinfo.py crash.dmp threads` |
| `dumpinfo.py $D stack $TID` | Stack walk: return addresses, annotated values | `dumpinfo.py crash.dmp stack 67900` |
| `dumpinfo.py $D exception` | Exception record, MSVC C++ type name decoding | `dumpinfo.py crash.dmp exception` |
| `dumpinfo.py $D read $VA $T` | Read typed data from dump memory | `dumpinfo.py crash.dmp read 0x7FFE0030 uint64` |

### Dynamic Analysis (`livetools/`) -- Frida-based, attaches to running process

```
python -m livetools attach <process>    # start session
python -m livetools detach              # end session
python -m livetools status              # check connection
```

| Command | Purpose |
|---------|---------|
| `trace $VA` | Non-blocking: log N hits with register/memory reads |
| `steptrace $VA` | Instruction-level trace (Stalker) with call depth control |
| `collect $VA [$VA2...]` | Multi-address hit counting over duration |
| `bp add/del/list $VA` | Breakpoints (stops target) |
| `watch` | Wait for breakpoint hit |
| `regs` / `stack` / `bt` | Inspect registers, stack, backtrace at break |
| `mem read $VA $SIZE` | Read live process memory (supports --as float32) |
| `mem write $VA $HEX` | Write live process memory |
| `disasm [$VA]` | Disassemble from live process |
| `scan $PATTERN` | Search process memory for byte pattern |
| `modules` | List loaded modules with base addresses |
| `dipcnt on/off/read` | D3D9 DrawIndexedPrimitive call counter |
| `dipcnt callers [N]` | Sample N DIP calls and histogram return addresses |
| `memwatch start/stop/read` | Memory write watchpoint with backtrace |
| `analyze $FILE` | Offline analysis of collected .jsonl trace data |

**NOTE**: Some processes require their window to be focused for traces to capture data.

### Decision Guide

- "What does this function do?" → `decompiler.py` (best), then `disasm.py` + `cfg.py`
- "Decompile with named structs and functions" → `decompiler.py --types` (inline, stdin from `structrefs.py --aggregate`, or knowledge base file)
- "Who calls this function?" → `xrefs.py` (flat) or `callgraph.py --up` (tree)
- "What does this function call?" → `funcinfo.py` (list) or `callgraph.py --down` (tree)
- "Where is this global read/written?" → `datarefs.py`
- "Where is this string/pointer referenced?" → `datarefs.py --imm`
- "Find a string and who uses it" → `search.py strings --xrefs`
- "Where is struct field +0x54 used?" → `structrefs.py`
- "What does this struct look like?" → `structrefs.py --aggregate`
- "What C++ class is this vtable?" → `rtti.py vtable`
- "What type was a caught/thrown exception?" → `rtti.py throwinfo`
- "What DLL functions are exported?" → `search.py exports`
- "Find all instructions using a specific constant" → `search.py insn`
- "Find a mov-immediate near a struct field access" → `search.py insn --near`
- "Find a known byte sequence" → `search.py pattern`
- "What crashed and why?" → `dumpinfo.py exception`
- "Where is each thread stuck?" → `dumpinfo.py threads`
- "Walk a crashing thread's call stack" → `dumpinfo.py stack`
- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Who writes to this memory address?" → `livetools memwatch`

### Tool Caveats

#### `rtti.py` -- MSVC RTTI only

Works exclusively with **MSVC-compiled** binaries that have RTTI enabled (`/GR`, the default). Will not work with GCC/Clang/MinGW binaries, binaries compiled with `/GR-`, or partially stripped binaries.

**How to get a vtable address:**
1. From `vtable.py dump $VA` -- if you already know a vtable location
2. From `datarefs.py` / `structrefs.py` -- field at offset `+0x00` of a C++ object is typically the vtable pointer
3. From live debugging -- `livetools mem read` on an object, the first pointer-sized value is the vtable

**`throwinfo` input differs by bitness:**
- 64-bit: pass the RVA from the exception record (minidump param[2] minus param[3])
- 32-bit: pass the absolute VA directly (minidump param[2])

#### `funcinfo.py` -- call-target heuristic

`find_start()` locates function boundaries by building a table of all `CALL`/`JMP` targets. This misses functions only reachable via indirect calls (vtable dispatch, callbacks, function pointers). If `funcinfo.py` returns a clearly wrong function start, use `disasm.py` and look for padding/prologues manually.

#### `datarefs.py` / `search.py strings --xrefs` -- addressing modes

These tools find references via absolute memory operands, immediate values (with `--imm` flag), and RIP-relative addressing. If you suspect a reference exists but the tool doesn't find it, the address might be computed at runtime. Try `search.py pattern` with the address bytes directly, or use `livetools memwatch`.

### Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts:
- Knowledge base files (`kb.h`)
- One-off analysis scripts
- ASI patch specs and builds
- Notes, logs, collected trace data

Create the project subfolder on first use.

### Knowledge Base

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

**Always pass `--types <kb_file>` when using `decompiler.py`** so accumulated knowledge improves every decompilation.

