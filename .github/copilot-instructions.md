# GitHub Copilot Instructions

## Prerequisites

**BEFORE FIRST USE**: Run `python verify_install.py` from the repo root. Do NOT proceed with any tool until every check passes. Common failures: missing `git lfs pull` (LFS pointer stubs instead of real binaries), missing `pip install -r requirements.txt`, or no Python venv activated.

---

## Code Comments

### Principle

Each file reads as if it was always designed this way. Comments guide the next developer, not narrate the development journey.

Note: These rules are not exhaustive. Extrapolate from the principles and examples to the specific context you are working in.

### Remove

- **Implementation backstories**: "We do this because the other day X happened" or "This was added after we found a bug where Y"
- **Cross-extension internals**: "Tf.Notice fires synchronously during attr.Set" in code that is agnostic of USD
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

## Engineering Standards (No Copium)

### Principle

Every change should make the codebase better, not just make the problem go away. If a solution needs a paragraph to justify why it's not a hack, it's a hack.

Note: These rules are not exhaustive. Extrapolate from the principles and examples to the specific context you are working in.

### Remove

- **Fixes in the wrong layer**: a guard on a canvas to suppress commits that a model should own. Put the fix where the problem originates.
- **Tolerance inflation**: widening deltas or adding retries to hide flaky behavior. If the value is wrong, find out why.
- **Catch-all exception swallowing**: `try/except Exception: pass` to hide symptoms.
- **Excessive error/null handling**: adding too many error/None "if" checks and handling. If the error is expected, handle it. If the error is unexpected, raise it.
- **God methods**: 200+ line functions doing multiple things. Break into named steps. Focus on cognitive load for who reads and maintains the code. Design code for less tabs/indentation blocks too.
- **Leaky abstractions**: implementation details leaking into layers/modules that should be agnostic of one another.

### Design For

- **Single responsibility**: one component, one job. If you need "and" to describe it, split it.
- **Ownership**: the component that creates the problem owns the fix. Models guard their own notifications. Widgets manage their own UI/interaction state.
- **Minimal public surface**: expose what consumers need, nothing more. Internal state stays internal. Design for blackbox, self-contained, highly testable in isolation code.

### Commit to the New Code

- **No legacy fallbacks**: if you replace a system, remove the old one. No `try: new_way() except: old_way()` compatibility shims.
- **No dead code**: commented-out blocks, unused imports, orphan functions "just in case". Version control is the safety net.
- **No multiple paths to the same result**: one way to commit a curve, one way to select a key, one way to undo. If two paths exist, one is wrong.
- **No half-migrations**: if you rename an extension, update every reference. If you add an API, remove the old one. Finish the job.

### Smell Tests

- "It works if I add a sleep" -- broken data flow.
- "It works if I read from widget instead of storage" -- the two are out of sync.
- "It passes alone but fails with other tests" -- shared mutable state leaking.
- "I added a flag to skip this code path" -- why does that path run in the first place?

---

## Tool Catalog

All tools work on PE binaries (`.exe` and `.dll`). `$B` = path to binary, `$VA` = hex address, `$D` = path to minidump `.dmp` file. Check each tool's help command for more info on usage.

**Always consult this catalog before making any move.** Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

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
| `datarefs.py $B $VA` | Find instructions that reference a global address (mem deref + `--imm` for push/mov constants) | `datarefs.py binary.exe 0x7A0000 --imm` |
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

### Crash Dump Analysis

#### Throw-Site Mapper (`retools/throwmap.py`) -- static analysis of MSVC C++ throws

| Tool | Purpose | Example |
|------|---------|---------|
| `throwmap.py $B list` | Map all `_CxxThrowException` call sites to their error strings | `throwmap.py d3d9.dll list` |
| `throwmap.py $B match --dump $D` | **Deterministic crash diagnosis**: match dump stack against throw map | `throwmap.py d3d9.dll match --dump crash.dmp` |

#### Minidump Inspector (`retools/dumpinfo.py`) -- `.dmp` file analysis

| Tool | Purpose | Example |
|------|---------|---------|
| `dumpinfo.py $D diagnose [--binary $B]` | **One-shot crash analysis**: exception + threads + stack scan + throw match | `dumpinfo.py crash.dmp diagnose --binary d3d9.dll` |
| `dumpinfo.py $D exception` | Exception record, MSVC C++ type name decoding | `dumpinfo.py crash.dmp exception` |
| `dumpinfo.py $D threads` | All threads summary (one line each, exception thread marked) | `dumpinfo.py crash.dmp threads` |
| `dumpinfo.py $D threads -v` | Full register dump per thread | `dumpinfo.py crash.dmp threads -v` |
| `dumpinfo.py $D stack $TID` | Stack walk: return addresses, annotated values | `dumpinfo.py crash.dmp stack 67900 --depth 512` |
| `dumpinfo.py $D stackscan $TID` | Scan full stack for code addresses, grouped by module | `dumpinfo.py crash.dmp stackscan 67900 --module d3d9.dll` |
| `dumpinfo.py $D memmap` | List all captured memory regions with sizes and module affiliation | `dumpinfo.py crash.dmp memmap` |
| `dumpinfo.py $D strings` | Extract readable strings from dump memory | `dumpinfo.py crash.dmp strings --pattern "error\|fail"` |
| `dumpinfo.py $D memscan $PAT` | Search dump memory for byte pattern or text | `dumpinfo.py crash.dmp memscan "44 78 76 6B"` |
| `dumpinfo.py $D read $VA $T` | Read typed data from dump memory | `dumpinfo.py crash.dmp read 0x7FFE0030 uint64` |
| `dumpinfo.py $D info` | Module list with exception summary | `dumpinfo.py crash.dmp info` |

### Dynamic Analysis (`livetools/`) -- Frida-based, attaches to running process

All commands: `python -m livetools <command> [args]`

**Session:**
```
python -m livetools attach <name_or_pid>    # start daemon, attach Frida
python -m livetools detach                   # release target, stop daemon
python -m livetools status                   # check state
```

**Breakpoints (blocking):**
```
python -m livetools bp add <addr>            # set blocking code breakpoint
python -m livetools bp del <addr>            # remove breakpoint
python -m livetools bp list                  # list all BPs + hit counts
```

**Wait for Hit:**
```
python -m livetools watch --timeout 60       # block until BP hit (returns snapshot)
```

**Inspect (while frozen):**
```
python -m livetools regs                     # all registers
python -m livetools stack [N]                # top N dwords from ESP (default 16)
python -m livetools mem read <addr> <size>   # hex dump + multi-type interpretation
python -m livetools mem read <addr> <size> --as float32
python -m livetools disasm [addr] [-n count] # disassemble (default: EIP, 16 insns)
python -m livetools bt                       # call stack backtrace
```

Supported `--as` types: `float32`, `float64`, `half`, `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `ptr`, `ascii`, `utf16`.

**Control:**
```
python -m livetools step [over|into|out]     # advance one instruction (returns snapshot)
python -m livetools resume                   # unfreeze target
```

**Patch + Scan (anytime):**
```
python -m livetools mem write <addr> <hex>   # write bytes to live memory
python -m livetools scan <pattern> --range START:SIZE
```

**Non-blocking tracing:**
```
python -m livetools trace <addr> [--count N] [--read SPEC] [--read-leave SPEC] [--filter EXPR] [--timeout T] [--output FILE]
python -m livetools steptrace <addr> [--max-insn N] [--call-depth D] [--detail LEVEL] [--timeout T] [--output FILE]
python -m livetools collect <addr> [addr2 ...] [--duration N] [--read SPEC] [--fence ADDR] [--label ADDR=NAME] [--output FILE]
python -m livetools modules [--filter PATTERN]
python -m livetools analyze <file.jsonl> [--summary] [--group-by FIELD] [--filter EXPR] [--cross-tab F1 F2] [--histogram FIELD] [--export-csv FILE]
```

**D3D9 / Memory helpers:**
```
python -m livetools dipcnt on/off/read       # D3D9 DrawIndexedPrimitive call counter
python -m livetools dipcnt callers [N]       # sample N DIP calls and histogram return addresses
python -m livetools memwatch start/stop/read # memory write watchpoint with backtrace
```

**NOTE**: Some processes require their window to be focused for traces to capture data.

#### Read Spec Format

Used by `trace`, `collect`, and related commands to specify what data to capture at function entry/exit. Semicolon-separated fields:

| Syntax | Description | Example |
|--------|-------------|---------|
| `register` | Register value as hex | `ecx`, `eax`, `ebp` |
| `[reg+OFFSET]:SIZE:TYPE` | Read SIZE bytes from reg+OFFSET | `[esp+4]:12:float32` |
| `*[reg+OFFSET]:SIZE:TYPE` | Double-deref: follow pointer first | `*[esp+4]:64:float32` |
| `st0` | FPU top-of-stack (best-effort) | `st0` |

Types: `hex` (default), `float32`, `float64`, `uint32`, `int32`, `uint16`, `int16`, `uint8`, `int8`, `ascii`, `utf16`, `ptr`

Example: `"ecx; [esp+4]:12:float32; *[ecx+0x10]:64:hex"`

#### Filter Spec Format

Simple comparison on a readable field. Evaluated in-agent; non-matching calls are silently skipped.

```
[esp+8]==0x2
eax!=0
[ecx+0x54]:4:float32>0.5
```

#### `trace` -- Non-blocking enter/leave function hook

Hooks a function's entry and exit without freezing the target.

```bash
python -m livetools trace 0x401000 --count 10 --read "ecx; [esp+4]:12:float32"
python -m livetools trace 0x402000 --count 5 --filter "[esp+8]==0x2" --read "[esp+c]:64:float32"
python -m livetools trace 0x403000 --count 20 --read "ecx; [esp+4]:12:float32" --read-leave "eax"
python -m livetools trace 0x401000 --count 100 --read "ecx" --output trace.jsonl
```

#### `steptrace` -- Instruction-level execution recording via Stalker

Records every instruction executed from function entry through return.

```bash
python -m livetools steptrace 0x401000 --max-insn 500 --call-depth 1 --detail full
python -m livetools steptrace 0x402000 --max-insn 1000 --detail branches
python -m livetools steptrace 0x403000 --max-insn 5000 --detail blocks
python -m livetools steptrace 0x401000 --max-insn 500 --output steptrace.jsonl
```

Detail levels: **full** (every instruction + register snapshots at calls/rets), **branches** (good default), **blocks** (cheapest, path mapping only).

#### `collect` -- Long-running multi-function data collection

```bash
python -m livetools collect 0x401000 0x402000 \
  --duration 30 --output trace.jsonl \
  --read "ecx; [esp+4]:12:float32" \
  --fence 0x403000 \
  --label 0x401000=FuncA --label 0x402000=FuncB

python -m livetools collect 0x401000 0x402000 \
  --read@0x401000="ecx; [esp+4]:12:float32" \
  --read@0x402000="ecx; [esp+4]:28:hex" \
  --duration 15 --output multi.jsonl
```

The **fence** concept: hook a boundary function (e.g. DX Present) that increments an interval counter. Every trace record includes the current interval ID. Enables per-frame analysis and cross-function correlation.

Output: JSONL in `patches/<exe_name>/traces/` by default (gitignored).

#### `analyze` -- Offline JSONL aggregation (no Frida needed)

```bash
python -m livetools analyze trace.jsonl --summary
python -m livetools analyze trace.jsonl --group-by addr
python -m livetools analyze trace.jsonl --filter "addr==00401000" --group-by "leave.eax"
python -m livetools analyze trace.jsonl --filter "addr==00401000" --cross-tab caller leave.eax
python -m livetools analyze trace.jsonl --group-by interval --top 5
python -m livetools analyze trace.jsonl --interval 47
python -m livetools analyze trace.jsonl --compare-intervals 10 50
python -m livetools analyze trace.jsonl --filter "addr==00401000" --histogram "enter.reads.0.value.0"
python -m livetools analyze trace.jsonl --filter "addr==00401000" --export-csv output.csv
```

Field path syntax: dot-separated with array indices. `addr`, `leave.eax`, `enter.reads.0.value.0`, `interval`, `caller`.

### Decision Guide

- "What does this function do?" → `decompiler.py` (best), then `disasm.py` + `cfg.py`
- "Decompile with named structs and functions" → `decompiler.py --types`
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
- **"What crashed and what was the error message?"** → `dumpinfo.py diagnose --binary <dll>` (one-shot: exception + stack scan + throw-site match)
- "What C++ exception type was thrown?" → `dumpinfo.py exception`
- "Which module has frames on the crash stack?" → `dumpinfo.py stackscan <tid> --module <name>`
- "Map all throw sites to error strings in a DLL" → `throwmap.py <dll> list`
- "Match a specific dump against throw sites" → `throwmap.py <dll> match --dump <dmp>`
- "Where is each thread stuck?" → `dumpinfo.py threads`
- "Walk a crashing thread's call stack" → `dumpinfo.py stack <tid>`
- "Is a specific string in the dump memory?" → `dumpinfo.py memscan <pattern>` or `strings --pattern`
- "What memory regions are captured in the dump?" → `dumpinfo.py memmap`
- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Who writes to this memory address?" → `livetools memwatch`

### Tool Caveats

#### `rtti.py` -- MSVC RTTI only

Works exclusively with MSVC-compiled binaries that have RTTI enabled (`/GR`). Will not work with GCC/Clang/MinGW binaries, `/GR-` builds, or partially stripped binaries.

How to get a vtable address:
1. From `vtable.py dump $VA` -- if you already know a vtable location
2. From `datarefs.py` / `structrefs.py` -- field at offset `+0x00` of a C++ object is the vtable pointer
3. From live debugging -- `livetools mem read` on an object; the first pointer-sized value is the vtable

`throwinfo` input differs by bitness:
- 64-bit: pass the RVA from the exception record (minidump param[2] minus param[3])
- 32-bit: pass the absolute VA directly (minidump param[2])

#### `throwmap.py` -- MSVC C++ exceptions only

Maps `_CxxThrowException` call sites to their string arguments by static analysis of the PE's code sections. Works on both 32-bit and 64-bit MSVC-compiled binaries.

**`match` requires the original binary**: the PE file passed to `throwmap.py` must be the exact version that was loaded when the crash dump was captured. If the binary was rebuilt or updated since the crash, the throw-site RVAs won't match. Check file timestamps and hashes.

**How it works** (deterministic, zero bias):
1. Finds IAT slot for `_CxxThrowException`, then all `CALL`/`JMP` thunks to it
2. Walks backward from each call site to find LEA/PUSH loading the string argument
3. In `match` mode, scans the crashing thread's stack for return addresses (call_rva + insn_size)
4. Reports exact matches -- no heuristics, no keyword filtering

**Will not work for**: non-MSVC binaries, custom exception mechanisms, binaries that don't import `_CxxThrowException`, or dumps where the crashing thread's stack memory wasn't captured.

#### `dumpinfo.py` -- minidump completeness

Minidumps vary in how much data they capture depending on `MiniDumpWriteDump` flags. Common limitations:
- **Heap data missing**: the thrown object's `std::string` may point to heap memory not in the dump. `diagnose` reports this and falls back to `throwmap` matching.
- **Stack truncated**: small dumps may not capture enough stack depth. Use `memmap` to see what's actually available.
- **`stackscan` shows data AND code pointers**: not every value on the stack is a return address. Values at `+0x0` are likely the module base (data), not code. Use `throwmap match` for definitive call-site identification.

#### `funcinfo.py` -- call-target heuristic

`find_start()` misses functions only reachable via indirect calls (vtable dispatch, callbacks, function pointers). If it returns a clearly wrong function start, use `disasm.py` and look for padding/prologues manually.

#### `datarefs.py` / `search.py strings --xrefs` -- addressing modes

Finds references via: absolute memory operands, immediate values (with `--imm`), and RIP-relative addressing. If a reference isn't found, the address may be computed at runtime -- try `search.py pattern` with the address bytes, or use `livetools memwatch`.

### Project Workspace

Use `patches/<project_name>/` for all project-specific artifacts (gitignored). Create whatever you need: knowledge base files (`kb.h`), one-off scripts, ASI patch specs, notes, trace data. Create the project subfolder on first use.

### Knowledge Base

Maintain a knowledge base file (`.h`) at `patches/<project>/kb.h` that accumulates discoveries.

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
- Identified a function's purpose → add `@ 0xADDR` with name and signature
- Reconstructed a struct (e.g. from `structrefs.py --aggregate`) → add struct definition
- Identified a global via `datarefs.py` → add `$ 0xADDR` with name and type
- Identified magic constants → define an enum with named values
- `rtti.py` reveals a class name → use it in struct/function names

**Always pass `--types <kb_file>` when using `decompiler.py`** so accumulated knowledge improves every decompilation.

---

## Dynamic Analysis Thinking Patterns

1. **Hypothesis first.** Form a hypothesis from static analysis BEFORE tracing. Example: "I think ECX is the visibility struct pointer. Let me verify with trace."

2. **State what you learned.** After inspecting trace data or a snapshot, explicitly state what the values tell you and what question remains.

3. **Use trace before breakpoints.** Non-blocking `trace` is less disruptive than blocking `bp`+`watch`. Start with trace to understand call frequency and typical arguments, then use breakpoints only when you need to freeze and step.

4. **Use collect for volume.** When you need data from thousands of calls across many frames, `collect` with a fence gives you structured JSONL that `analyze` can slice and dice deterministically.

5. **Use analyze for deterministic answers.** Never hallucinate statistics. Always run `analyze` on real collected data to get ground-truth numbers.

6. **Cross-reference with static analysis.** Match live register values and call sites against static disassembly from `retools` to identify struct offsets, vtable slots, and data pointers.

7. **Use modules to find DLL bases.** Before hooking a DLL function (e.g. D3D9 vtable), use `modules` to find the actual loaded base address.

8. **Composable pipeline.** `trace` captures raw records. `collect` streams them to disk. `analyze` aggregates offline. Chain them for any investigation.

### Workflow Recipes

**Recipe 1: Quick function behavior check**
```
python -m livetools trace 0x401000 --count 10 --read "ecx; [esp+4]:12:float32"
```

**Recipe 2: Understand a function's code path**
```
python -m livetools steptrace 0x401000 --max-insn 500 --call-depth 1 --detail branches
```

**Recipe 3: Per-frame analysis**
```bash
python -m livetools collect 0x401000 0x402000 \
  --duration 30 --fence 0x403000 \
  --read "ecx; [esp+4]:12:float32" \
  --label 0x401000=FuncA --label 0x402000=FuncB \
  --output trace.jsonl
python -m livetools analyze trace.jsonl --summary
python -m livetools analyze trace.jsonl --compare-intervals 10 50
```

**Recipe 4: Find DLL base for vtable hooks**
```
python -m livetools modules --filter kernel
```

**Recipe 5: Register inspection at a breakpoint**
```
python -m livetools bp add 0x401000
python -m livetools watch --timeout 60
python -m livetools resume
```

**Recipe 6: Read struct fields from a register pointer**

After a snapshot shows ECX=008800A0 and you suspect a float at offset +0x54:
```
python -m livetools mem read 0x008800F4 4 --as float32
```

**Recipe 7: Step through a function**
```
python -m livetools bp add <function_entry>
python -m livetools watch --timeout 60
python -m livetools step over
python -m livetools mem read <addr> 32
python -m livetools resume
```

**Recipe 8: Patch a byte and verify**
```
python -m livetools mem write 0x00401000 "B0 01 C3"
python -m livetools disasm 0x00401000 -n 3
```

**Recipe 9: Multi-function data-driven investigation**
```bash
python -m livetools collect 0x401000 0x402000 0x403000 \
  --duration 60 --fence 0x404000 --output scene.jsonl \
  --label 0x401000=FuncA --label 0x402000=FuncB --label 0x403000=FuncC
python -m livetools analyze scene.jsonl --summary
python -m livetools analyze scene.jsonl --group-by addr
python -m livetools analyze scene.jsonl --filter "addr==0x00401000" --group-by "leave.eax"
python -m livetools analyze scene.jsonl --filter "addr==0x00401000" --cross-tab caller leave.eax
python -m livetools analyze scene.jsonl --export-csv scene.csv
```

---

## RTX Remix — DX9 FFP Porting

### Purpose

Some DX9 games use custom vertex shaders that RTX Remix cannot inject into because Remix requires fixed-function pipeline (FFP) geometry to apply path-traced lighting and replaceable assets. The FFP template (`rtx_remix_tools/dx/dx9_ffp_template/`) is a D3D9 proxy DLL that intercepts `IDirect3DDevice9`, captures the game's VS constant matrices (View/Projection/World), NULLs the shaders on draw calls, applies the matrices through `SetTransform`, and chain-loads RTX Remix. It is not a drop-in solution — adapt it per-game using `retools` and `livetools`.

**When to suggest this workflow**: whenever the user mentions RTX Remix compatibility, FFP rendering, DX9 shader-to-FFP conversion, or building a `d3d9.dll` proxy for a game. Proactively recommend loading `#dx9-ffp-port` in Copilot Chat for full porting context — it walks through the complete workflow and common pitfalls.

### File Map

| Path | Role |
|------|------|
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_device.c` | Core FFP conversion — 119-method `IDirect3DDevice9` wrapper |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_main.c` | DLL entry, logging, Remix chain-loading, INI parsing |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_wrapper.c` | `IDirect3D9` wrapper — intercepts `CreateDevice` |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/proxy.ini` | Runtime config: Remix chain load, albedo texture stage |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `rtx_remix_tools/dx/dx9_ffp_template/scripts/` | Analysis scripts (see below) |
| `rtx_remix_tools/dx/dx9_ffp_template/kb.h` | Blank knowledge base — copy to `patches/<GameName>/` and accumulate RE discoveries |

Per-game copies live at `patches/<GameName>/` (copy the whole template directory there).

### Analysis Scripts

| Script | What it finds |
|--------|---------------|
| `scripts/find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `scripts/find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites and register/count args |
| `scripts/find_device_calls.py <game.exe>` | Device vtable call patterns and device pointer refs |
| `scripts/find_vtable_calls.py <game.exe>` | D3DX constant table usage and D3D9 vtable calls |
| `scripts/decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES → skinning) |
| `scripts/scan_d3d_region.py <game.exe> 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region |

Run these from the template directory or from a per-game copy under `patches/<GameName>/`.

### Porting Workflow (Summary)

1. **Static analysis** — run the scripts above against the game binary; identify `SetVertexShaderConstantF` call sites and vertex declaration formats.
2. **Discover VS constant layout** — determine which registers hold View, Projection, and World matrices. Use `retools.decompiler` on the call sites, then confirm with a live `livetools trace` reading `[esp+4]:4:uint32; [esp+8]:4:uint32; [esp+c]:64:float32` (device, startReg, count, data).
3. **Copy template + update defines** — copy `rtx_remix_tools/dx/dx9_ffp_template/` to `patches/<GameName>/`, then edit the `GAME-SPECIFIC` block at the top of `d3d9_device.c` with the discovered register ranges (`VS_REG_VIEW_START/END`, `VS_REG_PROJ_*`, `VS_REG_WORLD_*`).
4. **Build and deploy** — run `build.bat` from `patches/<GameName>/proxy/`, copy `d3d9.dll` + `proxy.ini` to the game directory alongside `d3d9_remix.dll`.
5. **Iterate with the log** — `ffp_proxy.log` records per-frame draw call data (VS regs written, vertex decls, matrices). Wrong matrices → re-check register mapping. White/black objects → adjust `AlbedoStage` in `proxy.ini`. Geometry piled at origin → world matrix register is wrong.

### Key `d3d9_device.c` Defines

```c
#define VS_REG_VIEW_START       0   // First register of view matrix
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // First register of projection matrix
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // First register of world matrix
#define VS_REG_WORLD_END       20
#define VS_REG_BONE_THRESHOLD  20   // Registers at/beyond this are bone candidates
#define VS_REGS_PER_BONE        3   // Registers per bone (3 = packed 4x3)
```

For the full workflow, common pitfalls, and architecture details, load `#dx9-ffp-port` in Copilot Chat.
