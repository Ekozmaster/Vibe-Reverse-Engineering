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

### D3D9 Frame Trace (`graphics/directx/dx9/tracer/`) -- full-frame API capture and analysis

A proxy DLL that intercepts all 119 `IDirect3DDevice9` methods, capturing every call with arguments, backtraces, pointer-followed data (matrices, constants, shader bytecodes), and in-process shader disassembly (via the game's own d3dx9 DLL). Outputs JSONL for offline analysis. Like `apitrace` but with RE-focused analysis built in.

**Architecture**: Python codegen (`d3d9_methods.py`) → C proxy DLL (`src/`) → JSONL → Python analyzer (`analyze.py`). The proxy chains to the real d3d9 (or another wrapper) and adds near-zero overhead when not capturing.

#### Setup and Capture

```
python -m graphics.directx.dx9.tracer codegen -o d3d9_trace_hooks.inc   # regenerate C hooks
cd graphics/directx/dx9/tracer/src && build.bat                              # build proxy DLL
# Deploy d3d9.dll + proxy.ini to game directory
python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>     # trigger capture (3s countdown)
```

**proxy.ini** settings: `CaptureFrames=N`, `CaptureInit=1` (capture boot-time calls), `Chain.DLL=<wrapper.dll>` (or empty for system d3d9).

**IMPORTANT**: `--game-dir` must point to the directory containing the deployed proxy DLL.

#### Analysis Commands

All analysis: `python -m graphics.directx.dx9.tracer analyze <JSONL> [OPTIONS]`

| Option | Purpose |
|--------|---------|
| `--summary` | Overview: calls per frame/method, backtrace completeness |
| `--draw-calls` | List every draw call with state deltas |
| `--callers METHOD` | Caller histogram for a specific method |
| `--hotpaths` | Frequency-sorted call paths from backtraces |
| `--state-at SEQ` | Reconstruct full device state at a specific sequence number |
| `--render-loop` | Detect the render loop entry point from backtraces |
| `--render-passes` | Group draws by render target, classify pass types |
| `--matrix-flow` | Track matrix uploads per SetTransform/SetVertexShaderConstantF |
| `--shader-map` | Disassemble all shaders (CTAB names, register map, instructions) |
| `--const-provenance` | Compact: for each draw, show which seq# set each named constant |
| `--const-provenance-draw N` | Detailed: all register values and sources for draw #N |
| `--classify-draws` | Auto-tag draws (alpha, ztest, fog, fullscreen-quad, etc.) with draw method (DIP/DP/DPUP/DIPUP) and vertex shader breakdown |
| `--vtx-formats` | Group draws by vertex declaration with element breakdown |
| `--redundant` | Find redundant state-set calls |
| `--texture-freq` | Texture binding frequency across all draws |
| `--rt-graph` | Render target dependency graph (mermaid) |
| `--diff-draws A B` | State diff between two draw calls |
| `--diff-frames A B` | Compare two captured frames |
| `--const-evolution RANGE` | Track how specific registers change across draws (e.g. `vs:c4-c6`, `ps:c0-c3`). Shows per-register stability, 3x3 rotation grouping to identify shared View matrix, translation spread |
| `--state-snapshot DRAW#` | Complete state dump at a draw index: shaders + CTAB names, constants, vertex decl, textures, render states, transforms, samplers |
| `--transform-calls` | Analyze SetTransform/SetViewport usage: timing relative to draws, matrix values, whether game uses FFP transforms or shader constants |
| `--animate-constants` | Cross-frame constant register tracking |
| `--pipeline-diagram` | Auto-generate mermaid render pipeline diagram |
| `--resolve-addrs BINARY` | Resolve backtrace addresses to function names via retools |
| `--filter EXPR` | Filter records by field |
| `--export-csv FILE` | Export raw records to CSV |

#### Key Data Captured

- **Every D3D9 call**: method name, slot, arguments, return value, full backtrace
- **Shader bytecodes + disassembly**: CTAB with **named parameters** (e.g. `WorldViewProj`, `FogValue`), register mappings, full instructions
- **Created object handles**: `CreateVertexDeclaration`/`CreateVertexShader`/`CreatePixelShader` output pointers for handle→bytecode linking
- **Constant values**: float/int constant registers with source seq# tracking
- **Matrices**: 4x4 float matrices from `SetTransform`/`MultiplyTransform`
- **Vertex declarations**: full `D3DVERTEXELEMENT9` arrays with type/usage/stream decoded

#### Source Files

| Path | Role |
|------|------|
| `graphics/directx/dx9/tracer/cli.py` | CLI entry point (codegen, trigger, analyze) |
| `graphics/directx/dx9/tracer/analyze.py` | Analysis engine (all `--*` options) |
| `graphics/directx/dx9/tracer/d3d9_methods.py` | Single source of truth: method signatures, D3D9 enum constants, codegen |
| `graphics/directx/dx9/tracer/src/` | C proxy DLL source (edit and rebuild for advanced use cases) |
| `graphics/directx/dx9/tracer/bin/` | Pre-built d3d9.dll + proxy.ini (deploy directly) |

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
- **"What does the game's full render frame look like?"** → `dx9tracer analyze --summary` + `--render-passes` + `--pipeline-diagram`
- "What shaders does the game use and what constants do they need?" → `dx9tracer analyze --shader-map`
- "Which code set a specific shader constant at draw time?" → `dx9tracer analyze --const-provenance` or `--const-provenance-draw N`
- "What vertex formats does the game use?" → `dx9tracer analyze --vtx-formats`
- "What is the full device state at a specific call?" → `dx9tracer analyze --state-at SEQ` or `--state-snapshot DRAW#` (by draw index, with CTAB names)
- "How do registers change across draws? Which are per-object vs frame-global?" → `dx9tracer analyze --const-evolution vs:c0-c8`
- "Does the game use SetTransform or only shader constants for matrices?" → `dx9tracer analyze --transform-calls`
- "How do two draw calls differ?" → `dx9tracer analyze --diff-draws A B`
- "What is the render target dependency graph?" → `dx9tracer analyze --rt-graph`
- "Where is the render loop entry point?" → `dx9tracer analyze --render-loop --resolve-addrs <binary>`
- "Which draw method (DIP/DP) and which shaders account for most draws?" → `dx9tracer analyze --classify-draws`
- "Which state sets are redundant?" → `dx9tracer analyze --redundant`

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

#### `livetools` -- static vs runtime addresses

**x86 games without ASLR** (most 32-bit games): the PE preferred base matches the runtime load address. Addresses from `retools` can be passed directly to `livetools`.

**DLLs and ASLR-enabled executables**: runtime base may differ. Run `python -m livetools modules --filter <name>` and compare against the PE's preferred base. If they differ: `runtime_addr = runtime_base + (static_addr - preferred_base)`.

**Hook the game's CALL, not the DLL entry.** To trace a D3D9/API method, hook the `call [reg+offset]` instruction *in the game's .exe* (found via `xrefs.py` or `vtable.py calls`), NOT the function entry point inside the DLL. The game's call site has arguments on the stack in known positions; the DLL entry point may be wrapped by proxies and is shared across all callers.

### Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts:
- Knowledge base files (`kb.h`)
- One-off analysis scripts
- ASI patch specs and builds
- Notes, logs, collected trace data

Create the project subfolder on first use.

### Backups

Before modifying project files (proxy source, kb.h, proxy.ini, build scripts, ASI specs), create a timestamped backup in `patches/<project>/backups/`:

```
patches/<project>/backups/YYYY-MM-DD_HHMM_<description>/
```

Copy ALL files being modified into the backup folder. The description should be a short slug of what the update does (e.g. `added-world-matrix-regs`, `fixed-albedo-stage`, `enabled-skinning`).

Example:
```
patches/MyGame/backups/2026-03-19_1430_added-world-matrix-regs/
├── d3d9_device.c
├── proxy.ini
└── kb.h
```

Create the backup BEFORE making changes so it captures the last known-good state. This applies to all development work — FFP proxy edits, ASI patch specs, build config changes, and any other project file modifications.

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

---

## RTX Remix — DX9 FFP Porting

Some DX9 games use custom vertex shaders that RTX Remix cannot inject into because Remix requires fixed-function pipeline (FFP) geometry for path-traced lighting and replaceable assets. The FFP template (`rtx_remix_tools/dx/dx9_ffp_template/`) is a D3D9 proxy DLL that intercepts `IDirect3DDevice9`, captures the game's VS constant matrices (View/Projection/World), NULLs the shaders on draw calls, applies the matrices through `SetTransform`, and chain-loads RTX Remix. Each game requires its own RE investigation.

**When to use this workflow**: whenever the user mentions FFP rendering, DX9 shader-to-FFP conversion, RTX Remix compatibility, or building a `d3d9.dll` proxy for a game.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable `ENABLE_SKINNING`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support.

### File Map

| Path | Role |
|------|------|
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_device.c` | Core FFP conversion — 119-method `IDirect3DDevice9` wrapper |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_main.c` | DLL entry, logging, Remix chain-loading, INI parsing |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/d3d9_wrapper.c` | `IDirect3D9` wrapper — intercepts `CreateDevice` |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/proxy.ini` | Runtime config: Remix chain load, albedo texture stage |
| `rtx_remix_tools/dx/dx9_ffp_template/proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `extensions/skinning/README.md` | Guide for enabling skinning (late-stage only) |

Per-game copies live at `patches/<GameName>/` (copy the whole template directory).

### Analysis Scripts

These scripts are purpose-built for FFP porting — run ALL of them on the target binary before using retools. They surface D3D9-specific call sites, VS constant patterns, and vertex declarations that would take many retools commands to find manually.

| Script | What it surfaces |
|--------|-----------------|
| `python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites and register/count args |
| `python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_device_calls.py <game.exe>` | Device vtable call patterns |
| `python rtx_remix_tools/dx/dx9_ffp_template/scripts/decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats |
| `python rtx_remix_tools/dx/dx9_ffp_template/scripts/scan_d3d_region.py <game.exe> 0xSTART 0xEND` | D3D9 vtable calls in a code region |

Use the script output to guide deeper analysis with `retools` (decompile specific call sites) and `livetools` (trace live values).

### Game-Specific Defines

The top of `proxy/d3d9_device.c` has a `GAME-SPECIFIC` section that must be set from RE findings:

```c
#define VS_REG_VIEW_START       0   // First register of view matrix
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // First register of projection matrix
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // First register of world matrix
#define VS_REG_WORLD_END       20
#define ENABLE_SKINNING         0   // Off by default; only set to 1 after rigid FFP works
#define EXPAND_SKIN_VERTICES    0   // 0=use original VB, 1=expand to fixed 48-byte layout
```

### Porting Workflow

1. **Static analysis**: Run `find_d3d_calls.py`, `find_vs_constants.py`, `decode_vtx_decls.py`. Use `retools.decompiler` on `SetVertexShaderConstantF` call sites to identify matrix register layout.
2. **Dynamic confirmation**: Trace `SetVertexShaderConstantF` live:
   ```bash
   python -m livetools trace <call_addr> --count 50 \
       --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
   ```
   Captures: startRegister, Vector4fCount, and the actual float data (first 4 vec4 constants, dereferenced).
3. **Copy template**: `patches/<GameName>/` — update the `GAME-SPECIFIC` defines.
4. **Build**: `cd patches/<GameName>/proxy && build.bat`
5. **Deploy**: Copy `d3d9.dll` + `proxy.ini` to the game directory.
6. **Iterate via log**: The proxy writes `ffp_proxy.log` after a 50-second delay. Check VS regs written, vertex declarations, actual matrix values. Do not change the logging delay unless the user asks.

**Always tell the user when you need them to interact with the game** for logging or hooking purposes. They must be in-game with real geometry visible.

### Editing d3d9_device.c — What to Edit vs Leave Alone

| Section | Edit Per-Game? |
|---------|----------------|
| `VS_REG_*` and `ENABLE_SKINNING` defines | **YES** |
| `FFP_SetupLighting`, `FFP_SetupTextureStages`, `FFP_ApplyTransforms` | MAYBE |
| `WD_DrawPrimitive` / `WD_DrawIndexedPrimitive` | **YES** — draw routing |
| IUnknown + relay thunks | NO — naked ASM, never edit |
| Everything else | NO |

**DrawIndexedPrimitive routing**: no NORMAL → HUD passthrough; rigid with NORMAL → FFP convert; skinned → FFP skinned draw (only when `ENABLE_SKINNING=1`).

### Common Pitfalls

- **Wrong matrices**: D3D9 FFP expects row-major. Proxy transposes. If game stores row-major in VS constants, remove the transpose in `FFP_ApplyTransforms`.
- **White/black objects**: Albedo texture on stage 1+. Set `AlbedoStage` in `proxy.ini`, or trace `SetTexture` to find the right stage.
- **Geometry at origin**: World matrix register mapping wrong — re-check VS constant writes via `livetools trace`.
- **Game crashes on startup**: Set `Enabled=0` in `proxy.ini [Remix]` to test without Remix.
- **Missing world geometry**: Check whether its vertex decl has NORMAL and whether `viewProjValid` is true at draw time.

