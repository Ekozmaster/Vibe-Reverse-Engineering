---
description: Complete reference for all RE tools — retools (static analysis), livetools (dynamic/Frida), and dx9 tracer. Consult before choosing any tool.
inclusion: auto
---

# Tool Catalog

All tools work on PE binaries (`.exe` and `.dll`). `$B` = path to binary, `$VA` = hex address, `$D` = path to minidump `.dmp` file. Check tools help command for more info on usage.

Always consult this catalog before making any move to take the best decision on what to use with best bang for your buck.

IMPORTANT: Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

## Static Analysis (`retools/`) — offline, on-disk PE files

| Tool | Purpose | Example |
|------|---------|---------|
| `disasm.py $B $VA` | Disassemble N instructions at VA | `disasm.py binary.exe 0x401000 -n 50` |
| `decompiler.py $B $VA` | Ghidra-quality C decompilation (r2ghidra, auto-configured) | `python -m retools.decompiler binary.exe 0x401000` |
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
| `throwmap.py $B list` | List all throw sites and their MSVC exception strings | `python -m retools.throwmap binary.exe list` |
| `throwmap.py $B match --dump $D` | Match a minidump crash stack against the throw map to identify the throw site | `python -m retools.throwmap binary.exe match --dump crash.dmp` |

## Minidump Analysis (`retools/dumpinfo.py`) — crash dump files

| Tool | Purpose | Example |
|------|---------|---------|
| `dumpinfo.py $D info` | Crash dump overview: modules, exception summary | `dumpinfo.py crash.dmp info` |
| `dumpinfo.py $D threads` | All threads with registers resolved to module+offset | `dumpinfo.py crash.dmp threads` |
| `dumpinfo.py $D threads --verbose` | Full register dump per thread | `dumpinfo.py crash.dmp threads --verbose` |
| `dumpinfo.py $D stack $TID` | Stack walk: return addresses, annotated values | `dumpinfo.py crash.dmp stack 67900` |
| `dumpinfo.py $D stack $TID --depth N` | Stack walk with custom slot depth (default 512) | `dumpinfo.py crash.dmp stack 67900 --depth 1024` |
| `dumpinfo.py $D stackscan $TID` | Scan thread stack for code addresses by module | `dumpinfo.py crash.dmp stackscan 67900` |
| `dumpinfo.py $D stackscan $TID --module X` | Filter stackscan to a specific module | `dumpinfo.py crash.dmp stackscan 67900 --module game.exe` |
| `dumpinfo.py $D exception` | Exception record, MSVC C++ type name decoding | `dumpinfo.py crash.dmp exception` |
| `dumpinfo.py $D read $VA $T` | Read typed data from dump memory | `dumpinfo.py crash.dmp read 0x7FFE0030 uint64` |
| `dumpinfo.py $D strings` | Extract strings from dump memory (optional regex filter) | `dumpinfo.py crash.dmp strings --pattern "error"` |
| `dumpinfo.py $D memscan $PAT` | Search dump memory for byte or text pattern | `dumpinfo.py crash.dmp memscan "48 65 6C 6C 6F"` |
| `dumpinfo.py $D memmap` | List all captured memory regions in the dump | `dumpinfo.py crash.dmp memmap` |
| `dumpinfo.py $D diagnose` | One-shot crash analysis pipeline (exception + stack + throw match) | `dumpinfo.py crash.dmp diagnose --binary game.exe` |

## Dynamic Analysis (`livetools/`) — Frida-based, attaches to running process

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
| `mem alloc $SIZE` | Allocate RWX memory in the target process, returns address |
| `disasm [$VA]` | Disassemble from live process |
| `scan $PATTERN` | Search process memory for byte pattern |
| `modules` | List loaded modules with base addresses |
| `dipcnt on/off/read` | D3D9 DrawIndexedPrimitive call counter |
| `dipcnt on $DEV_PTR` | Start DIP counter — requires global IDirect3DDevice9* pointer address |
| `dipcnt callers [N]` | Sample N DIP calls and histogram return addresses |
| `memwatch start/stop/read` | Memory write watchpoint with backtrace |
| `vishook on $JMP $ORIG` | Patch jmp trampoline to force visibility for callers above threshold |
| `vishook off` | Restore original jmp, disable override |
| `vishook stats` | Show override/passthrough call counts |
| `analyze $FILE` | Offline analysis of collected .jsonl trace data |

## Game Window Automation (`livetools/gamectl.py`) — no Frida needed

Sends keystrokes and mouse clicks to a game window via Windows **SendInput**. Works standalone — no `attach` session required. All key bindings and sequences are CLI arguments; nothing is hardcoded.

**Why SendInput, not PostMessage/SendMessage**: DirectInput and RawInput games (most DX9-era titles) read raw device state — they ignore `WM_KEYDOWN` posted to the window entirely. `SendInput` injects into the global input stream, which these games do see. The game window must be in the foreground first; `gamectl` handles this automatically via `AttachThreadInput` + `SetForegroundWindow` to bypass the Windows foreground lock.

**Window lookup** — use `--exe` (preferred, matches by process name) or `--window` (title substring fallback):

```
python -m livetools gamectl --exe <game.exe> info
python -m livetools gamectl --exe <game.exe> key <KEY>
python -m livetools gamectl --exe <game.exe> keys "<SEQUENCE>" [--delay-ms N]
python -m livetools gamectl --exe <game.exe> click <X> <Y>
python -m livetools gamectl --exe <game.exe> macro --macro-file patches/<Game>/macros.json <NAME>
python -m livetools gamectl --exe <game.exe> macros --macro-file patches/<Game>/macros.json
```

Key names: `RETURN`, `ESCAPE`, `SPACE`, `UP`, `DOWN`, `LEFT`, `RIGHT`, `TAB`, `F1`–`F12`, `A`–`Z`, `0`–`9`, `NUMPAD0`–`9`, `SHIFT`, `CTRL`, `ALT`.

Sequence token syntax (used in `keys` and macro `steps`):
- `KEY_NAME` — keydown + keyup
- `WAIT:N` — pause N milliseconds
- `HOLD:KEY_NAME:N` — hold key N ms before keyup

Macro file (`macros.json`) — one file per game, stored in `patches/<GameName>/macros.json`:
```json
{
  "navigate_menu": {
    "description": "Navigate from title screen into a race",
    "steps": "RETURN WAIT:1000 DOWN DOWN RETURN WAIT:500 RETURN"
  },
  "pause": {
    "description": "Open pause menu",
    "steps": "ESCAPE"
  }
}
```

NOTE: Some processes require their window to be focused for traces to capture data.

## D3D9 Frame Trace (`graphics/directx/dx9/tracer/`) — full-frame API capture and analysis

A proxy DLL that intercepts all 119 `IDirect3DDevice9` methods, capturing every call with arguments, backtraces, pointer-followed data (matrices, constants, shader bytecodes), and in-process shader disassembly. Outputs JSONL for offline analysis.

**Architecture**: Python codegen (`d3d9_methods.py`) → C proxy DLL (`src/`) → JSONL → Python analyzer (`analyze.py`).

### Setup and Capture

```
python -m graphics.directx.dx9.tracer codegen -o d3d9_trace_hooks.inc
cd graphics/directx/dx9/tracer/src && build.bat
python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>
```

**proxy.ini** settings: `CaptureFrames=N`, `CaptureInit=1`, `Chain.DLL=<wrapper.dll>`.

IMPORTANT: `--game-dir` must point to the directory containing the deployed proxy DLL.

### Key Data Captured

- **Every D3D9 call**: method name, slot, arguments, return value, full backtrace
- **Shader bytecodes + disassembly**: CTAB with named parameters (e.g. `WorldViewProj`, `FogValue`), register mappings, full instructions
- **Created object handles**: `CreateVertexDeclaration`/`CreateVertexShader`/`CreatePixelShader` output pointers for handle→bytecode linking
- **Constant values**: float/int constant registers with source seq# tracking
- **Matrices**: 4x4 float matrices from `SetTransform`/`MultiplyTransform`
- **Vertex declarations**: full `D3DVERTEXELEMENT9` arrays with type/usage/stream decoded

### Source Files

| Path | Role |
|------|------|
| `graphics/directx/dx9/tracer/cli.py` | CLI entry point (codegen, trigger, analyze) |
| `graphics/directx/dx9/tracer/analyze.py` | Analysis engine (all `--*` options) |
| `graphics/directx/dx9/tracer/d3d9_methods.py` | Single source of truth: method signatures, D3D9 enum constants, codegen |
| `graphics/directx/dx9/tracer/src/` | C proxy DLL source (edit and rebuild for advanced use cases) |
| `graphics/directx/dx9/tracer/bin/` | Pre-built d3d9.dll + proxy.ini (deploy directly) |

## RTX Remix FFP Scripts (`rtx_remix_tools/dx/dx9_ffp_template/scripts/`)

Static scanners for D3D9 game analysis. Fast first-pass only — always follow up with `retools`/`livetools`.

| Script | What it surfaces |
|--------|-----------------|
| `find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites, startRegister and count args |
| `find_device_calls.py <game.exe>` | Device vtable call patterns and device pointer refs |
| `find_vtable_calls.py <game.exe>` | ID3DXConstantTable vtable calls (SetMatrix, SetVector, etc.) AND direct D3D9 device vtable calls — useful when engine uses d3dx9 constant tables instead of raw `SetVertexShaderConstantF` |
| `decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES = skinning, POSITIONT = screen-space) |
| `scan_d3d_region.py <game.exe> 0xSTART 0xEND` | All D3D9 vtable calls within a specific code region |

## Bundled Radare2 (`tools/radare2-6.1.0-w64/`)

Radare2 6.1.0 is bundled at `tools/radare2-6.1.0-w64/bin/`. The `retools` scripts use it internally via r2pipe — you generally don't invoke it directly. Key executables if needed:

| Binary | Purpose |
|--------|---------|
| `radare2.exe` | Interactive RE session (`r2 binary.exe`) |
| `rabin2.exe` | Binary info: imports, exports, sections, strings (`rabin2 -i binary.exe`) |
| `rasm2.exe` | Assemble/disassemble single instructions (`rasm2 -a x86 -b 32 "nop"`) |
| `rafind2.exe` | Search for byte patterns in files |
| `rahash2.exe` | Hash files or byte ranges |
| `radiff2.exe` | Binary diff between two files |
| `rax2.exe` | Number base converter (`rax2 0x401000`) |

### Analysis Commands

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

## Decision Guide

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
- "Find all instructions using a specific constant" → `search.py insn`
- "Find a mov-immediate near a struct field access" → `search.py insn --near`
- "What crashed and why?" → `dumpinfo.py exception` then `dumpinfo.py diagnose --binary` for full pipeline
- "Where is each thread stuck?" → `dumpinfo.py threads` (add `--verbose` for full register dump)
- "Walk a crashing thread's call stack" → `dumpinfo.py stack` (add `--depth` for deeper scan)
- "Find code addresses on a thread's stack by module" → `dumpinfo.py stackscan`
- "Search dump memory for a string or byte pattern" → `dumpinfo.py memscan`
- "What memory regions are in the dump?" → `dumpinfo.py memmap`
- "Extract strings from a crash dump" → `dumpinfo.py strings --pattern`
- "What exception strings does this binary throw?" → `throwmap.py list`
- "Which throw site caused this crash?" → `throwmap.py match --dump`
- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Who writes to this memory address?" → `livetools memwatch`
- "Force visibility for callers above a threshold address" → `livetools vishook on`
- "Allocate executable memory in the target process" → `livetools mem alloc`
- "Send keystrokes or navigate game menus automatically" → `livetools gamectl keys` or `gamectl macro`
- "What does the game's full render frame look like?" → `dx9tracer analyze --summary` + `--render-passes` + `--pipeline-diagram`
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

## Tool Caveats

### `rtti.py` — MSVC RTTI only

Works exclusively with MSVC-compiled binaries that have RTTI enabled (`/GR`). Will not work with GCC/Clang/MinGW binaries or binaries compiled with `/GR-`.

`throwinfo` input differs by bitness:
- 64-bit: pass the RVA from the exception record (minidump param[2] minus param[3])
- 32-bit: pass the absolute VA directly (minidump param[2])

### `funcinfo.py` — call-target heuristic

`find_start()` misses functions only reachable via indirect calls (vtable dispatch, callbacks). If it returns a wrong function start, use `disasm.py` and look for padding/prologues manually.

### `datarefs.py` / `search.py strings --xrefs` — addressing modes

If a reference isn't found, the address might be computed at runtime. Try `search.py pattern` with the address bytes, or use `livetools memwatch`.

### `throwmap.py` — x86/x64 MSVC only

Finds throw sites by scanning for `__CxxThrowException` IAT calls and resolving the string argument. Works on MSVC binaries only. The `match` subcommand cross-references a minidump's exception record against the throw map to pinpoint the exact throw site — more precise than `dumpinfo.py exception` alone when the exception type name isn't enough.

## Project Workspace

Use `patches/<project_name>/` (git-ignored) for all project-specific artifacts:
- Knowledge base files (`kb.h`)
- One-off analysis scripts
- ASI patch specs and builds
- Notes, logs, collected trace data

## Knowledge Base

When reverse engineering a binary, maintain a knowledge base file (`.h`) at `patches/<project>/kb.h`.

**Format:**
```c
// C type definitions (structs, enums, typedefs) — no prefix
struct Foo { int x; float y; };
enum Mode { MODE_A=0, MODE_B=1 };

// Function signatures at addresses — @ prefix
@ 0x401000 void __cdecl ProcessInput(int key);
@ 0x402000 float __thiscall Object_GetValue(Object* this);

// Global variables at addresses — $ prefix
$ 0x7C5548 Object* g_mainObject
$ 0x7C554C Flags g_renderFlags
```

When to update the KB:
- Identified a function's purpose → add `@ 0xADDR` with name and signature
- Reconstructed a struct → add the struct definition
- Identified a global variable → add `$ 0xADDR` with name and type
- Identified magic constants → define an enum with named values
- `rtti.py` revealed a class name → use it in struct/function names

Always pass `--types <kb_file>` when using `decompiler.py` so accumulated knowledge improves every decompilation.
