---
applyTo: "retools/**,livetools/**,graphics/**,tools/**,patches/**"
---

# Tool Catalog

**BEFORE FIRST USE**: Run `python verify_install.py` from the repo root. Do NOT proceed with any tool until every check passes. Common failures: missing `git lfs pull` (LFS pointer stubs instead of binaries), missing `pip install -r requirements.txt`.

All tools work on PE binaries (`.exe` and `.dll`). `$B` = path to binary, `$VA` = hex address, `$D` = path to minidump `.dmp` file. Check tools help command for more info on usage.
Always consult this catalog before making any move to take the best decision on what to use with best bang for your buck.
Run all tools from the repo root directory using `python -m <module>` syntax (e.g. `python -m retools.search`). Do NOT modify files inside `retools/`, `livetools/`, or `graphics/` unless working on the tools themselves.

IMPORTANT: Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

## Decision Guide

### Run Directly (fast, <5s)

These are fast and can be run inline without delegation:

- "What compiler built this?" → `python -m retools.sigdb fingerprint $B`
- "Is this a known library function?" → `python -m retools.sigdb identify $B $VA`
- "Get full context before reasoning about a function" → `python -m retools.context assemble $B $VA --project $P`
- "Clean up decompiler output with known names" → pipe through `python -m retools.context postprocess`
- "Read a typed value from the PE file" → `python -m retools.readmem $B $VA $TYPE`
- "Build an ASI patch DLL" → `python -m retools.asi_patcher build spec.json`

### Delegate to the static-analyzer agent

Everything else. Specify WHAT you need, not HOW to run it — the agent has the full tool catalog.

**D3D9-specific questions?** Check the DX analysis scripts section below first — they're faster and more targeted than general retools for D3D API usage, device calls, shader constants, and vertex formats.

- "What does this function do?" → decompile + callgraph + xrefs
- "Who calls this function?" → xrefs or callgraph --up
- "What does this function call?" → callgraph --down
- "Find a string and who uses it" → string search with xrefs
- "Where is this global read/written?" → datarefs
- "Where is struct field +0x54 used?" → structrefs
- "What does this struct look like?" → structrefs --aggregate
- "What C++ class is this vtable?" → RTTI resolution
- "What type was a caught/thrown exception?" → RTTI throwinfo
- "Find instructions using a specific constant" → instruction search
- "What crashed and what was the error message?" → dump diagnosis + throwmap
- "Map all throw sites to error strings" → throwmap list
- "First time analyzing a binary?" → bootstrap (2-5 min)
- "Bulk signature scan" → sigdb scan (1-3 min)
- Any combination of the above

### Live tools (requires attached process)

- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Who writes to this memory address?" → `livetools memwatch`

### DX analysis scripts (fast first-pass)

These are targeted D3D9 scanners under `rtx_remix_tools/dx/scripts/`. They run in seconds and surface D3D-specific patterns that general-purpose retools would take longer to find. **Use these BEFORE retools** when the question is about D3D9 API usage, device calls, shaders, or vertex formats.

- "How does the game use D3D9?" → `find_d3d_calls.py <game.exe>` (imports + call sites)
- "Which VS constant registers hold matrices?" → `find_vs_constants.py <game.exe>` (SetVertexShaderConstantF call sites with register/count)
- "Which PS constant registers are used?" → `find_ps_constants.py <game.exe>` (SetPixelShaderConstantF/I/B with register/count)
- "Where does the game call the D3D device?" → `find_device_calls.py <game.exe>` (vtable call patterns + device pointer refs)
- "What render states does the game set?" → `find_render_states.py <game.exe>` (SetRenderState args: culling, blending, depth, fog)
- "How does the texture pipeline work?" → `find_texture_ops.py <game.exe>` (SetTexture stages, TSS ops, sampler filter/address modes)
- "Which transform types are used?" → `find_transforms.py <game.exe>` (SetTransform: World, View, Projection, Texture)
- "What surface formats does the game create?" → `find_surface_formats.py <game.exe>` (CreateTexture/RT/DS format extraction)
- "Does the game use state blocks?" → `find_stateblocks.py <game.exe>` (state block creation/recording/apply)
- "Does the game use FVF or vertex declarations?" → `decode_fvf.py <game.exe>` (FVF bitfield decoding)
- "What vertex formats does the game use?" → `decode_vtx_decls.py <game.exe> --scan` (vertex declarations, detects skinning)
- "Are shaders embedded in the binary?" → `find_shader_bytecode.py <game.exe>` (shader bytecode extraction with version/size)
- "What's the FFP vs shader draw call mix?" → `classify_draws.py <game.exe>` (draw call classification by state context)
- "D3DX constant table or vtable calls?" → `find_vtable_calls.py <game.exe>` (D3DX CTAB usage + D3D9 vtable calls)
- "Map all D3D calls in a code region" → `scan_d3d_region.py <game.exe> 0xSTART 0xEND`

These are fast first-pass scanners — they surface candidate addresses. Follow up with `retools` (decompiler, xrefs) and `livetools` (trace, bp) for deep analysis of the addresses they find.

### dx9tracer (capture inline, delegate analysis)

- "Trigger a frame capture" → `python -m graphics.directx.dx9.tracer trigger`
- "Analyze captured frames" → delegate to the static-analyzer agent: summary, render-passes, shader-map, etc.

## Static Analysis (`retools/`) -- offline, on-disk PE files

**ALWAYS pass `--types patches/<project>/kb.h`** when using `decompiler.py`. Create the kb.h file on first decompilation if it doesn't exist. Every discovery (function names, struct layouts, globals) should be added to kb.h so subsequent decompilations produce richer output.

| Tool | Purpose | Example |
|------|---------|---------|
| `disasm.py $B $VA` | Disassemble N instructions at VA | `disasm.py binary.exe 0x401000 -n 50` |
| `decompiler.py $B $VA --types` | **Ghidra-quality C decompilation** with knowledge base | `python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h` |
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
| `bootstrap.py $B --project $P` | Auto-seed KB: compiler ID, signatures, RTTI, imports, propagation | `bootstrap.py game.exe --project Warband` |
| `sigdb.py scan $B` | Bulk signature scan against DB | `sigdb.py scan game.exe` |
| `sigdb.py identify $B $VA` | Single function signature lookup (multi-tier) | `sigdb.py identify game.exe 0x401200` |
| `sigdb.py fingerprint $B` | Identify compiler version (Rich header + markers + imports) | `sigdb.py fingerprint game.exe` |
| `context.py assemble $B $VA --project $P` | Gather full analysis context for a function | `context.py assemble game.exe 0x401500 --project Warband` |
| `context.py postprocess $B $VA --project $P` | Mechanically rename/annotate decompiler output (pipe) | `decompiler.py ... \| context.py postprocess ...` |
| `sigdb.py build $MANIFEST` | Build/extend signature DB from manifest | `sigdb.py build sources.json` |
| `sigdb.py pull` | Download signature DB from HuggingFace | `sigdb.py pull` or `sigdb.py pull --sources` |

> **Note:** `scan` and `identify` default to `retools/data/signatures.db` when `--db` is omitted. Run `sigdb.py pull` after first clone to download the database.

## Crash Dump Analysis

### Throw-Site Mapper (`retools/throwmap.py`) -- static analysis of MSVC C++ throws

| Tool | Purpose | Example |
|------|---------|---------|
| `throwmap.py $B list` | Map all `_CxxThrowException` call sites to their error strings | `throwmap.py d3d9.dll list` |
| `throwmap.py $B match --dump $D` | **Deterministic crash diagnosis**: match dump stack against throw map | `throwmap.py d3d9.dll match --dump crash.dmp` |

### Minidump Inspector (`retools/dumpinfo.py`) -- `.dmp` file analysis

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

## Dynamic Analysis (`livetools/`) -- Frida-based, attaches to running process

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

## D3D9 Frame Trace (`graphics/directx/dx9/tracer/`) -- full-frame API capture and analysis

A proxy DLL that intercepts all 119 `IDirect3DDevice9` methods, capturing every call with arguments, backtraces, pointer-followed data (matrices, constants, shader bytecodes), and in-process shader disassembly (via the game's own d3dx9 DLL). Outputs JSONL for offline analysis.

**Architecture**: Python codegen (`d3d9_methods.py`) → C proxy DLL (`src/`) or C++ remix-comp dispatch (`tracer_dispatch.inc`) → JSONL → Python analyzer (`analyze.py`). The standalone proxy chains to the real d3d9 (or another wrapper) and adds near-zero overhead when not capturing. The remix-comp integrated tracer records from within the dinput8.dll hook.

### Setup and Capture

```
python -m graphics.directx.dx9.tracer codegen -o d3d9_trace_hooks.inc            # C hooks (standalone proxy)
python -m graphics.directx.dx9.tracer codegen -f cpp -o tracer_dispatch.inc      # C++ dispatch (remix-comp module)
cd graphics/directx/dx9/tracer/src && build.bat                                  # build standalone proxy DLL
# Deploy d3d9.dll + proxy.ini to game directory
python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>              # trigger capture (3s countdown)
```

**proxy.ini** settings: `CaptureFrames=N` (frames to record), `CaptureInit=1` (capture boot-time calls like shader creation), `Chain.DLL=<wrapper.dll>` (chain to another d3d9 wrapper, or leave empty for system d3d9).

**IMPORTANT**: `--game-dir` must point to the directory containing the deployed proxy DLL (where the game runs).

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
| `--classify-draws` | Auto-tag draws (alpha, ztest, fog, fullscreen-quad, etc.) with draw method and vertex shader breakdown |
| `--vtx-formats` | Group draws by vertex declaration with element breakdown |
| `--redundant` | Find redundant state-set calls (same value set twice before a draw) |
| `--texture-freq` | Texture binding frequency across all draws |
| `--rt-graph` | Render target dependency graph (mermaid) |
| `--diff-draws A B` | State diff between two draw calls |
| `--diff-frames A B` | Compare two captured frames |
| `--const-evolution RANGE` | Track how specific registers change across draws (e.g. `vs:c4-c6`, `ps:c0-c3`) |
| `--state-snapshot DRAW#` | Complete state dump at a draw index: shaders + CTAB names, constants, vertex decl, textures, render states, transforms, samplers |
| `--transform-calls` | Analyze SetTransform/SetViewport usage: timing relative to draws, matrix values, whether game uses FFP transforms or shader constants |
| `--animate-constants` | Cross-frame constant register tracking |
| `--pipeline-diagram` | Auto-generate mermaid render pipeline diagram |
| `--resolve-addrs BINARY` | Resolve backtrace addresses to function names via retools |
| `--filter EXPR` | Filter records by field (e.g. `frame==0`, `slot==83`) |
| `--export-csv FILE` | Export raw records to CSV |

## DX Analysis Scripts (`rtx_remix_tools/dx/scripts/`) -- fast D3D9 scanners

Targeted first-pass scanners for D3D9 games. Run from repo root. Output is candidate addresses and patterns — always follow up with retools/livetools for confirmation.

| Script | What it surfaces | Example |
|--------|-----------------|---------|
| `find_d3d_calls.py $B` | D3D9/D3DX imports and call sites | `python rtx_remix_tools/dx/scripts/find_d3d_calls.py game.exe` |
| `find_vs_constants.py $B` | `SetVertexShaderConstantF` call sites with register/count args | `python rtx_remix_tools/dx/scripts/find_vs_constants.py game.exe` |
| `find_device_calls.py $B` | Device vtable call patterns and device pointer refs | `python rtx_remix_tools/dx/scripts/find_device_calls.py game.exe` |
| `find_vtable_calls.py $B` | D3DX constant table usage and D3D9 vtable calls | `python rtx_remix_tools/dx/scripts/find_vtable_calls.py game.exe` |
| `decode_vtx_decls.py $B --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES = skinning) | `python rtx_remix_tools/dx/scripts/decode_vtx_decls.py game.exe --scan` |
| `scan_d3d_region.py $B 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region | `python rtx_remix_tools/dx/scripts/scan_d3d_region.py game.exe 0x401000 0x500000` |

## Tool Caveats

### `rtti.py` -- MSVC RTTI only

Works exclusively with **MSVC-compiled** binaries that have RTTI enabled (`/GR`, the default). Will not work with:
- GCC/Clang/MinGW binaries (different ABI)
- Binaries compiled with `/GR-` (RTTI disabled)
- Partially stripped binaries where `.rdata` RTTI structures were removed

**How to get a vtable address to pass to `rtti.py vtable`:**
1. From `vtable.py dump $VA` -- if you already know a vtable location
2. From `datarefs.py` / `structrefs.py` -- field at offset `+0x00` of a C++ object is typically the vtable pointer
3. From live debugging -- `livetools mem read` on an object, the first pointer-sized value is the vtable

**If `rtti.py vtable` fails**, the error message tells you exactly why (bad signature, null pointers, corrupt name). Common causes:
- The address is not actually a vtable (try nearby aligned addresses)
- The binary has no RTTI at this vtable (abstract base, COM interface, etc.)
- The vtable belongs to a non-MSVC component

**`throwinfo` input differs by bitness:**
- 64-bit: pass the RVA from the exception record (minidump param[2] minus param[3])
- 32-bit: pass the absolute VA directly (minidump param[2])

### `throwmap.py` -- MSVC C++ exceptions only

Maps `_CxxThrowException` call sites to their string arguments by static analysis of the PE's code sections. Works on both 32-bit and 64-bit MSVC-compiled binaries.

**`match` requires the original binary**: the PE file must be the exact version loaded when the crash dump was captured. If rebuilt or updated since the crash, throw-site RVAs won't match.

**Will not work for**: non-MSVC binaries, custom exception mechanisms, binaries that don't import `_CxxThrowException`, or dumps where the crashing thread's stack memory wasn't captured.

### `dumpinfo.py` -- minidump completeness

Minidumps vary in how much data they capture depending on `MiniDumpWriteDump` flags. Common limitations:
- **Heap data missing**: the thrown object's `std::string` may point to heap memory not in the dump. `diagnose` reports this and falls back to `throwmap` matching.
- **Stack truncated**: small dumps may not capture enough stack depth. Use `memmap` to see what's actually available.
- **`stackscan` shows data AND code pointers**: not every value on the stack is a return address. Use `throwmap match` for definitive call-site identification.

### `funcinfo.py` -- call-target heuristic

`find_start()` locates function boundaries by building a table of all `CALL`/`JMP` targets. This misses functions only reachable via indirect calls (vtable dispatch, callbacks, function pointers). If `funcinfo.py` returns a clearly wrong function start, use `disasm.py` and look for padding/prologues manually.

### `datarefs.py` / `search.py strings --xrefs` -- addressing modes

These tools find references via absolute memory operands, immediate values (with `--imm` flag), and RIP-relative addressing. If you suspect a reference exists but the tool doesn't find it, the address might be computed at runtime. Try `search.py pattern` with the address bytes directly, or use `livetools memwatch`.

### `livetools` -- static vs runtime addresses

**x86 games without ASLR** (most 32-bit games): the PE preferred base matches the runtime load address. Addresses from `retools` can be passed directly to `livetools`.

**DLLs and ASLR-enabled executables**: runtime base may differ. Run `python -m livetools modules --filter <name>` and compare against the PE's preferred base. If they differ: `runtime_addr = runtime_base + (static_addr - preferred_base)`.

**Hook the game's CALL, not the DLL entry.** To trace a D3D9/API method, hook the `call [reg+offset]` instruction *in the game's .exe* (found via `xrefs.py` or `vtable.py calls`), NOT the function entry point inside the DLL. The game's call site has arguments on the stack in known positions; the DLL entry point may be wrapped by proxies and is shared across all callers.
