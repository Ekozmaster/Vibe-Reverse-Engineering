---
description: Complete catalog of all RE tools (retools, livetools, dx9 tracer) with syntax, examples, and caveats. Consult before choosing which tool to use.
---

# Tool Catalog

**BEFORE FIRST USE**: Run `python verify_install.py` from the repo root. Do NOT proceed with any tool until every required check passes. If pyghidra/Ghidra shows as WARN, run `python verify_install.py --setup` to auto-download JDK 21 + Ghidra + pyghidra. Common failures: missing `git lfs pull` (LFS pointer stubs instead of binaries), missing `pip install -r requirements.txt`.

All tools work on PE binaries (`.exe` and `.dll`). `$B` = path to binary, `$VA` = hex address, `$D` = path to minidump `.dmp` file. Check tools help command for more info on usage.
Always consult this catalog before making any move to take the best decision on what to use with best bang for your buck.
Run all tools from the repo root directory using `python -m <module>` syntax (e.g. `python -m retools.search`). Do NOT modify files inside `retools/`, `livetools/`, or `graphics/` unless working on the tools themselves.

IMPORTANT: Collecting MORE INFORMATION per command run is encouraged over minor snippets of data/output that don't reveal the whole picture.

## Decision Guide

### Run Directly (main agent)

These are fast (<5s) and allowed inline:

- "What compiler built this?" → `python -m retools.sigdb fingerprint $B`
- "Is this a known library function?" → `python -m retools.sigdb identify $B $VA`
- "Get full context before reasoning about a function" → `python -m retools.context assemble $B $VA --project $P`
- "Clean up decompiler output with known names" → pipe through `python -m retools.context postprocess`
- "Read a typed value from the PE file" → `python -m retools.readmem $B $VA $TYPE`
- "What constant flows into this register?" (x86 binaries only) → `python -m retools.dataflow $B $VA --constants`
- "Trace where this value comes from" (x86 binaries only) → `python -m retools.dataflow $B $VA --slice TARGET_VA:REG`
- "Build an ASI patch DLL" → `python -m retools.asi_patcher build spec.json --vcvarsall <path to vcvarsall.bat>`
- "Does a Ghidra project exist for this binary?" → `python retools/pyghidra_backend.py status $B --project $P`
- "What's in this game's index?" → `python -m retools.index status <Game> [--db PATH]`
- "Query facts already indexed (funcs, names, xrefs, strings, imports, callers/callees)" → `python -m retools.query <Game> "SQL" [--db PATH] [--json] [--list-tables] [--schema TABLE]`

### Delegate to `static-analyzer` subagent

Everything else. Tell the subagent WHAT you need, not HOW to run it — it has the full tool catalog.

**D3D9-specific questions?** Check the DX analysis scripts section below first — they're faster and more targeted than general retools for D3D API usage, device calls, shader constants, and vertex formats.

- "What does this function do?" → decompile + callgraph + xrefs + dataflow --constants
- "Who calls this function?" → xrefs or callgraph --up (prefer `retools.query "SELECT * FROM callers WHERE callee_addr=..."` when index.db exists)
- "What does this function call?" → callgraph --down (add --indirect for vtable calls) (prefer `retools.query "SELECT * FROM callees WHERE caller=..."` when index.db exists)
- "Who calls this virtual method?" → xrefs --indirect + filter by vtable slot offset
- "What constant reaches this call?" → dataflow --constants or --slice VA:REG
- "Resolve a switch/jump table" → cfg (auto-resolves MSVC switch patterns)
- "Find a string and who uses it" → string search with xrefs (prefer `retools.query "SELECT * FROM grep WHERE name LIKE '%...%'"` when index.db exists)
- "Where is this global read/written?" → datarefs (prefer `retools.query` against `names`/`xrefs` when index.db exists)
- "Where is struct field +0x54 used?" → structrefs
- "What does this struct look like?" → structrefs --aggregate
- "What C++ class is this vtable?" → RTTI resolution
- "What type was a caught/thrown exception?" → RTTI throwinfo
- "Find instructions using a specific constant" → instruction search
- "What crashed and what was the error message?" → dump diagnosis + throwmap
- "Map all throw sites to error strings" → throwmap list
- "First time analyzing a binary?" → bootstrap (2-5 min) + pyghidra analyze (5-15 min) in parallel
- "Bulk signature scan" → sigdb scan (1-3 min)
- "Seed/refresh the index from a Ghidra project" → `pyghidra_backend.py export` (funcs/names/xrefs/blocks, source='ghidra', authoritative over provisional bootstrap rows)
- "Push kb.h names/prototypes into the Ghidra project" → `pyghidra_backend.py kb-apply` (idempotent)
- Any combination of the above

### Live tools (main agent, requires attached process)

- "Is this function reached at runtime?" → `livetools trace` or `collect`
- "What are the actual register values?" → `livetools trace --read` or `bp` + `regs`
- "How many draw calls happen?" → `livetools dipcnt`
- "Does anything touch this memory page, and from where?" → `livetools memwatch` (first access per page, read or write; not a write watchpoint)
- "Send keys/clicks to the game window?" → `livetools gamectl`

### DX analysis scripts (main agent, fast first-pass)

These are targeted D3D9 scanners under `rtx_remix_tools/dx/scripts/`. They run in seconds and surface D3D-specific patterns that general-purpose retools would take longer to find. **Use these BEFORE retools** when the question is about D3D9 API usage, device calls, shaders, or vertex formats. Run as `python rtx_remix_tools/dx/scripts/<script> <args>`.

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
- "Which registers are View/Proj/World?" → `find_matrix_registers.py <game.exe>` (CTAB names + frequency heuristics + a suggested `[FFP.Registers]` section for `remix-comp-proxy.ini`)
- "D3DX constant table or vtable calls?" → `find_vtable_calls.py <game.exe>` (D3DX CTAB usage + D3D9 vtable calls)
- "Does the game have skinned meshes? What config does the proxy need?" → `find_skinning.py <game.exe>` (skinned decls, bone palettes, blend states, suggested INI)
- "Does the game use FFP vertex blending?" → `find_blend_states.py <game.exe>` (D3DRS_VERTEXBLEND + INDEXEDVERTEXBLENDENABLE + WORLDMATRIX)
- "Map all D3D calls in a code region" → `scan_d3d_region.py <game.exe> 0xSTART 0xEND`

These are fast first-pass scanners — they surface candidate addresses. Follow up with `retools` (decompiler, xrefs) and `livetools` (trace, bp) for deep analysis of the addresses they find.

### dx9tracer (main agent for capture, delegate analysis)

- "Trigger a frame capture" → main agent: `python -m graphics.directx.dx9.tracer trigger`
- "Analyze captured frames" → delegate to `static-analyzer`: summary, render-passes, shader-map, etc.

## Static Analysis (`retools/`) -- offline, on-disk PE files

**ALWAYS pass `--types patches/<project>/kb.h`** when using `decompiler.py`. Create the kb.h file on first decompilation if it doesn't exist. Every discovery (function names, struct layouts, globals) should be added to kb.h so subsequent decompilations produce richer output.

What each decompiler takes from kb.h:

- **r2ghidra** reads it on every call (`--types`): structs, unions and enums (also written over several lines), `typedef <type> Name;`, function names with their prototypes, and globals as named addresses. Two things radare2 itself does not take: `typedef struct X Y;` for a struct declared on another line (write `typedef struct X { ... } Y;`), and a pointer as the type of a global (the name still applies).
- **Ghidra** reads it only when `kb-apply` runs, and keeps the result in the project. Types are stored first, so a prototype can use a struct from the same file. A prototype may carry a calling convention (`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`). When Ghidra cannot resolve a type in a prototype (one that is missing from kb.h, or a spelling such as `unsigned __int64`), the function still gets its name and the prototype is reported as skipped.

| Tool | Purpose | Example |
|------|---------|---------|
| `disasm.py $B $VA` | Disassemble N instructions at VA | `disasm.py binary.exe 0x401000 -n 50` |
| `decompiler.py $B $VA --types --project` | **C decompilation** -- pyghidra (if project exists) or r2ghidra | `python -m retools.decompiler binary.exe 0x401000 --types patches/proj/kb.h --project patches/proj` |
| `pyghidra_backend.py analyze $B --project $P` | **Full Ghidra analysis** -- one-time, saves reusable project | `pyghidra_backend.py analyze game.exe --project patches/MyGame` |
| `pyghidra_backend.py decompile $B $VA --project $P` | Decompile via saved Ghidra project | `pyghidra_backend.py decompile game.exe 0x401000 --project patches/MyGame` |
| `pyghidra_backend.py status $B --project $P` | Check if Ghidra project exists | `pyghidra_backend.py status game.exe --project patches/MyGame` |
| `pyghidra_backend.py export $B --project $P [--db]` | Seed funcs/names/xrefs/blocks from an analyzed Ghidra program into index.db (names include the data labels `kb-apply` creates, namespace-qualified) (`source='ghidra'`, overwrites provisional bootstrap rows at the same address) | `pyghidra_backend.py export game.exe --project patches/MyGame` |
| `pyghidra_backend.py kb-apply $B --project $P --kb $KB` | Push kb.h names/prototypes/globals/typedefs into the Ghidra project. Idempotent — safe to re-run. Prints one count per kind (`functions`, `labels`, `globals`, `typedefs`, `prototypes`) and `skipped`, the entries Ghidra refused; each of those is listed on stderr with Ghidra's reason | `pyghidra_backend.py kb-apply game.exe --project patches/MyGame --kb patches/MyGame/kb.h` |
| `index.py status $GAME [--db]` | Per-table row counts + schema_version for `patches/<game>/index.db` | `python -m retools.index status MyGame` |
| `query.py $GAME "SQL" [--db] [--json] [--list-tables] [--schema TABLE]` | Read-only SQL over index.db. Views: `callers`, `callees`, `grep`. Addresses are stored and printed as decimal integers; select `printf('0x%x', address)` to get hex. Connection is opened read-only, so it cannot change index.db, and attaching is refused, so `ATTACH DATABASE` and `VACUUM INTO` fail with an authorization error instead of creating the file they name | `python -m retools.query MyGame "SELECT * FROM grep WHERE name LIKE '%Ground%'"` |
| `ghidra_server.py $GAME [--idle SECS]` | Run a per-project Ghidra daemon (port 27043; livetools owns 27042) holding one warm program so repeat `decompile`/`export`/`kb-apply` calls are sub-second instead of paying JVM+analysis startup each time. Tracks itself in `patches/<game>/ghidra/.state.json` (pid/port/project/binary), deleted on shutdown once the Ghidra program is closed | `python -m retools.ghidra_server MyGame --idle 600` |
| `funcinfo.py $B $VA` | Find function start/end, rets, calling convention, callees. Prefer `retools.query` on `funcs`/`blocks` when index.db exists | `funcinfo.py binary.exe 0x401000` |
| `cfg.py $B $VA` | Control flow graph (basic blocks + edges, text or mermaid). Resolves MSVC switch/jump tables automatically. `--switch-details` shows table info | `cfg.py binary.exe 0x401000 --format mermaid` |
| `callgraph.py $B $VA` | Caller/callee tree (multi-level, --up/--down N). `--indirect` adds vtable/fptr calls to --down trees | `callgraph.py binary.exe 0x401000 --down 2 --indirect` |
| `xrefs.py $B $VA` | Find all calls/jumps TO an address. `--indirect` also scans for `call [reg+offset]`, `call [reg]`, `call [addr]`. Prefer `retools.query "SELECT * FROM callers WHERE callee_addr=..."` when index.db exists | `xrefs.py binary.exe 0x401000 --indirect` |
| `dataflow.py $B $VA` | Forward constant propagation (`--constants`) or backward register slice (`--slice VA:REG`) within a function. `--constants` models `mov`, `add`, `sub`, `lea`, `xor reg, reg`, `push`/`pop` and calls; a register written by anything else is left out, not reported with its old value. **x86 only**: a 64-bit binary is refused with an error | `dataflow.py binary.exe 0x401000 --constants` |
| `datarefs.py $B $VA` | Find instructions that reference a global address (mem deref + `--imm` for push/mov constants), each labelled `[r ]`, `[w ]` or `[rw]`. `--access w` keeps every instruction that writes it (`w` and `rw`), `--access r` every one that reads it, `--access rw` only those that do both. Prefer `retools.query` against `xrefs`/`names` when index.db exists | `datarefs.py binary.exe 0x7A0000 --imm` |
| `structrefs.py $B $OFF` | Find all `[reg+offset]` accesses (struct field usage) | `structrefs.py binary.exe 0x54 --base esi` |
| `structrefs.py $B --aggregate` | Reconstruct C struct from all field accesses in a function | `structrefs.py binary.exe --aggregate --fn 0x401000 --base esi` |
| `vtable.py $B dump $VA` | Dump C++ vtable slots with instruction preview | `vtable.py binary.exe dump 0x6A0000` |
| `vtable.py $B calls $OFF` | Find all indirect `call [reg+offset]` (vtable call sites) | `vtable.py binary.exe calls 0xB0` |
| `rtti.py $B vtable $VA` | Resolve C++ class name + inheritance chain from vtable (MSVC RTTI) | `rtti.py binary.dll vtable 0x6A0000` |
| `rtti.py $B throwinfo $RVA` | Resolve exception type from `_ThrowInfo` (MSVC RTTI) | `rtti.py binary.dll throwinfo 0x5040CF8` |
| `search.py $B strings` | Extract strings with keyword filter. Prefer `retools.query "SELECT * FROM grep WHERE name LIKE '%...%'"` when index.db exists | `search.py binary.exe strings -f render,draw` |
| `search.py $B strings --xrefs` | Find strings AND code locations that reference them | `search.py binary.exe strings -f "error" --xrefs` |
| `search.py $B pattern` | Find exact byte pattern | `search.py binary.exe pattern "D9 56 54 D8 1D"` |
| `search.py $B imports` | List PE imports, filter by DLL | `search.py binary.exe imports -d kernel32` |
| `search.py $B exports` | List PE exports, filter by keyword | `search.py binary.dll exports -f Create` |
| `search.py $B insn` | Find instructions by mnemonic/operand pattern | `search.py binary.dll insn "mov *,0x10000"` |
| `search.py $B insn --near` | Find instructions near another pattern | `search.py binary.dll insn "mov *,0x10000" --near "cmp *,0x10000" --range 0x400` |
| `readmem.py $B $VA $TYPE` | Read typed data (float, uint32, ptr, bytes...) | `readmem.py binary.exe 0x401000 float` |
| `asi_patcher.py build` | Generate .asi DLL patch from JSON spec | `asi_patcher.py build spec.json --vcvarsall ...` |
| `bootstrap.py $B --project $P` | Auto-seed KB: compiler ID, signatures, RTTI, imports, propagation. `--project` is the **output directory** (`$P` = `patches/<project>`), not a bare name | `bootstrap.py game.exe --project patches/Warband` |
| `sigdb.py scan $B` | Bulk signature scan against DB | `sigdb.py scan game.exe` |
| `sigdb.py identify $B $VA` | Single function signature lookup (multi-tier) | `sigdb.py identify game.exe 0x401200` |
| `sigdb.py fingerprint $B` | Identify compiler version (Rich header + markers + imports) | `sigdb.py fingerprint game.exe` |
| `context.py assemble $B $VA --project $P` | Gather full analysis context for a function. Includes forward constant propagation by default (`--no-dataflow` to skip); on a 64-bit binary that section is a `[dataflow] skipped` line, since dataflow models x86 registers only | `context.py assemble game.exe 0x401500 --project patches/Warband` |
| `context.py postprocess $B $VA --project $P` | Mechanically rename/annotate decompiler output (pipe) | `decompiler.py ... \| context.py postprocess ...` |
| `sigdb.py build $MANIFEST` | Build/extend signature DB from manifest (binary + `address,name[,size]` CSV): skips functions under 16 bytes and prefixes with more than one name, wildcards prefix bytes past a short function's end and E8/E9 rel32 operands (including one cut off at the end of the prefix), stores a FLIRT CRC16 up to the first call, outside branch or address operand (on x86 that includes indexed `[reg*s + abs32]` and `[reg + abs32]`). Prefixes are unique per `(pattern, mask, crc_len, crc16)`, and a prefix already in the DB is skipped only when its compiler label can match the same binaries | `sigdb.py build sources.json` |
| `sigdb.py import-pat $PAT -d $DB --compiler $C --source $S` | Add a FLIRT `.pat` file (e.g. rizin `sigdb-source`) to a DB: offset-0 names only, keeps each line's CRC16, drops local labels, functions under 16 bytes and prefixes with more than one name | `sigdb.py import-pat VisualStudio2008.pat -d sigs.db --compiler msvc2008 --source rizin_vs2008` |
| `sigdb.py pull` | Download signature DB from HuggingFace (`--revision` picks an HF branch, tag or commit; default `main`) | `sigdb.py pull`, `sigdb.py pull --sources` or `sigdb.py pull --revision schema-v2` |

> **Note:** `scan` and `identify` default to `retools/data/signatures.db` when `--db` is omitted. Run `sigdb.py pull` after first clone to download the database. Opening a DB never writes to it: `scan` and `identify` read a schema-1 DB as it is, and the first `build` or `import-pat` adds the CRC16 columns in place.
>
> **Matching rules:** a sig with a FLIRT CRC16 matches only when the bytes after its 32-byte prefix pass the CRC. Sigs whose compiler label names MSVC versions (`msvc2008`, `msvc6.0`, `msvc2003_2005`) are skipped on binaries whose Rich header lists none of those versions. `scan` drops a name that is the best match at more than one address.

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

Main-agent only (requires a live process; static-analyzer subagents must not use these). Canonical command reference with syntax, read-spec format, and recipes: the `/dynamic-analysis` skill (`.claude/skills/dynamic-analysis/SKILL.md`). Covers attach/spawn, breakpoints, trace/steptrace/collect, mem read/write/alloc, scan, disasm, modules, dipcnt, memwatch, vishook, gamectl, and offline `analyze`.

**NOTE**: Some processes require their window to be focused for traces to capture data.

## D3D9 Frame Trace (`graphics/directx/dx9/tracer/`) -- full-frame API capture and analysis

A proxy DLL that intercepts all 119 `IDirect3DDevice9` methods, capturing every call with arguments, backtraces, pointer-followed data (matrices, constants, shader bytecodes), and in-process shader disassembly (via the game's own d3dx9 DLL). Outputs JSONL for offline analysis.

**Architecture**: Python codegen (`d3d9_methods.py`) → C proxy DLL (`src/`) or C++ remix-comp-proxy dispatch (`tracer_dispatch.inc`) → JSONL → Python analyzer (`analyze.py`). The standalone proxy chains to the real d3d9 (or another wrapper) and adds near-zero overhead when not capturing. The remix-comp-proxy integrated tracer records from the proxy's own `IDirect3DDevice9` wrapper (`src/comp/modules/d3d9ex.cpp`) and writes to `captures/dxtrace_<timestamp>.jsonl` under the game directory.

### Setup and Capture

```
python -m graphics.directx.dx9.tracer codegen -o d3d9_trace_hooks.inc            # C hooks (standalone proxy)
python -m graphics.directx.dx9.tracer codegen -f cpp -o tracer_dispatch.inc      # C++ dispatch (remix-comp-proxy module)
cd graphics/directx/dx9/tracer/src && build.bat                                  # build standalone proxy DLL (finds VS 2022+ or Build Tools through vswhere)
# Deploy d3d9.dll + proxy.ini to game directory
python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>              # trigger capture (3s countdown)
```

**proxy.ini** settings: `CaptureFrames=N` (frames to record when the trigger file names no count; `trigger --frames` overrides it), `CaptureInit=1` (capture boot-time calls like shader creation), `Chain.DLL=<wrapper.dll>` (chain to another d3d9 wrapper, or leave empty for system d3d9).

**IMPORTANT**: `--game-dir` must point to the directory containing the deployed proxy DLL (where the game runs). It defaults to the current directory.

`trigger --wait` follows the capture and exits 0 only after the tracer reports the capture `done`, which it writes once the captured frames are flushed to the JSONL file (with `CaptureInit=1` the standalone tracer keeps that file open afterwards and goes on appending `Create*` calls as frame `-1` until the game exits, so the file keeps growing and its last line may be half written; `analyze` skips such a line); in every other case it prints an `[error]` line saying what it saw and exits 1:

- No tracer took the trigger within 120 s (game not running, or the DLL is in another folder): the trigger file is removed again, so a later game start does not begin a capture.
- The capture stopped short of `--frames` (reported at once when the tracer says `done`).
- The tracer reached the last frame but never reported the file written in full: the `d3d9.dll` in the game folder predates the `done` report. Copy the current `graphics/directx/dx9/tracer/bin/d3d9.dll` there.
- The trigger was taken but no progress appears: the tracer is older than the progress report, most likely a per-game remix-comp-proxy copy under `patches/` built from an older `tracer.cpp`. Port the template's tracer into that copy (`src/comp/modules/tracer.cpp`, `tracer.hpp`, `tracer_dispatch.inc`, the `TRACE_CREATION_IF_ACTIVE` calls in `d3d9ex.cpp` and `<atomic>` in `src/comp/std_include.hpp`) and rebuild, or look for the capture in its output folder (`[Tracer] OutputDir`).

A progress file left by an earlier capture is deleted before the trigger is written.

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

**32-bit only.** Every script except `find_d3d_calls.py` reads PE32 code and exits with an error on a 64-bit binary or on a file that is not a PE.

**How call arguments are reported.** A script reads the pushes and the `mov [esp+disp]` stores in front of each call and assigns them to the method's parameters by stack slot, so a pushed register counts as an argument; the latest write to a slot wins. A constant is decoded. A register or memory operand is shown in angle brackets (`<eax>`): the value is only known at run time. `<unknown>` means the code in front of the call does not settle the argument (an earlier call, a stack adjustment, a store that is not a whole dword such as `fstp [esp]`, or a jump target — including the call itself — where two code paths join); nothing is guessed. Sites whose arguments are not constants are left out of summaries such as register ranges, so follow them up with `livetools trace --probe` on the call site.

**Which calls are found.** `call [reg+offset]` in both its encodings, which covers every vtable slot. A `mov reg, [reg+offset]` load, in both its encodings, is listed as an indirect call only when a `call reg` through that register follows it, and the arguments are read at that call. Another call may run in between when the register is `ebx`, `esi`, `edi` or `ebp`, which calls preserve; with `eax`, `ecx` or `edx` the load is dropped there. A hit is then dropped when the code in front of it shows it is a call of another method. *COM `this`*: a site whose pushed `this` is an immediate or a different value than the object its vtable was read from, or that loads that object into `ecx` (the `__thiscall` form), is dropped; a site whose `this` the code does not settle is kept. *Argument count*: a hit is dropped when the walk back from its call reaches an earlier call, a stack-pointer change it cannot follow, or the start of the code (after a `ret`, a `jmp` or padding) with fewer stack slots written than the method's parameters plus `this`; it is kept when the walk stops at a jump target or at the start of the window it decodes, and extra slots never drop it (an outer call's arguments precede an inner one's). *Device provenance*: COM calls on other interfaces still pass both checks, and every class shares the slots below `vtable+0x80`. So the scripts learn where the game keeps its device from the hits at `vtable+0x80` and above: each hit's object is followed back from `mov vt, [obj]` through register copies (across calls for `ebx`/`esi`/`edi`/`ebp`) and loads to a global, `[0x009D915C]`, or a field of an object held in one, `[[0x009D915C]+0x1C]`; a location qualifies when hits on it call at least 12 different device methods there and at least half as many as the most-called location. A game's device is called through 25 or more of them; an `ID3DXEffect` (`SetFloatArray`/`SetVector`/`SetMatrix` sit at `+0x80`/`+0x88`/`+0x98`) or a large game class through fewer than ten. A hit below `vtable+0x80` is reported as a device call only when its object is read from a learned location; the others are counted as unconfirmed (`--unconfirmed` lists them in `find_device_calls.py` and `find_surface_formats.py`), and the header line names the learned location. A device the code reaches through a field of `this`, an argument or a stack local has no learnable location: the header says so and every low-slot hit stays unconfirmed. Hits at `vtable+0x80` and above are reported whatever their object.

| Script | What it surfaces | Example |
|--------|-----------------|---------|
| `find_d3d_calls.py $B` | D3D9/D3DX imports and call sites | `python rtx_remix_tools/dx/scripts/find_d3d_calls.py game.exe` |
| `find_vs_constants.py $B` | `SetVertexShaderConstantF` call sites with register/count args | `python rtx_remix_tools/dx/scripts/find_vs_constants.py game.exe` |
| `find_ps_constants.py $B` | `SetPixelShaderConstantF/I/B` call sites with register/count args | `python rtx_remix_tools/dx/scripts/find_ps_constants.py game.exe` |
| `find_device_calls.py $B` | Device vtable call patterns and device pointer refs; `--unconfirmed` lists low-slot hits not shown to be on the device | `python rtx_remix_tools/dx/scripts/find_device_calls.py game.exe` |
| `find_render_states.py $B` | SetRenderState arguments decoded by category (culling, blending, depth, fog) | `python rtx_remix_tools/dx/scripts/find_render_states.py game.exe` |
| `find_texture_ops.py $B` | Texture pipeline: SetTexture stages, TSS color/alpha ops, sampler states | `python rtx_remix_tools/dx/scripts/find_texture_ops.py game.exe` |
| `find_transforms.py $B` | SetTransform/MultiplyTransform types (World, View, Projection, Texture) | `python rtx_remix_tools/dx/scripts/find_transforms.py game.exe` |
| `find_surface_formats.py $B` | CreateTexture/RenderTarget/DepthStencil D3DFMT extraction, confirmed device calls only; `--unconfirmed` lists the rest | `python rtx_remix_tools/dx/scripts/find_surface_formats.py game.exe` |
| `find_stateblocks.py $B` | State block creation, recording, and apply patterns | `python rtx_remix_tools/dx/scripts/find_stateblocks.py game.exe` |
| `decode_fvf.py $B` | FVF bitfield decode from SetFVF calls (or `--decode 0xNNN` manual) | `python rtx_remix_tools/dx/scripts/decode_fvf.py game.exe` |
| `find_vtable_calls.py $B` | D3DX constant table usage and D3D9 vtable calls | `python rtx_remix_tools/dx/scripts/find_vtable_calls.py game.exe` |
| `decode_vtx_decls.py $B --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES = skinning) | `python rtx_remix_tools/dx/scripts/decode_vtx_decls.py game.exe --scan` |
| `find_shader_bytecode.py $B` | Embedded shader bytecode extraction (version, size, `--dump-dir`) | `python rtx_remix_tools/dx/scripts/find_shader_bytecode.py game.exe` |
| `classify_draws.py $B` | Draw call classification by state context (FFP/shader/hybrid %) | `python rtx_remix_tools/dx/scripts/classify_draws.py game.exe` |
| `find_matrix_registers.py $B` | Identify View/Proj/World registers (CTAB + frequency + suggested `[FFP.Registers]` INI section) | `python rtx_remix_tools/dx/scripts/find_matrix_registers.py game.exe` |
| `find_skinning.py $B` | Consolidated skinning analysis: skinned decls, bone palettes, blend states, suggested INI | `python rtx_remix_tools/dx/scripts/find_skinning.py game.exe` |
| `find_blend_states.py $B` | D3DRS_VERTEXBLEND + INDEXEDVERTEXBLENDENABLE + WORLDMATRIX transforms | `python rtx_remix_tools/dx/scripts/find_blend_states.py game.exe` |
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

### `funcinfo.py` -- where function starts come from

On x64 the exception table lists every function that has unwind information, with its extent, so an address inside such a function resolves to that function and an address in the gap behind one resolves to none. On x86, and for x64 leaf functions, only starts are known: targets of direct `CALL`s, exports, and `JMP` targets that sit behind padding, a return or another jump (functions reached by tail calls). That misses functions only reachable via indirect calls (vtable dispatch, callbacks, function pointers): 27% of the functions of one x86 C++ DLL, measured against its linker map. For such an address the nearest known start before it is reported. `funcinfo.py` prints a `[warning]` line when the address you asked about is not inside the range it reports; treat that range as a different function. If `funcinfo.py` returns a clearly wrong function start, use `disasm.py` and look for padding/prologues manually.

An `int3` ends `funcinfo`'s scan for the function end only when it follows a `ret` or `jmp` (padding) or when no branch seen so far jumps past it, so `je over; call noreturn; int3; over: ret` still finds the `ret`. In `cfg.py` an `int3` ends its block with no successor, so a `call noreturn; int3` does not run on into the next function. `cfg.py` treats `jecxz`/`jrcxz` and `loop`/`loope`/`loopne` as conditional branches.

### `datarefs.py` / `search.py strings --xrefs` -- addressing modes

These tools find references via absolute memory operands, immediate values (with `--imm` flag), and RIP-relative addressing. If you suspect a reference exists but the tool doesn't find it, the address might be computed at runtime. Try `search.py pattern` with the address bytes directly, or use `livetools memwatch`.

### `pyghidra_backend.py` -- Ghidra primary, r2ghidra fallback

Ghidra (via `pyghidra_backend.py`, indexed into `index.db`, daemon-backed, kb-applied) is the **primary** decompilation backend once a project exists — it gives better type propagation, library call resolution, and lets `retools.query` answer structural questions without re-scanning the binary. r2ghidra (`decompiler.py --backend pdg`) is the **zero-setup fallback and second opinion**: no Ghidra install required, faster on small functions, and useful to cross-check a pyghidra result that looks wrong. `decompiler.py --backend auto` tries pyghidra first and falls back to r2ghidra automatically — this routing is unchanged.

Requires Ghidra 11.x+ and JDK 21+. `python verify_install.py --setup` downloads both into `tools/`, where retools finds them on its own; set `GHIDRA_INSTALL_DIR` only to use a Ghidra installed somewhere else. The JDK is the first of `JAVA_HOME`, `java` on PATH and `tools/jdk-*` (highest version first) that is version 21 or newer, so an older Java on PATH is passed over; a `JAVA_HOME_OVERRIDE` you set yourself is kept. **Optional** -- the toolkit works without it (r2ghidra remains the fallback).

**Disk usage**: Ghidra projects are ~10-20x the binary size. A 30MB game exe produces a ~300-600MB `.rep/` directory under `patches/<project>/ghidra/`. This directory is already covered by `.gitignore` (the `patches/` exclusion).

**First-time analysis** takes 5-15 minutes depending on binary size. Subsequent decompilation from the saved project is near-instant (<1s plus ~3s JVM startup per cold process) -- or truly sub-second when a `ghidra_server.py` daemon is warm for that project. `export` and `kb-apply` route through the same live daemon when one is running; `RETOOLS_GHIDRA_COLD=1` or `--cold` forces a cold in-process run for either.

**Index-first**: after `export`, prefer `retools.query` over datarefs/xrefs/search/funcinfo for anything already captured in `index.db` (funcs, names, xrefs, strings, imports, blocks) -- it's a local SQL query instead of a fresh binary scan. Fall back to the scanners only for facts index.db doesn't have yet.

### `livetools` -- static vs runtime addresses

**x86 games without ASLR** (most 32-bit games): the PE preferred base matches the runtime load address. Addresses from `retools` can be passed directly to `livetools`.

**DLLs and ASLR-enabled executables**: runtime base may differ. Run `python -m livetools modules --filter <name>` and compare against the PE's preferred base. If they differ: `runtime_addr = runtime_base + (static_addr - preferred_base)`.

**A function hook goes on a function entry; a call site takes `--probe`.** `livetools trace` and `collect` trap the function's return through the top stack slot, which is a return address only at a function entry, so they refuse a `call [reg+offset]` instruction (there the slot is the first stack argument, the device pointer). To watch one call site, add `--probe`: it records the registers and `--read` data at that instruction and has no caller or return value (`[esp]` is `this` at an x86 call instruction). To watch every caller of a D3D9/API method, hook the entry of the method the game calls (read it from the object's vtable at runtime with `livetools mem read`) and use each record's `caller` (the return address) to tell call sites apart. Breakpoints (`livetools bp`) and `collect --fence` may sit on any instruction. Details: pattern 9 in the `/dynamic-analysis` skill.
