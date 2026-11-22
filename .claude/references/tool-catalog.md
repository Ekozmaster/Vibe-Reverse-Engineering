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
| `query.py $GAME "SQL" [--db] [--json] [--list-tables] [--schema TABLE]` | Read-only SQL over index.db. Views: `callers`, `callees`, `grep`. Addresses are stored and printed as decimal integers; select `printf('0x%x', address)` to get hex. Connection is opened read-only, so it cannot change index.db, and every statement but a query or a schema pragma is refused with an authorization error, so `ATTACH DATABASE`, `VACUUM INTO` and `CREATE TEMP TABLE` cannot create a file. SQLite itself keeps `index.db-shm` and `index.db-wal` beside a WAL-mode index while it is read | `python -m retools.query MyGame "SELECT * FROM grep WHERE name LIKE '%Ground%'"` |
| `ghidra_server.py $GAME [--idle SECS]` | Run a per-project Ghidra daemon (port 27043; livetools owns 27042) holding one warm program so repeat `decompile`/`export`/`kb-apply` calls are sub-second instead of paying JVM+analysis startup each time. Tracks itself in `patches/<game>/ghidra/.state.json` (pid/port/project/binary), deleted on shutdown once the Ghidra program is closed | `python -m retools.ghidra_server MyGame --idle 600` |
| `funcinfo.py $B $VA` | Find function start/end, rets, calling convention, callees. The end is the last `ret`, or a later instruction a branch of the function reaches, so bytes behind a `ret` or `jmp` that nothing jumps to (alignment, a jump table) are not counted and a function that ends in a tail `jmp` has a range too. The scan stops at a known function start that the function's code does not run into; a known start that live code falls through to, or that a branch of the function jumps past, is a call target inside its body and does not end it. The cases of a `jmp [table+reg*4]` are branches of the function: a case behind the last `ret` is counted, the table's own bytes are stepped over, and the scan ends behind a table that no branch jumps past (another function follows it). A table is read up to the first entry outside the scan window and no further than the table of another `jmp [table+reg*4]`. A `jmp` past the next function is a tail call when it lands on a function entry (a known start, or an address behind padding, a `ret`, a `jmp` including an import thunk's `jmp [mem]`, or at a section start); into straight-line code it is a branch, and the known start it passes lies inside the function. Function starts come from a byte heuristic on x86, so a function still loses its tail when every `jmp` over a false start that follows a `ret` or `jmp` lands exactly on that start, and a case is not counted when its table is addressed through a register, or on x64, where no jump table is followed. Prefer `retools.query` on `funcs`/`blocks` when index.db exists | `funcinfo.py binary.exe 0x401000` |
| `cfg.py $B $VA` | Control flow graph (basic blocks + edges, text or mermaid). Resolves MSVC switch/jump tables automatically. `--switch-details` shows table info | `cfg.py binary.exe 0x401000 --format mermaid` |
| `callgraph.py $B $VA` | Caller/callee tree (multi-level, --up/--down N). `--indirect` adds vtable/fptr calls to --down trees | `callgraph.py binary.exe 0x401000 --down 2 --indirect` |
| `xrefs.py $B $VA` | Find all calls/jumps TO an address. `--indirect` also scans for `call [reg+offset]`, `call [reg]`, `call [addr]`. Prefer `retools.query "SELECT * FROM callers WHERE callee_addr=..."` when index.db exists | `xrefs.py binary.exe 0x401000 --indirect` |
| `dataflow.py $B $VA` | Forward constant propagation (`--constants`) or backward register slice (`--slice VA:REG`) within a function. `--constants` models `mov`, `add`, `sub`, `lea`, `xor reg, reg`, `push`/`pop` and calls; a register written by anything else is left out, not reported with its old value. A `pop` yields a pushed value only while every esp change since the push is followed: any call, `leave`, or an unaligned or register-sized adjustment forgets the stack, so a register restored after a call is not reported; a store through `[esp+N]` forgets the slots it covers, and an indexed store or `fxsave`/`fnsave`/`xsave` forgets all. **x86 only**: a 64-bit binary is refused with an error | `dataflow.py binary.exe 0x401000 --constants` |
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
| `bootstrap.py $B --project $P` | Auto-seed KB: compiler ID, signatures, RTTI, imports, propagation. `--project` is the **output directory** (`$P` = `patches/<project>`), not a bare name | `bootstrap.py game.exe --project patches/MyGame` |
| `sigdb.py scan $B` | Bulk signature scan against DB | `sigdb.py scan game.exe` |
| `sigdb.py identify $B $VA` | Single function lookup: byte signatures, then the structural tier only when no byte signature fits; byte signatures that fit and disagree on the name give `No match` | `sigdb.py identify game.exe 0x401200` |
| `sigdb.py fingerprint $B` | Identify compiler version (Rich header + markers + imports) | `sigdb.py fingerprint game.exe` |
| `context.py assemble $B $VA --project $P` | Gather full analysis context for a function. Includes forward constant propagation by default (`--no-dataflow` to skip); on a 64-bit binary that section is a `[dataflow] skipped` line, since dataflow models x86 registers only. `--db` adds the best structural match (`[similar]`) among signatures whose MSVC version the binary's Rich header lists, and refuses a path with no database or a file that is not a signature database | `context.py assemble game.exe 0x401500 --project patches/MyGame` |
| `context.py postprocess $B $VA --project $P` | Mechanically rename/annotate decompiler output (pipe) | `decompiler.py ... \| context.py postprocess ...` |
| `sigdb.py build $MANIFEST` | Build/extend signature DB from manifest (binary + `address,name[,size]` CSV): skips functions under 16 bytes, wildcards prefix bytes past a short function's end and E8/E9 rel32 operands (including one cut off at the end of the prefix), stores a FLIRT CRC16 up to the first call, outside branch or address operand (an immediate or displacement that lies inside the image; on x86 that includes indexed `[reg*s + abs32]` and `[reg + abs32]`). Byte and structural rows are written in one transaction, and building the same manifest again adds nothing. A row is one `(pattern, mask, crc_len, crc16)` key under one name, size, tail CRC, compiler label and source: every distinct row is kept, none is deleted, and a key held under more than one name is left to matching to refuse. A manifest entry whose binary is missing or does not load fails the build, as does a compiler label that starts with `msvc` and names no version | `sigdb.py build sources.json` |
| `sigdb.py import-pat $PAT -d $DB --compiler $C --source $S` | Add a FLIRT `.pat` file (e.g. rizin `sigdb-source`) to a DB: offset-0 names only, keeps each line's CRC16, wildcards prefix bytes past a short function's end, drops local labels (a name `?` or one marked `@`), functions under 16 bytes (measured to the next public of the module) and lines with a malformed hex byte or a CRC length outside 0..255. A prefix held under another name is kept beside it (counted as `ambiguous_prefix` when their compiler labels share a version) and matching refuses the key; importing the same file again under the same `--source` adds nothing. A `--compiler` label that starts with `msvc` and names no version is refused. The `.pat` file is checked before the DB is created | `sigdb.py import-pat VisualStudio2008.pat -d sigs.db --compiler msvc2008 --source rizin_vs2008` |
| `sigdb.py pull` | Download signature DB from HuggingFace (`--revision` picks an HF branch, tag or commit; default `main`). The download replaces the local DB only once it opens as a signature database this code reads; a refused download leaves the local DB as it was. A `-wal`/`-shm` left beside the local DB is set aside and deleted once the download is in place; if the DB or its log is held open, pull fails with `cannot replace` and the DB and its log are unchanged. A `--sources` manifest path that names no file inside the destination folder (it leaves the folder, names the folder itself, or has a part of only dots and spaces) is refused, as is a manifest that is not JSON or whose `sources` is not a list of paths | `sigdb.py pull`, `sigdb.py pull --sources` or `sigdb.py pull --revision schema-v2` |

> **Note:** `scan` and `identify` default to `retools/data/signatures.db` when `--db` is omitted. Run `sigdb.py pull` after first clone to download the database. `scan`, `identify` and `context assemble` open the DB read-only and refuse a file that lacks any of the four tables (`schema_version`, `byte_sigs`, `structural_sigs`, `compiler_fingerprints`), leaving it as it is; they read a schema-1 DB as it stands, and the first `build` or `import-pat` adds the CRC16 columns in place. `build` and `import-pat` create a schema only in a new or empty file, and refuse any other file that lacks one of the tables.
>
> **Matching rules:** a sig with a FLIRT CRC16 matches only when the bytes after its 32-byte prefix pass the CRC. Sigs whose compiler label names MSVC versions (`msvc2008`, `msvc6.0`, `msvc2003_2005`) are skipped on binaries whose Rich header has C or C++ compiler entries, none of them from those versions (linker, import-library, MASM and resource entries are not counted, and a header without a known compiler entry filters nothing); a label for 14.0 or later (`msvc14.0`, `msvc2019`) stands for every VS 2015+ toolset. A byte key or a structural shape the DB holds under more than one name, among the rows whose compiler label allows the binary, matches nothing. Neither do different keys that score equally under different names, a weaker sig never names a function whose best-scored key is held under several names, and a function left unnamed this way is not passed to the structural tier. A sig shorter than 32 bytes that pins nothing after its function's end matches only a function measured to end there: the first return, leaving jump, or call followed by `int3` that no earlier branch passes, or the size estimate for sigs built without map sizes; a stored size that also counts the `int3`/`nop` filler after that end still matches. `msvc7.10` names 7.1. A structural sig is stored with the version of the block and edge counting it was built by (`cfg.SHAPE_VERSION`, now 2) and matches only under that version; a row from before rows carried one counts as version 1, so it matches nothing, and `build` and `scan` print how many such rows the DB holds. They come back only by running `sigdb build` again on the binaries they were built from, which adds the current-shape rows beside them. `scan` drops a name that is the best match at more than one address.

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

**proxy.ini** settings: `CaptureFrames=N` (frames to record when the trigger file names no count; `trigger --frames` overrides it and takes 1 to 100000, the range both tracers keep to), `CaptureInit=1` (the standalone tracer writes one JSONL file from device creation to exit: `Create*` calls outside a capture are frame `-1`, every capture is appended, and frames and `seq` continue; with `0` each capture starts the file anew), `Chain.DLL=<wrapper.dll>` (chain to another d3d9 wrapper, or leave empty for system d3d9).

**IMPORTANT**: `--game-dir` must point to the directory containing the deployed proxy DLL (where the game runs). It defaults to the current directory.

The trigger file carries `frames=<N>` and `id=<token>`, and the tracer writes one line to `dxtrace_progress.txt`: `<frame> <calls> <id>`, with ` done` added at the end of a capture; `0 0 <id> failed <reason>` when it could not start, and `<frame> <calls> <id> failed <reason>` when a write to the capture file failed (the standalone tracer ends the capture at that write, the proxy's tracer at the end of that frame) (`-` stands for the id of a capture no trigger with an id started, such as one from the proxy's ImGui button). `trigger --wait` counts only lines that carry its own id. It follows the capture and exits 0 only after the tracer reports that capture `done`, which it writes once the captured frames are flushed to the JSONL file (with `CaptureInit=1` the standalone tracer keeps that file open afterwards and goes on appending `Create*` calls as frame `-1` until the game exits, so the file keeps growing and its last line may be half written; `analyze` skips such a line and reports the count on stderr); in every other case it prints an `[error]` line saying what it saw and exits 1:

- No tracer took the trigger within 120 s (game not running, the DLL is in another folder, or the tracer is still writing an earlier capture, during which it leaves a new trigger alone): the trigger file is removed again, so a later game start does not begin a capture.
- The capture stopped short of `--frames` (reported at once when the tracer says `done`, or after 120 s without new progress; a capture that keeps reporting progress is followed for as long as it takes).
- The tracer reached the last frame but never reported the file written in full: the `d3d9.dll` in the game folder predates the `done` report. Copy the current `graphics/directx/dx9/tracer/bin/d3d9.dll` there.
- The tracer could not create the capture file (a read-only game folder, a file another program holds open): the reason is printed, and is also in `dxtrace_proxy.log` or the proxy's log.
- The trigger was taken but no progress line carries its id (reported at once: the tracer writes its first line before it removes the trigger): the tracer could not write `dxtrace_progress.txt` (its log says so), or it predates progress lines that name their trigger, most likely an older `d3d9.dll` of the standalone tracer or a per-game remix-comp-proxy copy under `patches/` built from an older `tracer.cpp`. Port the template's tracer into that copy (`src/comp/modules/tracer.cpp`, `tracer.hpp`, `tracer_dispatch.inc`, the `TRACE_CREATION_IF_ACTIVE` calls in `d3d9ex.cpp` and `<atomic>` in `src/comp/std_include.hpp`) and rebuild, or look for the capture in its output folder (`[Tracer] OutputDir`).

A progress line left by another capture is ignored: it does not carry this trigger's id. `frames=` must be followed at once by the digits of a number from 1 up, and it and the 16-hex `id=` by nothing but blanks; any other count is answered with a `failed` line, and any other id is read as `-`. A trigger that cannot be deleted starts one capture in both tracers and is deleted at the first later Present that can delete it.

Standalone records: `seq` and `frame` are assigned when a call returns; calls made inside a recorded call get their own records, and a nested Present ends a frame. A call still in the driver when its capture ends, or one that spans two captures, is dropped (a `Create*` is kept as frame `-1` with `CaptureInit=1`). A game folder too long for the file names disables tracing, and `dxtrace_proxy.log` says so. Both tracers log a progress file they cannot write, once per capture.

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

**32-bit only.** Every script except `find_d3d_calls.py` reads PE32 code and exits with an error on a 64-bit binary, on a file that is not a PE, or on a path that cannot be read. `find_d3d_calls.py` also reads PE32+: there it matches `call [rip+rel32]` against the IAT slot and reports a REX-prefixed call at its `FF 15` opcode.

**How call arguments are reported.** A script reads the pushes and the `mov [esp+disp]` stores in front of each call and assigns them to the method's parameters by stack slot, so a pushed register counts as an argument; the latest write to a slot wins. A constant is decoded. A register or memory operand is shown in angle brackets (`<eax>`): the value is only known at run time. `<unknown>` means the code in front of the call does not settle the argument (an earlier call that is neither followed at once by `add esp, N` nor the Control Flow Guard check, a stack adjustment the walk cannot follow (a push or pop of less than a dword, or `enter`, among them), a store that is not a whole dword such as `fstp [esp]`, a jump target — including the call itself — where two code paths join, or a jump-table case that the code above it falls into); nothing is guessed. Sites whose arguments are not constants are left out of summaries such as register ranges, and the first 10 are listed under `<Method>: N call site(s) not decoded` with their arguments, then `... and N more` (`--all` lists every one), so follow them up with `livetools trace --probe` on the call site.

**Which calls are found.** `call [reg+offset]` in both its encodings, which covers every vtable slot. A `mov reg, [reg+offset]` load, in both its encodings, is listed as an indirect call only when a `call reg` through that register follows it, and the arguments are read at that call. Each later `call reg` through a register that calls preserve is a site of its own, listed at its call instruction with the load it calls through. Another call may run in between when the register is `ebx`, `esi`, `edi` or `ebp`, which calls preserve; with `eax`, `ecx` or `edx` the load is dropped there. *Control Flow Guard*: when the image's load configuration names a check pointer (`GuardCFCheckFunctionPointer`), the `call [__guard_check_icall_fptr]` that `/guard:cf` puts before an indirect call is passed: arguments pushed before it are read, and `eax`/`ecx`/`edx` count as overwritten by it. An image with no such field has no such call. A hit is then dropped when the code in front of it shows it is a call of another method. *COM `this`*: a site whose pushed `this` is an immediate or a different value than the object its vtable was read from, or that loads that object into `ecx` (the `__thiscall` form), is dropped; a site whose `this` the code does not settle is kept. *Argument count*: a hit is dropped when the walk back from its call reaches the start of the code (after a `ret`, a `jmp`, padding or the end of a jump table in the code section), or a `sub esp` reservation the code leaves partly unwritten, with fewer stack slots written than the method's parameters plus `this`. A block behind a `jmp` that is a case of a jump table starts with the stack its dispatch left, so such a hit is kept when the block pushes `this` and the code in front of every `jmp [table+reg*4]` that leads to it writes the missing slots (an argument pushed before a `switch` that picks another one); it stays dropped when that code shows less, when the table lies outside the code section, or when the arguments were pushed further back than the walk decodes. An earlier call is no such bound, because arguments pushed before an inner call are still on the stack (`push value; push state; call GetDevice; push eax; call [ecx+0xE4]`), so the hit is kept there, as it is at a jump target, a stack-pointer change the walk cannot follow or the start of the window it decodes; extra slots never drop it (an outer call's arguments precede an inner one's). *No `this`*: a call reached with nothing put on top of the stack since the call before it is dropped, since a COM call pushes `this` last. *Whole instruction*: a hit that lies inside another instruction is dropped, which is known when decodings that start more than 48 bytes back step over it and none lands on it, unless a decoding from a function start within those 48 bytes (a direct-call target, or a 16-byte-aligned address right after `CC`/`90` padding) lands on it. A hit inside a jump table of the code section, or the byte index table of its `movzx`/`jmp` dispatch, is dropped, and nothing in front of a table's end is decoded. When decodings step over a direct-call target within those 48 bytes, only the instructions the decoding from that target shares are used. Data no dispatch reads, followed at once by a function no direct call reaches, can still be decoded into a wrong argument. *Register argument*: a site that loads all of `ecx` with `mov` or `lea` (not the padding forms `mov ecx, ecx` and `lea ecx, [ecx+0]`) and reads it nowhere before the call is dropped: no call preserves `ecx`, so the load is an argument for a `__thiscall` callee. *Device provenance*: COM calls on other interfaces still pass both checks, and every class shares the slots below `vtable+0x80`. So the scripts learn where the game keeps its device from the hits at `vtable+0x80` and above: each hit's object is followed back from `mov vt, [obj]` through register copies (across calls for `ebx`/`esi`/`edi`/`ebp`) and loads to a global, `[0x009D915C]`, or a field of an object held in one, `[[0x009D915C]+0x1C]`; a location qualifies when hits on it call at least 12 different device methods there, a draw method among them, and at least half as many as the most-called location. A game's device is called through 25 or more of them; an `ID3DXEffect` (`SetFloatArray`/`SetVector`/`SetMatrix` sit at `+0x80`/`+0x88`/`+0x98`) or a large game class through fewer than ten. A hit below `vtable+0x80` is reported as a device call only when its object is read from a learned location; the others are counted as unconfirmed (`--unconfirmed` lists them in `find_device_calls.py` and `find_surface_formats.py`; `scan_d3d_region.py` labels them `unconfirmed` in place), and the header line names the learned location. A device the code reaches through a field of `this`, an argument or a stack local has no learnable location: the header says so and every low-slot hit stays unconfirmed. Hits at `vtable+0x80` and above are reported whatever their object.

| Script | What it surfaces | Example |
|--------|-----------------|---------|
| `find_d3d_calls.py $B` | D3D9/D3DX imports and call sites | `python rtx_remix_tools/dx/scripts/find_d3d_calls.py game.exe` |
| `find_vs_constants.py $B` | `SetVertexShaderConstantF` call sites with register/count args | `python rtx_remix_tools/dx/scripts/find_vs_constants.py game.exe` |
| `find_ps_constants.py $B` | `SetPixelShaderConstantF/I/B` call sites with register/count args | `python rtx_remix_tools/dx/scripts/find_ps_constants.py game.exe` |
| `find_device_calls.py $B` | Device vtable call patterns and device pointer refs; `--unconfirmed` lists low-slot hits not shown to be on the device | `python rtx_remix_tools/dx/scripts/find_device_calls.py game.exe` |
| `find_render_states.py $B` | SetRenderState arguments decoded by category (culling, blending, depth, fog); calls whose State is not a constant are listed as not decoded (first 10, `--all` lists every one) | `python rtx_remix_tools/dx/scripts/find_render_states.py game.exe` |
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
| `scan_d3d_region.py $B 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region, found with the same call checks as the other scripts. The region must lie in one section. A reference below `vtable+0x80` is labelled `unconfirmed` unless its object is read from the learned device location; a region holding such a reference costs one scan of the whole section to learn it (about 3 s on a 4 MB code section) | `python rtx_remix_tools/dx/scripts/scan_d3d_region.py game.exe 0x401000 0x500000` |

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

On x64 the exception table lists every function that has unwind information, with its extent, so an address inside such a function resolves to that function and an address in the gap behind one resolves to none. On x86, and for x64 leaf functions, only starts are known: targets of direct `CALL`s, exports, and `JMP` targets that sit behind padding, a return, another jump (including a `jmp [mem]` thunk) or at a section start (functions reached by tail calls). That misses functions only reachable via indirect calls (vtable dispatch, callbacks, function pointers): 27% of the functions of one x86 C++ DLL, measured against its linker map. For such an address the nearest known start before it is reported. `funcinfo.py` prints a `[warning]` line when the address you asked about is not inside the range it reports; treat that range as a different function. If `funcinfo.py` returns a clearly wrong function start, use `disasm.py` and look for padding/prologues manually.

An `int3` ends `funcinfo`'s scan for the function end only when it follows a `ret` or `jmp` (padding) or when no branch seen so far jumps past it to a label of the same function, so `je over; call noreturn; int3; over: ret` still finds the `ret`. A `jmp` to a function entry at or beyond the next known function that follows a function end is a tail call and does not carry the scan over an `int3`. In `cfg.py` an `int3` ends its block with no successor, so a `call noreturn; int3` does not run on into the next function. `cfg.py` treats `jecxz`/`jrcxz` and `loop`/`loope`/`loopne` as conditional branches.

### `datarefs.py` / `search.py strings --xrefs` -- addressing modes

These tools find references via absolute memory operands, immediate values (with `--imm` flag), and RIP-relative addressing. If you suspect a reference exists but the tool doesn't find it, the address might be computed at runtime. Try `search.py pattern` with the address bytes directly, or use `livetools memwatch`.

### `pyghidra_backend.py` -- Ghidra primary, r2ghidra fallback

Ghidra (via `pyghidra_backend.py`, indexed into `index.db`, daemon-backed, kb-applied) is the **primary** decompilation backend once a project exists — it gives better type propagation, library call resolution, and lets `retools.query` answer structural questions without re-scanning the binary. r2ghidra (`decompiler.py --backend pdg`) is the **zero-setup fallback and second opinion**: no Ghidra install required, faster on small functions, and useful to cross-check a pyghidra result that looks wrong. `decompiler.py --backend auto` tries pyghidra first and falls back to r2ghidra automatically — this routing is unchanged.

Requires Ghidra 11.x+ and JDK 21+. `python verify_install.py --setup` downloads both into `tools/`, where retools finds them on its own; set `GHIDRA_INSTALL_DIR` only to use a Ghidra installed somewhere else. The JDK is the first of `JAVA_HOME`, `java` on PATH and `tools/jdk-*` (highest version first) that is version 21 or newer, so an older Java on PATH is passed over; a `JAVA_HOME_OVERRIDE` you set yourself is kept, pyghidra starts it whatever its version, and `verify_install.py` checks that one in place of the others. **Optional** -- the toolkit works without it (r2ghidra remains the fallback).

**Disk usage**: Ghidra projects are ~10-20x the binary size. A 30MB game exe produces a ~300-600MB `.rep/` directory under `patches/<project>/ghidra/`. This directory is already covered by `.gitignore` (the `patches/` exclusion).

**First-time analysis** takes 5-15 minutes depending on binary size. Subsequent decompilation from the saved project is near-instant (<1s plus ~3s JVM startup per cold process) -- or truly sub-second when a `ghidra_server.py` daemon is warm for that project. `export` and `kb-apply` route through the same live daemon when one is running; `RETOOLS_GHIDRA_COLD=1` or `--cold` forces a cold in-process run for either.

**Index-first**: after `export`, prefer `retools.query` over datarefs/xrefs/search/funcinfo for anything already captured in `index.db` (funcs, names, xrefs, strings, imports, blocks) -- it's a local SQL query instead of a fresh binary scan. Fall back to the scanners only for facts index.db doesn't have yet.

### `livetools` -- static vs runtime addresses

**x86 games without ASLR** (most 32-bit games): the PE preferred base matches the runtime load address. Addresses from `retools` can be passed directly to `livetools`.

**DLLs and ASLR-enabled executables**: runtime base may differ. Run `python -m livetools modules --filter <name>` and compare against the PE's preferred base. If they differ: `runtime_addr = runtime_base + (static_addr - preferred_base)`.

**A function hook goes on a function entry; a call site takes `--probe`.** `livetools trace` and `collect` trap the function's return through the top stack slot, which is a return address only at a function entry, so they refuse a `call [reg+offset]` instruction (there the slot is the first stack argument, the device pointer). To watch one call site, add `--probe`: it records the registers and `--read` data at that instruction and has no caller or return value (`[esp]` is `this` at an x86 call instruction). The probed call runs from memory Frida frees with the probe, so remove a probe on a call that blocks only once that call has returned. To watch every caller of a D3D9/API method, hook the entry of the method the game calls (read it from the object's vtable at runtime with `livetools mem read`) and use each record's `caller` (the return address) to tell call sites apart. A breakpoint (`livetools bp`) is one `int3` byte and may sit on any instruction except the entry of a kernel32 function the breakpoint handler itself calls (`CreateEventW`, `SetEvent`, `CloseHandle`, `WaitForSingleObject`, `VirtualProtect`, `VirtualQuery`, `FlushInstructionCache`) or the address its stub jumps to, and memory Frida keeps to itself. A probe or a `collect --fence` hook is a jump of at least 5 bytes, and is refused where a `ret` or `jmp` ends the code before the jump fits, where a later branch targets the replaced bytes, or on a `jmp` that Frida follows to its target; the result names the bytes replaced, or says the number is unknown when the jump was never seen in place. Details: pattern 9 in the `/dynamic-analysis` skill.
