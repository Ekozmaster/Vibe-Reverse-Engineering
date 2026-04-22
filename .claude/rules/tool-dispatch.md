---
description: Quick decision guide — which RE tool to use and whether to run it directly or delegate
---

# Tool Dispatch

**BEFORE FIRST USE**: Run `python verify_install.py` from repo root. If pyghidra/Ghidra shows WARN, run `python verify_install.py --setup`.

Run all tools from repo root via `python -m <module>`. **ALWAYS pass `--types patches/<project>/kb.h`** to `decompiler.py`. For full syntax tables and caveats, read `.claude/references/tool-catalog.md`.

## Run Directly (main agent, <5s)

- `python -m retools.sigdb fingerprint $B` — compiler ID
- `python -m retools.sigdb identify $B $VA` — single function signature lookup
- `python -m retools.context assemble $B $VA --project $P` — full analysis context
- pipe through `python -m retools.context postprocess` — rename/annotate decompiler output
- `python -m retools.readmem $B $VA $TYPE` — read typed PE data
- `python -m retools.dataflow $B $VA --constants` — forward constant propagation
- `python -m retools.dataflow $B $VA --slice TARGET_VA:REG` — backward register slice
- `python -m retools.asi_patcher build spec.json` — build ASI patch DLL

## Delegate to `static-analyzer`

Everything else in `retools`. Tell it WHAT you need, not HOW. D3D9-specific questions — try DX scripts first (faster).

- Decompile / callgraph / xrefs / string search / datarefs / structrefs / RTTI / throwmap / dumpinfo
- Bootstrap new binary (2-5 min) / pyghidra analyze (5-15 min) / bulk sigdb scan (1-3 min)
- dx9tracer offline analysis (summary, render-passes, shader-map, etc.)

## Live tools (main agent, attached process)

- `livetools attach <name_or_pid>` — attach to running process
- `livetools attach <path> --spawn` — launch exe suspended, instrument, resume (catches init code)
- `livetools trace` / `collect` — hit logging, register reads
- `livetools bp` / `watch` / `regs` / `stack` / `bt` — breakpoints + inspection
- `livetools mem read/write` / `scan` — memory ops
- `livetools dipcnt` / `memwatch` — D3D9 counters, write watchpoints
- `livetools modules` — loaded module list

## DX analysis scripts (main agent, fast first-pass)

Under `rtx_remix_tools/dx/scripts/`. Use BEFORE retools for D3D9 questions. Run as `python rtx_remix_tools/dx/scripts/<script> <args>`.

- `find_d3d_calls.py $B` — D3D9/D3DX imports + call sites
- `find_vs_constants.py $B` — SetVertexShaderConstantF sites with register/count
- `find_ps_constants.py $B` — SetPixelShaderConstantF/I/B sites with register/count
- `find_device_calls.py $B` — device vtable call patterns
- `find_vtable_calls.py $B` — D3DX CTAB + D3D9 vtable calls
- `find_render_states.py $B` — SetRenderState arguments with enum decoding
- `find_texture_ops.py $B` — texture pipeline: stages, TSS ops, sampler states
- `find_transforms.py $B` — SetTransform types (World, View, Projection, Texture)
- `find_surface_formats.py $B` — CreateTexture/RT/DS format extraction
- `find_stateblocks.py $B` — state block creation/recording/apply patterns
- `decode_fvf.py $B` — FVF bitfield decode from SetFVF calls
- `decode_vtx_decls.py $B --scan` — vertex declaration formats
- `find_shader_bytecode.py $B` — embedded shader bytecode extraction
- `classify_draws.py $B` — draw call classification (FFP/shader/hybrid)
- `find_matrix_registers.py $B` — identify View/Proj/World matrix registers (CTAB + frequency)
- `find_skinning.py $B` — consolidated skinning analysis (decls, bone palettes, blend states, INI suggestion)
- `find_blend_states.py $B` — D3DRS_VERTEXBLEND / INDEXEDVERTEXBLENDENABLE + WORLDMATRIX transforms
- `scan_d3d_region.py $B 0xSTART 0xEND` — D3D calls in code region

## RenderDoc capture analysis (main agent)

- `python -m renderdoctools events <rdc>` — list events/draw calls
- `python -m renderdoctools analyze <rdc> --summary` — capture overview
- `python -m renderdoctools pipeline <rdc> --event EID` — pipeline state
- `python -m renderdoctools textures <rdc> --event EID` — bound textures
- `python -m renderdoctools shaders <rdc> --event EID` — shader disassembly
- `python -m renderdoctools mesh <rdc> --event EID` — vertex data
- `python -m renderdoctools counters <rdc>` — GPU counters
- `python -m renderdoctools open <rdc>` — launch RenderDoc GUI

## dx9tracer

- Capture (main agent): `python -m graphics.directx.dx9.tracer trigger --game-dir <DIR>`
- Analysis (delegate): `python -m graphics.directx.dx9.tracer analyze <JSONL> [OPTIONS]`
