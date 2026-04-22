---
applyTo: "**"
---

# Tool Dispatch — Quick Reference

Run all tools from repo root via `python -m <module>`. **ALWAYS pass `--types patches/<project>/kb.h`** to `decompiler.py`.

## Run Directly (<5s)

- `sigdb fingerprint/identify` — compiler ID, single function lookup
- `context assemble/postprocess` — full context gathering, annotation
- `dataflow --constants/--slice` — forward propagation, backward trace
- `readmem` — typed PE read
- `asi_patcher build` — build step
- `pyghidra_backend status` — project check

## DX Scripts First (for D3D9 questions)

Run BEFORE retools. Under `rtx_remix_tools/dx/scripts/`:
`find_d3d_calls`, `find_vs_constants`, `find_ps_constants`, `find_device_calls`, `find_render_states`, `find_texture_ops`, `find_transforms`, `find_surface_formats`, `find_stateblocks`, `decode_fvf`, `decode_vtx_decls`, `find_shader_bytecode`, `classify_draws`, `find_matrix_registers`, `find_vtable_calls`, `find_skinning`, `find_blend_states`, `scan_d3d_region`

## Delegate to `static-analyzer`

Everything else: decompile, callgraph, xrefs, strings, datarefs, structrefs, RTTI, throwmap, dumpinfo, bootstrap, pyghidra analyze, bulk sigdb scan, dx9tracer analysis.

If you're about to run a second `retools` command, stop and delegate.

## Live Tools (main agent, attached process)

`attach`, `trace`, `collect`, `bp`, `watch`, `regs`, `stack`, `bt`, `mem read/write`, `scan`, `dipcnt`, `memwatch`, `modules`, `steptrace`
