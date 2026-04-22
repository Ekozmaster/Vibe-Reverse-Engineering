---
name: 'renderdoc-analysis'
description: 'RenderDoc GPU capture analysis. Use for .rdc files, draw call inspection, pipeline state, textures/shaders, mesh data, GPU counters.'
user-invocable: true
---

# RenderDoc Analysis

All commands: `python -m renderdoctools <command> [args]`. All support `--json` and `--output FILE`.

## Capturing

Launch a game with RenderDoc injection and capture — no GUI required:
```
python -m renderdoctools capture <exe>                    # launch + capture
python -m renderdoctools capture <exe> --output out.rdc   # specify output filename
python -m renderdoctools capture <exe> -- --arg1 --arg2   # pass args to the game
```

The game launches with RenderDoc hooked in. Press **F12** / **Print Screen** in-game to trigger the capture. The `.rdc` file is written to the working directory (or the `--output` path).

**Use this as the default capture method.** The agent can run this directly — no need to walk the user through the GUI.

D3D11/D3D12/Vulkan/OpenGL/DX9 supported. DX9 requires the custom RenderDoc build with D3D9 driver. Use `--opt-hook-children` for games with launchers, `--opt-ref-all-resources` if game crashes on inject.

## Commands

| Command | Purpose |
|---------|---------|
| `events <rdc> [--draws-only]` | List events/draw calls |
| `analyze <rdc> --summary` | Capture overview stats |
| `analyze <rdc> --biggest-draws N` | Top N draws by vertex count |
| `analyze <rdc> --render-targets` | Unique render targets |
| `pipeline <rdc> --event EID` | Pipeline state (optional `--stage pixel`) |
| `textures <rdc> --event EID [--save-all DIR]` | Bound textures, export |
| `shaders <rdc> --event EID [--cbuffers]` | Shader disassembly + constants |
| `mesh <rdc> --event EID [--post-vs]` | Vertex data |
| `descriptors <rdc> --event EID [--type srv]` | Descriptor bindings |
| `api-calls <rdc> [--event EID] [--filter NAME]` | API call params |
| `counters <rdc> [--zero-samples]` | GPU counters, find wasted draws |
| `pixel-history <rdc> --event EID --resource RID --x X --y Y` | What drew to pixel? |
| `pick-pixel <rdc> --resource RID --x X --y Y` | Read pixel value |
| `usage <rdc> --resource RID [--filter read\|write]` | Resource usage across events |
| `debug-shader <rdc> --event EID --mode vertex\|pixel --vertex-index N` | Debug shader execution |
| `messages <rdc> [--severity high]` | API debug/validation messages |
| `tex-stats <rdc> --resource RID [--histogram]` | Min/max RGBA, value distribution |
| `tex-data <rdc> --resource RID [--output-file F]` | Raw texture bytes |
| `frame-info <rdc>` | Frame stats: draws, dispatches, binds |
| `custom-shader <rdc> --event EID --source F --output F` | Apply custom viz shader |
| `capture <exe> [--output FILE] [-- EXE_ARGS]` | Launch game with RenderDoc injection, capture on F12 |
| `open <rdc>` | Launch RenderDoc GUI |

## Finding the Right Draw Call

1. **Render targets**: `analyze --render-targets` → dump RTs → `usage --resource <RID> --filter write` → narrow by EID
2. **Binary search**: `events --draws-only`, pick midpoint, dump RT, converge
3. **By name**: `events --filter "shadow"` (if engine uses debug markers)
4. **By size**: `analyze --biggest-draws 20`

## Verification

Always confirm you're looking at the right thing:
- Dump and visually check RTs: `textures --event <EID> --save-all ./verify`
- Spot-check pixels: `pick-pixel --resource <RID> --x 100 --y 100`
- Compare before/after EIDs

## Multi-Pass Reconstruction

1. `analyze --render-targets` — list all RTs
2. Per RT: `usage --resource <RID>` — writes = pass boundaries, reads = consumers
3. Dump textures at key EIDs to label passes (shadow, GBuffer, lighting, post)

## Interpreting Shader Debug Output

`debug-shader` produces inputs, constant blocks, per-step variable changes. Look for:
- **NaN/Inf**: division by zero or bad input — trace the step
- **Unexpected zeros**: wrong binding or uninitialized resource
- **Bad transforms**: check `finalState` output position + constant blocks
- **Shader discards**: `shaderDiscarded: true` in pixel history — debug the discard condition

## When Data Looks Wrong

1. **Correct EID?** All queries reflect state at the queried EID
2. **Correct resource?** Resource IDs are per-capture — re-discover with `textures`
3. **Correct format?** `pick-pixel` with wrong `--comp-type` reads garbage
4. **Initialized?** All zeros = not yet written. `usage --filter write` finds first write
5. **Mip/slice?** Querying mip 0 of a texture only written at mip 1+ returns stale data

## Workflow Recipes

**Quick overview**: `analyze --summary` > `events --draws-only` > `analyze --biggest-draws 10`

**Investigate draw**: `pipeline --event EID` > `textures --event EID --save-all ./dump` > `shaders --event EID --cbuffers`

**Full frame audit**: `analyze --render-targets` > `messages --severity high` > `counters --zero-samples`

## When to Use GUI

`python -m renderdoctools open <rdc>` — better for texture scrubbing, 3D mesh viewer, shader debugger with source, overlay modes (wireframe, depth, overdraw).
