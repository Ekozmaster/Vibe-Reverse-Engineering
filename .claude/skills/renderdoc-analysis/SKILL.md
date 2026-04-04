---
name: renderdoc-analysis
description: RenderDoc-based GPU capture analysis toolkit for reverse engineering. Use when loading .rdc capture files, inspecting draw calls, examining pipeline state, viewing textures/shaders, decoding mesh data, analyzing GPU counters, or performing any graphics debugging task on a captured frame.
---

# RenderDoc Analysis with renderdoctools

Programmatic GPU capture analysis. Analyze .rdc files headlessly or launch the RenderDoc GUI for manual inspection.

All commands: `python -m renderdoctools <command> [args]`
All commands support `--json` for raw JSON and `--output FILE`.

## Quick Reference

| Command | Description |
|---------|-------------|
| `events <rdc>` | List all events/draw calls |
| `events <rdc> --draws-only` | Draw calls only |
| `pipeline <rdc> --event EID` | Pipeline state at event |
| `pipeline <rdc> --event EID --stage pixel` | Single stage |
| `textures <rdc> --event EID` | List bound textures |
| `textures <rdc> --event EID --save-all DIR` | Export all textures |
| `shaders <rdc> --event EID` | Disassemble bound shaders |
| `shaders <rdc> --event EID --cbuffers` | Include constant buffer values |
| `mesh <rdc> --event EID` | Vertex input data |
| `mesh <rdc> --event EID --post-vs` | Post-VS output |
| `descriptors <rdc> --event EID` | All descriptors accessed at event |
| `descriptors <rdc> --event EID --type srv` | Filter: sampler/cbuffer/srv/uav |
| `api-calls <rdc>` | List all API calls with inline params |
| `api-calls <rdc> --event EID` | Detailed params for one event |
| `api-calls <rdc> --filter "Map"` | Filter calls by function name |
| `api-calls <rdc> --range 100 200` | Calls in event ID range |
| `counters <rdc>` | List GPU counters |
| `counters <rdc> --zero-samples` | Find wasted draws |
| `analyze <rdc> --summary` | Capture overview stats |
| `analyze <rdc> --biggest-draws 10` | Top N draws by vertex count |
| `analyze <rdc> --render-targets` | Unique render targets |
| `pixel-history <rdc> --event EID --resource RID --x X --y Y` | What drew to this pixel? |
| `pixel-history <rdc> --event EID --resource RID --x X --y Y --json` | Full pixel history as JSON |
| `pick-pixel <rdc> --resource RID --x X --y Y` | Read pixel value at (x,y) |
| `pick-pixel <rdc> --resource RID --x X --y Y --comp-type float` | Pick with type override |
| `messages <rdc>` | All API debug/validation messages |
| `messages <rdc> --severity high` | Only high+ severity messages |
| `messages <rdc> --severity medium` | Medium+ severity messages |
| `tex-stats <rdc> --resource RID` | Min/max RGBA values of a texture |
| `tex-stats <rdc> --resource RID --histogram` | Min/max + value distribution histogram |
| `tex-stats <rdc> --resource RID --histogram --hist-min 0 --hist-max 10` | HDR range histogram |
| `custom-shader <rdc> --event EID --source FILE --output FILE` | Apply custom viz shader and save result |
| `custom-shader <rdc> --event EID --source FILE --output FILE --encoding hlsl` | Explicit encoding (hlsl/glsl/spirv/dxbc/dxil) |
| `custom-shader <rdc> --event EID --source FILE --output FILE --entry-point ps_main` | Custom entry point |
| `tex-data <rdc> --resource RID` | Raw bytes + hex preview of a texture |
| `tex-data <rdc> --resource RID --output-file out.bin` | Save raw texture bytes to file |
| `tex-data <rdc> --resource RID --sub-mip 1` | Specific mip/slice/sample subresource |
| `usage <rdc> --resource RID` | Which events read/write this resource? |
| `usage <rdc> --resource RID --filter read` | Only read usages (SRV, VB, IB, constants) |
| `usage <rdc> --resource RID --filter write` | Only write usages (RT, DS, UAV, copy dest) |
| `frame-info <rdc>` | Detailed frame stats: draws, dispatches, binds, state changes, per-stage shader changes |
| `debug-shader <rdc> --event EID --mode vertex --vertex-index N` | Debug vertex shader invocation |
| `debug-shader <rdc> --event EID --mode pixel --x X --y Y` | Debug pixel shader at screen coord |
| `debug-shader <rdc> --event EID --mode pixel --x X --y Y --primitive P` | Debug specific primitive's pixel shader |
| `debug-shader <rdc> --event EID --mode compute --group 0,0,0 --thread 0,0,0` | Debug compute thread |
| `open <rdc>` | Launch RenderDoc GUI |
| `capture <exe>` | Capture via renderdoccmd |

## Workflow Recipes

### Quick capture overview
```
python -m renderdoctools analyze capture.rdc --summary
python -m renderdoctools events capture.rdc --draws-only
python -m renderdoctools analyze capture.rdc --biggest-draws 10
```

### Investigate a specific draw call
```
python -m renderdoctools events capture.rdc --filter "Draw"
python -m renderdoctools pipeline capture.rdc --event <EID>
python -m renderdoctools textures capture.rdc --event <EID>
python -m renderdoctools shaders capture.rdc --event <EID> --cbuffers
```

### Export textures for inspection
```
python -m renderdoctools textures capture.rdc --event <EID> --save-all ./dump
```

### Read a specific pixel value
```
python -m renderdoctools textures capture.rdc --event <EID>
python -m renderdoctools pick-pixel capture.rdc --resource <RID> --x 512 --y 384
python -m renderdoctools pick-pixel capture.rdc --resource <RID> --x 0 --y 0 --sub-mip 1 --comp-type float --json
```

### Pixel history -- what drew to this pixel?
```
python -m renderdoctools analyze capture.rdc --render-targets
python -m renderdoctools pixel-history capture.rdc --event <EID> --resource <RID> --x 512 --y 384
python -m renderdoctools pixel-history capture.rdc --event <EID> --resource <RID> --x 512 --y 384 --json
```

### Audit descriptor bindings at a draw
```
python -m renderdoctools descriptors capture.rdc --event <EID>
python -m renderdoctools descriptors capture.rdc --event <EID> --type srv
python -m renderdoctools descriptors capture.rdc --event <EID> --type cbuffer --json
```

### Check for API errors and warnings
```
python -m renderdoctools messages capture.rdc
python -m renderdoctools messages capture.rdc --severity high
python -m renderdoctools messages capture.rdc --severity medium --json
```

### Analyze texture value ranges (HDR debugging)
```
python -m renderdoctools textures capture.rdc --event <EID>
python -m renderdoctools tex-stats capture.rdc --resource <RID>
python -m renderdoctools tex-stats capture.rdc --resource <RID> --histogram --hist-min 0.0 --hist-max 10.0 --json
```

### Apply a custom visualization shader
```
python -m renderdoctools custom-shader capture.rdc --event <EID> --source depth_only.hlsl --output depth.png
python -m renderdoctools custom-shader capture.rdc --event <EID> --source normals.hlsl --output normals.png --encoding hlsl
python -m renderdoctools custom-shader capture.rdc --event <EID> --source channel_r.glsl --output red_channel.hdr --encoding glsl
```

### Trace the exact API call sequence
```
python -m renderdoctools api-calls capture.rdc
python -m renderdoctools api-calls capture.rdc --filter "Draw"
python -m renderdoctools api-calls capture.rdc --range 100 200
python -m renderdoctools api-calls capture.rdc --event <EID>
python -m renderdoctools api-calls capture.rdc --event <EID> --json
```

### Extract raw texture data for programmatic analysis
```
python -m renderdoctools textures capture.rdc --event <EID>
python -m renderdoctools tex-data capture.rdc --resource <RID>
python -m renderdoctools tex-data capture.rdc --resource <RID> --output-file rt_dump.bin
python -m renderdoctools tex-data capture.rdc --resource <RID> --sub-mip 2 --json
```

### Track resource dependencies between passes
```
python -m renderdoctools analyze capture.rdc --render-targets
python -m renderdoctools usage capture.rdc --resource <RID>
python -m renderdoctools usage capture.rdc --resource <RID> --filter write
python -m renderdoctools usage capture.rdc --resource <RID> --filter read --json
```

### Debug a shader step-by-step
```
python -m renderdoctools pipeline capture.rdc --event <EID>
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode vertex --vertex-index 0
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode pixel --x 512 --y 384
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode pixel --x 512 --y 384 --primitive 0 --json
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode compute --group 0,0,0 --thread 0,0,0
```

### Find overdraw / wasted draws
```
python -m renderdoctools counters capture.rdc --zero-samples
```

### Full frame audit
```
python -m renderdoctools analyze capture.rdc --summary
python -m renderdoctools analyze capture.rdc --render-targets
python -m renderdoctools analyze capture.rdc --biggest-draws 20
```

## Thinking Patterns

1. **Start broad, narrow down.** `analyze --summary` first, then `events --draws-only` to find the region, then `pipeline`/`shaders`/`textures` on the specific draw.

2. **Export to verify.** When unsure what a render target contains, `textures --save-all` and look at the images.

3. **Cross-reference with livetools.** Match draw call patterns here with function traces from dynamic analysis to map game code to GPU operations.

4. **Use counters for performance.** `--zero-samples` quickly finds draws that produce no visible pixels.

5. **Track dependencies with usage.** Use `usage --resource` to see every event that touches a resource. Filter by `--filter write` to find producers and `--filter read` to find consumers -- essential for mapping render pass dependencies.

6. **Debug shaders to understand transforms.** Use `debug-shader` to step through vertex/pixel/compute shaders and inspect intermediate values. Combine with `shaders --cbuffers` to see constant buffer inputs, then trace how they flow through the shader.

7. **JSON for programmatic use.** Pipe `--json` output for cross-command analysis or custom scripts.
