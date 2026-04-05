---
name: renderdoc-analysis
description: RenderDoc-based GPU capture analysis toolkit for reverse engineering. Use when loading .rdc capture files, inspecting draw calls, examining pipeline state, viewing textures/shaders, decoding mesh data, analyzing GPU counters, or performing any graphics debugging task on a captured frame.
---

# RenderDoc Analysis with renderdoctools

Programmatic GPU capture analysis. Analyze .rdc files headlessly or launch the RenderDoc GUI for manual inspection.

All commands: `python -m renderdoctools <command> [args]`
All commands support `--json` for raw JSON and `--output FILE`.

## Capturing

A capture (`.rdc`) is a snapshot of one frame's entire GPU command stream: every draw call, state change, resource binding, and buffer/texture content at that point in time.

### How to capture
```
python -m renderdoctools capture <exe>           # launch + capture via renderdoccmd
python -m renderdoctools open <rdc>              # open existing capture in GUI
```

**Via GUI:** RenderDoc > File > Launch Application. Set executable + working dir. Hit Launch, press F12 (or Print Screen) in-game to trigger capture.

**Via renderdoccmd:** `renderdoccmd capture --opt-hook-children <exe>`. Output `.rdc` written to working directory.

### Capture tips
- Navigate to the exact game state first, then capture. The captured frame is whatever's rendering at trigger time.
- For games with launchers, use `--opt-hook-children` to capture the child game process.
- D3D11/D3D12/Vulkan/OpenGL supported. DX9 is NOT supported.
- If the game crashes on inject, try `--opt-ref-all-resources` (slower but more compatible).
- Capture files can be 100MB-1GB+. Each contains full texture/buffer data for that frame.

### When to guide the user to capture
If no `.rdc` exists, walk through: (1) what game state to be in, (2) launch method (GUI attach vs CLI), (3) how to trigger (F12), (4) where the `.rdc` file ends up.

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
| `pick-pixel <rdc> --resource RID --x X --y Y` | Read pixel value at (x,y) |
| `pick-pixel <rdc> --resource RID --x X --y Y --comp-type float` | Pick with type override |
| `messages <rdc>` | All API debug/validation messages |
| `messages <rdc> --severity high` | Only high+ severity messages |
| `tex-stats <rdc> --resource RID` | Min/max RGBA values of a texture |
| `tex-stats <rdc> --resource RID --histogram` | Value distribution histogram |
| `custom-shader <rdc> --event EID --source FILE --output FILE` | Apply custom viz shader |
| `tex-data <rdc> --resource RID` | Raw bytes + hex preview |
| `tex-data <rdc> --resource RID --output-file out.bin` | Save raw texture bytes |
| `usage <rdc> --resource RID` | Which events read/write a resource? |
| `usage <rdc> --resource RID --filter read` | Only read usages |
| `usage <rdc> --resource RID --filter write` | Only write usages |
| `frame-info <rdc>` | Frame stats: draws, dispatches, binds, state changes |
| `debug-shader <rdc> --event EID --mode vertex --vertex-index N` | Debug vertex shader |
| `debug-shader <rdc> --event EID --mode pixel --x X --y Y` | Debug pixel shader |
| `debug-shader <rdc> --event EID --mode compute --group 0,0,0 --thread 0,0,0` | Debug compute |
| `open <rdc>` | Launch RenderDoc GUI |
| `capture <exe>` | Capture via renderdoccmd |

## Verification: Confirm Before You Dig

Always verify you're looking at the right thing before deep analysis.

**Dump and check render targets:**
```
python -m renderdoctools textures capture.rdc --event <EID> --save-all ./verify
```
Open the images. Confirm the render target matches expected game output. If it's a depth buffer, GBuffer, or intermediate pass you don't recognize — wrong draw.

**Spot-check pixel values:**
```
python -m renderdoctools pick-pixel capture.rdc --resource <RID> --x 100 --y 100
```
Normal map: expect RGB near (0.5, 0.5, 1.0). HDR color: expect values > 1.0. All zeros: resource uninitialized or cleared at that EID.

**Compare before/after:** Dump textures at two EIDs to confirm a draw changes what you expect.

## Finding the Right Draw Call

Core RE question: "which draw call renders X?"

### Strategy 1: Work backwards from render targets
```
python -m renderdoctools analyze capture.rdc --render-targets
```
Dump the most-written RTs, visually identify which contains your target, then:
```
python -m renderdoctools usage capture.rdc --resource <RT_RID> --filter write
```
Lists every draw writing to it. Narrow by EID range.

### Strategy 2: Binary search by EID
`events --draws-only`, pick midpoint EID, dump its RTs. Content there? Search earlier. Not there? Search later. Converge on the exact draw.

### Strategy 3: Filter by name
Many engines annotate draws with debug markers:
```
python -m renderdoctools events capture.rdc --filter "shadow"
python -m renderdoctools events capture.rdc --filter "GBuffer"
```

### Strategy 4: Filter by geometry size
```
python -m renderdoctools analyze capture.rdc --biggest-draws 20
```

## Multi-Pass Analysis

Reconstruct a render pipeline — who writes what, who reads it:

1. `analyze --render-targets` — list all unique RTs
2. For each RT: `usage --resource <RID>` — all reads and writes
3. Write events = pass boundaries. Reads between writes = consumers of that pass.
4. Dump textures at key EIDs to label each pass (shadow, GBuffer, lighting, post, final)

RT written at EID 100, 300, 500. Read at EID 200, 400. Means: Pass A (100) produces, Pass B (200) consumes, Pass C (300) overwrites, etc.

## Interpreting Shader Debug Output

`debug-shader` produces: inputs, constant blocks, per-step variable changes, source locations.

**What to look for:**
- **NaN/Inf:** float values becoming NaN mid-shader = division by zero or bad input. Trace the step that introduced it.
- **Unexpected zeros:** input that should be nonzero reads as 0 = wrong binding or uninitialized resource.
- **Matrix transforms:** check `finalState` output position in vertex shaders. Offscreen or degenerate = bad matrices in constant blocks.
- **Shader discards:** `shaderDiscarded: true` in pixel history. Debug the pixel shader to find the discard condition.

**Combine with cbuffer inspection:**
```
python -m renderdoctools shaders capture.rdc --event <EID> --cbuffers
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode pixel --x X --y Y
```

## When Data Looks Wrong

Checklist:

1. **Correct EID?** All pipeline/texture/resource queries reflect state at the queried EID. Wrong EID = wrong data.
2. **Correct resource?** Resource IDs are per-capture. Re-discover with `textures` or `analyze --render-targets`.
3. **Correct format?** `pick-pixel` with wrong `--comp-type` reads garbage. Check `textures` output for actual format.
4. **Initialized?** All zeros = resource not yet written at that EID. `usage --resource <RID> --filter write` finds the first write.
5. **Mip/slice?** Querying mip 0 of a texture only written at mip 1+ returns stale data. Use `--sub-mip`.

## Falling Back to the GUI

When programmatic analysis can't get you there:

```
python -m renderdoctools open capture.rdc
```

**GUI strengths over CLI:**
- **Texture viewer scrubbing:** step through events watching render targets update live. Fastest way to find "which draw renders X."
- **Mesh viewer:** 3D vertex visualization with rotation/zoom. Essential for understanding vertex transforms.
- **Shader debugger with source:** step through HLSL/GLSL with variable watch, breakpoints, source highlighting. Far richer than JSON trace.
- **Overlay modes:** wireframe, depth, stencil, overdraw heat map.
- **Resource inspector:** browse all textures/buffers with format decoding, mip/slice selection.

**Workflow:** Open in GUI, visually locate the draw/resource, note the EID and resource ID, return to CLI for scripted/batch operations.

## Workflow Recipes

### Quick capture overview
```
python -m renderdoctools analyze capture.rdc --summary
python -m renderdoctools events capture.rdc --draws-only
python -m renderdoctools analyze capture.rdc --biggest-draws 10
```

### Investigate a specific draw
```
python -m renderdoctools pipeline capture.rdc --event <EID>
python -m renderdoctools textures capture.rdc --event <EID> --save-all ./dump
python -m renderdoctools shaders capture.rdc --event <EID> --cbuffers
```

### Shader debugging
```
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode vertex --vertex-index 0
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode pixel --x 512 --y 384
python -m renderdoctools debug-shader capture.rdc --event <EID> --mode compute --group 0,0,0 --thread 0,0,0
```

### Resource tracking
```
python -m renderdoctools usage capture.rdc --resource <RID>
python -m renderdoctools usage capture.rdc --resource <RID> --filter write
```

### Full frame audit
```
python -m renderdoctools analyze capture.rdc --summary
python -m renderdoctools analyze capture.rdc --render-targets
python -m renderdoctools messages capture.rdc --severity high
python -m renderdoctools counters capture.rdc --zero-samples
```

## Thinking Patterns

1. **Broad to narrow.** `analyze --summary` > `events --draws-only` > `pipeline`/`shaders`/`textures` on the target draw.
2. **Verify with texture dumps.** Dump render targets and visually confirm before deep analysis.
3. **Cross-reference with livetools.** Match draw call patterns with function traces from dynamic analysis.
4. **Track dependencies with usage.** `--filter write` = producers. `--filter read` = consumers.
5. **Debug shaders for transforms.** `debug-shader` + `shaders --cbuffers` traces inputs through shader code.
6. **GUI when stuck.** Scrub through events in the texture viewer to visually identify draws.
7. **JSON for automation.** `--json` on any command for scripted pipelines.
