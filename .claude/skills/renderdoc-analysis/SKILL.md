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
| `counters <rdc>` | List GPU counters |
| `counters <rdc> --zero-samples` | Find wasted draws |
| `analyze <rdc> --summary` | Capture overview stats |
| `analyze <rdc> --biggest-draws 10` | Top N draws by vertex count |
| `analyze <rdc> --render-targets` | Unique render targets |
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

5. **JSON for programmatic use.** Pipe `--json` output for cross-command analysis or custom scripts.
