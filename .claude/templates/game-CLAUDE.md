# <GameName> — Game-Specific Context

## Binary
- **Executable:** `<game.exe>`
- **Version:** 
- **Compiler:** 
- **Engine:** 

## Analysis State
- **Bootstrap:** [ ] pending / [x] complete
- **Ghidra:** [ ] pending / [x] complete (`patches/<GameName>/ghidra/<stem>.gpr`)
- **DX9 Tracer capture:** [ ] pending / [x] complete (`patches/<GameName>/traces/`)

## VS Constant Register Layout
<!-- Fill in after running find_matrix_registers.py or /apply-trace-findings -->
| Matrix | Start | End | Source | Confidence |
|--------|-------|-----|--------|------------|
| View   |       |     |        |            |
| Projection |   |     |        |            |
| World  |       |     |        |            |
| Bone base |    |     |        |            |

**Concatenated WVP?** [ ] Yes — hook site at `0x` / [ ] No — separate matrices

## Vertex Declaration Notes
<!-- What vertex formats does the game use? NORMAL present? Skinning? -->

## Draw Routing Notes
<!-- Any non-standard routing needed in renderer.cpp? -->

## Known Quirks
<!-- Game-specific pitfalls discovered during porting -->

## Confirmed Addresses
<!-- Key addresses. Full list in patches/<GameName>/addresses.json -->
| Label | Address | Notes |
|-------|---------|-------|

## Build & Deploy
```bat
cd patches/<GameName>
build.bat release --name <GameName>
```
Deploy: copy `build/bin/release/d3d9.dll` + `remix-comp-proxy.ini` to game dir.
