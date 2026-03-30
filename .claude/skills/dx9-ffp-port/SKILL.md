---
name: dx9-ffp-port
description: DX9 shader-to-FFP proxy porting for RTX Remix compatibility. Use when porting a DX9 shader-based game to the fixed-function pipeline so RTX Remix can inject path-traced lighting. Covers the full workflow: static analysis with scripts, discovering VS constant register layout, dynamic live tracing of SetVertexShaderConstantF, editing remix-comp.ini with register mappings, customizing draw routing in renderer.cpp, building with Premake5/VS2022, deploying and iterating with ffp_proxy.log and ImGui (F4). Includes draw call routing logic, common pitfalls, and skinning guidance.
---

# DX9 FFP Proxy -- Game Porting

Port a DX9 shader-based game to fixed-function pipeline (FFP) for RTX Remix compatibility. Remix requires FFP geometry to inject path-traced lighting and replaceable assets.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning in `remix-comp.ini`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. When requested, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp` for the full implementation.

---

## What remix-comp Does

The codebase (`rtx_remix_tools/dx/remix-comp/`) is a dinput8.dll ASI proxy that:

1. Captures VS constants (View, Projection, World matrices) from `SetVertexShaderConstantF` via `ffp_state::on_set_vs_const_f`
2. Parses `SetVertexDeclaration` via `ffp_state::on_set_vertex_declaration` to detect BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL presence, and per-element byte offsets
3. Routes `DrawIndexedPrimitive` via `renderer::on_draw_indexed_prim`:
   - No NORMAL -> HUD/UI pass-through
   - Skinned + skinning module enabled -> `skinning::draw_skinned_dip()`
   - Rigid 3D (has NORMAL) -> NULLs shaders, applies FFP transforms
4. Routes `DrawPrimitive` via `renderer::on_draw_primitive`: world-space (has decl, no POSITIONT, not skinned) -> FFP; otherwise pass-through
5. Applies captured matrices via `ffp_state::apply_transforms` -> `SetTransform`
6. Sets up texture stages and lighting for FFP rendering
7. Chain-loads RTX Remix (`d3d9_remix.dll`) via d3d9ex module

## Codebase File Map

| File | Role |
|------|------|
| `src/comp/modules/renderer.cpp` | Draw routing -- `on_draw_indexed_prim()` and `on_draw_primitive()` |
| `src/comp/modules/renderer.hpp` | `drawcall_mod_context` for save/restore state around draws |
| `src/shared/common/ffp_state.cpp` | Core FFP state tracker -- engage/disengage, transforms, texture stages |
| `src/shared/common/ffp_state.hpp` | FFP state class with all accessors |
| `src/shared/common/config.hpp` | Config structure parsed from `remix-comp.ini` |
| `src/comp/main.cpp` | DLL entry, window finder, config loading, module registration |
| `src/comp/comp.cpp` | Module init: registers renderer, diagnostics, skinning, imgui |
| `src/comp/modules/d3d9ex.cpp` | `IDirect3DDevice9` / `IDirect3D9` wrapper -- intercepts all 119 methods |
| `src/comp/modules/d3d9ex.hpp` | D3D9 wrapper class declarations |
| `src/comp/modules/diagnostics.cpp` | 50-sec delay, 3-frame diagnostic log to `ffp_proxy.log` |
| `src/comp/modules/skinning.cpp` | Optional skinning module (vertex expansion + bone upload) |
| `src/comp/modules/skinning.hpp` | Skinning class declaration |
| `src/comp/modules/imgui.cpp` | ImGui debug overlay (F4) with FFP tab |
| `src/comp/game/game.cpp` | Per-game address init (patterns, hooks) |
| `src/comp/game/game.hpp` | Per-game variables and function typedefs |
| `remix-comp.ini` | Runtime config: register layout, albedo stage, skinning toggle, diagnostics |
| `build.bat` | Build script: `build.bat [release\|debug] [--name Name] [--comp CompDir]` |

Per-game: copy `src/comp/` to `patches/<GameName>/proxy/comp/`, then build with `build.bat release --name <GameName> --comp <path>`.

---

## Porting Workflow

### Step 1: Static Analysis

Run the analysis scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/scripts/find_device_calls.py "<game.exe>"
```

Scripts are fast first-pass scanners -- surface candidate addresses only. Always follow up with `retools` and `livetools` for deep analysis.

**Alternative: DX9 Tracer capture.** Deploy the tracer proxy (`graphics/directx/dx9/tracer/`) to capture a full frame, then analyze with `--matrix-flow`, `--vtx-formats`, `--shader-map`, and `--const-provenance` to discover the register layout without reverse engineering the binary.

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 -> CreateDevice)
- Which functions call `SetVertexShaderConstantF` and with what register/count patterns
- What vertex declaration formats are used (BLENDWEIGHT/BLENDINDICES = skinning)
- Where the main render loop / draw calls live

### Step 2: Discover VS Constant Register Layout

This is the **most critical** step. Determine which VS constant registers hold View, Projection, and World matrices.

**Static approach:** Decompile call sites:
```bash
python -m retools.decompiler <game.exe> <call_site_addr> --types patches/<project>/kb.h
```

**Dynamic approach:** Trace `SetVertexShaderConstantF` live:
```bash
python -m livetools trace <call_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```
Captures: startRegister, Vector4fCount, and the first 4 vec4 constants of actual float data.

**DX9 Tracer approach:** Capture a frame and analyze:
```bash
python -m graphics.directx.dx9.tracer analyze <JSONL> --const-provenance
python -m graphics.directx.dx9.tracer analyze <JSONL> --matrix-flow
python -m graphics.directx.dx9.tracer analyze <JSONL> --shader-map
```

**How to identify matrices:**
- View matrix: changes with camera movement; contains camera orientation
- Projection matrix: contains aspect ratio and FOV; rarely changes
- World matrix: changes per object; contains position/rotation/scale
- Look for 4x4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Set Up Per-Game Project

1. Copy `rtx_remix_tools/dx/remix-comp/src/comp/` to `patches/<GameName>/proxy/comp/`
2. Edit `remix-comp.ini` with discovered register layout (see INI Config section below)
3. Edit `comp/main.cpp`: set `WINDOW_CLASS_NAME` to the game's window class
4. Customize `comp/modules/renderer.cpp` draw routing if needed (see Decision Trees below)
5. Customize `comp/game/game.cpp` with game-specific address init if hooks are needed
6. Update `kb.h` with discovered function signatures, structs, and globals

### Step 4: Build and Deploy

```bash
cd rtx_remix_tools/dx/remix-comp
build.bat release --name <GameName> --comp ..\..\..\..\patches\<GameName>\proxy\comp
```

The build produces `<GameName>-comp.asi` and `dinput8.dll` in `patches/<GameName>/build/release/`. Deploy:
- `<GameName>-comp.asi` to the game directory (or `plugins/` subfolder)
- `dinput8.dll` to the game directory (copied automatically by build)
- `remix-comp.ini` to the game directory
- `d3d9_remix.dll` to the game directory if using Remix

### Step 5: Diagnose with Log and ImGui

**ffp_proxy.log:** Written to the game directory after a configurable delay (default 50 seconds), then logs 3 frames of detailed draw call data:

- **VS regs written**: which constant registers the game actually fills
- **Vertex declarations**: what vertex elements each draw uses
- **Draw calls**: primitive type, vertex count, index count, textures per stage
- **Matrices**: actual View/Proj/World values being applied
- **Raw vertex bytes**: hex dump of first vertices for early draw calls

Do not change the logging delay unless the user asks -- it ensures the user gets into the game with real geometry before logging begins.

**ImGui overlay (F4):** Press F4 to toggle the debug overlay. The FFP tab shows real-time draw call stats, VS constant register write history, and enables a fake camera for testing transforms.

**Tell the user when you need them to interact with the game** for logging or hooking purposes. They must be in-game with geometry visible for the log to be useful.

---

## INI Config (`remix-comp.ini`)

All game-specific tuning is in `remix-comp.ini` -- no recompile needed for register changes.

```ini
[FFP]
Enabled=1
AlbedoStage=0
; Albedo texture stage (0-7). Set to whichever stage the game binds the diffuse texture.

[FFP.Registers]
ViewStart=0
ViewEnd=4
ProjStart=4
ProjEnd=8
WorldStart=16
WorldEnd=20
; These map VS constant registers to View, Projection, and World matrices.
; Each matrix occupies 4 consecutive vec4 registers (= 16 floats).

; Bone defines below only matter when [Skinning] Enabled=1
BoneThreshold=20
RegsPerBone=3
BoneMinRegs=3

[Skinning]
Enabled=0
; Only set to 1 after rigid FFP works correctly.

[Diagnostics]
Enabled=1
DelayMs=50000
LogFrames=3

[Remix]
Enabled=1
DLLName=d3d9_remix.dll

[Chain]
PreloadDLL=
; Optional: chain-load another DLL before initialization.
```

---

## Architecture: What to Edit vs What to Leave Alone

| Component | Edit Per-Game? |
|-----------|----------------|
| `remix-comp.ini` register layout, albedo stage | **YES** |
| `comp/main.cpp` WINDOW_CLASS_NAME | **YES** |
| `comp/modules/renderer.cpp` draw routing | **YES** -- main draw routing |
| `comp/game/game.cpp` address init and hooks | **YES** -- per-game hooks |
| `comp/game/structs.hpp` game structs | **YES** -- per-game data structures |
| `shared/common/ffp_state.cpp` engage/disengage/transforms | MAYBE -- only for unusual FFP needs |
| `shared/common/ffp_state.cpp` on_set_vertex_declaration | MAYBE -- element parsing |
| `shared/common/config.hpp` | NO -- add new INI sections if needed |
| `comp/modules/d3d9ex.cpp` D3D9 wrapper methods | NO -- forwards all 119 methods |
| `comp/modules/diagnostics.cpp` | NO -- generic frame logger |
| `comp/modules/imgui.cpp` | NO -- debug overlay |
| `shared/` everything else | NO -- framework code |

### DrawIndexedPrimitive Decision Tree

```
ffp.is_enabled() AND ffp.view_proj_valid()?
+-- NO  -> passthrough with shaders
+-- YES
    +-- ffp.cur_decl_is_skinned()?
    |   +-- YES + skinning module -> skinning::draw_skinned_dip()
    |   +-- YES + no skinning     -> passthrough with shaders
    +-- !ffp.cur_decl_has_normal()?
    |   +-- passthrough (HUD/UI)
    |   GAME-SPECIFIC: remove this filter if world geometry lacks NORMAL
    +-- else (rigid 3D mesh)
        +-- ffp.engage() + draw + restore
```

**Common per-game changes:**
- World geometry omits NORMAL -> remove or change `!ffp.cur_decl_has_normal()` filter
- Special passes (shadow, reflection) -> filter by shader pointer, render target, or vertex count
- UI drawn with DrawIndexedPrimitive + NORMAL -> add a filter (e.g. check stride or texture)

### DrawPrimitive Decision Tree

```
ffp.is_enabled() AND ffp.view_proj_valid() AND ffp.last_decl()
AND !ffp.cur_decl_has_pos_t() AND !ffp.cur_decl_is_skinned()?
+-- YES -> ffp.engage() (world-space particles / non-indexed geometry)
+-- NO  -> passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

---

## Analysis Scripts Reference

| Script | What it surfaces |
|--------|-----------------|
| `rtx_remix_tools/dx/scripts/find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `rtx_remix_tools/dx/scripts/find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites and register/count args |
| `rtx_remix_tools/dx/scripts/find_device_calls.py <game.exe>` | Device vtable call patterns and device pointer refs |
| `rtx_remix_tools/dx/scripts/find_vtable_calls.py <game.exe>` | D3DX constant table usage and D3D9 vtable calls |
| `rtx_remix_tools/dx/scripts/decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES -> skinning) |
| `rtx_remix_tools/dx/scripts/scan_d3d_region.py <game.exe> 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region |

---

## RE Tool Workflows for FFP Porting

### Find all SetVertexShaderConstantF call sites
```bash
python -m retools.xrefs <game.exe> <iat_addr> -t call
```

### Decompile a VS constant setup function
```bash
python -m retools.decompiler <game.exe> <func_addr> --types patches/<project>/kb.h
```

### Trace live VS constant writes
```bash
python -m livetools trace <SetVSConstF_call_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```

### Count draw calls and find callers
```bash
python -m livetools dipcnt on
# wait in-game
python -m livetools dipcnt read
python -m livetools dipcnt callers 100
```

### Understand render path depth
```bash
python -m retools.callgraph <game.exe> <render_func_addr> --down 3
```

### Understand a specific draw call path
```bash
python -m livetools steptrace <draw_func_addr> --max-insn 1000 --call-depth 1 --detail branches
```

### Find vertex declaration setup
```bash
python -m retools.search <game.exe> strings -f "vertex,decl,shader" --xrefs
```

### DX9 Tracer full-frame capture and analysis
```bash
python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>
python -m graphics.directx.dx9.tracer analyze <JSONL> --summary
python -m graphics.directx.dx9.tracer analyze <JSONL> --const-provenance
python -m graphics.directx.dx9.tracer analyze <JSONL> --vtx-formats
python -m graphics.directx.dx9.tracer analyze <JSONL> --shader-map
python -m graphics.directx.dx9.tracer analyze <JSONL> --render-passes
```

---

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major. `ffp_state::apply_transforms` transposes column-major VS constants. If the game stores matrices row-major in VS constants (uncommon), remove the transpose in `ffp_state::apply_transforms`.
- **Everything is white/black**: Albedo texture is on stage 1+, not stage 0. Set `AlbedoStage` in `remix-comp.ini`, or trace `SetTexture` calls to find the correct stage.
- **Some objects render, others don't**: Check whether missing geometry has NORMAL in its vertex decl. Check `ffp.view_proj_valid()` is true at draw time. DrawPrimitive routes on decl presence + no POSITIONT + not skinned.
- **Skinned meshes invisible**: Set `[Skinning] Enabled=1` in `remix-comp.ini`. Check log for skinning errors. Verify `bone_start_reg` and `num_bones` are non-zero in the log.
- **Game crashes on startup**: Set `[Remix] Enabled=0` in `remix-comp.ini` to test without Remix. Check `WINDOW_CLASS_NAME` in `comp/main.cpp`.
- **Geometry at origin / piled up**: World matrix register mapping wrong. Re-examine VS constant writes via `livetools trace` or DX9 tracer `--const-provenance`.
- **World geometry shifts after skinned draws**: `WORLDMATRIX(0)` clobbered by bone[0]. The proxy tracks `world_dirty_` for re-application. If still broken, check for bone register overlap with world matrix range in `remix-comp.ini`.
- **ImGui overlay not appearing**: Press F4. Check that `WINDOW_CLASS_NAME` is correct and the window was found (console output). Check for DirectInput hook conflicts.
