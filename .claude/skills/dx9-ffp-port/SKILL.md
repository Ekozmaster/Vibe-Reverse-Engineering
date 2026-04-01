---
name: dx9-ffp-port
description: DX9 FFP Proxy -- Game Porting. TRIGGER when: user mentions porting a game for RTX Remix, working on renderer.cpp / ffp_state / remix-comp.ini / draw routing / VS constants / vertex declarations / matrix mapping / skinning, building or deploying a remix-comp patch, or diagnosing rendering issues in a patched game (white geometry, missing objects, wrong transforms, ImGui F4, diagnostics.log). Covers full workflow: static analysis, VS constant discovery, draw routing, INI config, build/deploy, pitfall diagnosis.
---

# DX9 FFP Proxy -- Game Porting

Port a DX9 shader-based game to fixed-function pipeline (FFP) for RTX Remix compatibility. Remix requires FFP geometry to inject path-traced lighting and replaceable assets.

**NEVER MODIFY TEMPLATE CODE.** The following directories are read-only templates:
- `rtx_remix_tools/dx/remix-comp/` — remix-comp framework template
- `retools/asi_patcher.py` and `retools/asi_patcher/` — ASI patcher tooling

To create a game patch, **copy** the template to `patches/<GameName>/` and edit the copy. If the user asks you to edit remix-comp code, always confirm whether they mean the template or a game-specific copy under `patches/`. Only modify the template if the user **explicitly** says to change the template itself.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning in `remix-comp.ini`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. When requested, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp` for the full implementation.

---

## What remix-comp Does

Each game folder under `patches/<GameName>/` is a self-contained remix-comp project (copied from `rtx_remix_tools/dx/remix-comp/`). It is a dinput8.dll ASI proxy that:

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
| `src/comp/modules/diagnostics.cpp` | 50-sec delay, 3-frame diagnostic log to `rtx_comp/diagnostics.log` |
| `src/comp/modules/skinning.cpp` | Optional skinning module (vertex expansion + bone upload) |
| `src/comp/modules/skinning.hpp` | Skinning class declaration |
| `src/comp/modules/imgui.cpp` | ImGui debug overlay (F4) with FFP tab |
| `src/comp/game/game.cpp` | Per-game address init (patterns, hooks) |
| `src/comp/game/game.hpp` | Per-game variables and function typedefs |
| `remix-comp.ini` | Runtime config: register layout, albedo stage, skinning toggle, diagnostics |
| `build.bat` | Build script: `build.bat [release\|debug] [--name Name]` |

**`rtx_remix_tools/dx/remix-comp/` is the TEMPLATE.** Each game gets a full copy under `patches/<GameName>/` — the entire folder is self-contained and can be distributed as a standalone repo. Edit `src/comp/` directly in the game's copy.

**Before reading remix-comp source files**, read [references/remix-comp-context.md](references/remix-comp-context.md) for a skip-list of boilerplate files (~7,000 lines) you should never open, with summaries of what they do. It also lists the ~1,200 lines of files that actually matter for per-game work.

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

**IMPORTANT:** `rtx_remix_tools/dx/remix-comp/` is the **template**. NEVER edit it directly. Each game gets a full copy of the framework.

1. Copy the entire `rtx_remix_tools/dx/remix-comp/` folder to `patches/<GameName>/` (excluding `build/`)
2. Edit `src/comp/` directly in the game's copy — this is the per-game customization layer
3. Edit `remix-comp.ini` (at the game root) with discovered register layout (see INI Config section below)
4. Edit `src/comp/main.cpp`: set `WINDOW_CLASS_NAME` to the game's window class
5. Customize `src/comp/modules/renderer.cpp` draw routing if needed (see Decision Trees below)
6. Customize `src/comp/game/game.cpp` with game-specific address init if hooks are needed
7. Update `kb.h` with discovered function signatures, structs, and globals

The game folder is now fully self-contained and can be distributed as a standalone git repo.

### Step 4: Build and Deploy

From the game folder:
```bash
cd patches/<GameName>
build.bat release --name <GameName>
```

The build produces `<GameName>-comp.asi` and `dinput8.dll` in `patches/<GameName>/build/bin/release/`. Deploy:
- `<GameName>-comp.asi` to the game directory (or `plugins/` subfolder)
- `dinput8.dll` to the game directory (copied automatically by build)
- `remix-comp.ini` to the game directory
- `d3d9_remix.dll` to the game directory if using Remix

### Step 5: Diagnose with Log and ImGui

**rtx_comp/diagnostics.log:** Written to the `rtx_comp/` subfolder of the game directory after a configurable delay (default 50 seconds), then logs 3 frames of detailed draw call data:

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

Each game folder under `patches/<GameName>/` is a **self-contained** copy of the full remix-comp framework. Edit files directly in the game's copy.

| Component (in `patches/<GameName>/`) | Edit Per-Game? |
|-----------|----------------|
| `remix-comp.ini` register layout, albedo stage | **YES** |
| `src/comp/main.cpp` WINDOW_CLASS_NAME | **YES** |
| `src/comp/modules/renderer.cpp` draw routing | **YES** -- main draw routing |
| `src/comp/game/game.cpp` address init and hooks | **YES** -- per-game hooks |
| `src/comp/game/structs.hpp` game structs | **YES** -- per-game data structures |
| `src/shared/common/ffp_state.cpp` engage/disengage/transforms | MAYBE -- only for unusual FFP needs |
| `src/shared/common/config.hpp` | MAYBE -- add new INI sections if needed |
| `src/comp/modules/d3d9ex.cpp` | NO -- forwards all 119 methods |
| `src/comp/modules/diagnostics.cpp` | NO -- generic frame logger |
| `src/comp/modules/imgui.cpp` | NO -- debug overlay |
| `src/shared/` everything else | NO -- framework code |

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

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major. `ffp_state::apply_transforms` transposes column-major VS constants. If the game stores matrices row-major in VS constants (uncommon), remove the transpose in `ffp_state::apply_transforms`.
- **Everything is white/black**: Albedo texture is on stage 1+, not stage 0. Set `AlbedoStage` in `remix-comp.ini`, or trace `SetTexture` calls to find the correct stage.
- **Some objects render, others don't**: Check whether missing geometry has NORMAL in its vertex decl. Check `ffp.view_proj_valid()` is true at draw time. DrawPrimitive routes on decl presence + no POSITIONT + not skinned.
- **Skinned meshes invisible**: Set `[Skinning] Enabled=1` in `remix-comp.ini`. Check log for skinning errors. Verify `bone_start_reg` and `num_bones` are non-zero in the log.
- **Game crashes on startup**: Set `[Remix] Enabled=0` in `remix-comp.ini` to test without Remix. Check `WINDOW_CLASS_NAME` in `comp/main.cpp`.
- **Geometry at origin / piled up**: World matrix register mapping wrong. Re-examine VS constant writes via `livetools trace` or DX9 tracer `--const-provenance`.
- **World geometry shifts after skinned draws**: `WORLDMATRIX(0)` clobbered by bone[0]. The proxy tracks `world_dirty_` for re-application. If still broken, check for bone register overlap with world matrix range in `remix-comp.ini`.
- **ImGui overlay not appearing**: Press F4. Check that `WINDOW_CLASS_NAME` is correct and the window was found (console output). Check for DirectInput hook conflicts.
