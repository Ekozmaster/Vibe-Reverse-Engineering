---
name: 'DX9 FFP Port'
description: 'Port a DX9 shader-based game to fixed-function pipeline for RTX Remix compatibility'
argument-hint: '<game.exe path>'
---

# DX9 FFP Proxy — Game Porting Prompt

You are helping a user port a DX9 shader-based game to the fixed-function pipeline using the `rtx_remix_tools/dx/remix-comp/` codebase in this workspace. The goal is RTX Remix compatibility: Remix requires FFP geometry to inject path-traced lighting and replaceable assets. Also use the Vibe RE tools (retools, livetools) for static and dynamic analysis to assist with developing this wrapper. They are meant to be used together.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. Until then, treat skinning as non-existent. When the user does request it, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp` for the full implementation.

---

## What remix-comp Does

The codebase is a C++20 compatibility mod based on remix-comp-base that intercepts `IDirect3DDevice9` and:

1. Captures vertex shader constants (View, Projection, World matrices) from `SetVertexShaderConstantF`
2. Parses `SetVertexDeclaration` to detect per-element attributes: BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL presence, and per-element byte offsets and types
3. Routes `DrawIndexedPrimitive` by vertex layout:
   - No NORMAL -> HUD/UI pass-through (uses different VS constant layout than world geometry)
   - Skinned with skinning module enabled -> expands vertices to a fixed FLOAT layout, then draws with FFP indexed vertex blending
   - Rigid 3D (has NORMAL) -> NULLs shaders, applies FFP transforms, draws
4. Routes `DrawPrimitive` by declaration state: world-space draws (have decl, no POSITIONT, not skinned) engage FFP; screen-space and no-decl draws pass through
5. Applies captured matrices via `SetTransform` (FFP)
6. Sets up texture stages and lighting for FFP rendering (stages 1-7 disabled to prevent stale auxiliary textures reaching Remix)
7. Chain-loads RTX Remix (`d3d9_remix.dll`)

## Source File Map

| File | Role |
|------|------|
| `src/comp/main.cpp` | DLL entry, module loading, initialization |
| `src/comp/modules/renderer.cpp` | Draw call routing -- `on_draw_indexed_prim()` and `on_draw_primitive()` |
| `src/comp/modules/d3d9ex.cpp` | `IDirect3DDevice9` hook layer -- intercepts all 119 methods |
| `src/comp/modules/skinning.cpp` | Skinning module (vertex expansion, bone upload, FFP blending) |
| `src/comp/modules/diagnostics.cpp` | Diagnostic logging to `ffp_proxy.log` |
| `src/comp/modules/imgui.cpp` | ImGui debug overlay (F4 toggle) |
| `src/shared/common/ffp_state.cpp` | FFP state tracker -- engage/disengage, matrix transforms, texture stages |
| `src/shared/common/ffp_state.hpp` | `ffp_state` class with all state accessors |
| `src/shared/common/config.hpp` | Config structures: `ffp_settings`, `skinning_settings`, etc. |
| `remix-comp.ini` (in `assets/`) | Runtime config: `[FFP.Registers]`, `[Skinning]`, `[Diagnostics]`, `[Remix]` |
| `premake5.lua` | Build system (Premake5 + VS2022) |

The codebase is C++20, uses Premake5 for build generation, component module system for extensibility.

## What Needs to Change Per Game

The `remix-comp.ini` file has a `[FFP.Registers]` section that must be set based on RE findings:

```ini
[FFP.Registers]
ViewStart=0
ViewEnd=4
ProjStart=4
ProjEnd=8
WorldStart=16
WorldEnd=20
BoneThreshold=20
RegsPerBone=3
BoneMinRegs=3
```

Beyond the INI config, users may need to modify:
- `renderer.cpp` `on_draw_indexed_prim()` -- draw call routing (which draws get FFP vs shader pass-through)
- `renderer.cpp` `on_draw_primitive()` -- UI/particle handling
- `ffp_state.cpp` `setup_lighting()`, `setup_texture_stages()`, `apply_transforms()` -- FFP render state and matrix configuration
- `AlbedoStage` in `remix-comp.ini` `[FFP]` section -- which texture stage holds the diffuse/albedo

## Porting Workflow

Follow these steps in order for ideal results. Each step depends on the previous. Be sure to use the Vibe Reverse Engineering tools (retools, livetools) for static and dynamic analysis as well. You do not need to strictly follow the order laid out here.

### Step 1: Static Analysis

Run the analysis scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/scripts/find_device_calls.py "<game.exe>"
```

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 call site -> CreateDevice call)
- Which functions call `SetVertexShaderConstantF` and with what register/count patterns
- What vertex declaration formats the game uses (BLENDWEIGHT/BLENDINDICES = skinning)
- Where the main rendering loop/draw calls live

### Step 2: Discover VS Constant Layout

This is the **most critical** step. You must determine which VS constant registers hold View, Projection, and World matrices.

**Static approach:** Decompile functions that call `SetVertexShaderConstantF`:
```bash
python -m retools.decompiler <game.exe> <call_site_addr> --types patches/<project>/kb.h
```

**Dynamic approach:** Trace `SetVertexShaderConstantF` calls live:
```bash
python -m livetools trace <call_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```
This captures: startRegister, Vector4fCount, and the actual float data (first 4 vec4 constants, dereferenced from `pConstantData`).

**How to identify matrices:**
- View matrix: changes with camera movement, contains camera orientation
- Projection matrix: contains aspect ratio and FOV, rarely changes
- World matrix: changes per object, contains position/rotation/scale
- Look for 4x4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Copy comp/ and Configure

1. Copy `rtx_remix_tools/dx/remix-comp/src/comp/` to `patches/<GameName>/proxy/comp/`
2. Copy `remix-comp.ini` from `assets/` to `patches/<GameName>/proxy/`
3. Edit `remix-comp.ini` `[FFP.Registers]` section with discovered register values
4. Use the Premake5 template (`premake5_game.lua.template`) for the game-specific build
5. Update `kb.h` with any function signatures, structs, or globals discovered

### Step 4: Build and Deploy

```bash
cd patches/<GameName>/proxy
premake5 vs2022
# Build with Visual Studio or MSBuild
```

Deploy to game directory: `.asi` file + `remix-comp.ini` + `dinput8.dll` (Ultimate ASI Loader). If using Remix, also place `d3d9_remix.dll` there.

### Step 5: Diagnose with Log and ImGui

The proxy writes `ffp_proxy.log` in the game directory. After a configurable delay (default 50 seconds via `[Diagnostics] DelayMs`), it logs frames of detailed draw call data:

- **VS regs written**: shows which constant registers the game actually fills
- **Vertex declarations**: what vertex elements each draw uses (POSITION, NORMAL, TEXCOORD, BLENDWEIGHT, etc.)
- **Draw calls**: primitive type, vertex count, index count, textures bound per stage
- **Matrices**: actual View/Proj/World values being applied

Press **F4** to open the ImGui debug overlay with live draw call stats and FFP conversion info.

Use this to iterate: wrong matrices -> re-check register mapping. Missing textures -> adjust AlbedoStage. Objects at wrong positions -> world matrix register is wrong.

## Architecture Details for Editing

### Code Map: Edit vs Do-Not-Touch

| File / Section | Edit Per-Game? |
|----------------|----------------|
| `remix-comp.ini` `[FFP.Registers]` | **YES** -- set register layout |
| `remix-comp.ini` `[Skinning] Enabled=` | **YES** -- only after rigid FFP works |
| `renderer.cpp` `on_draw_indexed_prim()` | **YES** -- main draw routing |
| `renderer.cpp` `on_draw_primitive()` | **YES** -- draw routing for non-indexed draws |
| `ffp_state.cpp` `setup_lighting()`, `setup_texture_stages()`, `apply_transforms()` | MAYBE -- tweak if game needs different FFP state |
| `ffp_state.cpp` `on_set_vs_const_f()` | MAYBE -- dirty tracking |
| `ffp_state.cpp` `on_set_vertex_declaration()` | MAYBE -- element parsing |
| `d3d9ex.cpp` hooks, `skinning.cpp`, `diagnostics.cpp`, `imgui.cpp` | NO -- infrastructure |
| `ffp_state.cpp` `engage()` / `disengage()` | NO |

### DrawIndexedPrimitive Decision Tree

This is the routing logic in `renderer.cpp` `on_draw_indexed_prim()`:

```
viewProjValid?
+-- NO  -> shader passthrough (transforms not captured yet)
+-- YES
    +-- curDeclIsSkinned?
    |   +-- YES + skinning module -> skinning::draw_skinned_dip()
    |   +-- YES + no skinning     -> shader passthrough
    +-- NOT skinned
        +-- !curDeclHasNormal -> shader passthrough (HUD/UI)
        +-- hasNormal -> ffp_state::engage + rigid FFP draw
```

**Common per-game changes to this tree:**
- Game's world geometry omits NORMAL -> remove or change the `!cur_decl_has_normal()` filter
- Game has special passes (shadow, reflection) -> filter by shader pointer, render target, or vertex count
- Game draws UI with DrawIndexedPrimitive + NORMAL -> add a filter (e.g. check stride or texture)

### DrawPrimitive Decision Tree

```
viewProjValid AND lastDecl AND !curDeclHasPosT AND !curDeclIsSkinned?
+-- YES -> ffp_state::engage (world-space particles, non-indexed geometry)
+-- NO  -> shader passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

### Skinning Data Flow

When skinning is enabled via `[Skinning] Enabled=1` in `remix-comp.ini`:

1. **`ffp_state::on_set_vertex_declaration()`** -- Parses `D3DVERTEXELEMENT9` array. If both BLENDWEIGHT and BLENDINDICES are present, sets `cur_decl_is_skinned_` and captures per-element byte offsets and types.

2. **`ffp_state::on_set_vs_const_f()`** -- When a write hits registers >= `BoneThreshold` with count >= `BoneMinRegs` and divisible by `RegsPerBone`, stores `bone_start_reg_` and `num_bones_`.

3. **`skinning::draw_skinned_dip()`** -- Locks the game's source vertex buffer, calls `expand_skin_vertex()` per vertex, caches results by hash key.

4. **`skinning::upload_bones()`** -- Reads bone matrices from VS constants, transposes, uploads via `SetTransform(WORLDMATRIX(i))`. Sets `D3DRS_VERTEXBLEND` and `D3DRS_INDEXEDVERTEXBLENDENABLE`.

5. **Draw** -- The expanded VB + shared declaration are bound, draw executes with FFP indexed vertex blending. After the draw, original VB/decl/textures are restored.

All of this is infrastructure (no per-game edits). The only game-specific parts are the INI `[FFP.Registers]` bone settings and `[Skinning] Enabled=` toggle.

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major matrices. The proxy transposes them. If the game stores matrices column-major in VS constants (the common case), the transpose is correct. If the game is already row-major, remove the transpose in `ffp_state::apply_transforms()`.
- **Everything is white/black**: The game's albedo texture might be on stage 1+ instead of stage 0. Set `AlbedoStage` in `remix-comp.ini` `[FFP]`, or trace `SetTexture` calls to find the pattern.
- **Some objects render, others don't**: `on_draw_primitive()` routes by vertex declaration -- world-space draws (have decl, no POSITIONT, not skinned) engage FFP; screen-space/no-decl pass through. `on_draw_indexed_prim()` additionally filters out draws without NORMAL as likely HUD/UI. If world geometry is missing, check whether its vertex decl has NORMAL and whether `view_proj_valid()` is true when those draws happen.
- **Skinned meshes are invisible**: Enable skinning with `[Skinning] Enabled=1` in `remix-comp.ini`. Check the diagnostic log for bone count and declaration issues.
- **Game crashes on startup**: The chain-loaded Remix DLL might not be present. Set `Enabled=0` in `remix-comp.ini` `[Remix]` section to test without Remix first.
- **Geometry at origin / piled up**: World matrix register mapping is wrong. Every object gets identity world transform. Re-examine VS constant writes.
- **Characters' world geometry shifts after a skinned draw**: After uploading bone matrices, WORLDMATRIX(0) is clobbered by bone[0]. The proxy tracks world dirty state so `apply_transforms()` re-applies the world matrix on the next rigid draw. If this still causes issues, the bone threshold register may overlap with the world matrix register range.

## Using the RE Tools

All the Vibe RE tools described in the workspace instructions (retools, livetools) are available. Key workflows for FFP porting:

- `retools.decompiler` with `--types kb.h` for decompiling rendering functions
- `livetools trace` on `SetVertexShaderConstantF` to see register + data patterns
- `livetools trace` on `DrawIndexedPrimitive` to see call frequency and arguments
- `livetools steptrace` on a rendering function to understand control flow
- `retools.search strings --xrefs` to find error messages or shader-related strings
- `retools.xrefs` / `retools.callgraph --up` to find who calls rendering functions

## Notes
- Do not change the time frame of the logging (unless specified by the user). The delay is important to ensure the user is able to get into the game with actual geometry being drawn before the logs start, otherwise they may get lost in the initial burst of draw calls during loading.
- Tell the user when you want to launch a game and have them interact with it for logging or hooking purposes. They MUST interact with the game to have this task be useful.
