---
applyTo: "rtx_remix_tools/**,patches/**/proxy/**,**/renderer.cpp,**/renderer.hpp,**/ffp_state.cpp,**/ffp_state.hpp,**/d3d9ex.cpp,**/d3d9ex.hpp,**/remix-comp.ini,**/premake5.lua,**/skinning.cpp,**/diagnostics.cpp"
---

# DX9 FFP Proxy — Game Porting

The remix-comp codebase (`rtx_remix_tools/dx/remix-comp/`) is a C++20 compatibility mod based on remix-comp-base that intercepts `IDirect3DDevice9`, captures VS constant matrices (View/Projection/World) from `SetVertexShaderConstantF`, NULLs shaders on draw calls, applies matrices through `SetTransform`, and chain-loads RTX Remix.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks. When requested, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp`.

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

Per-game copies: copy `src/comp/` to `patches/<GameName>/proxy/comp/`, use Premake template.

## Game-Specific Configuration

The `remix-comp.ini` `[FFP.Registers]` section:

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

Other game-specific INI settings:
- `[FFP] AlbedoStage=0` -- which texture stage holds the diffuse/albedo
- `[Skinning] Enabled=0` -- only set to 1 after rigid FFP works
- `[Remix] Enabled=1` -- set to 0 to test without Remix

## Porting Workflow

### Step 1: Static Analysis

Run scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/decode_vtx_decls.py "<game.exe>" --scan
```

Scripts are fast first-pass scanners -- follow up with `retools` and `livetools`.

### Step 2: Discover VS Constant Register Layout (MOST CRITICAL)

**Static**: Decompile `SetVertexShaderConstantF` call sites with `retools.decompiler --types kb.h`.

**Dynamic**: Trace live:

```bash
python -m livetools trace <call_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```

**How to identify matrices**: View = changes with camera; Projection = aspect ratio/FOV, rarely changes; World = changes per object. Look for 4 registers (16 floats), row 3 often `[0, 0, 0, 1]`.

### Step 3: Copy comp/ and Configure

1. Copy `rtx_remix_tools/dx/remix-comp/src/comp/` to `patches/<GameName>/proxy/comp/`
2. Copy `remix-comp.ini` from `assets/`
3. Edit `[FFP.Registers]` in `remix-comp.ini`

### Step 4: Build and Deploy

```bash
cd patches/<GameName>/proxy
premake5 vs2022
# Build with VS2022
```

Deploy: `.asi` + `remix-comp.ini` + `dinput8.dll` to game directory. Place `d3d9_remix.dll` there if using Remix.

### Step 5: Diagnose with Log and ImGui

The proxy writes `ffp_proxy.log` after a configurable delay (default 50 seconds) -- do not change the delay. Check VS regs written, vertex declarations, matrix values. Press **F4** for ImGui debug overlay.

The user must be in-game with geometry visible when captures are needed.

## Architecture: What to Edit

| File / Section | Edit Per-Game? |
|----------------|----------------|
| `remix-comp.ini` `[FFP.Registers]` | **YES** |
| `remix-comp.ini` `[FFP] AlbedoStage` | **YES** |
| `remix-comp.ini` `[Skinning] Enabled` | **YES** (after rigid works) |
| `renderer.cpp` `on_draw_indexed_prim()` | **YES** -- main draw routing |
| `renderer.cpp` `on_draw_primitive()` | **YES** -- draw routing |
| `ffp_state.cpp` `setup_lighting()`, `setup_texture_stages()`, `apply_transforms()` | MAYBE |
| `ffp_state.cpp` `on_set_vs_const_f()` | MAYBE -- dirty tracking |
| `ffp_state.cpp` `on_set_vertex_declaration()` | MAYBE -- element parsing |
| `d3d9ex.cpp` hooks, `skinning.cpp`, `diagnostics.cpp`, `imgui.cpp` | NO -- never edit |

### DrawIndexedPrimitive Decision Tree

```
viewProjValid?
+-- NO  -> shader passthrough
+-- YES
    +-- curDeclIsSkinned?
    |   +-- YES + skinning module -> skinning::draw_skinned_dip()
    |   +-- YES + no skinning     -> shader passthrough
    +-- NOT skinned
        +-- !curDeclHasNormal -> shader passthrough (HUD/UI)
        +-- hasNormal -> ffp_state::engage + rigid FFP draw
```

**Common per-game changes**: world geometry omits NORMAL -> change filter; special passes -> filter by shader/RT/count; UI with NORMAL -> add filter.

### DrawPrimitive Decision Tree

```
viewProjValid AND lastDecl AND !curDeclHasPosT AND !curDeclIsSkinned?
+-- YES -> ffp_state::engage (world-space particles / non-indexed geometry)
+-- NO  -> shader passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

## Common Pitfalls

- **Wrong matrices**: FFP expects row-major; proxy transposes. If game stores row-major, remove transpose in `ffp_state::apply_transforms()`.
- **White/black objects**: Albedo texture on stage 1+. Set `AlbedoStage` in `remix-comp.ini` `[FFP]`.
- **Some objects missing**: Check NORMAL in vertex decl and `view_proj_valid()` at draw time.
- **Game crashes on startup**: Set `Enabled=0` in `remix-comp.ini` `[Remix]` to test without Remix.
- **Geometry at origin**: World matrix register mapping wrong -- re-check VS constant writes.
- **World shifts after skinned draws**: `WORLDMATRIX(0)` clobbered by bone[0]. Proxy re-applies via world dirty tracking.
