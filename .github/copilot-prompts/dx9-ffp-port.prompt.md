# DX9 FFP Proxy — Game Porting Prompt

You are helping a user port a DX9 shader-based game to the fixed-function pipeline using the `patches/dx9_ffp_template/` template in this workspace. The goal is RTX Remix compatibility: Remix requires FFP geometry to inject path-traced lighting and replaceable assets. Also use the Vibe RE tools (retools, livetools) for static and dynamic analysis to assist with developing this wrapper. They are meant to be used together.

---

## What the Template Does

The template is a d3d9.dll proxy that intercepts `IDirect3DDevice9` and:

1. Captures vertex shader constants (View, Projection, World matrices) from `SetVertexShaderConstantF`
2. NULLs both vertex and pixel shaders on `DrawIndexedPrimitive` calls
3. Applies captured matrices via `SetTransform` (FFP)
4. Sets up texture stages and lighting for FFP rendering
5. Chain-loads RTX Remix (`d3d9_remix.dll`)

## Template Source Files

| File | Role |
|------|------|
| `proxy/d3d9_main.c` | DLL entry, logging, Remix chain loading, INI parsing |
| `proxy/d3d9_wrapper.c` | Wrapped `IDirect3D9` (17 methods), intercepts `CreateDevice` |
| `proxy/d3d9_device.c` | Wrapped `IDirect3DDevice9` (119 methods) — **core FFP conversion** |
| `proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `proxy/d3d9.def` | Exports `Direct3DCreate9` |
| `proxy/proxy.ini` | Runtime config: `[Remix]` chain load, `[FFP]` AlbedoStage |

The codebase is plain C, no CRT, links only `kernel32.lib`. Uses `__declspec(naked)` relay thunks for the ~104 non-intercepted methods.

## What Needs to Change Per Game

The top of `d3d9_device.c` has a `GAME-SPECIFIC` section with `#define`s that must be set based on RE findings:

```c
#define VS_REG_VIEW_START       0   // First register of view matrix
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // First register of projection matrix
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // First register of world matrix
#define VS_REG_WORLD_END       20
#define VS_REG_BONE_THRESHOLD  20   // Registers at/beyond this are bone candidates
#define VS_REGS_PER_BONE        3   // Registers per bone (3 = packed 4x3)
#define VS_BONE_MIN_REGS        9   // Minimum register count for bone detection
```

Beyond the defines, users may need to modify:
- `WD_DrawIndexedPrimitive` — draw call routing (which draws get FFP vs shader pass-through)
- `WD_DrawPrimitive` — UI/particle handling
- `FFP_Setup` — texture stage and render state configuration
- `AlbedoStage` in proxy.ini — which texture stage holds the diffuse/albedo

## Porting Workflow

Follow these steps in order for ideal results. Each step depends on the previous. Be sure to use the Vibe Reverse Engineering tools (retools, livetools) for static and dynamic analysis as well. You do not need to strictly follow the order laid out here.

### Step 1: Static Analysis

Run the template's analysis scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_device_calls.py "<game.exe>"
```

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 call site → CreateDevice call)
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
    --read "[esp+4]:4:uint32; [esp+8]:4:uint32; [esp+c]:64:float32"
```
This captures: device ptr, startRegister, registerCount, and the actual float data.

**How to identify matrices:**
- View matrix: changes with camera movement, contains camera orientation
- Projection matrix: contains aspect ratio and FOV, rarely changes
- World matrix: changes per object, contains position/rotation/scale
- Look for 4×4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Copy Template and Update Defines

1. Copy `patches/dx9_ffp_template/` to `patches/<GameName>/`
2. Update the `GAME-SPECIFIC` section in `proxy/d3d9_device.c` with discovered register values
3. Update `kb.h` with any function signatures, structs, or globals discovered

### Step 4: Build and Deploy

```bash
cd patches/<GameName>/proxy
build.bat
```

Copy `d3d9.dll` + `proxy.ini` to the game directory. If using Remix, also place `d3d9_remix.dll` there.

### Step 5: Diagnose with Log

The proxy writes `ffp_proxy.log` in the game directory. After a 50-second delay, it logs 3 frames of detailed draw call data:

- **VS regs written**: shows which constant registers the game actually fills
- **Vertex declarations**: what vertex elements each draw uses (POSITION, NORMAL, TEXCOORD, BLENDWEIGHT, etc.)
- **Draw calls**: primitive type, vertex count, index count, textures bound per stage
- **Matrices**: actual View/Proj/World values being applied

Use this to iterate: wrong matrices → re-check register mapping. Missing textures → adjust AlbedoStage. Objects at wrong positions → world matrix register is wrong.

## Architecture Details for Editing

- **FFP_Engage / FFP_Disengage**: These track whether the proxy is in FFP mode. `FFP_Engage` NULLs shaders, applies transforms, sets up texture stages. `FFP_Disengage` restores the game's shaders. The proxy avoids redundant state changes between consecutive FFP draw calls.
- **FFP_Setup**: Called once per FFP engagement. Configures texture stages (stage 0 = MODULATE texture×diffuse), disables lighting, sets white material, disables fog. Modify this if the game needs different FFP state.
- **FFP_ApplyTransforms**: Reads from the `vsConst[]` array using the `VS_REG_*` defines and calls `SetTransform` with transposed matrices (D3D9 FFP expects row-major).
- **Relay thunks**: The 104 non-intercepted methods use `__declspec(naked)` ASM to swap `this` and jump directly to the real vtable. Zero overhead. Don't touch these unless you need to intercept a new method.
- **Skinning**: Behind `#if ENABLE_SKINNING`. Bone palette detection triggers when a large `SetVertexShaderConstantF` write lands at registers ≥ `VS_REG_BONE_THRESHOLD` with a count divisible by `VS_REGS_PER_BONE`. Default behavior passes skinned meshes through with original shaders.

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major matrices. The proxy transposes them. If the game stores matrices column-major in VS constants (the common case), the transpose is correct. If the game is already row-major, remove the transpose in `FFP_ApplyTransforms`.
- **Everything is white/black**: The game's albedo texture might be on stage 1+ instead of stage 0. Set `AlbedoStage` in proxy.ini, or trace `SetTexture` calls to find the pattern.
- **Some objects render, others don't**: DrawPrimitive (non-indexed) calls pass through with shaders by default. Some games use DP for 3D geometry, not just UI. Check the diagnostic log.
- **Game crashes on startup**: The chain-loaded Remix DLL might not be present. Set `Enabled=0` in proxy.ini `[Remix]` section to test without Remix first.
- **Geometry at origin / piled up**: World matrix register mapping is wrong. Every object gets identity world transform. Re-examine VS constant writes.

## Using the RE Tools

All the Vibe RE tools described in the workspace instructions (retools, livetools) are available. Key workflows for FFP porting:

- `retools.decompiler` with `--types kb.h` for decompiling rendering functions
- `livetools trace` on `SetVertexShaderConstantF` to see register + data patterns
- `livetools trace` on `DrawIndexedPrimitive` to see call frequency and arguments
- `livetools steptrace` on a rendering function to understand control flow
- `retools.search strings --xrefs` to find error messages or shader-related strings
- `retools.xrefs` / `retools.callgraph --up` to find who calls rendering functions
