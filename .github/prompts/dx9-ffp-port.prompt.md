---
name: 'DX9 FFP Port'
description: 'Port a DX9 shader-based game to fixed-function pipeline for RTX Remix compatibility'
argument-hint: '<game.exe path>'
---

# DX9 FFP Proxy — Game Porting Prompt

You are helping a user port a DX9 shader-based game to the fixed-function pipeline using the `rtx_remix_tools/dx/dx9_ffp_template/` template in this workspace. The goal is RTX Remix compatibility: Remix requires FFP geometry to inject path-traced lighting and replaceable assets. Also use the Vibe RE tools (retools, livetools) for static and dynamic analysis to assist with developing this wrapper. They are meant to be used together.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable `ENABLE_SKINNING`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. Until then, treat skinning as non-existent. When the user does request it, read `extensions/skinning/README.md` and `proxy/d3d9_skinning.h` for the full guide.

---

## What the Template Does

The template is a d3d9.dll proxy that intercepts `IDirect3DDevice9` and:

1. Captures vertex shader constants (View, Projection, World matrices) from `SetVertexShaderConstantF`
2. Parses `SetVertexDeclaration` to detect per-element attributes: BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL presence, and per-element byte offsets and types
3. Routes `DrawIndexedPrimitive` by vertex layout:
   - No NORMAL → HUD/UI pass-through (uses different VS constant layout than world geometry)
   - Skinned with `ENABLE_SKINNING=1` → expands vertices to a fixed FLOAT layout, then draws with FFP indexed vertex blending
   - Rigid 3D (has NORMAL) → NULLs shaders, applies FFP transforms, draws
4. Routes `DrawPrimitive` by declaration state: world-space draws (have decl, no POSITIONT, not skinned) engage FFP; screen-space and no-decl draws pass through
5. Applies captured matrices via `SetTransform` (FFP)
6. Sets up texture stages and lighting for FFP rendering (stages 1-7 disabled to prevent stale auxiliary textures reaching Remix)
7. Chain-loads RTX Remix (`d3d9_remix.dll`)

## Template Source Files

| File | Role |
|------|------|
| `proxy/d3d9_main.c` | DLL entry, logging, Remix chain loading, INI parsing |
| `proxy/d3d9_wrapper.c` | Wrapped `IDirect3D9` (17 methods), intercepts `CreateDevice` |
| `proxy/d3d9_device.c` | Wrapped `IDirect3DDevice9` (119 methods) — **core FFP conversion** |
| `proxy/d3d9_skinning.h` | Skinning extension (included only when `ENABLE_SKINNING=1`) |
| `proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `proxy/d3d9.def` | Exports `Direct3DCreate9` |
| `proxy/proxy.ini` | Runtime config: `[Remix]` chain load, `[FFP]` AlbedoStage |
| `extensions/skinning/README.md` | Guide for enabling skinning (late-stage) |

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
// Bone defines below only matter when ENABLE_SKINNING=1 (off by default)
#define VS_REG_BONE_THRESHOLD  20   // Registers at/beyond this are bone candidates
#define VS_REGS_PER_BONE        3   // Registers per bone (3 = packed 4x3)
#define VS_BONE_MIN_REGS        3   // Minimum register count for bone detection (1 bone)
#define ENABLE_SKINNING         0   // Late-stage: set to 1 only after rigid FFP works
```

Beyond the defines, users may need to modify:
- `WD_DrawIndexedPrimitive` — draw call routing (which draws get FFP vs shader pass-through)
- `WD_DrawPrimitive` — UI/particle handling
- `FFP_SetupLighting`, `FFP_SetupTextureStages`, `FFP_ApplyTransforms` — FFP render state and matrix configuration
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
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```
This captures: startRegister, Vector4fCount, and the actual float data (first 4 vec4 constants, dereferenced from `pConstantData`).

**How to identify matrices:**
- View matrix: changes with camera movement, contains camera orientation
- Projection matrix: contains aspect ratio and FOV, rarely changes
- World matrix: changes per object, contains position/rotation/scale
- Look for 4×4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Copy Template and Update Defines

1. Copy `rtx_remix_tools/dx/dx9_ffp_template/` to `patches/<GameName>/`
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

### Code Map: Edit vs Do-Not-Touch

The core file `proxy/d3d9_device.c` (~1660 lines) has clear zones. **Only edit sections marked YES or MAYBE:**

| Section | Approx Lines | Edit Per-Game? |
|---------|-------------|----------------|
| `VS_REG_*` and `ENABLE_SKINNING` defines | 29–53 | **YES** — set register layout (skinning OFF by default) |
| D3D9 constants, enums, vtable slot indices | 54–257 | NO — fixed D3D9 API values |
| `WrappedDevice` struct | 258–337 | NO — internal state bookkeeping |
| Shader addref/release helpers | 338–366 | NO — COM ref counting |
| `FFP_SetupLighting`, `FFP_SetupTextureStages`, `FFP_ApplyTransforms` | 367–486 | MAYBE — tweak if game needs different FFP state |
| `#include "d3d9_skinning.h"` (conditional) | 477–481 | NO — included only when ENABLE_SKINNING=1 |
| `FFP_Engage` / `FFP_Disengage` | 487–559 | NO — enter/leave FFP mode |
| IUnknown + relay thunks | 560–683 | NO — naked ASM forwarding, never edit |
| `WD_Reset` / `WD_Present` / `WD_BeginScene` / `WD_EndScene` | 684–780 | NO — frame/scene lifecycle |
| `WD_DrawPrimitive` | 781–824 | **YES** — draw routing for non-indexed draws |
| `WD_DrawIndexedPrimitive` | 825–993 | **YES** — main draw routing (see decision tree below) |
| `WD_SetVertexShaderConstantF` | 995–1085 | MAYBE — dirty tracking uses `VS_REG_*` |
| `WD_SetVertexDeclaration` | 1134–1293 | MAYBE — element parsing; add extra usages if needed |
| `WrappedDevice_Create` + vtable wiring | 1297–1476 | NO — initialization |

### DrawIndexedPrimitive Decision Tree

This is the routing logic that determines which draws get FFP-converted vs passed through with shaders:

```
viewProjValid?
├─ NO  → shader passthrough (transforms not captured yet)
└─ YES
    ├─ curDeclIsSkinned?
    │   ├─ YES + ENABLE_SKINNING=1
    │   │   ├─ skinExpDecl exists + expansion succeeds?
    │   │   │   ├─ YES → FFP_Engage + FFP_UploadBones + draw expanded VB
    │   │   │   └─ NO  → shader passthrough (fallback)
    │   │   └─ (never reached if ENABLE_SKINNING=1)
    │   └─ YES + ENABLE_SKINNING=0 → shader passthrough
    └─ NOT skinned
        ├─ !curDeclHasNormal → shader passthrough (HUD/UI)
        └─ hasNormal → FFP_Engage + rigid FFP draw
```

**Common per-game changes to this tree:**
- Game's world geometry omits NORMAL → remove or change the `!curDeclHasNormal` filter
- Game has special passes (shadow, reflection) → filter by shader pointer, render target, or vertex count
- Game draws UI with DrawIndexedPrimitive + NORMAL → add a filter (e.g. check stride or texture)

### DrawPrimitive Decision Tree

```
viewProjValid AND lastDecl AND !curDeclHasPosT AND !curDeclIsSkinned?
├─ YES → FFP_Engage (world-space particles, non-indexed geometry)
└─ NO  → shader passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

### Skinning Data Flow

When `ENABLE_SKINNING=1`, skinned meshes flow through these stages:

1. **`WD_SetVertexDeclaration`** — Parses `D3DVERTEXELEMENT9` array. If both BLENDWEIGHT and BLENDINDICES are present, sets `curDeclIsSkinned=1` and captures per-element byte offsets: `curDeclPosOff`, `curDeclBlendWeightOff`, `curDeclBlendIndicesOff`, `curDeclNormalOff`, `curDeclTexcoordOff` and their types. Also infers `curDeclNumWeights` from the BLENDWEIGHT element type.

2. **`WD_SetVertexShaderConstantF`** — When a write hits registers ≥ `VS_REG_BONE_THRESHOLD` with count ≥ `VS_BONE_MIN_REGS` and divisible by `VS_REGS_PER_BONE`, stores `boneStartReg` and `numBones`.

3. **`WD_DrawIndexedPrimitive`** — Sees `curDeclIsSkinned=1`, calls `SkinVB_GetExpanded()` which:
   - Locks the game's source vertex buffer
   - Calls `expand_skin_vertex()` per vertex → decodes compressed normals/UVs, writes fixed 48-byte layout
   - Caches the result by hash key (source VB ptr + baseVtx + count + stride + decl ptr)
   - On cache hit, returns the previously expanded buffer (no re-expansion)

4. **`FFP_UploadBones`** — Reads bone matrices from `vsConst[]` starting at `boneStartReg`, transposes each 4×3 → 4×4, uploads via `SetTransform(WORLDMATRIX(i))`. Sets `D3DRS_VERTEXBLEND` and `D3DRS_INDEXEDVERTEXBLENDENABLE`. Marks `worldDirty=1` (bone[0] clobbers WORLDMATRIX(0)).

5. **Draw** — The expanded VB + shared `skinExpDecl` are bound, draw executes with FFP indexed vertex blending. After the draw, original VB/decl/textures are restored.

All of this is infrastructure (no per-game edits). The only game-specific parts are the `VS_REG_BONE_*` defines and `ENABLE_SKINNING` toggle.

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major matrices. The proxy transposes them. If the game stores matrices column-major in VS constants (the common case), the transpose is correct. If the game is already row-major, remove the transpose in `FFP_ApplyTransforms`.
- **Everything is white/black**: The game's albedo texture might be on stage 1+ instead of stage 0. Set `AlbedoStage` in proxy.ini, or trace `SetTexture` calls to find the pattern.
- **Some objects render, others don't**: DrawPrimitive routes by vertex declaration — world-space draws (have decl, no POSITIONT, not skinned) engage FFP; screen-space/no-decl pass through. DrawIndexedPrimitive additionally filters out draws without NORMAL as likely HUD/UI. If world geometry is missing, check whether its vertex decl has NORMAL and whether `viewProjValid` is true when those draws happen.
- **Skinned meshes are invisible**: Enable skinning with `#define ENABLE_SKINNING 1`. Check the log for `skinExpDecl: 00000000` — if NULL, `CreateVertexDeclaration` failed (device may not have been ready). Also verify `boneStartReg` and `numBones` are non-zero in DIP log entries.
- **Game crashes on startup**: The chain-loaded Remix DLL might not be present. Set `Enabled=0` in proxy.ini `[Remix]` section to test without Remix first.
- **Geometry at origin / piled up**: World matrix register mapping is wrong. Every object gets identity world transform. Re-examine VS constant writes.
- **Characters' world geometry shifts after a skinned draw**: After uploading bone matrices, WORLDMATRIX(0) is clobbered by bone[0]. The proxy sets `worldDirty=1` so `FFP_ApplyTransforms` re-applies the world matrix on the next rigid draw. If this still causes issues, the bone start register may overlap with the world matrix register range.

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
