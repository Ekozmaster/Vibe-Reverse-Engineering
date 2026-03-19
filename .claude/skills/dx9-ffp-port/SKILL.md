---
name: dx9-ffp-port
description: DX9 shader-to-FFP proxy porting for RTX Remix compatibility. Use when porting a DX9 shader-based game to the fixed-function pipeline so RTX Remix can inject path-traced lighting. Covers the full workflow: static analysis with scripts, discovering VS constant register layout, dynamic live tracing of SetVertexShaderConstantF, updating game-specific defines, building the d3d9.dll proxy, deploying and iterating with the proxy log. Includes draw call routing logic, common pitfalls, and skinning guidance.
---

# DX9 FFP Proxy — Game Porting

Port a DX9 shader-based game to fixed-function pipeline (FFP) for RTX Remix compatibility. Remix requires FFP geometry to inject path-traced lighting and replaceable assets.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable `ENABLE_SKINNING`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. When requested, read `extensions/skinning/README.md` and `proxy/d3d9_skinning.h` for the full guide.

---

## What the Template Does

The template (`rtx_remix_tools/dx/dx9_ffp_template/`) is a d3d9.dll proxy that:

1. Captures VS constants (View, Projection, World matrices) from `SetVertexShaderConstantF`
2. Parses `SetVertexDeclaration` to detect BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL presence, and per-element byte offsets
3. Routes `DrawIndexedPrimitive`:
   - No NORMAL → HUD/UI pass-through
   - Skinned + `ENABLE_SKINNING=1` → FFP indexed vertex blending
   - Rigid 3D (has NORMAL) → NULLs shaders, applies FFP transforms
4. Routes `DrawPrimitive`: world-space (has decl, no POSITIONT, not skinned) → FFP; otherwise pass-through
5. Applies captured matrices via `SetTransform`
6. Sets up texture stages and lighting for FFP rendering
7. Chain-loads RTX Remix (`d3d9_remix.dll`)

## Template File Map

| File | Role |
|------|------|
| `proxy/d3d9_device.c` | Core FFP conversion — 119-method `IDirect3DDevice9` wrapper |
| `proxy/d3d9_main.c` | DLL entry, logging, Remix chain-loading, INI parsing |
| `proxy/d3d9_wrapper.c` | `IDirect3D9` wrapper — intercepts `CreateDevice` |
| `proxy/d3d9_skinning.h` | Skinning extension (included only when `ENABLE_SKINNING=1`) |
| `proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `proxy/d3d9.def` | Exports `Direct3DCreate9` |
| `proxy/proxy.ini` | Runtime config: `[Remix]` chain load, `[FFP]` AlbedoStage |
| `extensions/skinning/README.md` | Guide for enabling skinning (late-stage) |

Per-game copies live at `patches/<GameName>/` (copy the whole template directory).

---

## Porting Workflow

### Step 1: Static Analysis

Run the template's scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_device_calls.py "<game.exe>"
```

Scripts are fast first-pass scanners — surface candidate addresses only. Always follow up with `retools` and `livetools` for deep analysis.

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 → CreateDevice)
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

**How to identify matrices:**
- View matrix: changes with camera movement; contains camera orientation
- Projection matrix: contains aspect ratio and FOV; rarely changes
- World matrix: changes per object; contains position/rotation/scale
- Look for 4×4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Copy Template and Update Defines

1. Copy `rtx_remix_tools/dx/dx9_ffp_template/` to `patches/<GameName>/`
2. Update the `GAME-SPECIFIC` section in `proxy/d3d9_device.c` (top of file)
3. Update `kb.h` with discovered function signatures, structs, and globals

### Step 4: Build and Deploy

```bash
cd patches/<GameName>/proxy
build.bat
```

Copy `d3d9.dll` + `proxy.ini` to the game directory. Place `d3d9_remix.dll` there too if using Remix.

### Step 5: Diagnose with Log

The proxy writes `ffp_proxy.log` in the game directory after a 50-second delay, then logs 3 frames of detailed draw call data:

- **VS regs written**: which constant registers the game actually fills
- **Vertex declarations**: what vertex elements each draw uses
- **Draw calls**: primitive type, vertex count, index count, textures per stage
- **Matrices**: actual View/Proj/World values being applied

Do not change the logging delay unless the user asks — it ensures the user gets into the game with real geometry before logging begins.

**Tell the user when you need them to interact with the game** for logging or hooking purposes. They must be in-game with geometry visible for the log to be useful.

---

## Game-Specific Defines

The top of `proxy/d3d9_device.c` has a `GAME-SPECIFIC` section:

```c
#define VS_REG_VIEW_START       0   // First register of view matrix
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // First register of projection matrix
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // First register of world matrix
#define VS_REG_WORLD_END       20
// Bone defines below only matter when ENABLE_SKINNING=1 (off by default)
#define VS_REG_BONE_THRESHOLD  20
#define VS_REGS_PER_BONE        3
#define ENABLE_SKINNING         0   // Only set to 1 after rigid FFP works
#define EXPAND_SKIN_VERTICES    0   // 0=use original VB, 1=expand to fixed 48-byte layout
```

---

## Architecture: What to Edit vs What to Leave Alone

| Section | Approx Lines | Edit Per-Game? |
|---------|-------------|----------------|
| `VS_REG_*` and `ENABLE_SKINNING` defines | 29–53 | **YES** |
| D3D9 constants, enums, vtable slot indices | 54–257 | NO |
| `WrappedDevice` struct | 258–337 | NO |
| `FFP_SetupLighting`, `FFP_SetupTextureStages`, `FFP_ApplyTransforms` | 367–486 | MAYBE |
| `FFP_Engage` / `FFP_Disengage` | 487–559 | NO |
| IUnknown + relay thunks | 560–683 | NO — naked ASM, never edit |
| `WD_Reset` / `WD_Present` / `WD_BeginScene` / `WD_EndScene` | 684–780 | NO |
| `WD_DrawPrimitive` | 781–824 | **YES** — draw routing |
| `WD_DrawIndexedPrimitive` | 825–993 | **YES** — main draw routing |
| `WD_SetVertexShaderConstantF` | 995–1085 | MAYBE — dirty tracking |
| `WD_SetVertexDeclaration` | 1134–1293 | MAYBE — element parsing |
| `WrappedDevice_Create` + vtable wiring | 1297–1476 | NO |

### DrawIndexedPrimitive Decision Tree

```
viewProjValid?
├─ NO  → shader passthrough
└─ YES
    ├─ curDeclIsSkinned?
    │   ├─ YES + ENABLE_SKINNING=1 → FFP skinned draw (or passthrough on failure)
    │   └─ YES + ENABLE_SKINNING=0 → shader passthrough
    └─ NOT skinned
        ├─ !curDeclHasNormal → shader passthrough (HUD/UI)
        └─ hasNormal → FFP_Engage + rigid FFP draw
```

**Common per-game changes:**
- World geometry omits NORMAL → remove or change `!curDeclHasNormal` filter
- Special passes (shadow, reflection) → filter by shader pointer, render target, or vertex count
- UI drawn with DrawIndexedPrimitive + NORMAL → add a filter (e.g. check stride or texture)

### DrawPrimitive Decision Tree

```
viewProjValid AND lastDecl AND !curDeclHasPosT AND !curDeclIsSkinned?
├─ YES → FFP_Engage (world-space particles / non-indexed geometry)
└─ NO  → shader passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

---

## Analysis Scripts Reference

| Script | What it surfaces |
|--------|-----------------|
| `scripts/find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `scripts/find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites and register/count args |
| `scripts/find_device_calls.py <game.exe>` | Device vtable call patterns and device pointer refs |
| `scripts/find_vtable_calls.py <game.exe>` | D3DX constant table usage and D3D9 vtable calls |
| `scripts/decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES → skinning) |
| `scripts/scan_d3d_region.py <game.exe> 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region |

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

---

## Common Pitfalls

- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major. The proxy transposes. If the game stores matrices row-major in VS constants (uncommon), remove the transpose in `FFP_ApplyTransforms`.
- **Everything is white/black**: Albedo texture is on stage 1+, not stage 0. Set `AlbedoStage` in `proxy.ini`, or trace `SetTexture` calls to find the correct stage.
- **Some objects render, others don't**: Check whether missing geometry has NORMAL in its vertex decl. Check `viewProjValid` is true at draw time. DrawPrimitive routes on decl presence + no POSITIONT + not skinned.
- **Skinned meshes invisible**: Enable `ENABLE_SKINNING 1`. Verify `numBones` is non-zero in DIP log entries. If using `EXPAND_SKIN_VERTICES=1`, check log for `skinExpDecl: 00000000` (CreateVertexDeclaration failed).
- **Bones mixed up between NPCs**: Stale WORLDMATRIX slots from a previous object. The proxy clears them on object boundary detection (startReg jump or `bonesDrawn` flag). If still broken, the game may need a game-specific reset hook.
- **Game crashes on startup**: Set `Enabled=0` in `proxy.ini [Remix]` to test without Remix.
- **Geometry at origin / piled up**: World matrix register mapping wrong. Re-examine VS constant writes via `livetools trace`.
- **World geometry shifts after skinned draws**: `WORLDMATRIX(0)` clobbered by bone[0]. The proxy sets `worldDirty=1` for re-application. If still broken, check for bone register overlap with world matrix range.

### Skinning Stability: Finding Game-Specific Hook Points

The proxy's generic heuristics (startReg jump, `bonesDrawn` flag, declaration change) handle most games. If bones still leak between objects, the game needs a hook at a per-object boundary function — one that's called once per skinned object, before its bones are uploaded.

**Finding the per-object function:**

1. **Capture** 2+ frames with the D3D9 tracer while multiple skinned NPCs are on screen
2. **Hotpaths**: `--hotpaths --resolve-addrs <game.exe>` — look at callers of bone-range `SetVertexShaderConstantF` writes
3. **Caller histogram**: `--callers SetVertexShaderConstantF` — the function that appears N times per frame (N = number of skinned objects) is the per-object boundary
4. **Live confirm**: `livetools trace <candidate_addr> --count 50` — with 3 NPCs, expect ~3 hits/frame
5. **Static context**: `callgraph.py --up` + `decompiler.py` on the caller — confirm it loops over objects

**Hooking it**: The hook is a 5-byte code cave (JMP to allocated memory) at the CALL instruction that invokes the per-object function. After calling the original function, the stub sets a `g_boneResetPending` flag that the `SetVertexShaderConstantF` handler checks. See `WORKING_SKINNING_CODE/d3d9_device.c` lines 1592-1675 for a reference implementation (per-object hook at 0xB991E7 wrapping call to 0x43D450).

**Optional batch bracket**: One level up in the call graph is typically the "render all skinned objects" function (e.g. at 0xB99110, called from 0xB99598 in the reference implementation). Hooking entry/exit with a `g_renderSkinned` flag lets you gate bone detection more precisely (avoids false positives from non-bone constant writes in the bone register range).
