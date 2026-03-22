---
applyTo: "rtx_remix_tools/**,patches/**/proxy/**,**/d3d9_device.c,**/d3d9_main.c,**/d3d9_wrapper.c,**/proxy.ini,**/build.bat"
---

# DX9 FFP Proxy — Game Porting

The FFP template (`rtx_remix_tools/dx/dx9_ffp_template/`) is a D3D9 proxy DLL that intercepts `IDirect3DDevice9`, captures VS constant matrices (View/Projection/World) from `SetVertexShaderConstantF`, NULLs shaders on draw calls, applies matrices through `SetTransform`, and chain-loads RTX Remix.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable `ENABLE_SKINNING`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks. When requested, read `extensions/skinning/README.md` and `proxy/d3d9_skinning.h`.

## Template File Map

| File | Role |
|------|------|
| `proxy/d3d9_device.c` | Core FFP conversion — 119-method `IDirect3DDevice9` wrapper |
| `proxy/d3d9_main.c` | DLL entry, logging, Remix chain-loading, INI parsing |
| `proxy/d3d9_wrapper.c` | `IDirect3D9` wrapper — intercepts `CreateDevice` |
| `proxy/d3d9_skinning.h` | Skinning extension (included only when `ENABLE_SKINNING=1`) |
| `proxy/build.bat` | MSVC x86 no-CRT build (auto-finds VS via vswhere) |
| `proxy/proxy.ini` | Runtime config: `[Remix]` chain load, `[FFP]` AlbedoStage |

Per-game copies live at `patches/<GameName>/` (copy the whole template directory).

## Game-Specific Defines

The top of `proxy/d3d9_device.c` has a `GAME-SPECIFIC` section:

```c
#define VS_REG_VIEW_START       0   // First register of view matrix
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // First register of projection matrix
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // First register of world matrix
#define VS_REG_WORLD_END       20
#define ENABLE_SKINNING         0   // Only set to 1 after rigid FFP works
```

## Porting Workflow

### Step 1: Static Analysis

Run scripts to understand the game's D3D9 usage:

```bash
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/dx9_ffp_template/scripts/decode_vtx_decls.py "<game.exe>" --scan
```

Scripts are fast first-pass scanners — follow up with `retools` and `livetools`.

### Step 2: Discover VS Constant Register Layout (MOST CRITICAL)

**Static**: Decompile `SetVertexShaderConstantF` call sites with `retools.decompiler --types kb.h`.

**Dynamic**: Trace live:

```bash
python -m livetools trace <call_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+10]:4:uint32; *[esp+c]:64:float32"
```

**How to identify matrices**: View = changes with camera; Projection = aspect ratio/FOV, rarely changes; World = changes per object. Look for 4 registers (16 floats), row 3 often `[0, 0, 0, 1]`.

### Step 3: Copy Template and Update Defines

1. Copy `rtx_remix_tools/dx/dx9_ffp_template/` to `patches/<GameName>/`
2. Update `GAME-SPECIFIC` defines in `proxy/d3d9_device.c`

### Step 4: Build and Deploy

```bash
cd patches/<GameName>/proxy && build.bat
```

Copy `d3d9.dll` + `proxy.ini` to the game directory. Place `d3d9_remix.dll` there if using Remix.

### Step 5: Diagnose with Log

The proxy writes `ffp_proxy.log` after a 50-second delay — do not change the delay. Check VS regs written, vertex declarations, matrix values.

The user must be in-game with geometry visible when captures are needed.

## Architecture: What to Edit

| Section | Edit Per-Game? |
|---------|----------------|
| `VS_REG_*` and `ENABLE_SKINNING` defines | **YES** |
| `FFP_SetupLighting`, `FFP_SetupTextureStages`, `FFP_ApplyTransforms` | MAYBE |
| `WD_DrawPrimitive` | **YES** — draw routing |
| `WD_DrawIndexedPrimitive` | **YES** — main draw routing |
| `WD_SetVertexShaderConstantF` | MAYBE — dirty tracking |
| `WD_SetVertexDeclaration` | MAYBE — element parsing |
| D3D9 constants, enums, vtable slots, IUnknown + relay thunks | NO — never edit |

### DrawIndexedPrimitive Decision Tree

```
viewProjValid?
+-- NO  -> shader passthrough
+-- YES
    +-- curDeclIsSkinned?
    |   +-- YES + ENABLE_SKINNING=1 -> FFP skinned draw
    |   +-- YES + ENABLE_SKINNING=0 -> shader passthrough
    +-- NOT skinned
        +-- !curDeclHasNormal -> shader passthrough (HUD/UI)
        +-- hasNormal -> FFP_Engage + rigid FFP draw
```

**Common per-game changes**: world geometry omits NORMAL -> change filter; special passes -> filter by shader/RT/count; UI with NORMAL -> add filter.

### DrawPrimitive Decision Tree

```
viewProjValid AND lastDecl AND !curDeclHasPosT AND !curDeclIsSkinned?
+-- YES -> FFP_Engage (world-space particles / non-indexed geometry)
+-- NO  -> shader passthrough (screen-space UI, POSITIONT, no decl, skinned)
```

## Common Pitfalls

- **Wrong matrices**: FFP expects row-major; proxy transposes. If game stores row-major, remove transpose in `FFP_ApplyTransforms`.
- **White/black objects**: Albedo texture on stage 1+. Set `AlbedoStage` in `proxy.ini`.
- **Some objects missing**: Check NORMAL in vertex decl and `viewProjValid` at draw time.
- **Game crashes on startup**: Set `Enabled=0` in `proxy.ini [Remix]` to test without Remix.
- **Geometry at origin**: World matrix register mapping wrong — re-check VS constant writes.
- **World shifts after skinned draws**: `WORLDMATRIX(0)` clobbered by bone[0]. Proxy re-applies via `worldDirty=1`.
