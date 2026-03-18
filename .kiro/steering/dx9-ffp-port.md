---
description: RTX Remix DX9 FFP porting — per-game folders, address mapping, VS constant discovery, build/deploy, pitfalls.
inclusion: fileMatch
fileMatchPattern: "patches/**,rtx_remix_tools/**,**/d3d9_device.c,**/d3d9_main.c,**/d3d9_wrapper.c,**/proxy.ini,**/build.bat"
---

# RTX Remix — DX9 FFP Porting

The FFP template (`rtx_remix_tools/dx/dx9_ffp_template/`) is a D3D9 proxy DLL that captures VS constant matrices, NULLs shaders on draw calls, applies matrices via `SetTransform`, and chain-loads RTX Remix.

**When to use**: user mentions FFP rendering, DX9 shader-to-FFP conversion, RTX Remix compatibility, or building a `d3d9.dll` proxy for a game.

**SKINNING IS OFF BY DEFAULT.** Do not enable `ENABLE_SKINNING` or discuss skinning unless the user explicitly asks. When asked, read `extensions/skinning/README.md` and `proxy/d3d9_skinning.h`.

---

## Per-Game Folder Rule

Each game gets its own isolated folder. Never edit the template directly. Never share artifacts between games.

```
patches/<GameName>/
  kb.h          <- all discovered addresses, structs, globals for THIS game
  proxy/        <- copy of the template proxy/ for THIS game
    d3d9_device.c
    d3d9_main.c
    d3d9_wrapper.c
    d3d9_skinning.h
    d3d9.def
    build.bat
    proxy.ini
  d3d9.dll      <- build output
  traces/       <- livetools JSONL (gitignored)
```

Create a new game folder:
```bash
xcopy /E /I rtx_remix_tools\dx\dx9_ffp_template patches\<GameName>
```

---

## Knowledge Base (`patches/<GameName>/kb.h`)

Maintain throughout the session. Pass to every decompiler call: `--types patches/<GameName>/kb.h`.

```c
// ── Structs (add as discovered via structrefs.py --aggregate) ─────────────────

// ── IAT Addresses ─────────────────────────────────────────────────────────────
@ 0x______  // IAT: Direct3DCreate9
@ 0x______  // IAT: IDirect3DDevice9::SetVertexShaderConstantF  (slot 94)
@ 0x______  // IAT: IDirect3DDevice9::DrawIndexedPrimitive      (slot 82)
@ 0x______  // IAT: IDirect3DDevice9::DrawPrimitive             (slot 81)
@ 0x______  // IAT: IDirect3DDevice9::SetVertexDeclaration      (slot 87)
@ 0x______  // IAT: IDirect3DDevice9::SetTexture                (slot 65)
@ 0x______  // IAT: IDirect3DDevice9::Present                   (slot 17)

// ── SetVertexShaderConstantF Call Sites ───────────────────────────────────────
@ 0x______  void __cdecl UploadViewMatrix(IDirect3DDevice9* dev);        // writes c??-c??
@ 0x______  void __cdecl UploadProjMatrix(IDirect3DDevice9* dev);        // writes c??-c??
@ 0x______  void __cdecl UploadWorldMatrix(IDirect3DDevice9* dev, ...);  // writes c??-c??

// ── VS Constant Register Layout (fill after tracing) ─────────────────────────
// View matrix:        c__ - c__  (startReg=__, count=4)
// Projection matrix:  c__ - c__  (startReg=__, count=4)
// World matrix:       c__ - c__  (startReg=__, count=4)
// Bone matrices:      c__ - c__  (startReg=__, count=__ per bone) [if skinned]

// ── Render Loop ───────────────────────────────────────────────────────────────
@ 0x______  void __cdecl RenderScene(IDirect3DDevice9* dev);
@ 0x______  void __cdecl RenderObject(IDirect3DDevice9* dev, ...);

// ── Globals ───────────────────────────────────────────────────────────────────
$ 0x______  IDirect3DDevice9*  g_pDevice
$ 0x______  IDirect3D9*        g_pD3D
```

Mark uncertain addresses `// UNVERIFIED`. Remove once confirmed or disproven.

---

## Address Discovery Checklist

Work through these steps in order. Fill `kb.h` as you go.

### Step 1 — Find IAT stubs (fast, static)

```bash
python -m retools.search <game.exe> imports -d d3d9
python -m retools.search <game.exe> imports -d d3dx9
```

Record every `d3d9.dll` and `d3dx9_*.dll` import address into `kb.h` under `IAT Addresses`.

### Step 2 — Find SetVertexShaderConstantF call sites

```bash
python rtx_remix_tools/dx/dx9_ffp_template/scripts/find_vs_constants.py <game.exe>
```

For each call site, decompile to see startRegister and count:

```bash
python -m retools.decompiler <game.exe> <call_site_addr> --types patches/<GameName>/kb.h
```

### Step 3 — Confirm register layout live

Attach livetools and trace each call site:

```bash
python -m livetools attach <game.exe>
python -m livetools trace <SetVSCF_callsite> --count 100 \
    --read "[esp+8]:4:uint32; [esp+0xC]:4:uint32; *[esp+0x10]:64:float32"
# reads: startRegister, Vector4fCount, first 4 vec4 floats (dereferenced)
```

Identify which startReg/count combo produces a 4x4 rotation+translation matrix (View), a perspective matrix (Proj), and per-object transforms (World).

### Step 4 — Find render loop and device pointer

```bash
python -m graphics.directx.dx9.tracer analyze <trace.jsonl> --render-loop --resolve-addrs <game.exe>
python -m retools.datarefs <game.exe> <Direct3DCreate9_IAT_addr> --imm
```

Decompile the render loop entry to find `g_pDevice`:

```bash
python -m retools.decompiler <game.exe> <render_loop_addr> --types patches/<GameName>/kb.h
```

### Step 5 — Decode vertex declarations

```bash
python rtx_remix_tools/dx/dx9_ffp_template/scripts/decode_vtx_decls.py <game.exe> --scan
```

Look for `BLENDWEIGHT`/`BLENDINDICES` (skinning), `POSITIONT` (screen-space/HUD), `NORMAL` (lit geometry).

---

## Game-Specific Defines

Edit the `GAME-SPECIFIC` block at the top of `patches/<GameName>/proxy/d3d9_device.c`:

```c
// ── GAME-SPECIFIC — fill from kb.h after RE ───────────────────────────────────
#define VS_REG_VIEW_START       0   // startRegister of view matrix upload
#define VS_REG_VIEW_END         4   // exclusive end (start + 4)
#define VS_REG_PROJ_START       4   // startRegister of projection matrix upload
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // startRegister of world/object matrix upload
#define VS_REG_WORLD_END       20
#define ENABLE_SKINNING         0   // NEVER set to 1 until rigid FFP is confirmed working
```

Rules:
- `*_END = *_START + 4` for a single 4x4 matrix (4 vec4 rows)
- If View and Proj are uploaded together as one 8-row block, set VIEW_START=0, VIEW_END=4, PROJ_START=4, PROJ_END=8
- If the game uploads a combined ViewProj, treat it as View (START=0, END=4) and leave Proj as identity

---

## What to Edit vs Leave Alone

| Section in d3d9_device.c | Edit per-game? | Notes |
|--------------------------|---------------|-------|
| `VS_REG_*` defines | YES | Primary per-game config |
| `ENABLE_SKINNING` define | NO (default 0) | Only after rigid FFP confirmed |
| `FFP_ApplyTransforms` | MAYBE | Only if matrix row-major/column-major mismatch |
| `FFP_SetupLighting` | MAYBE | Only if lighting looks wrong |
| `FFP_SetupTextureStages` | MAYBE | Only if textures missing/wrong |
| `WD_DrawIndexedPrimitive` | YES | Draw routing logic |
| `WD_DrawPrimitive` | YES | Draw routing logic |
| IUnknown thunks | NO | Naked ASM — never touch |
| All other relay thunks | NO | Auto-generated, never touch |

---

## Draw Routing Decision Trees

### DrawIndexedPrimitive

```
Has vertex decl?
├── NO  → passthrough (HUD/UI, no NORMAL)
└── YES → has NORMAL?
    ├── NO  → passthrough (screen-space or unlit)
    └── YES → ENABLE_SKINNING == 1 AND has BLENDWEIGHT?
        ├── YES → FFP skinned draw
        └── NO  → FFP rigid draw (NULL shader + SetTransform)
```

### DrawPrimitive

```
Has vertex decl?
├── NO  → passthrough
└── YES → has NORMAL?
    ├── NO  → passthrough
    └── YES → FFP rigid draw (same as DIP rigid path)
```

**viewProjValid gate**: both paths check `viewProjValid` before FFP conversion. If View or Proj matrix was never uploaded (registers never written), `viewProjValid` stays false and all draws passthrough. This is the most common cause of "nothing renders" on first run.

---

## Build and Deploy

```bash
# Build (from game's proxy folder)
cd patches\<GameName>\proxy
build.bat

# Deploy to game directory
copy d3d9.dll  <game_dir>\d3d9.dll
copy proxy.ini <game_dir>\proxy.ini
```

`build.bat` uses `vswhere` to auto-locate MSVC. Requires Visual Studio with C++ workload installed.

`proxy.ini` minimum config:
```ini
[Remix]
Enabled=1
Chain.DLL=

[Proxy]
AlbedoStage=0
LogDelaySec=50
```

Set `Enabled=0` to test the proxy without Remix (geometry should still render correctly).

---

## Log Diagnosis (`ffp_proxy.log`)

The proxy writes `ffp_proxy.log` in the game directory after `LogDelaySec` seconds (default 50). Always check this first.

| Log entry | Meaning | Action |
|-----------|---------|--------|
| `viewProjValid=0` at draw time | View/Proj registers never written | Re-check VS_REG_VIEW/PROJ_START values |
| `worldValid=0` at draw time | World register never written | Re-check VS_REG_WORLD_START |
| `DIP passthrough (no decl)` | Draw has no vertex declaration | Expected for HUD — verify it's not 3D geometry |
| `DIP passthrough (no NORMAL)` | Vertex decl lacks NORMAL element | Check `decode_vtx_decls.py` output |
| `FFP draw: world=identity` | World matrix is all-zeros or identity | World register mapping wrong |
| `SetVSCF reg=N count=M` | Constant upload logged | Verify N matches VS_REG_*_START |
| `Chain load failed` | Remix DLL not found | Check `Chain.DLL` path in proxy.ini |

---

## Common Pitfalls

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| All geometry at world origin | Wrong world matrix register | Re-trace `SetVertexShaderConstantF`, check startReg for per-object uploads |
| Camera/view wrong | View and Proj registers swapped | Swap VS_REG_VIEW_START and VS_REG_PROJ_START |
| Objects white or black | Albedo texture on wrong stage | Trace `SetTexture`, set `AlbedoStage` in proxy.ini |
| Nothing renders at all | `viewProjValid` never set | Wrong VIEW/PROJ register range — check log |
| Game crashes on startup | Remix chain-load failure | Set `Enabled=0` in proxy.ini to isolate |
| Geometry renders but Remix doesn't inject | Remix not in game dir or wrong chain | Check `Chain.DLL` path |
| Skinned meshes T-pose | Skinning not implemented | Enable `ENABLE_SKINNING=1` only after rigid FFP works |
| Matrix looks transposed | Game stores row-major in VS constants | Remove transpose in `FFP_ApplyTransforms` |
| HUD/UI geometry broken | HUD draws being FFP-converted | Ensure passthrough for no-NORMAL vertex decls |
