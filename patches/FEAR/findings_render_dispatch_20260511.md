# FEAR Render Dispatch + Per-Pass Stage Layout (2026-05-11)

## What this document is

Synthesis of three parallel analyses run 2026-05-11 ~14:30:

1. **Diag log mining** ([analyze_diag_shader_stages.py](livetools_logs/analyze_diag_shader_stages.py)) — parses `diag_20260506_234317.log` (5800 DIPs, 17 shaders) to produce a per-VS-pointer stage-usage map.
2. **Heuristic scoring** ([analyze_albedo_heuristic.py](livetools_logs/analyze_albedo_heuristic.py)) — tests runtime rules for picking the diffuse stage per draw.
3. **LithTech Jupiter EX research** — material/.fx pipeline conventions via NOLF2, Jupiter SDK, and the FEAR `.Mat00p` format parser ([io_scene_jupex](https://github.com/Five-Damned-Dollarz/io_scene_jupex)).

## Critical correction to prior assumption

The previous `[FFP] AlbedoStage=1` setting works because **for the dominant world shader (VS=0x234b8ba0, 2093 of 5800 draws) the diffuse happens to be on stage 1**, NOT because stage 1 is the universal albedo slot. For ~53% of draws, stage 1 is bound to **a global LUT (deferred lighting / shadow / env map)** and the real diffuse is on a different stage.

Authoritative source: [io_scene_jupex/RenderMeshes.py](https://github.com/Five-Damned-Dollarz/io_scene_jupex/blob/main/RenderMeshes.py) parses real FEAR `.Mat00p` material files. Textures are bound by named parameter (`tDiffuseMap`, `tNormalMap`, `tSpecularMap`, `tEmissiveMap`, `tReflectionMap`, `tEnvironmentMap`, `tEnvironmentMapMask`, `tWaveMap`) — the sampler register each name maps to is determined inside the `.fxo` shader, NOT by the engine.

**Implication**: there is no "always-correct" stage for a global `AlbedoStage` setting. The diffuse stage is **per-shader**, decided inside each .fx file's HLSL.

## Per-shader stage layout (top 17 VS pointers, draws ≥5)

| VS pointer | Draws | Stride | Decl signature | Diffuse stage (high-variety) | Likely role |
|---|---|---|---|---|---|
| `0x234b8ba0` | 2093 | 56 | POS+NOR+TC+TAN+BIN | **stage 1** (57 unique) | World walls/floor — what current setting tunes for |
| `0x28f353c0` | 835 | 36 | POS+NOR+TC+**COLOR** | **stage 0** (19 unique) | Vertex-lit static geom (lightmapped) |
| `0x234b7c60` | 593 | 56 | POS+NOR+TC+TAN+BIN | stages 0/1/2 all per-mat | Multi-tex DNS material |
| `0x423e0a40` | 453 | 56 | POS+NOR+TC+TAN+BIN | **stage 0** (15 unique) | Model |
| `0x423e0020` | 406 | 56 | POS+NOR+TC+TAN+BIN | stages 0/1/2 per-mat | DNS material |
| `0x423d7f00` | 377 | 64 | +**BLENDW+BLENDI** | stage 1 (6 unique) | **SKINNED character** |
| `0x423d6840` | 290 | 64 | +**BLENDW+BLENDI** | stages 0/1/2 per-mat | Skinned DNS character |
| `0x2d7e3980` | 203 | 56 | POS+NOR+TC+TAN+BIN | stage 0 (5 unique) | Model |
| `0x2d7e3e80` | 141 | 56 | POS+NOR+TC+TAN+BIN | stage 1 (3 unique) | Variable-lit object |
| `0x423de440` | 87 | 64 | +**BLENDW+BLENDI** | (one instance, 142v) | Single character (NPC?) |
| `0x423de6c0` | 87 | 64 | +**BLENDW+BLENDI** | (one instance, 142v) | Single character |
| `0x423e41e0` | 47 | 32 | POS+NOR+TC, **24 verts always** | stage 0: cube tex `0x12697e40` | **SKYBOX** (24v = 12 tris = 6 cube faces) |
| `0x2997eec0` | 47 | 60 | POS+**COL**+TC+NOR+TAN+BIN | low variety | 8-vert detail |
| `0x423e16e0` | 47 | 32 | POS+**COL**+TC+TC, **no NORMAL** | stage 2 (2 unique) | **HUD/UI quad** (4 verts) |
| `0x28f34c20` | 47 | 56 | POS+NOR+TC+TAN+BIN | (one instance, 79v) | One-off prop |

## Global LUT textures (NOT diffuse — exclude from albedo selection)

From web research + diag log:
- `0xe0a0650` — shadow map / depth buffer render target. Bound on stages 0 OR 1 of all draws. Top texture in `analysis_albedo1_v2_20260511_1310.txt` for both stages.
- `0x128579c0` — global lighting / deferred LUT. Bound on stage 0 of normal-mapped decls AND stage 1 of vertex-lit decls.
- `0x39edde00` — bound on stages 5/6 of every draw. Already detected by H3.
- Likely more `0x236c*`, `0x15dd8d80`, `0x1615a7e0`, etc. — environment maps reused frame-wide.

## Heuristic scoring (% draws routed to ground-truth diffuse stage)

| Heuristic | Score |
|---|---|
| H1 (current): always stage 1 | 46.6% |
| H2: decl-based (TAN+BIN → stage 1; else stage 0) | 60.2% |
| H3: LUT exclusion (lowest stage whose tex isn't on stages 5+) | 51.7% |

H3 underperformed because the LUT pool was only built from stages 5+. A more accurate H3 would build the pool from textures that appear on >threshold draws across **all** stages — capturing `0x128579c0` and `0xe0a0650` which currently slip through.

## Blocker analysis (with fix candidates)

### Blocker #1 — Gun renders flat-gray

**Cause**: gun is rendered with one of the model shaders (`0x423e0a40` / `0x423e0020` / similar) whose diffuse is on stage 0. Current `AlbedoStage=1` setting binds the global lighting LUT `0x128579c0` instead of the gun diffuse, then `SELECTARG1` outputs uniform gray.

**Detection (next session, live)**:
- `livetools collect` with filter on `NumVertices < 500` (the gun is low-poly per the screenshot's faceted polys).
- Confirm the VS pointer used for the gun draws.
- Confirm the gun has a separate VS pointer not shared with world geometry.
- Alternative: dump view-space Z range per draw and identify "verts close to camera" (gun verts cluster at view-Z 0.1–2m per LithTech weapon convention; web-research source: ModDB FEAR weapon modding tutorial).

**Fix (proxy-level)**:
- **Best**: build a runtime LUT pool ("textures bound across many draws") and pick per-draw albedo as "the lowest stage whose current texture is NOT in the LUT pool." This auto-corrects per shader without hardcoded tables.
- **Workaround**: ship `AlbedoStage=0`, which fixes models but breaks the dominant world shader. Or ship two builds and let the user pick.

### Blocker #2 — Stray gray sky panels

**Cause**: a non-skybox shader is rendering large quads facing the sky region but the proxy isn't routing them as sky (rtx.skyBoxTextures only catches texture-tagged draws). The "correct" sky shader is `0x423e41e0` (47 draws, 24 verts always = 6 cube faces); the stray panels are likely a DIFFERENT shader that has its texture bound on a stage whose albedo gets read as `0x128579c0` (the lighting LUT), which is NOT in `rtx.skyBoxTextures`.

**Fix**: improving the per-draw albedo routing (Blocker #1 fix) should reveal the real texture for these stray panels. Then either add their hash to `rtx.skyBoxTextures` or use the in-game Remix UI to inspect them as the HANDOFF suggests.

### Blocker #3 — Water iridescent rainbow

**Cause**: water draws are alpha-blended but the proxy's `engage()` overwrites the alpha-blend state and binds `D3DTOP_SELECTARG1` with no blend awareness. Remix sees opaque chrome.

**Detection signal (from web research)**: `D3DRS_ALPHABLENDENABLE = TRUE` AND `D3DRS_ZWRITEENABLE = FALSE`. LithTech's `drawobjects.cpp` separates the frame into opaque queue (Z-write on) then translucent queue (Z-write off, sorted back-to-front). Z-write OFF is a reliable translucent indicator.

**Fix**:
1. Add `GetRenderState(D3DRS_ALPHABLENDENABLE)` + `GetRenderState(D3DRS_ZWRITEENABLE)` check at start of `on_draw_indexed_prim`.
2. If alpha-blend ON AND z-write OFF → route as passthrough with shader (preserves blend, sacrifices path-traced reflection)
3. OR engage FFP but keep `D3DRS_ALPHABLENDENABLE = TRUE` through `engage()`, AND set up `D3DTSS_ALPHAOP = D3DTOP_SELECTARG1` with `D3DTA_TEXTURE` (already done), but ALSO ensure the texture pipeline passes through the blend op into Remix's translucent classification.

### Blocker #4 — White NPC bodies

**Cause**: skinned shaders (`0x423d7f00`, `0x423d6840`, `0x423de440`, `0x423de6c0`, `0x423d8ba0`) are routed as passthrough — the original VS+PS run, the FFP doesn't engage, and Remix can't extract a clean material identifier from the running shader's output.

**Fix**: enable skinning via FFP `D3DRS_INDEXEDVERTEXBLENDENABLE` + `D3DTS_WORLDMATRIX(n)`. The diagnostic log shows skinned decls carry `BLENDWEIGHT0:D3DCOLOR` + `BLENDINDICES0:D3DCOLOR` (4 bytes each, packed). Live SVSCF showed `start_reg=0 count=72` events (18 bones × 4 regs) which IS the bone palette upload — `vs_reg_bone_threshold_` would need to be tuned (currently 20, may overlap with non-bone constants). Risk: the skinning module is generic and may need FEAR-specific tuning.

**Alternative fix**: CPU-side vertex blending in the proxy (skill calls this "last resort"). Tanks frame rate but produces clean FFP geometry that Remix path-traces perfectly.

## Recommended next-session action plan

1. **Implement runtime LUT pool + per-draw albedo stage selection** in `ffp_state::setup_albedo_texture`. Tracks the texture-pointer-on-stage frequency across recent draws, builds a pool of "shared LUT" textures, picks albedo as "lowest stage whose current texture is NOT in the pool." This is shader-agnostic and self-tuning.
2. **Add alpha-blend translucent detection** at top of `on_draw_indexed_prim`. Route alpha-blended + Z-write-off draws as passthrough.
3. **Optionally extract a real `.fxo` from the FEAR install** via `fx_decomp` (https://github.com/Five-Damned-Dollarz/fx_decomp) to confirm `tDiffuseMap` sampler register for one or two key shaders. This validates the runtime LUT-exclusion heuristic.
4. **Test in-game and use Remix UI (Alt+X) → click on gray panels** to read texture hashes. With the runtime LUT fix in place, those hashes should now correspond to actual albedo textures, not lighting LUTs.

## Source materials

- [io_scene_jupex/RenderMeshes.py](https://github.com/Five-Damned-Dollarz/io_scene_jupex/blob/main/RenderMeshes.py) — authoritative `.Mat00p` parser, confirms parameter names
- [jsj2008/lithtech drawobjects.cpp](https://github.com/jsj2008/lithtech/blob/master/runtime/render_a/src/sys/d3d/drawobjects.cpp) — opaque/translucent queue separation, `IsTranslucent()`
- [xfw5/Fear-SDK-1.08 iltrenderer.h](https://github.com/xfw5/Fear-SDK-1.08/blob/master/engine/sdk/inc/iltrenderer.h) — `ILTRenderer::SetInstanceParamTexture`, render target enums
- [fx_decomp](https://github.com/Five-Damned-Dollarz/fx_decomp) — `.fxo` shader bytecode decompiler for FEAR shaders
- Local files: [analyze_diag_shader_stages.py](livetools_logs/analyze_diag_shader_stages.py), [analyze_albedo_heuristic.py](livetools_logs/analyze_albedo_heuristic.py), [shader_stage_layout_20260511.txt](livetools_logs/shader_stage_layout_20260511.txt), [albedo_heuristic_score_20260511.txt](livetools_logs/albedo_heuristic_score_20260511.txt)

## Gap analysis (static, 2026-05-11)

Four static-analysis gaps from the synthesis above, resolved against `FEAR.exe` (clean install, ImageBase 0x00400000) using r2ghidra (`--backend pdg --types patches/FEAR/kb.h`). The headline result: **FEAR.exe makes direct D3D9 calls for state but routes all draws through ILTRenderer** — a hybrid architecture, not the pure-indirection model previously assumed.

### Gap A — Render dispatch loop

**Resolved.** The central per-VB draw dispatcher is `LTRender_DrawVB` at **0x00469D50** (already in kb.h line 3609). It is called from a single site at 0x46ECA8 inside a higher-level traversal at 0x46EC00-ish that iterates over visible draw objects (checks `param_1[0x14] & 4`, `[ebp+0x70]` retry counter, etc.).

`LTRender_DrawVB` does NOT call `IDirect3DDevice9::DrawIndexedPrimitive` directly. Instead it makes ~10 dispatches into the LT renderer at `*0x572b68` via slots:
- `0x180` — generic non-indexed draw entry (post-setup)
- `0x184` — indexed draw with vertex range (the "DIP" analog; `(this, vbState, startVtx, vtxCount, startIdx + 0x10, primCount, 0)`)
- `0x188` — alternative draw path (skinned/dynamic?)
- `0x18C` + `0x190` (=400) — set scissor/viewport bounds and apply
- `0x21C`, `0x220` — instance/material-bind path
- `0x150` — pre-draw VB activation

The actual DIP into the D3D9 device happens inside the LT renderer DLL, **not in FEAR.exe**. Confirmation: `find_device_calls.py` reported 23 "DIP" call sites at `[reg+0x148]` clustered in 0x4F8xxx; **all are false positives** — decompilation of 0x4F814F, 0x4F8276, 0x4F86C0 shows they are game-object field reads at offset +0x148 followed by `**0x577190 + 0x28` resource-manager calls, NOT D3D9 device vtable dispatch.

Caller chain (one site, no fan-out):
```
fcn.0046EC00 (game-side traversal/render-everything)
  └─ call 0x469D50 LTRender_DrawVB(VBState* state)
       └─ (*0x572b68)->vtable[0x184]  // LT-renderer indexed draw
            └─ [inside renderer DLL] IDirect3DDevice9::DrawIndexedPrimitive
```

**There is ONE central draw-issuing function in FEAR.exe** (0x469D50), called from a single loop site. Per-draw decisions (scissor, projection bake, skinned vs static path) are inside `LTRender_DrawVB` via switches on `param_1[2]+0x10` (vertex format tag: 0x11, 0x55).

### Gap B — Opaque/translucent split

**Resolved with named function.** The depth-mode dispatcher is `fcn.004F5F60` (now named `Render_SetDepthMode` in the suggested KB update below). It's a 4-case switch on `*(param_1 + 0x6c)` that sets `(D3DRS_ZENABLE=7, D3DRS_ZWRITEENABLE=14)` together:

```c
void __thiscall Render_SetDepthMode(int param_1, IDirect3DDevice9* dev) {
    switch (*(param_1 + 0x6c)) {  // depth mode tag
        case 0: dev->SetRenderState(ZENABLE, 0); dev->SetRenderState(ZWRITEENABLE, 0); return;  // HUD/UI
        case 1: dev->SetRenderState(ZENABLE, 0); dev->SetRenderState(ZWRITEENABLE, 1); return;
        case 2: dev->SetRenderState(ZENABLE, 1); dev->SetRenderState(ZWRITEENABLE, 0); return;  // TRANSLUCENT
        case 3: dev->SetRenderState(ZENABLE, 1); dev->SetRenderState(ZWRITEENABLE, 1); return;  // OPAQUE
    }
}
```

Called from a wrapper at 0x4F6336 that follows with `SetRenderState(ZFUNC=8, 3=LESSEQUAL)` and `SetRenderState(FILLMODE=0x1C, 0)`. Only 2 xrefs in FEAR.exe — this dispatcher is the centralized depth-mode entry.

**Key discovery: `*0x576ff0` is the live `IDirect3DDevice9*`.** It has 203 reads, 0 writes from FEAR.exe — initialized by the renderer DLL into FEAR.exe's data section. All 147 `SetRenderState` direct calls and the 16-stage `SetSamplerState` loop in `fcn.004F8DB0` go through this pointer. The sampler-state loop at 0x4F8DB0 (`Render_ResetDeviceState`) is a per-frame state reset that:
- Sets ZWRITEENABLE=1, ZFUNC=4 (LESS), CULLMODE=1 (NONE), ALPHATESTENABLE=0
- Loops all 16 stages: MAGFILTER, ADDRESSU/V, MIPFILTER, MINFILTER, MAXANISOTROPY
- Reads filter settings from globals `*0x56D5D4`, `*0x56D604`, `*0x56D6AC`, `*0x56D5EC`, `*0x577070`

The ALPHABLENDENABLE toggles split between two clusters:
- 0x004F6D76 (TRUE), 0x004F8E63 (FALSE) — game render path (paired with the depth-mode dispatcher above)
- 0x00516860-0x005180F2 — debug-overlay / HUD path (the 0x517134 function uses indirect setters at `*0x576ff0+0xe4` and looks like a 2D pass)

**The opaque/translucent boundary in FEAR.exe is `Render_SetDepthMode(0x4F5F60)`**, not a per-draw alpha-blend toggle. To detect "we're now in the translucent pass" globally, a livetools hook on 0x4F5F60 reading `*(ecx+0x6c)` gives the mode tag (3=opaque, 2=translucent, 0=HUD).

### Gap C — Bone palette upload site

**Not present in FEAR.exe.** The bone-palette `SetVertexShaderConstantF(start=0, count=72)` is issued entirely inside the renderer DLL, not the .exe.

Investigation: `find_vs_constants.py` reports only 3 direct `call [reg+0x178]` sites and 7 indirect. The wrapper at `fcn.0046C320` does call vtable slot 0x178:
```c
uint fcn.0046C320(void* data, uint count) {
    if (data && *0x572b68)
        (**0x572b68)->vtable[0x178/4](data, 0, count);  // LT renderer slot 0x178
    return 0;
}
```
But `*0x572b68` is the **ILTRenderer object**, not an IDirect3DDevice9. Slot 0x178 on the LT renderer is an LT-specific shader-constant API, not the D3D9 SVSCF. The 3 direct sites at 0x46C33D, 0x46E59E, 0x46E5BA push 0x8500572B / 0x8B00572B / 0x8B000002 — those are float-encoded constant data values, not register counts, confirming this is the LT renderer's set-constant call.

Confirming the .exe doesn't own the bone palette: string searches for `"BLENDWEIGHT"`, `"bone"`, `"Skin"` in FEAR.exe return **zero hits**. Skinning vocabulary lives in the renderer DLL (and in .fxo bytecode).

**Implication for the proxy:** there is no FEAR.exe SVSCF call site to hook for "is this a bone-palette upload?" detection. The SVSCF(start=0,count=72) we see at runtime is issued from inside `LithTechRenderer.dll` (or equivalent). A proxy hook on `IDirect3DDevice9::SetVertexShaderConstantF` to filter on `start==0 && count>=64` is the only static signal. The vertex declaration check (BLENDWEIGHT0+BLENDINDICES0 present) is the more reliable "this is a skinned draw" signal.

`g_LTRenderer` (renamed at kb.h line 3598) is the central object. Its vtable holds the LT-renderer API — slots 0x178 (set constants), 0x180/0x184/0x188 (draws), 0x18C (scissor), 0x190 (apply), 0x21C/0x220 (instance bind). These are LT methods, **not** offsets into the D3D9 device vtable.

### Gap D — Material parameter → sampler binding

**Not in FEAR.exe.** String searches for `"tDiffuseMap"`, `"tNormalMap"`, `"tSpecularMap"`, `"DiffuseMap"`, `"NormalMap"` all return zero hits. The strings `"DrawTranslucent"` (0x55E728), `"Translucent"` (0x55F52C), and `"DrawPrimModulateTranslucent.fx"` (0x55E384) exist but have **0 xrefs** — they're indirect runtime lookups (probably string-table or hash-based).

The shader-parameter name → sampler register binding is decided **inside each `.fxo`** (per the synthesis above, via [io_scene_jupex](https://github.com/Five-Damned-Dollarz/io_scene_jupex/blob/main/RenderMeshes.py)). FEAR.exe knows about parameters by hash, not name. There is no static path in FEAR.exe to "given this draw, which sampler holds tDiffuseMap" — the .fxo's constant table (CTAB) is the only authority.

**Implication for the proxy:** the runtime LUT-exclusion heuristic remains the only viable signal. Two alternatives to consider:
1. Hook `IDirect3DDevice9::SetPixelShader` and read the `.fxo` CTAB inline (the pixel shader bytecode is uploaded via `CreatePixelShader`; the proxy could intercept it once per shader and remember which sampler index corresponds to `tDiffuseMap`).
2. Use `fx_decomp` offline to extract sampler-name → register maps from FEAR's shipped `.fxo` files, then load that table at proxy init keyed by VS pointer or PS hash.

Neither path goes through FEAR.exe's static analysis. **The static analysis dead-ends here for the material→sampler mapping.**

### KB additions

The following entries should be appended to `patches/FEAR/kb.h`:

```c
// Render dispatch
@ 0x004F5F60 void __thiscall Render_SetDepthMode(int* mode, IDirect3DDevice9* dev);  // 4-case switch on mode[0x6c]: 0=HUD, 1=rare, 2=translucent, 3=opaque -- sets (D3DRS_ZENABLE, D3DRS_ZWRITEENABLE)
@ 0x004F8DB0 void __fastcall Render_ResetDeviceState(IDirect3DDevice9* dev);  // per-frame state reset: ZWRITE=1, ZFUNC=LESS, CULL=NONE, 16-stage sampler-state loop reading globals 0x56D5D4/0x56D604/0x56D6AC
@ 0x0046C320 uint __cdecl LTRender_SetConstantBlock(void* data, uint count);  // calls g_LTRenderer->vtable[0x178/4](data, 0, count) -- LT renderer set-constants (NOT D3D9 SVSCF); count is a vector4-count style argument

// State-update helpers (called from Render_SetDepthMode neighborhood)
@ 0x004F6336 void Render_SetDepthMode_thunk(void);  // calls Render_SetDepthMode then sets ZFUNC=LESSEQUAL, FILLMODE=SOLID

// Globals -- IDirect3DDevice9 (initialized externally by renderer DLL)
$ 0x576FF0 IDirect3DDevice9* g_pD3D9Device  // 203 reads, 0 writes; vtable slot 0xE4 (SetRenderState) hit 147x, slot 0x10C (SetTextureStageState) and 0x114 (SetSamplerState) hit in per-frame reset loop
$ 0x577190 void* g_pRenderResourceManager  // separate from D3D device; vtable slot 0x28 (resource lookup) called from object-update paths in 0x4F8xxx region

// Per-frame texture/filter globals (read by Render_ResetDeviceState)
$ 0x56D5D4 int g_DefaultMaxAnisotropy
$ 0x56D604 int g_TextureFilterMode  // 0=trilinear default, >=2=anisotropic
$ 0x56D6AC int g_PointFilterFlag
$ 0x56D5EC int g_MipmapFlag
$ 0x577070 int g_MaxSupportedAnisotropy
$ 0x577022 int g_ColorWriteEnableMask  // negated and AND'd with 1 for SetColorWriteEnable
```

### Suggested live verification

1. **Breakpoint 0x4F5F60** reading `*(ecx+0x6c)` (or `*(arg1+0x6c)` depending on calling convention). On every hit, log the mode (0/1/2/3) plus the current frame. This gives a global "opaque pass started / translucent pass started" signal that's independent of per-draw inspection.
2. **Breakpoint 0x469D50 (LTRender_DrawVB)** reading `param_1[2]+0x10` (vertex format tag). The dispatch into the LT renderer's slot 0x184 vs 0x188 vs 0x21C correlates with format tag 0x11 / 0x55 / other. This is a richer signal than the D3D9 DIP hook.
3. **Memwatch `0x576ff0`** to confirm WHEN the renderer DLL writes the D3D9 device pointer into FEAR.exe's data section — this tells us when the proxy is allowed to assume the device is live.
