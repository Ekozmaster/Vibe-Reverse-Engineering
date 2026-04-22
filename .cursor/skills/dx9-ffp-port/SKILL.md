---
name: 'dx9-ffp-port'
description: 'DX9 shader-to-FFP proxy porting for RTX Remix compatibility. Use when porting a DX9 shader-based game to the fixed-function pipeline. Covers static analysis, VS constant register discovery, proxy build/deploy, and iteration.'
user-invocable: true
---

# DX9 FFP Proxy — Game Porting

Port a DX9 shader-based game to fixed-function pipeline (FFP) for RTX Remix compatibility. Remix requires FFP geometry to inject path-traced lighting and replaceable assets.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. When requested, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp` for the full implementation.

**SKINNING APPROACH: FFP indexed vertex blending, NOT CPU matrix math.** When skinning is enabled, keep BLENDINDICES and BLENDWEIGHT in the vertex declaration and buffer, upload bone matrices via `SetTransform(D3DTS_WORLDMATRIX(n), &boneMatrix[n])`, enable `D3DRS_INDEXEDVERTEXBLENDENABLE = TRUE`, and set `D3DRS_VERTEXBLEND` to the weight count. CPU-side vertex skinning is a **last resort** -- it is extremely expensive and tanks frame rate. Always prefer the hardware path.

---

## What remix-comp-proxy Does

**NEVER MODIFY the template at `rtx_remix_tools/dx/remix-comp-proxy/`.** Always copy to `patches/<GameName>/` first and edit the copy.

The codebase (`rtx_remix_tools/dx/remix-comp-proxy/`) is a C++20 compatibility mod based on remix-comp-base that:

1. Captures VS constants (View, Projection, World matrices) from `SetVertexShaderConstantF`
2. Parses `SetVertexDeclaration` to detect BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL presence, and per-element byte offsets
3. Routes `DrawIndexedPrimitive`:
   - No NORMAL -> HUD/UI pass-through
   - Skinned + skinning module enabled -> FFP indexed vertex blending
   - Rigid 3D (has NORMAL) -> NULLs shaders, applies FFP transforms
4. Routes `DrawPrimitive`: world-space (has decl, no POSITIONT, not skinned) -> FFP; otherwise pass-through
5. Applies captured matrices via `SetTransform`
6. Sets up texture stages and lighting for FFP rendering
7. Chain-loads RTX Remix (`d3d9_remix.dll`)

## Source File Map

| File | Role |
|------|------|
| `src/comp/main.cpp` | DLL entry, module loading, initialization |
| `src/comp/modules/renderer.cpp` | Draw call routing -- `on_draw_indexed_prim()` and `on_draw_primitive()` |
| `src/comp/modules/d3d9ex.cpp` | `IDirect3DDevice9` hook layer -- intercepts all 119 methods |
| `src/comp/modules/skinning.cpp` | Skinning module (vertex expansion, bone upload, FFP blending) |
| `src/comp/modules/diagnostics.cpp` | Diagnostic logging to `rtx_comp/diagnostics.log` |
| `src/comp/modules/imgui.cpp` | ImGui debug overlay (F4 toggle) |
| `src/comp/comp.cpp` | Module registration order |
| `src/comp/d3d9_proxy.cpp` | Loads real d3d9 chain, DLL pre/post-load |
| `src/comp/game/game.cpp` | Per-game address init (patterns, hooks) |
| `src/comp/game/game.hpp` | Per-game variables and function typedefs |
| `src/shared/common/ffp_state.cpp` | FFP state tracker -- engage/disengage, matrix transforms, texture stages |
| `src/shared/common/ffp_state.hpp` | `ffp_state` class with all state accessors |
| `src/shared/common/config.hpp` | Config structures: `ffp_settings`, `skinning_settings`, etc. |
| `remix-comp-proxy.ini` (in `assets/`) | Runtime config: `[FFP]`, `[Skinning]`, `[Diagnostics]`, `[Remix]`, `[Chain]` |
| `build.bat` | Build script: outputs d3d9.dll proxy |

Per-game setup: copy the entire `rtx_remix_tools/dx/remix-comp-proxy/` folder to `patches/<GameName>/`, then edit `src/comp/` directly.

**Before reading remix-comp-proxy source files**, read `references/remix-comp-context.md` for a skip-list of boilerplate files you should never open.

---

## Porting Workflow

### Step 1: Static Analysis

Run ALL of the analysis scripts on the game binary. These are purpose-built for FFP porting -- they surface D3D9-specific patterns (VS constant call sites, vertex declarations, device vtable usage) that would take many individual retools commands to find manually:

```bash
python rtx_remix_tools/dx/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_ps_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/scripts/decode_fvf.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_device_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_render_states.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_texture_ops.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_transforms.py "<game.exe>"
python rtx_remix_tools/dx/scripts/classify_draws.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_matrix_registers.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_skinning.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_blend_states.py "<game.exe>"
```

Use the script output to guide deeper analysis with `retools` (decompile specific call sites) and `livetools` (trace live values).

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 -> CreateDevice)
- Which functions call `SetVertexShaderConstantF` and with what register/count patterns
- What vertex declaration formats are used (BLENDWEIGHT/BLENDINDICES = skinning)
- Where the main render loop / draw calls live

### Step 1b: Capture with the DX9 Tracer (Before Live Analysis)

Before jumping to livetools for manual tracing, deploy the D3D9 frame tracer -- it answers most FFP questions from a single capture.

1. Deploy `graphics/directx/dx9/tracer/bin/d3d9.dll` + `proxy.ini` to the game directory
2. Launch the game, get to gameplay with visible geometry
3. Trigger: `python -m graphics.directx.dx9.tracer trigger --game-dir <GAME_DIR>`
4. Analyze:
```bash
python -m graphics.directx.dx9.tracer analyze <JSONL> --shader-map          # CTAB register names
python -m graphics.directx.dx9.tracer analyze <JSONL> --const-provenance    # which code set each constant
python -m graphics.directx.dx9.tracer analyze <JSONL> --vtx-formats         # vertex declarations
python -m graphics.directx.dx9.tracer analyze <JSONL> --render-passes       # render target grouping
python -m graphics.directx.dx9.tracer analyze <JSONL> --pipeline-diagram    # mermaid pipeline flowchart
```

`--shader-map` includes CTAB headers with named parameters (e.g. `WorldViewProj c0 4`). This often answers "which registers hold which matrices" directly without manual RE.

If the tracer gives you the register layout, skip the dynamic approach in Step 2 and go straight to Step 3. Use livetools only to fill gaps the tracer didn't cover. If the game crashes with the tracer proxy, fall back to Step 2's dynamic approach.

### Step 2: Discover VS Constant Register Layout

This is the **most critical** step. Determine which VS constant registers hold View, Projection, and World matrices.

**Remix REQUIRES separate World, View, and Projection matrices.** A concatenated WVP will NOT work. If the game uploads a pre-multiplied WorldViewProj, the proxy must intercept individual matrices before concatenation. Start with `find_matrix_registers.py` to detect this.

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
- Look for 4x4 matrices (16 floats = 4 registers). Row 3 often has `[0, 0, 0, 1]` for affine transforms.

### Step 3: Copy comp/ and Configure

Copy the entire `rtx_remix_tools/dx/remix-comp-proxy/` folder to `patches/<GameName>/` (excluding `build/`). The game folder is now self-contained. Edit files directly:

1. Edit register layout defaults in `src/shared/common/ffp_state.hpp`
2. Edit `src/comp/main.cpp`: set `WINDOW_CLASS_NAME` to the game's window class
3. Customize `src/comp/modules/renderer.cpp` draw routing if needed
4. Customize `src/comp/game/game.cpp` with game-specific hooks
5. Update `kb.h` with discovered function signatures, structs, and globals

### Step 4: Build and Deploy

```bash
cd patches/<GameName>
build.bat release --name <GameName>
```

Deploy to game directory: `d3d9.dll` + `remix-comp-proxy.ini`. Place `d3d9_remix.dll` there if using Remix.

### Step 5: Diagnose with Log and ImGui

The proxy writes `rtx_comp/diagnostics.log` in the game directory after a configurable delay (default 50 seconds via `[Diagnostics] DelayMs`), then logs frames of detailed draw call data:

- **VS regs written**: which constant registers the game actually fills
- **Vertex declarations**: what vertex elements each draw uses
- **Draw calls**: primitive type, vertex count, index count, textures per stage
- **Matrices**: actual View/Proj/World values being applied

Press **F4** to open the ImGui debug overlay with live draw call stats and FFP conversion info.

Do not change the logging delay unless the user asks -- it ensures the user gets into the game with real geometry before logging begins.

**Tell the user when you need them to interact with the game** for logging or hooking purposes. They must be in-game with geometry visible for the log to be useful.

---

## Game-Specific Configuration

The VS constant register layout is defined in `src/shared/common/ffp_state.hpp` as member defaults. Edit these when porting, then rebuild:

```cpp
int vs_reg_view_start_ = 0;    int vs_reg_view_end_ = 4;
int vs_reg_proj_start_ = 4;    int vs_reg_proj_end_ = 8;
int vs_reg_world_start_ = 16;  int vs_reg_world_end_ = 20;
int vs_reg_bone_threshold_ = 20;   // first register treated as bone palette
int vs_regs_per_bone_ = 3;        // 3 = 4x3 packed, 4 = full 4x4
int vs_bone_min_regs_ = 3;        // min count to qualify as bone upload
```

**Bone config:** Run `find_skinning.py` to determine bone start register and upload pattern. Some games upload all bones at once; others upload in groups until hitting a max (e.g., groups of 15, max 75). If grouped, lower `vs_bone_min_regs_`. If bone uploads overlap with non-bone constants, raise `vs_reg_bone_threshold_`.

Other game-specific INI settings:
- `[FFP] AlbedoStage=0` -- which texture stage holds the diffuse/albedo
- `[Skinning] Enabled=0` -- only set to 1 after rigid FFP works
- `[Remix] Enabled=1` -- set to 0 to test without Remix

---

## INI Config (`remix-comp-proxy.ini`)

Runtime settings (no recompile):

```ini
[FFP]
Enabled=1
AlbedoStage=0        ; Diffuse texture stage (0-7)

[Skinning]
Enabled=0            ; Only after rigid FFP works

[Diagnostics]
Enabled=1
DelayMs=50000
LogFrames=3

[Remix]
Enabled=1
DLLName=d3d9_remix.dll

[Chain]
PreLoad=             ; Semicolon-separated DLLs to load before d3d9 chain
PostLoad=
```

---

## Architecture: What to Edit vs What to Leave Alone

| File / Section | Edit Per-Game? |
|----------------|----------------|
| `ffp_state.hpp` register layout defaults | **YES** |
| `remix-comp-proxy.ini` `[FFP] AlbedoStage` | **YES** |
| `remix-comp-proxy.ini` `[Skinning] Enabled` | **YES** (after rigid works) |
| `renderer.cpp` `on_draw_indexed_prim()` | **YES** -- main draw routing |
| `renderer.cpp` `on_draw_primitive()` | **YES** -- draw routing |
| `src/comp/main.cpp` WINDOW_CLASS_NAME | **YES** |
| `src/comp/game/game.cpp` address init | **YES** -- per-game hooks |
| `ffp_state.cpp` `setup_lighting()`, `setup_texture_stages()`, `apply_transforms()` | MAYBE |
| `ffp_state.cpp` `on_set_vs_const_f()` | MAYBE -- dirty tracking |
| `ffp_state.cpp` `on_set_vertex_declaration()` | MAYBE -- element parsing |
| `d3d9ex.cpp` hooks | NO -- infrastructure |
| `ffp_state.cpp` `engage()` / `disengage()` | NO |
| `skinning.cpp` | NO -- infrastructure |
| `diagnostics.cpp` | NO -- logging |
| `imgui.cpp` | NO -- debug overlay |

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
- World geometry omits NORMAL -> remove or change `!cur_decl_has_normal()` filter
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
| `python rtx_remix_tools/dx/scripts/find_d3d_calls.py <game.exe>` | D3D9/D3DX imports and call sites |
| `python rtx_remix_tools/dx/scripts/find_vs_constants.py <game.exe>` | `SetVertexShaderConstantF` call sites and register/count args |
| `python rtx_remix_tools/dx/scripts/find_ps_constants.py <game.exe>` | `SetPixelShaderConstantF/I/B` call sites and register/count args |
| `python rtx_remix_tools/dx/scripts/find_device_calls.py <game.exe>` | Device vtable call patterns and device pointer refs |
| `python rtx_remix_tools/dx/scripts/find_vtable_calls.py <game.exe>` | D3DX constant table usage and D3D9 vtable calls |
| `python rtx_remix_tools/dx/scripts/decode_vtx_decls.py <game.exe> --scan` | Vertex declaration formats (BLENDWEIGHT/BLENDINDICES -> skinning) |
| `python rtx_remix_tools/dx/scripts/decode_fvf.py <game.exe>` | FVF bitfield decode from SetFVF calls |
| `python rtx_remix_tools/dx/scripts/find_render_states.py <game.exe>` | SetRenderState args decoded by category |
| `python rtx_remix_tools/dx/scripts/find_texture_ops.py <game.exe>` | Texture pipeline: stages, TSS ops, sampler states |
| `python rtx_remix_tools/dx/scripts/find_transforms.py <game.exe>` | SetTransform types (World, View, Projection, Texture) |
| `python rtx_remix_tools/dx/scripts/classify_draws.py <game.exe>` | Draw call classification (FFP/shader/hybrid %) |
| `python rtx_remix_tools/dx/scripts/find_matrix_registers.py <game.exe>` | Identify View/Proj/World registers (CTAB + frequency + layout suggestion) |
| `python rtx_remix_tools/dx/scripts/find_skinning.py <game.exe>` | Consolidated skinning analysis: skinned decls, bone palettes, blend states, suggested INI |
| `python rtx_remix_tools/dx/scripts/find_blend_states.py <game.exe>` | D3DRS_VERTEXBLEND + INDEXEDVERTEXBLENDENABLE + WORLDMATRIX transforms |
| `python rtx_remix_tools/dx/scripts/scan_d3d_region.py <game.exe> 0xSTART 0xEND` | Map all D3D9 vtable calls in a code region |

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

**The `<SetVSConstF_call_addr>` is the CALL instruction in the game's .exe** (from `find_vs_constants.py` or `xrefs.py`), NOT an address inside d3d9.dll. Hook the caller, not the callee.

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

1. **Concatenated WVP instead of separate matrices**: Remix REQUIRES separate World, View, Projection. If the game uploads a pre-multiplied WVP to a single VS constant, the proxy must intercept individual matrices before concatenation. Run `find_matrix_registers.py` first — if only one register appears with high frequency, it's likely WVP.
2. **Everything white/black**: Albedo on wrong stage. Set `[FFP] AlbedoStage` in INI, trace `SetTexture` to find correct stage.
3. **Some objects missing**: Check NORMAL in vertex decl, `view_proj_valid()` at draw time.
4. **Matrices look wrong**: FFP `SetTransform` expects row-major; proxy transposes. If game stores row-major in VS constants (uncommon), remove transpose in `apply_transforms()`.
5. **Skinned meshes invisible**: `[Skinning] Enabled=1` in INI. Check bone count > 0 in diagnostics.
6. **Bones mixed between NPCs**: Stale WORLDMATRIX slots. May need game-specific reset hook.
7. **Geometry at origin**: World matrix register mapping wrong. Trace VS constant writes.
8. **World shifts after skinned draws**: WORLDMATRIX(0) clobbered by bone[0]. Proxy re-applies via dirty tracking.
9. **ImGui overlay not appearing**: Check WINDOW_CLASS_NAME in `main.cpp` matches the game's window class. Use Spy++ or `FindWindow` to verify.
10. **Game crashes on startup**: Set `[Remix] Enabled=0` to test without Remix.

### Skinning Stability: Finding Game-Specific Hook Points

The proxy's generic heuristics handle most games. If bones still leak between objects, the game needs a hook at a per-object boundary function -- one that's called once per skinned object, before its bones are uploaded.

**Finding the per-object function:**

1. **Capture** 2+ frames with the D3D9 tracer while multiple skinned NPCs are on screen
2. **Hotpaths**: `--hotpaths --resolve-addrs <game.exe>` -- look at callers of bone-range `SetVertexShaderConstantF` writes
3. **Caller histogram**: `--callers SetVertexShaderConstantF` -- the function that appears N times per frame (N = number of skinned objects) is the per-object boundary
4. **Live confirm**: `livetools trace <candidate_addr> --count 50` -- with 3 NPCs, expect ~3 hits/frame
5. **Static context**: `callgraph.py --up` + `decompiler.py` on the caller -- confirm it loops over objects
