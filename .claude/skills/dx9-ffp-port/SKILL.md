---
name: dx9-ffp-port
description: Use when porting a game for RTX Remix or to the fixed-function pipeline, working on renderer.cpp / ffp_state / remix-comp-proxy.ini / draw routing / VS constants / vertex declarations / matrix mapping / skinning, building or deploying a remix-comp-proxy patch, or diagnosing rendering issues in a patched game (white geometry, missing objects, wrong transforms, ImGui F4, diagnostics.log).
---

# DX9 FFP Proxy -- Game Porting

Port a DX9 shader-based game to fixed-function pipeline (FFP) for RTX Remix compatibility. Remix requires FFP geometry to inject path-traced lighting and replaceable assets: its native path reads transforms from `SetTransform`, object-space vertices in formats it can decode, and the albedo from the texture stages. Remix's vertex capture of shader draws is an experimental fallback, not an alternative to converting: it still needs the fixed-function view and projection, cannot skin, and gives Remix no per-object transform, so asset replacement generally does not work on captured draws.

**Before changing draw routing, transforms, texture stages or skinning, and before changing proxy code to fix how something looks in Remix, read [references/remix-runtime-contract.md](references/remix-runtime-contract.md).** It states, with Remix source citations, which draws Remix path traces, how it picks the camera and the albedo texture, what it cannot do, and which symptoms are fixed in `rtx.conf` (texture categories such as UI and sky) instead of in the proxy.

**NEVER MODIFY TEMPLATE CODE.** The following directories are read-only templates:
- `rtx_remix_tools/dx/remix-comp-proxy/` — remix-comp-proxy framework template

To create a game patch, **copy** the template to `patches/<GameName>/` and edit the copy. If the user asks you to edit remix-comp-proxy code, always confirm whether they mean the template or a game-specific copy under `patches/`. Only modify the template if the user **explicitly** says to change the template itself.

**SKINNING IS OFF BY DEFAULT.** Do NOT enable skinning in `remix-comp-proxy.ini`, modify skinning code, or discuss skinning infrastructure unless the user explicitly asks for character model / bone / skeletal animation support. When requested, read `src/comp/modules/skinning.hpp` and `src/comp/modules/skinning.cpp` for the full implementation.

**SKINNING APPROACH: FFP indexed vertex blending, NOT CPU matrix math.** When skinning is enabled, the correct approach is:
1. Keep BLENDINDICES and BLENDWEIGHT elements in the vertex declaration and vertex buffer
2. Upload bone matrices via `SetTransform(D3DTS_WORLDMATRIX(n), &boneMatrix[n])` for each bone
3. Enable `D3DRS_INDEXEDVERTEXBLENDENABLE = TRUE`
4. Set `D3DRS_VERTEXBLEND` to the appropriate weight count (e.g. `D3DVBF_3WEIGHTS`)
5. Let the FFP hardware pipeline do the blending

Remix does the blending itself from this state: it needs the vertex shader cleared and reads at most 4 bones per vertex and palette slots `WORLDMATRIX(0..255)`. The game keeps submitting the same bind-pose vertex buffer, so the geometry Remix identifies does not change from frame to frame. The template relies on that too: it converts each vertex range of a skinned mesh once and reuses the result, so a game that rewrites a skinned mesh's vertex buffer is not handled; a `D3DUSAGE_DYNAMIC` source buffer, made to be rewritten, is not converted and stays on the game's shaders, as does a `D3DUSAGE_WRITEONLY` buffer outside the managed and system-memory pools, which Direct3D does not let the proxy read back.

CPU-side vertex skinning (manually multiplying vertices by bone matrices) is a **last resort only**. It is extremely expensive, tanks frame rate, and should only be considered when FFP indexed vertex blending is not feasible. Always prefer the hardware path above.

---

## What remix-comp-proxy Does

Each game folder under `patches/<GameName>/` is a self-contained remix-comp-proxy project (copied from `rtx_remix_tools/dx/remix-comp-proxy/`). It is a d3d9.dll proxy that:

1. Captures VS constants (View, Projection, World matrices) from `SetVertexShaderConstantF` via `ffp_state::on_set_vs_const_f`
2. Parses `SetVertexDeclaration` via `ffp_state::on_set_vertex_declaration` to detect BLENDWEIGHT+BLENDINDICES (skinned), POSITIONT (screen-space), NORMAL and TEXCOORD0 presence on any stream, and per-element byte offsets; `SetFVF` with a non-zero FVF clears that declaration state, so an FVF draw counts as a draw with no declaration
3. Routes `DrawIndexedPrimitive` via `renderer::on_draw_indexed_prim`:
   - No NORMAL -> HUD/UI pass-through
   - Skinned -> pass-through with shaders while `[Skinning] Enabled=0` (the default). With `Enabled=1`, `skinning::draw_skinned_dip()` draws it with FFP indexed vertex blending
   - Rigid 3D (has NORMAL) -> NULLs shaders, applies FFP transforms. While FFP is engaged the wrapper holds back `SetVertexShader` and `SetPixelShader`; the game's last shaders return before any passthrough draw, UP or patch draw, `ProcessVertices`, `ValidateDevice`, `GetVertexShader`/`GetPixelShader`, `CreateStateBlock` or `BeginStateBlock`
4. Routes `DrawPrimitive` via `renderer::on_draw_primitive`: world-space (has decl, no POSITIONT, not skinned) -> FFP; otherwise pass-through
5. Applies captured matrices via `ffp_state::apply_transforms` -> `SetTransform`
6. Sets up texture stages and lighting for FFP rendering (stages 1-7 disabled to prevent stale auxiliary textures reaching Remix)
7. Loads the real d3d9 chain (RTX Remix `d3d9_remix.dll` or system d3d9) via d3d9_proxy. `d3d9_remix.dll` is not a file Remix ships: it is Remix's own `d3d9.dll` (the 32-bit bridge client) renamed, with Remix's `.trex/` folder kept beside it

## Codebase File Map

| File | Role |
|------|------|
| `src/comp/modules/renderer.cpp` | Draw routing -- `on_draw_indexed_prim()` and `on_draw_primitive()` |
| `src/comp/modules/renderer.hpp` | `drawcall_mod_context` for save/restore state around draws |
| `src/shared/common/ffp_state.cpp` | Core FFP state tracker -- engage/disengage, transforms, texture stages |
| `src/shared/common/ffp_state.hpp` | FFP state class with all accessors |
| `src/shared/common/config.hpp` | Config structure parsed from `remix-comp-proxy.ini` |
| `src/comp/main.cpp` | DLL entry, d3d9 proxy init, window finder, config loading |
| `src/comp/comp.cpp` | Module init: registers renderer, diagnostics, skinning, imgui |
| `src/comp/d3d9_proxy.cpp` | Loads real d3d9 chain, DLL pre/post-load, forwarded exports |
| `src/comp/modules/d3d9ex.cpp` | `IDirect3DDevice9` / `IDirect3D9` wrapper + exported Direct3DCreate9 |
| `src/comp/modules/d3d9ex.hpp` | D3D9 wrapper class declarations |
| `src/comp/modules/diagnostics.cpp` | 50-sec delay, 3-frame diagnostic log to `rtx_comp/diagnostics.log` |
| `src/comp/modules/skinning.cpp` | Optional skinning module (vertex expansion + bone upload) |
| `src/comp/modules/skinning.hpp` | Skinning class declaration |
| `src/comp/modules/imgui.cpp` | ImGui debug overlay (F4) with FFP tab |
| `src/comp/game/game.cpp` | Per-game address init (patterns, hooks) |
| `src/comp/game/game.hpp` | Per-game variables and function typedefs |
| `remix-comp-proxy.ini` (in `assets/`) | Runtime config: register layout, albedo stage, skinning, diagnostics, DLL chain |
| `build.bat` | Build script: outputs d3d9.dll proxy. `build.bat [release\|debug] [--name Name]` |

**`rtx_remix_tools/dx/remix-comp-proxy/` is the TEMPLATE.** Each game gets a full copy under `patches/<GameName>/` — the entire folder is self-contained and can be distributed as a standalone repo. Edit `src/comp/` directly in the game's copy.

**Before reading remix-comp-proxy source files**, read [references/remix-comp-context.md](references/remix-comp-context.md) for a skip-list of boilerplate files (~7,000 lines) you should never open, with summaries of what they do. It also lists the ~1,200 lines of files that actually matter for per-game work.

---

## Porting Workflow

### Step 1: Static Analysis

Run the analysis scripts to understand the game's D3D9 usage:

```bash
# Core discovery
python rtx_remix_tools/dx/scripts/find_d3d_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_device_calls.py "<game.exe>"
python rtx_remix_tools/dx/scripts/classify_draws.py "<game.exe>"

# Shader constants and vertex formats
python rtx_remix_tools/dx/scripts/find_vs_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_ps_constants.py "<game.exe>"
python rtx_remix_tools/dx/scripts/decode_vtx_decls.py "<game.exe>" --scan
python rtx_remix_tools/dx/scripts/decode_fvf.py "<game.exe>"

# Skinning analysis (bone palettes, blend weights, suggested INI)
python rtx_remix_tools/dx/scripts/find_skinning.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_blend_states.py "<game.exe>"

# Render state and texture pipeline
python rtx_remix_tools/dx/scripts/find_render_states.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_texture_ops.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_transforms.py "<game.exe>"
python rtx_remix_tools/dx/scripts/find_surface_formats.py "<game.exe>"
```

Scripts are fast first-pass scanners -- surface candidate addresses only. Always follow up with `retools` and `livetools` for deep analysis.

`find_device_calls.py`, `find_surface_formats.py` and `scan_d3d_region.py` count a call through one of the first 32 device slots (`Present`, `Reset`, the `Create*` methods) only when its object comes from where the game's high-slot device calls get theirs, usually a device global named in the output's first line. A game that reaches its device only through `this` (`[[esi+4]+0x3C]`) has nothing learned, and those calls are listed with `--unconfirmed` (labelled `unconfirmed` in place by `scan_d3d_region.py`) instead; check them there before concluding the game never calls `Present` or creates a render target.

**Alternative: DX9 Tracer capture.** Deploy the tracer proxy (`graphics/directx/dx9/tracer/`) to capture a full frame, then analyze with `--matrix-flow`, `--vtx-formats`, `--shader-map`, and `--const-provenance` to discover the register layout without reverse engineering the binary.

Key things to find:
- How the game obtains its D3D device (Direct3DCreate9 -> CreateDevice)
- Which functions call `SetVertexShaderConstantF` and with what register/count patterns
- What vertex declaration formats are used (BLENDWEIGHT/BLENDINDICES = skinning)
- Where the main render loop / draw calls live

### Step 2: Discover VS Constant Register Layout

This is the **most critical** step. Determine which VS constant registers hold View, Projection, and World matrices.

**Remix REQUIRES separate World, View, and Projection matrices.** A concatenated WorldViewProj (WVP) or ViewProj (VP) matrix will NOT work -- Remix needs individual matrices to apply its own camera and per-object transforms. If the game uploads a pre-multiplied WVP, the proxy must intercept the individual W, V, P matrices *before* the game concatenates them. This is the #1 source of broken Remix ports.

Remix has a compatibility option for a combined WorldView matrix (`rtx.fusedWorldViewMode`). It is a last resort for when World and View cannot be recovered separately, not a reason to skip that reverse engineering: in fused mode Remix treats camera space as world space, so no object keeps a stable world position. With the projection folded in there is no fallback at all: Remix finds no camera and renders no path-traced frame. See "Transforms and camera" in [references/remix-runtime-contract.md](references/remix-runtime-contract.md).

**Start with the matrix register finder:**
```bash
python rtx_remix_tools/dx/scripts/find_matrix_registers.py "<game.exe>"
```
This cross-references SVSCF call patterns, shader CTAB names, and frequency analysis to suggest a register layout. Always verify its output with runtime data.

**Static approach:** Decompile call sites:
```bash
python -m retools.decompiler <game.exe> <call_site_addr> --types patches/<project>/kb.h
```

**Dynamic approach:** Trace `SetVertexShaderConstantF` live:
```bash
python -m livetools trace <func_entry_addr> --count 50 \
    --read "[esp+8]:4:uint32; [esp+0x10]:4:uint32; *[esp+0xc]:64:float32"
```
Captures: startRegister, Vector4fCount, and the first 4 vec4 constants of actual float data.

- `<func_entry_addr>` must be the **entry** of `SetVertexShaderConstantF` itself, not the address of a `call` instruction. Read it from the device vtable at runtime with three pointer reads (x86; each prints `As ptr: [-> 0x...]`): `python -m livetools mem read <dev_global> 4 --as ptr` gives the device object, where `<dev_global>` is the address of the game's global `IDirect3DDevice9*` variable (the same address `dipcnt on` takes); `mem read <device> 4 --as ptr` gives its vtable; `mem read <vtable + 0x178> 4 --as ptr` (slot 94) gives the entry. A `call` instruction is refused. To watch a single call site instead, add `--probe` and read the arguments one slot lower, because no return address has been pushed yet: `python -m livetools trace <call_site> --probe --count 50 --read "[esp+4]:4:uint32; [esp+0xc]:4:uint32; *[esp+8]:64:float32"`.
- The offsets are the stdcall layout at function entry: `[esp+4]` device, `[esp+8]` StartRegister, `[esp+0xc]` pConstantData, `[esp+0x10]` Vector4fCount. Offsets are decimal unless written with `0x`.
- Each record's `caller` is the return address, which tells you which call site made the upload.

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
- **Watch for concatenated matrices:** If the game only uploads one matrix per draw (e.g. WVP at c0-c3), the individual W/V/P are being multiplied before upload. Trace back to find where the multiplication happens -- you need to capture W, V, P separately before that point.

### Step 3: Set Up Per-Game Project

**IMPORTANT:** `rtx_remix_tools/dx/remix-comp-proxy/` is the **template**. NEVER edit it directly. Each game gets a full copy of the framework.

1. Copy the entire `rtx_remix_tools/dx/remix-comp-proxy/` folder to `patches/<GameName>/` (excluding `build/`)
2. Edit `src/comp/` directly in the game's copy — this is the per-game customization layer
3. Set the register layout in `assets/remix-comp-proxy.ini`, section `[FFP.Registers]` (see Register Layout below)
4. Edit `src/comp/main.cpp`: set `WINDOW_CLASS_NAME` to the game's window class
5. Customize `src/comp/modules/renderer.cpp` draw routing if needed (see Decision Trees below)
6. Customize `src/comp/game/game.cpp` with game-specific address init if hooks are needed
7. Update `kb.h` with discovered function signatures, structs, and globals

The game folder is now fully self-contained and can be distributed as a standalone git repo.

### Step 4: Build and Deploy

From the game folder:
```bash
cd patches/<GameName>
./build.bat release --name <GameName>
```

Use `./build.bat`: it runs from both Git Bash and PowerShell, while a bare `build.bat` is not found in either.

The build needs Visual Studio 2022 or later (any edition, or the Build Tools) with a Windows SDK and nothing else; `build.bat` finds the newest one through `vswhere`, wherever it is installed. The Direct3D 9 headers, DirectXMath and the image decoder (WIC) come from the Windows SDK, and the proxy does not use D3DX, so the built `d3d9.dll` needs no `d3dx9_*.dll` beside the game. The build is x86 only. A game folder copied from the template while it still used D3DX keeps its own dependency: it includes `d3dx9.h` and links `d3dx9.lib` from its `deps/dxsdk/Lib/x86/`, a file from Microsoft's legacy DirectX SDK that the template never shipped.

The build produces `d3d9.dll` in `patches/<GameName>/build/bin/release/`. Deploy to the game directory:
- `d3d9.dll` (the game loads this as its d3d9 proxy)
- `remix-comp-proxy.ini`
- For Remix: the RTX Remix runtime for x86 games. Rename its `d3d9.dll` (the bridge client) to `d3d9_remix.dll` and copy it together with its `.trex/` folder; the bridge finds `.trex/` next to itself. `[Remix] DLLName` in the INI names the renamed file.
- `assets/.trex/bridge.conf` into the game's `.trex/` folder only if the port uses the Remix API (its one active line is `exposeRemixApi = True`). The template is built against the API headers of Remix release 1.6.1, and a runtime only accepts callers built against its own API minor version; see "Remix API from the proxy" in the reference before pairing the port with another runtime

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

## Register Layout (`[FFP.Registers]`)

The VS constant register layout is read from `remix-comp-proxy.ini` when the game starts. Changing it takes a game restart, not a rebuild:

```ini
[FFP.Registers]
ViewStart=0
ViewEnd=4
ProjStart=4
ProjEnd=8
WorldStart=16
WorldEnd=20
```

`Start` is the first register of a matrix and `End` is one past its last, always `Start + 4`, so a matrix in c8-c11 is `Start=8`, `End=12`. The proxy reads each matrix as 4 consecutive vec4 registers (16 floats) from its `Start`. Draws are converted only once all four registers of View and of Projection have been written in one frame, in any order and by any number of uploads. `find_matrix_registers.py` prints this section with what it could determine and leaves the rest as comments. A range outside c0-c255 or an `End` other than `Start + 4` makes the proxy log an error in `rtx_comp/console.log` and fall back to the layout above. The log also states the layout in use: `[FFP] Registers: View=c0-c3 Proj=c4-c7 World=c16-c19`.

Every number in the INI is decimal: `ViewStart=8`, not `c8` or `0x8`. A `;` comment may follow it on its line (`ViewStart=8 ; view`). A value that is not a number is logged in `rtx_comp/console.log` (`[Config] [FFP.Registers] ViewStart=c8 is not a decimal number; using 0`) and the key keeps its default. Switches such as `Enabled` take `1` or `0`.

FFP draws use the world matrix the game uploaded last to the `World` registers, carried across scenes and frames; until the first upload after device creation or `Reset` they use identity.

Edit `assets/remix-comp-proxy.ini` in the game folder (the build copies it next to `d3d9.dll`) and the copy already deployed beside the game.

### Bone Configuration for Skinning

Three `[Skinning]` keys say which `SetVertexShaderConstantF` uploads are bone palettes. They only matter with `Enabled=1`:

```ini
[Skinning]
Enabled=0
; Lowest register a palette upload may start at
BoneThreshold=20
; 3 = 4x3 packed bones (most common), 4 = full 4x4
RegsPerBone=3
; Smallest upload, in registers, taken as bones
BoneMinRegs=3
```

Before enabling skinning, run `find_skinning.py`: it suggests `BoneThreshold` and `RegsPerBone`. The proxy takes the most recent upload that starts at or above `BoneThreshold`, covers at least `BoneMinRegs` registers and holds a whole number of bones as the palette for the skinned draws that follow. A game that uploads a small palette per mesh part needs `BoneMinRegs` no larger than its smallest upload. If other constants at or above `BoneThreshold` are mistaken for bones, raise `BoneThreshold`. With `Enabled=1`, View, Projection and World all have to lie below `BoneThreshold`; otherwise the proxy logs `[Skinning] BoneThreshold=... is not above every matrix in [FFP.Registers]` and uses the default register and bone layouts. A game that fills one palette with several uploads at different registers is not handled: only the last upload counts, and a vertex that names a bone past its end is left to the shaders.

`skinning::draw_skinned_dip` leaves a skinned draw to the game's shaders when no upload has matched yet (no palette), when the source vertex buffer is `D3DUSAGE_DYNAMIC` or is `D3DUSAGE_WRITEONLY` outside the managed and system-memory pools, when the device's declaration is not the one the proxy classified (a state block changed it), when its position, blend elements, normal or first texcoord is not on stream 0, when its normal is not `FLOAT3`/`DEC3N`/`UBYTE4N` or a texcoord not `FLOAT2`-`FLOAT4`/`FLOAT16_2`, when its position is not `FLOAT3`/`FLOAT4`, its blend indices not `UBYTE4`/`D3DCOLOR` or its blend weights not `FLOAT1`-`FLOAT4`/`UBYTE4N`, when the stream's stride is smaller than the vertex the declaration describes, or when a vertex is blended, with a weight that is not zero, by a bone index at or past the palette's bone count. `D3DCOLOR` indices are taken in memory byte order, the order a shader gets from `D3DCOLORtoUBYTE4`; a game shader that reads them as a plain colour (index 0 in the red byte) needs bytes 0 and 2 swapped in the game copy's `skinning.cpp`. A draw whose `NumVertices` runs past the end of the vertex buffer is converted for the vertices the buffer holds. The converted vertices are cached per source buffer, range and declaration in up to 64 default-pool buffers of 48 bytes per vertex, each spanning `MinVertexIndex + NumVertices` vertices so the draw needs no negative base index; each cache entry holds a reference to its source buffer and declaration until it is evicted, the device is `Reset`, the game releases its last reference to the device, or the game creates another device.

Bone indices are not limited to the device's `D3DCAPS9::MaxVertexBlendMatrixIndex`: Remix reports 8 there but reads the whole `WORLDMATRIX(0..255)` palette.

## INI Config (`remix-comp-proxy.ini`)

Runtime settings that don't require recompile (`[FFP.Registers]` and the bone keys of `[Skinning]` are described above):

```ini
[FFP]
Enabled=1
AlbedoStage=0
; Albedo texture stage (0-7). Set to whichever stage the game binds the diffuse texture.

[Skinning]
Enabled=0
; Only set to 1 after rigid FFP works correctly.
; Run find_skinning.py to determine bone register layout before enabling.

[Diagnostics]
Enabled=1
DelayMs=50000
LogFrames=3

[Remix]
Enabled=1
DLLName=d3d9_remix.dll

[Chain]
PreLoad=
PostLoad=
; Semicolon-separated DLLs/ASIs to load before/after the d3d9 chain.
; Example: PreLoad=patch.dll;fix.asi
```

---

## Architecture: What to Edit vs What to Leave Alone

Each game folder under `patches/<GameName>/` is a **self-contained** copy of the full remix-comp-proxy framework. Edit files directly in the game's copy.

| Component (in `patches/<GameName>/`) | Edit Per-Game? |
|-----------|----------------|
| `remix-comp-proxy.ini` register layout, albedo stage, skinning, diagnostics, chain | **YES** — no rebuild |
| `src/comp/main.cpp` WINDOW_CLASS_NAME | **YES** |
| `src/comp/modules/renderer.cpp` draw routing | **YES** -- main draw routing |
| `src/comp/game/game.cpp` address init and hooks | **YES** -- per-game hooks |
| `src/comp/game/structs.hpp` game structs | **YES** -- per-game data structures |
| `src/shared/common/ffp_state.cpp` engage/disengage/transforms | MAYBE -- only for unusual FFP needs |
| `src/shared/common/config.hpp` | MAYBE -- add new INI sections if needed |
| `src/comp/modules/d3d9ex.cpp` | NO -- forwards all 119 methods; passes a device through once a newer one exists |
| `src/comp/modules/diagnostics.cpp` | NO -- generic frame logger |
| `src/comp/modules/imgui.cpp` | NO -- debug overlay |
| `src/shared/` everything else | NO -- framework code |

### DrawIndexedPrimitive Decision Tree

```
ffp.is_enabled() AND ffp.view_proj_valid()?
+-- NO  -> passthrough with shaders
+-- YES
    +-- ffp.cur_decl_is_skinned()?
    |   +-- [Skinning] Enabled=1 -> skinning::draw_skinned_dip() (FFP indexed vertex blending;
    |   |   shaders without a bone palette or with vertices it cannot read)
    |   +-- [Skinning] Enabled=0 -> passthrough with shaders (the default)
    +-- !ffp.cur_decl_has_normal()?
    |   +-- passthrough (HUD/UI)
    |   GAME-SPECIFIC: remove this filter if world geometry lacks NORMAL
    +-- else (rigid 3D mesh)
        +-- ffp.engage() + draw + restore
```

**What the wrapper does not see.** A state block created or recorded through the device holds the game's shaders, but `Capture()` and `Apply()` on the block bypass the wrapper: a capture while FFP is engaged records no shaders. A rigid mesh whose normal is on another stream than 0 is converted; only its classification is tested, since converted draws are unlit in the test program. Only the device created last is converted: an older one draws with the game's shaders, stays that way after the newer one is released, and a tracer capture mixes the calls of both. Device calls must come from one thread.

**Passthrough does not hide a draw from Remix.** Remix's experimental vertex capture is on by default (`rtx.useVertexCapture`) and picks up passed-through vertex-shader draws, using whatever fixed-function view and projection are current. That is a hazard to manage, not a way to skip converting world geometry. A passed-through HUD stays out of the scene only if it uses pre-transformed vertices or its texture is tagged in `rtx.uiTextures` (Remix's orthographic-UI rule applies only to draws without a vertex shader). Remix also does not need vertex normals, so "no NORMAL" is only this proxy's guess at what is UI.

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

- **Check the Remix side before changing proxy code.** Once geometry reaches Remix, a dark scene, a HUD smeared into the world, missing sky or world geometry that disappears after the UI draws are usually fixed by tagging textures in Remix (`Alt+X` -> Developer Settings Menu -> `Game Setup`, saved to `rtx.conf`), not by editing the proxy's lighting or routing. `rtx-remix/logs/remix-dxvk.log` names why draws were skipped in lines starting `[RTX-Compatibility-Info]`. The symptom table in [references/remix-runtime-contract.md](references/remix-runtime-contract.md) says which side to check first.
- **Concatenated WVP/VP instead of separate matrices**: This is the **#1 Remix porting mistake**. Remix requires separate World, View, and Projection matrices passed via `SetTransform`. If the game uploads a pre-multiplied WorldViewProj or ViewProj to a single register range, the proxy gets a combined matrix it can't decompose. **Fix**: find where the game multiplies W*V*P (or V*P) and hook that function to capture the individual matrices *before* concatenation. Use `find_matrix_registers.py` to detect this -- if CTAB shows "WorldViewProj" or only one matrix register is uploaded per draw, you have this problem. `rtx.fusedWorldViewMode` only covers a combined WorldView and is a last resort, not the fix.
- **Matrices look wrong**: D3D9 FFP `SetTransform` expects row-major. `ffp_state::apply_transforms` transposes column-major VS constants. If the game stores matrices row-major in VS constants (uncommon), remove the transpose in `ffp_state::apply_transforms`.
- **Everything is white/black**: Albedo texture is on stage 1+, not stage 0. Set `AlbedoStage` in `remix-comp-proxy.ini`, or trace `SetTexture` calls to find the correct stage.
- **Some objects render, others don't**: Check whether missing geometry has NORMAL in its vertex decl. Check `ffp.view_proj_valid()` is true at draw time. DrawPrimitive routes on decl presence + no POSITIONT + not skinned.
- **Skinned meshes not converted**: Skinned draws pass through with their shaders until `[Skinning] Enabled=1` is set in `remix-comp-proxy.ini`. With it set, verify `boneStart=` and `numBones=` are non-zero in `rtx_comp/diagnostics.log`; if they are zero, no upload matched `BoneThreshold`, `RegsPerBone` and `BoneMinRegs`, and skinned draws stay on the game's shaders. Only `DrawIndexedPrimitive` draws are converted, and the bone matrices are used as uploaded: a game whose shader multiplies the blended position by a separate world matrix needs that multiplication added in the game copy's `skinning.cpp`.
- **Bones mixed up between NPCs**: Stale WORLDMATRIX slots from a previous object. The game may need a game-specific reset hook at a per-object boundary -- see Skinning Stability below.
- **Game crashes on startup**: Set `[Remix] Enabled=0` in `remix-comp-proxy.ini` to test without Remix.
- **Proxy loads but does nothing (two beeps after a wait of 30 seconds or more)**: `WINDOW_CLASS_NAME` in `comp/main.cpp` matched no window, so the modules never loaded. `rtx_comp/console.log` in the game directory lists the class name of every visible window the proxy saw (`> HWND: ... Class: ...`) and ends with `Could not find '...' Window. Not loading RTX Compatibility Mod.` Copy the game window's class name from that file.
- **Geometry at origin / piled up**: World matrix register mapping wrong. Re-examine VS constant writes via `livetools trace` or DX9 tracer `--const-provenance`.
- **World geometry shifts after skinned draws**: bone 0 is written to `WORLDMATRIX(0)`, which is `D3DTS_WORLD`. The proxy sends the world matrix again after each skinned draw (`ffp_state::restore_world`). If rigid geometry still moves, check whether the game uploads its world matrix where the proxy does not look for it.
- **ImGui overlay not appearing**: Press F4. Check that `WINDOW_CLASS_NAME` is correct and the window was found (`rtx_comp/console.log`). Check for DirectInput hook conflicts.

### Skinning Stability: Finding Game-Specific Hook Points

The proxy's generic heuristics handle most games. If bones still leak between objects, the game needs a hook at a per-object boundary function -- one that's called once per skinned object, before its bones are uploaded.

**Finding the per-object function:**

1. **Capture** 2+ frames with the D3D9 tracer while multiple skinned NPCs are on screen
2. **Hotpaths**: `--hotpaths --resolve-addrs <game.exe>` -- look at callers of bone-range `SetVertexShaderConstantF` writes
3. **Caller histogram**: `--callers SetVertexShaderConstantF` -- the function that appears N times per frame (N = number of skinned objects) is the per-object boundary
4. **Live confirm**: `livetools trace <candidate_addr> --count 50` -- with 3 NPCs, expect ~3 hits/frame
5. **Static context**: `callgraph.py --up` + `decompiler.py` on the caller -- confirm it loops over objects
