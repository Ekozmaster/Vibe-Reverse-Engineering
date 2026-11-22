# RTX Remix runtime contract: what Remix reads from a D3D9 game

Read this before changing draw routing, transforms, texture stages or skinning, and before changing proxy code to fix something that looks wrong in Remix. Many visual problems are owned by Remix configuration, not by the proxy (see [Which side owns the symptom](#which-side-owns-the-symptom)).

## Sources and how to read the tags

- Runtime: `github.com/NVIDIAGameWorks/dxvk-remix` at `3ec3592` (main, 2026-11-17). Release tag `remix-1.6.1` is commit `0a6cd5b`; statements marked *main-only* are not in that release. The 32-bit bridge lives in the same repo under `bridge/`.
- User docs: `github.com/NVIDIAGameWorks/toolkit-remix` at `82e0258`, folder `docs/`.
- Paths are in dxvk-remix unless prefixed `toolkit-remix:`.
- **[S]** read in Remix source. **[D]** stated in Remix docs or the generated `RtxOptions.md`. **[I]** inferred from the cited code and not tested in a game.

If a statement here disagrees with the Remix source you are running against, the source wins and this file needs fixing. Option defaults are the built-in ones; a per-executable default compiled into Remix or a value in `rtx.conf` can override them.

## Who owns what

| Concern | Owner |
|---|---|
| World draws arrive with no vertex shader, World/View/Projection in `SetTransform`, readable vertex formats, the albedo texture selectable | The proxy |
| Which textures are UI, sky, particles, decals, terrain, water, ignored | `rtx.conf`, edited in the Remix menu (see [Setting up the scene](#setting-up-the-scene-in-remix)) |
| World conventions: z-up, handedness, scene scale | `rtx.conf` |
| Geometry the engine never submits | The game. Remix cannot restore draws it never received |
| Lights | Game D3D9 lights are converted; otherwise the fallback light or lights added by a mod |

## Which draws are path traced

Every `DrawPrimitive`, `DrawIndexedPrimitive` and both `UP` variants is classified once per draw. FVF draws take the same path as vertex-declaration draws. `src/d3d9/d3d9_device.cpp:2601-2851`, `:3039-3058` [S]

Rules in evaluation order, first match wins. `src/d3d9/d3d9_rtx.cpp:418-566` (`makeDrawCallType`) [S]

| # | Condition | Result |
|---|---|---|
| 1 | Draw index outside `rtx.drawCallRange` | Ignored |
| 2 | Vertex shader bound and `rtx.useVertexCapture` is off | Ignored |
| 3 | Primitive type is not a triangle list, strip or fan (`src/d3d9/d3d9_rtx.h:251`) | Ignored |
| 4 | Alpha test or alpha blend enabled while `rtx.enableAlphaTest` / `rtx.enableAlphaBlend` is off | Ignored |
| 5 | Inside an occlusion query | Rasterized |
| 6 | No colour render target, a target with no GPU image, or RGB colour-write not fully enabled | Ignored |
| 7 | Shadow-mask heuristic: stage 0 colour op selects a non-texture argument, and the target is square, under a quarter of the backbuffer width, with an unrecognised format | Ignored |
| 8 | Render target is listed in `rtx.raytracedRenderTargetTextures` | Path traced with its own camera |
| 9 | Render target size differs from the backbuffer | Rasterized |
| 10 | Stencil-shadow heuristic: stencil on, `STENCILFUNC=ALWAYS`, z-fail increments or decrements, z-write off | Ignored |
| 11 | UI: no vertex shader, `rtx.orthographicIsUI`, `projection[3][3] == 1` and z-write off; or a bound texture is in `rtx.uiTextures` | Rasterized, and triggers injection |
| 12 | Vertex declaration has `POSITIONT` | Rasterized (also triggers injection if `rtx.preTransformedVerticesIsUI`) |
| 13 | Anything else | Path traced |

- **Ignored** draws are dropped, not rasterized, while `rtx.enableRaytracing` is on. **Rasterized** draws run as normal D3D9. `src/d3d9/d3d9_rtx.cpp:625-631` [S]
- **Injection**: the first UI draw of a frame makes Remix render the path-traced image. Every later draw that frame is rasterized on top of it, or dropped with `rtx.skipDrawCallsPostRTXInjection`. If nothing triggers injection it happens at present. `src/d3d9/d3d9_rtx.cpp:603-641`, `src/dxvk/rtx_render/rtx_context.cpp:917-922` [S]. A game that draws UI mid-frame therefore loses the world draws that follow it [D: `RtxOptions.md`, `rtx.uiTextures`].
- **No camera, no frame**: a path-traced frame is produced only when the main camera was updated that frame. Otherwise the log says `[RTX-Compatibility-Info] Trying to raytrace but not detecting a valid camera.` `src/dxvk/rtx_render/rtx_context.cpp:578-580` [S]
- Also skipped: an indexed draw whose minimum and maximum index are equal, a draw with zero vertices, a draw whose first selected texture has no hash, and a draw whose texture is in `rtx.ignoreTextures`. `src/d3d9/d3d9_rtx.cpp:671-685`, `:1124-1127`, `:1183-1185` [S]
- Not implemented: `DrawRectPatch`, `DrawTriPatch`, N-patches. Only one user clip plane is honoured. `src/d3d9/d3d9_device.cpp:3611-3644`, `src/d3d9/d3d9_rtx.cpp:368-387` [S]

## Fixed function is the native path; vertex capture is an experimental fallback

Remix requires fixed-function geometry. It "is designed for DirectX 8 and 9 games that use a fixed function pipeline" (`toolkit-remix:docs/introduction/intro-compatibility.md:3-4`) [D], and a port's job is to deliver every world draw on that path: no vertex shader, object-space vertices, World/View/Projection in `SetTransform`. Remix also has vertex capture for shader draws. It does not make a shader game compatible and is not a substitute for converting:

- Remix calls it "experimental support for simple vertex shaders" (`toolkit-remix:docs/introduction/intro-compatibility.md:32`) [D]. The option text says it is useful for shaders "that still also set the fixed function transform matrices" (`src/d3d9/d3d9_rtx.h:43`) [S].
- How it works: Remix adds code to each translated vertex shader that takes the shader's output position back through the inverse of the fixed-function projection, view and world matrices current at the draw, and writes position, texcoord 0, normal 0 and colour 0 per vertex to a buffer. `src/dxso/dxso_compiler.cpp:3729-3966`, `src/d3d9/d3d9_rtx.cpp:229-237` [S]
- It depends on the fixed-function matrices anyway. A shader game that never calls `SetTransform` hands it identity matrices, and an identity projection means no camera. [I]
- No per-object transform, so asset replacement generally does not work on captured draws. The draw's object-to-world matrix is `D3DTS_WORLD` (`src/d3d9/d3d9_rtx.cpp:349-363`), which a game that transforms in its shaders has no reason to set, so each captured mesh is baked wherever the shader put it that frame. The geometry hash is computed from the game's input buffer before capture runs (`src/d3d9/d3d9_rtx.cpp:727-741`). One model drawn in several places, or a model that moves, is therefore one hash with nothing telling Remix where each copy is, and a replacement asset for that hash cannot be placed per object. [S for the two mechanisms, I for the consequence]
- Further limits [S]:
  - The original raster draw still executes and a capture buffer is allocated per draw. `src/d3d9/d3d9_rtx.cpp:778`, `:197`
  - No bone path: skinning data is not read when a vertex shader is bound, so skinned shader meshes arrive already posed. `src/d3d9/d3d9_rtx.cpp:836-838`
  - Vertex-shader bytecode and all vertex-shader constants are hashed into the `vertexshader` hash component. `src/d3d9/d3d9_rtx_geometry.cpp:158-169`
  - Normals are captured only when the shader has a `NORMAL0` input and `rtx.useVertexCapturedNormals` is on; the option text says this "doesn't always work as normals can be in any coordinate space". `src/d3d9/d3d9_rtx.h:44`
- A pixel shader is never analysed. With one bound, Remix takes the textures on samplers 0 and 1. `src/d3d9/d3d9_rtx.cpp:962-970`, `:1112-1115` [S]

**Why capture still matters to the proxy.** `rtx.useVertexCapture` is on by default in the source at both `remix-1.6.1` and main (`src/d3d9/d3d9_rtx.h:43`) [S], although one docs page lists it as unchecked (`toolkit-remix:docs/runtimeinterface/remix-runtimeinterface-gamesetup.md:33`). So a draw the proxy passes through with its shaders is not hidden from Remix: it is captured with whatever fixed-function view and projection are current, unless rule 11 or 12 catches it or injection already happened, and a shader-drawn HUD that is not tagged as UI can land in the scene. [I] Treat that as a hazard to manage (tag the UI, or convert the draw), never as a second way to get geometry into Remix.

## Transforms and camera

- World, view and projection are read per draw from `D3DTS_WORLD`, `D3DTS_VIEW`, `D3DTS_PROJECTION`. `src/d3d9/d3d9_rtx.cpp:349-363` [S]
- Camera classification, `src/dxvk/rtx_render/rtx_camera_manager.cpp:48-170` [S]:
  - Identity projection: no camera (type Unknown).
  - With `rtx.fusedWorldViewMode = 0`: an identity view with a non-identity world: Unknown.
  - Projection with shear above 0.01 or a field of view below 0.001 rad: rejected.
  - Otherwise render-to-texture (tagged target), sky (sky category), view model (`rtx.viewModel.enable` and viewport `MaxZ` at or below `rtx.viewModel.maxZThreshold`, or a field of view different from the main camera), else main.
- The first draw of a frame on a camera type sets that camera; later draws do not change it. `src/dxvk/rtx_render/rtx_camera.cpp:634-639` [S]
- Draws with an Unknown camera are dropped when `rtx.skipObjectsWithUnknownCamera` is on (default off); otherwise they are treated as main-camera draws without updating the camera. `src/dxvk/rtx_render/rtx_context.cpp:1084-1092` [S]
- **Supply World, View and Projection as three separate matrices.** Remix is built around a camera that moves through a world in which objects keep their positions. Find where the engine builds each matrix and capture them separately.
- A matrix that folds in projection (ViewProj, WorldViewProj) cannot be used at all: Remix decomposes the projection for field of view, aspect, near/far and handedness. `src/dxvk/rtx_render/rtx_matrix_helpers.h:44-61` [S]
- `rtx.fusedWorldViewMode` is a compatibility option for a game whose World and View cannot be separated. It is not a reason to skip separating them. With `1` (the View slot holds world*view, World is identity) Remix copies the combined matrix into the object transform and sets the camera to identity; `2` expects the World slot to hold it with View at identity. `src/dxvk/rtx_render/rtx_options.h:143-147`, `:1284`, `src/dxvk/rtx_render/rtx_context.cpp:1058-1068` [S]. Either way Remix's world space is then camera space: the camera never leaves the origin and every object's transform changes whenever the camera moves. Whatever relies on positions staying put from frame to frame has nothing stable to work with, for example instance tracking (`rtx.uniqueObjectDistance` is the distance an object may move in one frame and still count as the same object), anti-culling, and replacements or lights anchored in the world. [I]
- `rtx.resolvePreCombinedMatrices` (default on) is a second fallback of the same kind: when a draw's view is exactly identity, Remix rebuilds its world matrix from a reference camera. The source calls it "an attempt to resolve cases where games pre-combine view and world matrices" and notes that stale camera data makes object transforms lag. `src/dxvk/rtx_render/rtx_context.cpp:1103-1115` [S]
- World conventions are separate options: `rtx.zUp`, `rtx.leftHandedCoordinateSystem`, `rtx.sceneScale` (described as "sceneScale = 1cm / GameUnit"), `rtx.camera.correctProjectionYFlip`. [D: `RtxOptions.md`]
- What breaks camera detection: projection left at identity or folded into another matrix, an orthographic or sheared projection, every candidate draw being classified as sky, view model or render-to-texture, or an early draw with a different camera winning "first draw". [I]

## Vertex data

- Elements read, from any stream: `POSITION`/`POSITIONT` 0, `NORMAL` 0, the `TEXCOORD` whose usage index matches the chosen stage's `TEXCOORDINDEX`, `COLOR` 0, `BLENDWEIGHT` 0, `BLENDINDICES` 0. Tangents, binormals, `COLOR1` and other texcoord sets are not read. `src/d3d9/d3d9_rtx.cpp:251-347` [S]
- Formats [S]:
  - Fast path: position `FLOAT3`/`FLOAT4`, normal `FLOAT3`/`FLOAT4`, texcoord `FLOAT2`/`3`/`4`, colour `D3DCOLOR`. `src/dxvk/rtx_render/rtx_types.h:456-472`
  - A converter also accepts `FLOAT2/3/4`, `FLOAT16_2`, `UBYTE4N`, `DEC3N` and `D3DCOLOR`. `src/dxvk/shaders/rtx/pass/interleave_geometry.h:55-75`
  - Positions in `SHORT2`, `SHORT4`, `SHORT4N`, `USHORT*`, `UDEC3` or `FLOAT16_4` are rejected with `[rtx-interleaver] Unsupported position buffer format`. Unsupported normal, texcoord or colour formats are skipped with a warning. `src/dxvk/rtx_render/rtx_geometry_utils.cpp:871-906`
  - A game with packed positions needs the proxy to expand them to floats.
- **Normals are not required.** Without them Remix falls back to the triangle normal; `rtx.smoothNormalsTextures` generates smooth normals for tagged textures. `src/dxvk/rtx_render/rtx_scene_manager.cpp:602-611` [S]
- Strips, fans and non-indexed draws are converted to indexed triangle lists. `src/dxvk/rtx_render/rtx_types.h:474-486` [S]

## Skinning

- Fixed-function only: `D3DRS_VERTEXBLEND` must not be `DISABLE`. With 1 to 3 weights the declaration needs `BLENDWEIGHT`; `D3DVBF_0WEIGHTS` needs `BLENDINDICES` plus `D3DRS_INDEXEDVERTEXBLENDENABLE`. At most 4 bones per vertex. `src/d3d9/d3d9_rtx.cpp:831-960` [S]
- Bone matrices are read from transform state starting at `D3DTS_WORLDMATRIX(0)`. Main snapshots all 256 slots per draw; `remix-1.6.1` copies up to the highest index seen. Blend indices are read as bytes. `src/d3d9/d3d9_rtx.cpp:891-904`, `src/d3d9/d3d9_rtx_utils.cpp:16-33` [S]
- Remix performs the skinning itself, so the bind-pose buffer is what gets hashed and the hash stays stable. `src/dxvk/rtx_render/rtx_geometry_utils.cpp:267-312` [S for the skinning, I for the hash consequence]
- Because the palette is read from transform state at draw time, slots the current object does not overwrite still hold the previous object's bones. [S for the read, I for the consequence]
- CPU skinning rewrites vertex positions every frame, which changes the `positions` hash every frame. Remix's FAQ says software animation "will likely flicker" and hardware animation "should be stable". `toolkit-remix:docs/remix-faq.md:46-49` [D]

## Textures and materials

- Fixed-function texture selection, `src/d3d9/d3d9_rtx.cpp:962-1212` [S]:
  - Stages 0 to 7 are scanned. A stage with no texture is skipped. The scan stops at the first stage that has a texture bound and `COLOROP = DISABLE`.
  - A stage counts only if its texture is an argument of the colour or alpha operation.
  - 2D textures only (cube maps with `rtx.allowCubemaps`, never volumes). Textures in `rtx.lightmapTextures` are skipped.
  - At most two textures survive, ordered by lowest `TEXCOORDINDEX`. The first is the albedo and its hash is the material hash. Stage 0 is not special.
- Stage state is interpreted for the first selected stage only: operations `MODULATE` (also the fallback for unlisted operations), `SELECTARG1`, `SELECTARG2`, `MODULATE2X`, `MODULATE4X`, `ADD`, `DISABLE`; arguments `TEXTURE`, `DIFFUSE`/`CURRENT` (vertex colour), `SPECULAR`, `TFACTOR`; the stage's texture transform (projected transforms unsupported); texgen from camera-space position or normal (sphere map and reflection vector unsupported). `src/d3d9/d3d9_rtx_utils.cpp:40-147` [S]
- Render state carried into the material: alpha test, blend factors and operation, `TEXTUREFACTOR`, and whether vertex colour feeds the albedo (lighting off with `COLOR0` present, or lighting on with `COLORVERTEX` and `DIFFUSEMATERIALSOURCE = COLOR1`). `src/d3d9/d3d9_rtx_utils.cpp:149-224` [S]. A shader game that keeps non-colour data in `COLOR0` will tint its albedo with it once converted with lighting off. [I]
- Blending: only `D3DBLENDOP_ADD` with a listed source/destination pair is recognised; anything else is treated as not blended. Particle and decal handling applies only when blending is on. `src/dxvk/rtx_render/rtx_instance_manager.cpp:801-1018` [S]
- An unreplaced draw becomes an opaque PBR material built from `rtx.legacyMaterial.*` defaults plus the albedo texture. `src/dxvk/rtx_render/rtx_materials.cpp:136-173` [S]
- Fog enable, colour, range, density and mode are captured. `src/d3d9/d3d9_rtx_utils.cpp:227-245` [S]

## Hashes

Replacement assets, captures and most `rtx.conf` category lists are keyed by hash, so unstable hashes mean replacements and tags that do not stick.

- Texture hash: XXH3-64 of the CPU copy of mip 0, computed once at first upload, for 2D non-depth textures. `src/d3d9/d3d9_common_texture.cpp:652-696` [S]. `rtx.recomputeTextureHashOnWrite` (default off) re-hashes when mip 0 is locked for writing.
- Render targets get a hash from their extent plus a creation counter, so it depends on creation order. `src/d3d9/d3d9_common_texture.cpp:347-360` [S]
- Geometry hash components: `positions`, `texcoords`, `indices` (rebased to the lowest index), `geometrydescriptor` (index count, vertex count, topology, index type), `vertexlayout` (stride), `vertexshader`. `src/dxvk/rtx_render/rtx_hashing.cpp:38-126` [S]
- `rtx.geometryAssetHashRuleString` defaults to `positions,indices,geometrydescriptor`; replacements, captures and `rtx.skyBoxGeometries` match on it. `rtx.geometryGenerationHashRuleString` defaults to `positions,indices,texcoords,geometrydescriptor,vertexlayout,vertexshader`. [D: `RtxOptions.md`]
- What moves a geometry hash: CPU-skinned or otherwise rewritten vertex data, and batching, level-of-detail or culling that changes the index range or counts. [I]
- Check stability in the Remix menu: enable the debug view and select "Geometry Hash"; colours should not flicker. `toolkit-remix:docs/remix-faq.md:30-49` [D]

## Lights

- Every enabled D3D9 light is forwarded when light state changed and a path-traced draw is processed. The loop does not test `D3DRS_LIGHTING`, so lights the game left enabled reach Remix even when the proxy turns lighting off. `src/d3d9/d3d9_rtx.cpp:391-405` [S]
- Point and spot lights become sphere lights (spot adds cone shaping); directional lights become distant lights. Lights with zero or negative radiance are discarded. `src/dxvk/rtx_render/rtx_lights_data.cpp:177-205`, `:351`, `:390-424` [S]
- `rtx.fallbackLightMode` (default 1) creates a fallback light only when no lights reach Remix [D: `RtxOptions.md`]. A game that lights entirely in shaders sends no D3D9 lights. [I]

## Setting up the scene in Remix

Once geometry reaches Remix, the remaining setup is done in Remix, not in the proxy.

1. Press `Alt+X` in game, open the Developer Settings Menu, then the `Game Setup` tab. `toolkit-remix:docs/gettingstarted/learning-runtimesetup.md:79-84` [D]
2. Step 1 tags UI textures. Remix's docs treat this as the first step, after which "the game's main menu and world should display correctly". [D, same file]
3. Tag sky, then the other categories as needed. Changes are saved to `rtx.conf`. [D, same file]

Categories come from the hash of the draw's first selected texture, looked up in hash sets in `rtx.conf`: `rtx.uiTextures`, `rtx.skyBoxTextures`, `rtx.ignoreTextures`, `rtx.lightmapTextures`, `rtx.particleTextures`, `rtx.decalTextures`, `rtx.terrainTextures`, `rtx.animatedWaterTextures`, `rtx.worldSpaceUiTextures`, `rtx.playerModelTextures`, `rtx.ignoreBakedLightingTextures`, `rtx.smoothNormalsTextures`, `rtx.raytracedRenderTargetTextures` and others. `src/dxvk/rtx_render/rtx_types.cpp:388-425` [S]

Sky is also detected by heuristics: viewport `MinZ` at or above `rtx.skyMinZThreshold`, an untextured draw with an index below `rtx.skyDrawcallIdThreshold`, or `rtx.skyAutoDetect`. Sky draws are rasterized into a sky probe, not path traced. `src/dxvk/rtx_render/rtx_types.cpp:536-592` [S]

Left untagged [I]: a UI draw that is neither orthographic nor pre-transformed is path traced as world geometry; a UI texture that is also used on world geometry triggers injection early; an untagged skybox is path traced as ordinary geometry around the scene and can win "first draw" for the main camera.

## Culling

- An instance the game stops drawing is dropped after `rtx.numFramesToKeepInstances` (default 1) frames unless anti-culling keeps it. `src/dxvk/rtx_render/rtx_draw_call_tracker.cpp:469-500` [S, main]
- Game frustum culling causes "incorrect indirect bounces, light leaks, and missing shadows". `rtx.antiCulling.object.enable` (default off) keeps instances from previous frames that left the frustum. `documentation/AntiCullingSystem.md` [D]
- Anti-culling "cannot predict draw calls that have never been sent by the game". Geometry the engine never submits has to be un-culled in the game. [D, same file]

## Deployment, configuration and logs

- **32-bit game.** The Remix package is `d3d9.dll` (the 32-bit bridge client) plus the folder `.trex/` containing `NvRemixBridge.exe` (64-bit server), the 64-bit runtime `d3d9.dll` and its dependencies. `documentation/RemixRuntimeBinaries.md` [D]
- **No file named `d3d9_remix.dll` ships.** It is Remix's bridge client `d3d9.dll`, renamed so the proxy can be `d3d9.dll`. Keep `.trex/` beside it: the client locates `.trex` from its own module directory, not from its file name. `bridge/src/client/d3d9_lss.cpp:399-415`, `bridge/src/util/util_filesys.cpp:85-87` [S]. The Remix docs at the pinned commits do not describe chaining a third-party `d3d9.dll`.
- `bridge.conf` is read from the `.trex` folder. `bridge/src/util/config/config.cpp:248` [S]
- `rtx.conf`, `user.conf` and `dxvk.conf` live in the game executable's folder. Later layers override earlier ones: `dxvk.conf`, per-executable defaults compiled into Remix, `rtx.conf`, quality presets, `user.conf`. `documentation/RemixConfig.md`, `src/dxvk/rtx_render/rtx_option_layer.cpp:686-712` [D, S]
- Logs are written under `rtx-remix/logs/` next to the game executable (the `DXVK_LOG_PATH` environment variable overrides the folder): `remix-dxvk.log` for the runtime, `bridge32.log` and `bridge64.log` for the bridge. `src/util/log/log.cpp:83`, `bridge/src/util/log/log.cpp:84-86`, `bridge/src/util/util_filesys.h:59-63` [S]
- Lines starting `[RTX-Compatibility-Info]` in `remix-dxvk.log` name why draws were skipped. Each reason is logged once per run, so one line can stand for thousands of draws. `src/d3d9/d3d9_rtx.cpp:446-559` [S]
- Calls the bridge client does not forward: `DrawRectPatch`, `DrawTriPatch`, `DeletePatch` (return success without doing anything); `ProcessVertices`, `PresentEx`, `WaitForVBlank`, `CheckResourceResidency` (flagged missing). `bridge/src/client/d3d9_device.cpp:2462`, `:3286-3300`, `:3375`, `:3419`, `:3428` [S]
- `d3d9.shaderModel` in `dxvk.conf` (default 3) sets the shader model reported to the game. Some games fall back to a fixed-function or simpler path when it is lowered. `dxvk.conf:274-285` [D for the option, I for the game behaviour]

## Remix API from the proxy

- Header `public/include/remix/remix_c.h`: version 0.6.12 on main, 0.6.5 at `remix-1.6.1`. [S]
- The API is documented as 64-bit only (`documentation/RemixSDK.md`), but the bridge exports a 32-bit entry point: set `exposeRemixApi = True` in `.trex/bridge.conf` (default off, marked experimental), then after `Direct3DCreate9` resolve `remixapi_InitializeLibrary` from the bridge client module. `bridge/src/client/remix_api.cpp:568-670`, `bridge/bridge.conf` [S, D]
- Through the bridge only a subset exists: create and destroy materials, meshes and lights, `DrawInstance`, `DrawLightInstance`, `SetConfigVariable`. Not available: `Startup`, `Shutdown`, `Present`, `SetupCamera`, picking and most `dxvk_*` calls. The camera must come from the D3D9 stream. `bridge/src/client/remix_api.cpp:544-562`, `:620-649` [S, I]
- **Version gate.** While the major version is 0, the caller's minor version must equal the runtime's; otherwise `remixapi_InitializeLibrary` returns `REMIXAPI_ERROR_CODE_INCOMPATIBLE_VERSION`. `src/util/util_remix_api_version.h:73-81`; at `remix-1.6.1`: `bridge/src/client/remix_api.cpp:38-49` [S]
- The proxy template vendors the headers of `remix-1.6.1`, version 0.6.5 (`deps/bridge_api/remix/remix_c.h` and `remix.h`, copied from `public/include/remix/`), and passes that version at init (`src/shared/common/remix_api.cpp`). That pairs it with runtimes whose API minor version is 6: release 1.6.1 and main at the commit above. For a runtime with another minor version, replace both files with the ones at that runtime's tag and rebuild; a game folder copied from an older template carries 0.5.2 headers. A refused version shows in `rtx_comp/console.log` as `Failed to initialize the remixApi - Code: 8` (`REMIXAPI_ERROR_CODE_INCOMPATIBLE_VERSION`). The template builds against these headers; it has not been run against a Remix runtime with them. [I]

## Options a port touches first

Names and defaults from `RtxOptions.md` at the pinned commit.

| Option | Default | Effect |
|---|---|---|
| `rtx.useVertexCapture` | True | Experimental capture of vertex-shader draws; off drops them. Not a substitute for converting to FFP |
| `rtx.orthographicIsUI` | True | Orthographic fixed-function draws with z-write off are UI |
| `rtx.preTransformedVerticesIsUI` | False | `POSITIONT` draws are UI and trigger injection |
| `rtx.skipDrawCallsPostRTXInjection` | False | Drop everything drawn after injection |
| `rtx.fusedWorldViewMode` | 0 | Compatibility fallback when World and View cannot be separated. 1: View slot holds world*view. 2: World slot holds it |
| `rtx.resolvePreCombinedMatrices` | True | Fallback: rebuild world from a reference camera when view is identity |
| `rtx.skipObjectsWithUnknownCamera` | False | Drop draws whose camera cannot be classified |
| `rtx.zUp`, `rtx.leftHandedCoordinateSystem`, `rtx.sceneScale` | False, False, 1 | World conventions |
| `rtx.uiTextures`, `rtx.skyBoxTextures`, `rtx.ignoreTextures`, `rtx.lightmapTextures` | empty | Category hash sets |
| `rtx.skyMinZThreshold`, `rtx.skyAutoDetect` | 1, 0 | Sky heuristics |
| `rtx.viewModel.enable`, `rtx.viewModel.maxZThreshold` | False, 0 | First-person weapon camera |
| `rtx.vertexColorStrength`, `rtx.vertexColorIsBakedLighting` | 0.6, True | How vertex colour affects albedo |
| `rtx.fallbackLightMode` | 1 | 0 never, 1 when no lights arrive, 2 always |
| `rtx.ignoreGameDirectionalLights`, `...PointLights`, `...SpotLights` | False | Drop converted game lights by type |
| `rtx.antiCulling.object.enable` | False | Keep instances that left the frustum |
| `rtx.numFramesToKeepInstances` | 1 | Frames an undrawn instance survives |
| `rtx.geometryAssetHashRuleString` | `positions,indices,geometrydescriptor` | Identity used by replacements |
| `d3d9.shaderModel` (`dxvk.conf`) | 3 | Shader model reported to the game |
| `exposeRemixApi` (`bridge.conf`) | False | Remix API through the bridge |
| `alwaysCopyEntireStaticBuffer` (`bridge.conf`) | False | Try when whole pieces of geometry are missing |

## Which side owns the symptom

Check the Remix side first when it is listed first; it is the cheaper test.

| Symptom | Check first | Then |
|---|---|---|
| Raster image only, nothing path traced | `remix-dxvk.log` for "not detecting a valid camera": projection is identity or folded into another matrix | Every draw matching the UI rule (orthographic projection with z-write off) |
| World appears, then some of it is missing | A UI texture drawn mid-frame triggered injection; tag UI correctly | Classification rules 6 to 10; unsupported position format in the log |
| HUD smeared into the world | UI textures not tagged in `rtx.uiTextures` | A passed-through shader HUD being captured by vertex capture |
| Scene dark or lit wrong after geometry shows up | Sky textures not tagged; no D3D9 lights reaching Remix (`rtx.fallbackLightMode`) | Stale game lights left enabled |
| Objects vanish at screen edges, light leaks | Game-side culling; `rtx.antiCulling.object.enable` | Patch the game's culling for geometry never submitted |
| Replacements or tags do not stick, surfaces flicker | Geometry Hash debug view: unstable hashes | CPU skinning or dynamic vertex data on the game side |
| Wrong or missing albedo | Which texture Remix selected first (stage scan rules), lightmap textures not tagged | Vertex colour tinting the albedo (`rtx.vertexColorStrength`) |
| Skinned meshes explode or share poses | Fixed-function blend state and declaration requirements above | Stale `WORLDMATRIX` slots from the previous object |
| Remix API calls do nothing | `exposeRemixApi` in `.trex/bridge.conf`; version gate | |

## Hard limits

Remix cannot:
- interpret pixel shaders (it only takes the textures on samplers 0 and 1);
- recover a camera when projection is identity or folded into another matrix;
- path trace pre-transformed vertices, points, lines or patches;
- path trace draws to a target whose size differs from the backbuffer, unless the target is tagged;
- read positions in `SHORT`, `USHORT`, `UDEC3` or `FLOAT16_4` formats;
- skin shader-driven meshes from bones;
- use more than two textures per draw, volume textures, projected texture transforms, or sphere-map and reflection texgen;
- restore geometry the game never submits;
- offer camera, present or picking API calls through the 32-bit bridge.

Remix's own statement of scope: it "is designed for DirectX 8 and 9 games that use a fixed function pipeline"; shader pipelines lead "to incompatibility", and mixed games "might result in only the fixed function parts being enhanced". `toolkit-remix:docs/introduction/intro-compatibility.md:3-30` [D]
