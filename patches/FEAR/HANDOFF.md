# FEAR → RTX Remix Port — Handoff

**As of:** 2026-05-11 evening — runtime LUT-exclusion albedo selector landed and confirmed firing in-game (11–13 LUTs detected per frame, scaling threshold via `AlbedoLutRatio=0.086`). Translucent-pass passthrough also landed but **A/B-disabled** — enabling it caused a per-frame camera flicker timed to sky motion (suspect: persistent `D3DRS_ALPHABLENDENABLE` state leakage misclassifying opaque draws as translucent, splitting Remix's matrix view per frame). Static analysis filled four FEAR.exe gaps — most useful new fact is `Render_SetDepthMode` at `0x4F5F60`, a 4-case ZENABLE+ZWRITEENABLE pair dispatcher (case 2 = translucent, case 3 = opaque) that gives a clean global pass-transition signal once hooked. See the *evening* TL;DR below. **Earlier today (14:15)**: primary sky texture confirmed and bound (`0xC39F926BC0BE15EE`).
**Workspace rule:** every build is auto-deployed into `FEAR Ultimate Shooter Edition/` via `deploy.ps1`. `deploy.ps1` now accepts `-GameDir <path>` for testing against alternate installs (e.g. CLEAN). The user does not copy files manually.

---

## TL;DR (2026-05-11 evening — runtime LUT-exclusion albedo + translucent A/B test)

### What shipped

Three INI-toggleable behaviors added to the proxy (`[FFP]` section of [`remix-comp-proxy.ini`](assets/remix-comp-proxy.ini)):

| Key | Default | What it does |
| --- | --- | --- |
| `AlbedoLutExclusion` | `1` | Each frame, count per-stage texture appearances across all 8 stages. Textures with count ≥ `ceil(AlbedoLutRatio × draws_in_frame)` in the previous frame are flagged as shared LUTs (shadow, deferred lighting, env maps) and excluded from albedo selection. The proxy then binds stage 0 to the **lowest stage 0–4 whose current texture is NOT in the LUT pool**. Falls back to static `AlbedoStage` when all stages 0–4 hold LUTs or on the first frame. |
| `AlbedoLutRatio` | `0.086` | Per-frame fraction-of-draws threshold. `0.086 = 500/5800` from the FEAR analysis where 13 LUTs were detected in a 5800-DIP gameplay frame. Scales automatically with scene complexity (menu vs. level). |
| `TranslucentPassthrough` | **`0`** (was `1`, A/B-disabled this session) | If enabled, draws with `D3DRS_ALPHABLENDENABLE=TRUE AND D3DRS_ZWRITEENABLE=FALSE` skip FFP engage and run through the original VS/PS path. Intended to fix water-iridescence (Blocker #3). |

Implementation seams (per-game copy, NOT template):

- [`src/shared/common/config.hpp`](src/shared/common/config.hpp) — `ffp_settings` struct grew three fields
- [`src/shared/common/ffp_state.cpp`](src/shared/common/ffp_state.cpp) — `tex_appearance_` map, `lut_pool_` set, `lut_frame_draws_` counter, `record_draw_for_lut_pool()`, `is_translucent_pass()`. Pool rebuild + diagnostic log line in `on_present()`; both flushed on `on_reset()`.
- [`src/comp/modules/renderer.cpp`](src/comp/modules/renderer.cpp) — `record_draw_for_lut_pool()` called per draw; `is_translucent_pass()` gated as a peer branch after the `cur_decl_has_normal()` check in both `on_draw_indexed_prim` and `on_draw_primitive`.

### What's confirmed

- **LUT pool fires.** Running console.log shows lines like `[FFP] LUT pool: 11 entries, threshold=14, draws_last_frame=166` and `[FFP] LUT pool: 13 entries, threshold=35, draws_last_frame=407` — pool size 11–13, threshold scales 14–38 with draw count. Matches the 13-LUT prediction from the offline analysis.
- **Original LUT pool threshold (absolute count `500`) was wrong for in-game testing** — the captured scenes were 200 DIPs/frame, so the threshold never tripped and the pool stayed empty (identical behavior to old code). Fixed by switching to ratio-based threshold this session.
- **`Render_SetDepthMode` at `0x4F5F60` is the clean global pass signal.** Per gap analysis appended to [`findings_render_dispatch_20260511.md`](findings_render_dispatch_20260511.md#L141-L167) — 4-case switch on `*(arg+0x6c)` setting (ZENABLE, ZWRITEENABLE) pairs: case 0 = HUD, case 1 = rare, case 2 = translucent, case 3 = opaque. Hooking this gives a clean "we're now in the translucent pass" tag that doesn't rely on persistent D3D9 state.
- **FEAR is hybrid, not fully indirected.** FEAR.exe makes ~147 direct `SetRenderState` calls to `*0x576FF0` (the live `IDirect3DDevice9*`) but routes draws through `g_LTRenderer` vtable slot `0x184`. Material parameter → sampler binding lives in `.fxo` bytecode only — there is no FEAR.exe static path to the diffuse sampler, so the runtime LUT-exclusion heuristic remains the only viable solution short of CTAB interception or offline `fx_decomp`.

### What's broken / open

1. **Camera flicker timed to sky motion** when `TranslucentPassthrough=1`. Disabled by default this session pending the A/B test in-progress. Hypothesis: `is_translucent_pass()` reads persistent D3D9 state — `ALPHABLENDENABLE=TRUE` set by a real translucent draw can leak into the next opaque draw if the engine doesn't reset it, splitting Remix's per-frame matrix view between FFP and shader paths. Fix path: rework detection to (a) add `D3DRS_ZENABLE=TRUE` to the check to exclude HUD draws, OR (b) hook `Render_SetDepthMode` at `0x4F5F60` for a clean global tag.
2. **Visual verification of the LUT-exclusion gain is still pending.** User reported "still doesn't look correct" after v2 build — flicker (above) is the leading symptom, but it's possible the heuristic is also misfiring in actual gameplay. The 92.3% offline accuracy used a 5800-DIP gameplay frame; the in-session captures so far were menu/transition scenes (200–438 DIPs/frame).
3. **Blocker #4 (white NPC bodies)** untouched — skinning remains the next major effort. Bone palette is uploaded from inside the renderer DLL (not FEAR.exe), so the only static signal is the vertex decl carrying `BLENDWEIGHT0+BLENDINDICES0` (already detected).

### Next-session plan

1. Confirm `TranslucentPassthrough=0` removes the camera flicker (in-progress test).
2. If yes — rework `is_translucent_pass()` to use a non-leaking signal, then re-enable.
3. Visually evaluate the gun (Blocker #1), stray sky panels (Blocker #2), and overall world rendering with LUT-exclusion in a real gameplay scene (not menu). Use the in-game Remix UI (Alt+X) to inspect hashes on previously-broken surfaces.
4. If LUT-exclusion produces wrong albedo selection in some specific shader/decl class, consider per-shader override tables keyed on VS pointer.
5. Skinning (Blocker #4) — separate effort, gated on the above.

---

## TL;DR (2026-05-11 ~14:15 update — primary sky texture identified and bound; 3-4 stray panels remain)

**Sky texture identification pipeline established.** `patches/FEAR/livetools_logs/find_sky.py` and `find_sky2.py` parse RTX Remix USDC captures via `usd-core` (installed via `pip install usd-core` this session), extract every mesh's vertex AABB + vertex count + material binding (the binding lives on the *parent Xform*, not the Mesh prim — see [find_sky.py:67](livetools_logs/find_sky.py#L67)), and rank candidates by cumulative extent. The dominant signal is unambiguous: across the 3 new outdoor captures (14-05-31, 14-05-43, 14-09-04), texture `0xC39F926BC0BE15EE` appears on **25 distinct meshes with max extent 390000 units and cumulative extent 11.4M units** — every other texture is on at most 3 meshes with max extent ≤330K. Adding this single hash to `rtx.skyBoxTextures` made the cloudscape appear at the top of the outdoor view.

**Capture hotkey rebound to `=`.** The user requested rebinding the Remix capture hotkey from default `CTRL+SHIFT+Q` to `=`. The correct option (per dxvk-remix `util_keybind.h`) is `rtx.captureHotKey = OEM_PLUS` — added to [`rtx.conf`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx.conf) at the CLEAN install. Three captures were successfully triggered with `=` in this session, confirming the rebind works under the b7de9a96 server build.

**Final `rtx.conf` skyBoxTextures binding** (as edited collaboratively this session):

```
rtx.skyBoxTextures = 0x5698A937F0FC5AA2, 0x5921933F6BBB32DB, 0x593CB5B9E9DB7F00, 0x7120A631D68D88EE, 0xC39F926BC0BE15EE, 0xD54E44E85BAE0B63
```

The 6-entry list includes:

- `0xC39F926BC0BE15EE` — **confirmed primary sky** (25 meshes, 390K extent). This one is doing the visible work.
- `0xD54E44E85BAE0B63`, `0x5698A937F0FC5AA2`, `0x5921933F6BBB32DB`, `0x593CB5B9E9DB7F00` — large-extent (300-330K) candidates, each on 1-3 meshes. Added defensively to see if they were the stray gray panels. **They aren't** — no visible difference vs. just the C39F binding alone.
- `0x7120A631D68D88EE` — pre-existing in rtx.conf from another game (kept by user choice). In the new FEAR captures this hash appears on a single 4-vert / 600-unit mesh — definitely not sky. Doesn't hurt anything but contributes nothing.

**Remaining sky issue — 3-4 stray gray rectangular panels in screenshot 1's bird's-eye exterior view.** Hypothesis: those panels are FFP-rendered terrain/horizon backdrop using the **default `AperturePBR_Model.mdl` material** with no albedo binding (so Remix renders them as plain gray). Or they're hitting the proxy's shader-passthrough path so Remix never sees their material binding. Diagnosis next session: in-game Remix UI (Alt+X) click directly on a gray panel → read its texture hash from the selected-mesh inspector → add to `rtx.skyBoxTextures` if it's a real sky face, or to `rtx.ignoreTextures` if it's a render-quirk fallback.

**User-driven manual rtx.conf additions this session** (not from my script — the user identified these via the in-game Remix UI):

```
rtx.worldSpaceUiBackgroundTextures = -0x8A041B24245A49C7
rtx.ignoreTextures = 0x17C88908898EC4B1, 0x1F984242B0F2DDF9, 0x25B553BB70D79EDE, 0x335C167D9C89D673,
                     0x60EB826E108F40D5, 0x9DAB87B7055E9B7B, 0xD8619671CBEDA20B, 0xDDD7D325CE9F08BA,
                     0xF7EB00287800979F, -0x446EA1CC4C8D7204, -0x94BDDB7881C6F5C6
rtx.uiTextures = 0x3C7450F5E764A06F, 0xA0FA2DD756D1B3A3, 0xA1D1483DD9B67BB7, 0xB214C050D40F5A53,
                 0xE0E7E6C0CF67EA35, 0xEF36A93DE9D547FF, -0x33B202D302B65CAA
```

Of these, only `0xB214C050D40F5A53` (UI) and `0x94BDDB7881C6F5C6`, `0x446EA1CC4C8D7204`, `0x17C88908898EC4B1` (ignored) exist in the captured `textures/` dir. The rest were picked from the live Remix UI mid-session. They're now durable in rtx.conf regardless of capture state.

**Filesystem changes this session:**

- `patches/FEAR/livetools_logs/find_sky.py` — single-capture sky-candidate analyzer (vertex AABB extents, material-binding extraction). Uses `pxr.Usd` from `usd-core==26.5`.
- `patches/FEAR/livetools_logs/find_sky2.py` — multi-capture aggregator. Groups texture-hash usage by cumulative extent across all 3 new captures. Output below.
- `patches/FEAR/livetools_logs/sky_candidates.csv` — CSV dump of every mesh's bbox + material from the latest capture.
- 3 new Remix captures at `a:\…\EditionCLEAN\rtx-remix\captures\` (the `02-*` captures are warehouse interior with no sky in frame; the `14-*` ones have real outdoor sky data):
  - `capture_2026-05-11_14-05-31.usd` — 214 meshes, 77KB
  - `capture_2026-05-11_14-05-43.usd` — 258 meshes, 89KB
  - `capture_2026-05-11_14-09-04.usd` — 310 meshes, 104KB
- [`rtx.conf`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx.conf) at CLEAN install — added `rtx.captureHotKey = OEM_PLUS`, expanded `rtx.skyBoxTextures` from 1 to 6 entries, user added `rtx.ignoreTextures`, `rtx.uiTextures`, `rtx.worldSpaceUiBackgroundTextures`. Backup at `rtx_pre_captureHotKey_*.conf.bak`.

**`find_sky2.py` output for archival reference** (top 10 textures by cumulative mesh extent across all 3 outdoor captures):

```
TexHash               #Meshes   MaxExt      SumExt        Verts     Y>500   Y<-1000   Captures
C39F926BC0BE15EE      25        390000      11377202      95939     0       49        3   ← PRIMARY SKY (confirmed working)
D54E44E85BAE0B63      1         330000        990000        96      0       3         3   ← added, no visible change
5698A937F0FC5AA2      1         324924        974773      6540      0       0         3   ← added, no visible change
5921933F6BBB32DB      1         315094        945280     12480      0       3         3   ← added, no visible change
593CB5B9E9DB7F00      3         327424        658449      2114      0       0         2   ← added, no visible change
17C88908898EC4B1     31           5700        143374     14123      1       44        2   ← user added to ignoreTextures
8761EB375A82AAF7      6           7900         93850       310      0       16        3
60D3E3E0F0FB7602     22           4950         91866     14335      0       45        3   ← generic shared (lightmap?)
682CBD5B3AC94A4D      4           8000         58100       277      0       11        3
747A7FC12EB55164      4           6722         58067      5628      0       12        3
```

**Visible state at 14:15 (from user screenshots)**:

- **Sky top of frame**: dark dramatic cloudscape now rendering correctly (the C39F texture). Previously: pure black void. ✅
- **Sky middle of frame**: 3-4 stray gray rectangular panels still floating in the void. Not fixed by adding the 4 next-largest candidates. ❌ (next-session task)
- **Water**: unchanged iridescent rainbow specular — blocker #3.
- **Warehouse exterior**: walls, floor, crate stacks all textured correctly (the AlbedoStage=1 fix continues to hold).
- **Indoor warehouse**: gun still flat-gray polys (blocker #1), white NPC body still white (blocker #4), floor now appears darker/blacker than the 13:15 screenshots — likely path-traced shadows from the dark overcast sky now actually contributing to lighting.

**Next session — concrete tasks in order:**

1. **Hunt the remaining 3-4 stray gray sky panels via in-game Remix UI.** Alt+X → click on a stray gray panel → read its texture hash from the selected-mesh inspector → add to `rtx.skyBoxTextures` if it's another sky face. If clicking returns "no texture / fallback material", that's diagnostic — the mesh isn't sampling any texture, which means either (a) the proxy's `setup_albedo_texture` is binding null to it, or (b) it's a shader-path passthrough draw whose material Remix can't identify. (a) is fixable in `ffp_state.cpp`; (b) requires routing those draws into the FFP path.
2. **Tackle blocker #1 (gun).** Plan: livetools `collect` filtered by low NumVertices DIPs (gun < 500 verts), correlate each gun DIP with its preceding 8 `SetTexture` calls, see which stage holds the gun's diffuse. Hypothesis from 13:15 captured data: gun probably uses stage 0 (not 1). Fix would be a per-draw albedo heuristic in [`ffp_state::setup_albedo_texture`](src/shared/common/ffp_state.cpp#L346) — pick the first stage whose texture is non-null AND not in a "shared/fallback" set. **No rebuild yet — needs the runtime data first.**
3. **Tackle blocker #3 (water iridescent rainbow).** Plan: in [`renderer::on_draw_indexed_prim`](src/comp/modules/renderer.cpp#L110), query `D3DRS_ALPHABLENDENABLE` via `GetRenderState` at draw time. If blended, either route as shader-passthrough (sacrifices path-traced reflections but preserves original blend) or apply a translucent-tagged stage setup that Remix categorizes via `rtx.translucentTextures`. Rebuild + deploy + visual verify.
4. **Optional bonus: examine the 14-05-31 capture's `0x7120A631D68D88EE` 600-unit mesh.** That hash was in rtx.conf as "sky" from before this session — it's now confirmed *not* sky in FEAR, only a tiny 4-vert mesh. Could safely remove from `rtx.skyBoxTextures`, freeing it for the actual stray-panel hash once identified.

**One-line summary for the next session bootstrap**: sky is half-fixed (top cloudscape works, mid-frame stray panels remain); skyBoxTextures has the right primary hash; gun/water/white-NPC are unchanged blockers from 13:15.

---

## TL;DR (2026-05-11 ~13:15 update — AlbedoStage=1 fixes white-wash, gun/sky/water now the remaining blockers)

**The texture pipeline works.** Changing `[FFP] AlbedoStage=0 → 1` in [assets/remix-comp-proxy.ini:48](assets/remix-comp-proxy.ini#L48) instantly restored textured surfaces on the warehouse walls, floor, garage doors, and crates. Two screenshots taken at 13:14 on the CLEAN install (PID 145124, ~5 min uptime, no crash) show:

- **Interior shot**: gun in foreground, blue corrugated-metal garage door on the left, warehouse interior wall (blue metal) at the back, dark concrete floor with clearly-readable yellow "DO NOT BLOCK" stencil, an upright white crate on the right with visible cardboard texture. A bright-white humanoid blob (NPC or launcher figure) floats mid-frame against the back wall.
- **Exterior bird's-eye shot** (likely an out-of-bounds clip): rooftops, stacks of cargo containers with subtle texture detail, iridescent rainbow water/ocean filling the right half (path-tracer specular on a translucent surface), and stray gray-and-white sky quads floating in a black void where the skybox should be.

**What's now solved (vs the 03:04 state):**

- World geometry positions: ✅ correct (rtx.conf `leftHandedCoordinateSystem + correctBakedTransforms`)
- Material capture: ✅ 67 per-mesh `mat_*.usd` + 62 `*.dds` per scene
- Diffuse texture sampling: ✅ visible on every textured surface (walls, floor, crates, sky panels)
- Bridge stability: ✅ 5+ minutes steady-state, no `d3d9_remix.dll+0xf0cc` crash this run

**Remaining blockers** (each is its own bug, ranked by how visible they make the scene "wrong"):

1. **Player weapon renders as flat-gray polygons** with zero texture sampling. The gun decl probably carries POSITION+NORMAL+TEXCOORD but uses a different stage layout than world geometry — likely binds the diffuse on stage 0 (not 1), or uses a special weapon-specific shader path that the proxy's draw router classifies into the wrong bucket. Worth dumping the gun's decl + texture bindings via a targeted breakpoint on its specific draw call.
2. **Skybox is a black void with stray gray quads.** The classic Remix "sky replacement claimed the wrong texture or the FFP sky pass is being routed to world geometry" pattern. The pre-existing `rtx.skyBoxTextures = 0x7120A631D68D88EE` line in rtx.conf does NOT match any captured FEAR texture hash (verified: not in `rtx-remix/captures/textures/`), so it's a no-op leftover from another game and not the cause. The real fix is either to identify FEAR's actual sky texture hashes and set them in `rtx.skyBoxTextures`, or route FEAR's sky-pass draws into Remix's sky-detection path.
3. **Water surfaces show iridescent rainbow specular.** Path-tracer is treating the translucent water as a smooth chrome surface with no roughness or absorption. Either Remix needs FEAR's water material to be tagged "translucent" via the AperturePBR_Translucent.mdl path, or the FFP color/alpha op combination we apply (`SELECTARG1`) doesn't preserve enough info for Remix to identify translucents.
4. **Some objects remain white** (NPC bodies, certain crate variants) — a subset of the world geometry. Could be different stage layout per draw, or could be vertex-color-based lighting that our `SELECTARG1` strips out and we don't apply a fallback diffuse for.

**Runtime instrumentation captured this session** (saved to [`patches/FEAR/livetools_logs/`](livetools_logs/) — 170 MB across 6 files):

- `collect_albedo1_20260511_1308.jsonl` / `_v2_…1310.jsonl` — 20s each of SetTransform + DrawIndexedPrimitive + SetTexture hits (~110K records). Stages 0–4 all carry per-draw textures: **stage0=124 unique tex, stage1=119, stage2=118, stage3=66, stage4=33, stage5=6, stage6=3.** All DIPs are `D3DPT_TRIANGLELIST`. SetTransform breakdown: 2233 `WORLDMATRIX(0)` (all identity per prior dump), 1933 `D3DTS_VIEW`, 1933 `D3DTS_PROJECTION`. Steady-state rate: 1464 DIP/s, 3796 SetTexture/s, 305 SetTransform/s under Remix path-tracing.
- `collect_svscf_20260511_1311.jsonl` — 15s SetVertexShaderConstantF capture. **Dominant pattern: `start_reg=0 count=4`** (the per-object WVP matrix at c0-c3) 7586 times, plus `start_reg=0 count=72` 2849 times (likely shader-path bone palettes — confirms FEAR's character rigging is shader-driven not FFP-skinned, matching static analysis).
- `analysis_albedo1_v2_20260511_1310.txt` / `analysis_svscf_20260511_1311.txt` — pre-computed Python summaries of the above.
- `console_albedo1_livetools_run_20260511_130720.log` / `diagnostics_albedo1_livetools_run_20260511_130720.log` — preserved console + diagnostics snapshot from the prior crashed AlbedoStage=1 run (180KB diagnostics; the actual frame capture data).

**Filesystem changes this session:**

- [`assets/remix-comp-proxy.ini`](assets/remix-comp-proxy.ini#L48): `AlbedoStage=0 → 1` with rationale comment. INI-only change; **no rebuild needed**, redeploy via `deploy.ps1 -GameDir <install>`.
- New persistent dir `patches/FEAR/livetools_logs/` for keeping JSONL traces + analysis text across sessions.

**Next session — concrete tasks in order:**

1. **Hunt the gun's draw call to find its decl + stage layout.** Set a `bp` on `DrawIndexedPrimitive` filtered by a small `NumVertices` range (the gun is low-poly — see screenshot 1, faceted gray polys → likely <500 verts) and grab the active vertex decl + each `SetTexture` immediately preceding it. If stage 0 holds the gun's diffuse and stage 1 doesn't, we need per-pass `AlbedoStage` routing rather than a global setting — option: add a "primary diffuse heuristic" in `setup_albedo_texture` that picks the first non-fallback non-shared texture across stages.
2. **Find FEAR's actual sky texture hashes.** Take a fresh Remix capture (F11 / Insert) on the warehouse, find the meshes whose vertices land in screen-top areas (sky panels), dump their material refs from the USDC, and map back to texture hashes. Then set `rtx.skyBoxTextures = <comma-separated>` in [`rtx.conf`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx.conf).
3. **Tag water draws as translucent.** FEAR's water uses `D3DRS_ALPHABLENDENABLE=1` per surface. If the proxy's draw router can detect alpha-blended FFP draws, it could either skip them entirely (let the shader path produce the original blend), or feed them through a different stage setup that signals translucent to Remix. Tradeoff: skipping them means no path-traced reflections; tagging them means picking the right Remix material category.
4. **(Optional) Find `ffp_state` static address** so we can `mem read` the live `cur_texture_[0..7]` array and `memwatch` it for state-change debugging. Failed once via byte-pattern scan (register layout `0,4,4,8,16,20` not found in proxy `.data`) — needs either PDB symbol resolution through a custom Frida script or a different distinctive byte pattern. Not blocking, but would speed up further iteration.

---

## Older TL;DR (2026-05-11 ~03:04 update — matrix-flow problem solved, textures/lighting then the blocker)

**The matrix mystery is closed.** A per-draw game-matrix dump added to [diagnostics.cpp:240-249](src/comp/modules/diagnostics.cpp) (delay lowered from 180s → 60s in [remix-comp-proxy.ini:75](assets/remix-comp-proxy.ini)) revealed that across all 60 captured draws:

- `SetTransform(D3DTS_WORLDMATRIX(0))` = **identity**, every draw
- `SetTransform(D3DTS_VIEW)` = real camera view; 6 unique values across 3 frames (main camera + a shadow/reflection sub-camera per frame)
- `SetTransform(D3DTS_PROJECTION)` = real perspective matrix, with `znear` varying per pass (skybox passes get `znear=-0.01`, world geometry `znear=-4.3`)
- Vertex positions in the buffers are already in **world space** (e.g. DIP #9 `pos=(26116.21, -1289.39, -13774.00)` — that's level world coords, not object-space)

So FEAR's actual world transform is **baked into the vertex stream**, and the engine passes identity to D3D9's FFP world matrix. This is the exact pattern that the Remix runtime documents as a "baked transforms" case ([RtxOptions.md](https://github.com/NVIDIAGameWorks/dxvk-remix/blob/main/RtxOptions.md)): *"individually captured meshes appear to be way off in the middle of nowhere OR instanced meshes appear to all have identity xform matrices, enabling will attempt to correct this."* That description matches our capture exactly — the 02:32 USD has 130 mesh files all carrying world-space vertex positions with no per-mesh transforms.

**Two `rtx.conf` settings added to fix it** ([rtx.conf](../../FEAR%20Ultimate%20Shooter%20Edition/rtx.conf) on dirty install and `a:\…\FEAR Ultimate Shooter EditionCLEAN\rtx.conf` on CLEAN):

```
rtx.leftHandedCoordinateSystem = True      # LithTech Jupiter EX is left-handed; Remix defaults to right-handed
rtx.capture.correctBakedTransforms = True  # derive per-mesh transforms from world-space vertex AABBs
```

After the 03:03 relaunch on CLEAN, the warehouse scene rendered with **geometry in plausibly correct positions and orientations** (visible: a corridor, stacked crates with vestigial "PACIFIC RIM" lettering, a dead body on the floor, the player's weapon at the bottom of the frame, an arch+door at the end of the corridor with a glowing red iris/reticle target overlay). No mirroring, no origin pile-up. The matrix-flow problem from 02:33 is functionally solved.

**Remaining blocker — surfaces render as washed-out white:** the floor, walls, crates, weapon, and body all appear in low-saturation light grey/white. A faint texture signal is visible on the gun (metal sheen), the body (skin tone hints), and the crate labels (just barely readable). Hypotheses to test next session:

1. **FFP texture stages aren't reaching Remix's material pipeline.** Our [`ffp_state::setup_texture_stages` in `ffp_state.cpp:441-465`](src/shared/common/ffp_state.cpp#L441) sets stage 0 to `SELECTARG1 + D3DTA_TEXTURE` and disables stages 1-7. That works under system d3d9 FFP, but Remix may be sampling a different stage or expect a specific texcoord index that we're not delivering. The 02:32 capture's `materials/` folder has 130+ `.mdl` files — Remix DID extract material hashes — but the runtime may be rendering with the fallback `AperturePBR_Model.mdl` (the 5 generic AperturePBR_*.mdl files in `materials/`) for all draws instead of the per-mesh ones.
2. **Path-traced lighting is fully blowing out the scene.** No FEAR lights are being recognized; ambient may be at 1.0; the path tracer's exposure may be way too bright. Need to open the Remix UI (Alt+X — the "Welcome to RTX Remix. Use ALT,X" banner is visible in the screenshot) and check `rtx.tonemap.exposure`, `rtx.fallbackLightMode`, and the per-mesh material assignment.
3. **`rtx.skyBoxTextures = 0x7120A631D68D88EE`** (an existing line in rtx.conf, predating this session) may be claiming a non-sky texture as skybox, which Remix replaces with environment lighting that washes everything to white. Worth testing with this line commented out.
4. **Albedo stage might be wrong.** [`AlbedoStage=0`](assets/remix-comp-proxy.ini#L48) currently. The 02:32 diag log shows FEAR binds 8 textures per draw (`tex0..tex7`); under Remix the per-stage binding may have shifted vs system d3d9. Worth iterating `AlbedoStage=1..7` to find which stage holds the diffuse.

**No `d3d9_remix.dll+0xf0cc` crash this session** — FEAR exited cleanly at 03:01:35 after a manual close, and at 03:03 ran without issue until manual close again. The crash from the 02:33 session has not reproduced in two consecutive launches with the new rtx.conf, but the runtime was also shorter (~55s and ~60s respectively); the prior crash was at +196s. Stability is now an *open* question, not a confirmed blocker.

**Captured Remix data from the 02:32 baseline (pre-rtx.conf-fix) lives at:**

```text
a:\SteamLibrary\steamapps\common\FEAR Ultimate Shooter EditionCLEAN\rtx-remix\captures\
  capture_2026-05-11_02-32-01.usd     ← 55 KB scene root (binary USDC)
  meshes/                              ← 130 mesh_XXXXXXXXXXXXXXXX.usd files
  materials/                           ← 130 mat_XXX.usd + 5 AperturePBR_*.mdl
  textures/                            ← 10 MB of .dds extracts
  skeletons/                           ← empty (no skinning, expected)
  thumbs/
```

A follow-up capture with the rtx.conf fix in place is the obvious next data point but was not taken this session.

**Diagnostic log with the matrix dump (the key evidence for the diagnosis):**

```text
a:\…\EditionCLEAN\rtx_comp\diagnostics_baseline_20260511_030040.log  (392 KB, 60 DIPs across 3 frames)
```

Sample for DIP #2 (a world-geometry draw):

```text
DIP #2  decl=… numVerts=8 stride=60 [POSITION/COLOR/TEXCOORD/NORMAL/TANGENT/BINORMAL]
  vtx0 pos: -2899.821045, -904.288696, -3115.251221   ← world-space
  game_WORLD:                                          ← identity
    row0: 1, 0, 0, 0
    row1: 0, 1, 0, 0
    row2: 0, 0, 1, 0
    row3: 0, 0, 0, 1
  game_VIEW:                                           ← real camera matrix
    row0: 0.479, -0.456, -0.750, 0
    row1: 0.007,  0.857, -0.516, 0
    row2: 0.878,  0.242,  0.414, 0
    row3: 4031.624, 524.686, -1078.150, 1
  game_PROJ:                                           ← real perspective
    row0: 0.803, 0, 0, 0
    row1: 0, 1.433, 0, 0
    row2: 0, -0.004, 1, 1
    row3: 0, 0, -0.010, 0
```

**Filesystem changes this session:**

- Added per-draw `game_WORLD/VIEW/PROJ` dump to [`diagnostics.cpp:240-249`](src/comp/modules/diagnostics.cpp#L240) (logged for first 20 draws per captured frame). Required new accessors in [`ffp_state.hpp:87-89`](src/shared/common/ffp_state.hpp#L87) (`game_view()`, `game_proj()`, `game_world()`).
- Dropped `[Diagnostics] DelayMs` from 180000 → 60000 in [`assets/remix-comp-proxy.ini`](assets/remix-comp-proxy.ini#L75). Restore to 180000 once stability is reconfirmed.
- Added [`FEAR Ultimate Shooter Edition/rtx.conf`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx.conf) (the dirty install had none until now) with the same handedness + bakedTransforms fix as CLEAN.
- Updated existing CLEAN `a:\…\rtx.conf` with the same two lines plus explanatory comments. Backup at `rtx_pre_handedness_20260511_030013.conf.bak`.

**Next session — three concrete tasks in order:**

1. Take a fresh Remix capture (F11 → Capture in the Remix UI, or Insert via NvRemixLauncher32) with the rtx.conf fix active and diff the `meshes/<hash>.usd` content against the 02:32 baseline. Specifically check whether `xformOp:transform` is now non-identity for the mesh instances.
2. Open Remix UI (Alt+X) in-game and inspect `rtx.tonemap.exposure`, `rtx.fallbackLightMode`, per-mesh material assignment. If everything is rendering with `AperturePBR_Model.mdl` (the generic fallback), the FFP-stage-0 SELECTARG1 path may not be tagged correctly for Remix's material capture.
3. Iterate `[FFP] AlbedoStage` 0 → 1 → 2 (rebuild + redeploy each time, fast cycle) and observe whether textures snap into focus on any stage. The 02:32 diag log shows 8 textures bound per draw — one of them is the diffuse, but FEAR's pixel shader composes them, and our SELECTARG1 only takes one.

---

## TL;DR (2026-05-11 ~02:33 update — RTX Remix bridge handshake succeeds, FEAR renders through Remix)

**FEAR + a03c16db bridge + minimal `bridge.conf` + deferred `init_debug_lines()` = stable rendering through Remix for ~3 minutes.** Bridge log reaches `Server side D3D9 Device created successfully!` 9 seconds after launch (matching Brotherhood's working baseline), the proxy's per-draw `SetTransform` interceptor captures World/View/Proj matrices into [ffp_state](src/shared/common/ffp_state.cpp), and the bridge processes ~72K commands over 3 minutes before crashing with a *separate* `d3d9_remix.dll+0xf0cc` access violation that's unrelated to startup. The 2026-05-07 fixes (fog-off + SELECTARG1 stage 0) ride along untouched — FFP world geometry that already rendered correctly in `[Remix]=0` should now path-trace.

**Three combined changes unblocked the chain:**

1. **Bridge swap b7de9a96 → a03c16db** (`patches/FEAR/deps/remix-bridge-x86/d3d9.dll` and both game-dir `.trex/` runtimes). b7de9a96 under driver `32.0.15.9636` hung at the kernel call between `Server started up...` and `Registering exit callback` (per HANDOFF's archived Cause A — that hang is now reliably reproducible AND escapable by switching to a03c16db). The working a03c16db build came from the user's `A:\SteamLibrary\steamapps\common\Assassins Creed Brotherhood\.trex\` install. Old b7de9a96 `.trex/` preserved as `.trex.b7de9a96.bak/` in both DIRTY and CLEAN game dirs.

2. **`bridge.conf` minimized** ([assets/.trex/bridge.conf](assets/.trex/bridge.conf)). All FEAR-specific overrides except three are now commented out with explanatory notes:
   - `exposeRemixApi = True` (load-bearing for the proxy's `remix_api::initialize()`)
   - `infiniteRetries = True` (required — the server's CONTINUE-wait timeout is hardcoded short in BOTH bridge versions; FEAR's LithTech+DirectInput client takes ~17ms from ACK→Continue which exceeds it. Brotherhood works without this only because its Ubisoft engine sends Continue in <1ms.)
   - `disableTimeouts = True` (companion belt-and-suspenders for the same CONTINUE-wait race)
   `commandTimeout`, `startupTimeout`, `commandRetries`, `ackTimeout`, `logLevel = Trace` — all reverted to defaults.

3. **Deferred `init_debug_lines()` from `remix_api::initialize()` to `begin_scene_callback_internal()`** ([src/shared/common/remix_api.cpp:15-22, :676-679](src/shared/common/remix_api.cpp)). The 4× `RemixApi_CreateMaterial` calls used to fire inside `Direct3DCreate9` — *before any `IDirect3DDevice9` existed* — posting commands on the bridge's Device queue when no device was created. This stalled the server's Module-queue handler such that FEAR's next call (`IDirect3D9Ex::GetDeviceCaps`) waited forever, Windows logged `AppHangTransient`, and the bridge eventually saw the process exit. Moving the call to BeginScene (guarded by the existing `m_debug_lines_initialized` flag) makes materials run after the device is created. This is the actual root cause of every prior post-handshake failure mode — the bridge wasn't broken, the call order was.

**Working configuration (verified on CLEAN install at 02:29:19 → 02:32:35):**

```text
[02:29:42.714] info:  NVIDIA RTX Remix Bridge Server  Version: remix-main+a03c16db
[02:29:43.178] info:  D3D9 interface object creation succeeded!
[02:29:43.179] info:  Handshake completed! Now waiting for incoming commands...
[02:29:48.235] info:  Server side D3D9 Device created successfully!
[02:29:57.173] info:  Server side D3D9 Device created successfully!   ← LithTech's real device
```

Proxy console mirrors this:

```text
[INFO] [d3d9] m_pIDirect3D9->CreateDevice
[INFO] [d3d9] Device wrapper @ 0xa7e590 vtable @ 0x2a20da8 SVSCF=0x2930220 SetTransform=0x292b590 DIP=0x292f0f0
[INFO] [FFP] Game-supplied World matrix received from per-game hook
[INFO] [ImGui] ImGui_ImplDX9_Init
[INFO] [FFP] Game-supplied View matrix received from per-game hook
[INFO] [FFP] Game-supplied Proj matrix received from per-game hook
```

`bridge32.log` grew to **72,060 lines** over the 3-minute run — every D3D9 call from FEAR flowing through the IPC.

**Open issue (deferred to next session) — `d3d9_remix.dll+0xf0cc` crash ~3 minutes in.** After ~3 minutes of stable rendering, the bridge client crashed in FEAR.exe at `d3d9_remix.dll+0xf0cc` with `c0000005`, immediately after a window-focus toggle (`Client window became inactive` → `Client window became active` → crash within ms). The bridge server then crashed in its `OnServerExited` cleanup. Hypothesis: race between our forced `disableTimeouts=True` and the bridge's runtime focus-toggle that dynamically writes the same setting. No PDB for the new a03c16db `d3d9_remix.dll` locally — decompiling the crash site is a separate task. **This did NOT happen during init and does NOT block the proxy's rendering path** — it's a steady-state stability problem to investigate next.

**Why diagnostic capture didn't fire this session:** `[Diagnostics] DelayMs=180000` (3 min); the bridge crashed at `+196s` (02:32:35), 7 seconds before capture would have run at `+200s` (02:32:42). Next session: either lower DelayMs to ~30s, or fix the focus-toggle crash so capture can fire normally.

**SetTransform-based matrix capture (from 2026-05-06) is now confirmed end-to-end through the bridge.** The "concatenated WVP at c0–c3" problem is permanently sidestepped — we hook FEAR's per-draw `IDirect3DDevice9::SetTransform(D3DTS_WORLDMATRIX(0)/VIEW/PROJECTION, ...)` and feed clean matrices into `ffp_state::on_game_world/view/proj`. Capture fires every frame; the 12 log lines visible above are throttled output, not 12 total events.

---

## TL;DR (2026-05-11 ~02:05 update — CLEAN install validation)

**Reproduced the FFP port end-to-end on a fresh "CLEAN" install** at `a:\SteamLibrary\steamapps\common\FEAR Ultimate Shooter EditionCLEAN\` (no echo mod, no dxwrapper, no debug artifacts). After hitting and resolving the SecuROM child-respawn issue, the proxy initializes identically to the dirty install:

```text
[INFO] [d3d9] Direct3DCreate9 called. Creating proxy interface.
[STATUS] [RemixApi] Initialized RemixApi
[INFO] [FFP] Registers: View=c0-c3 Proj=c4-c7 World=c16-c19
[INFO] [Renderer] Module initialized.
[INFO] [Diagnostics] Module initialized, auto=1 delay=180000ms frames=3
```

The bridge handshake then deadlocks at the documented SYN/ACK point (`bridge32.log: "Sending SYN command, waiting for ACK from server..."` / `bridge64.log: "Server started up, waiting for connection from client..."`) → FEAR hangs and Windows shows "F.E.A.R. is not responding". **This is the same regression already documented below** (Cause A: driver 32.0.15.9636 + bridge b7de9a96 incompatibility) — not a new CLEAN-specific bug.

**SecuROM finding (new, cost ~1h of dead-end testing):**
Stock retail `FEAR.exe` (1978368 B, sha256 `D5EBC38A…`) is SecuROM-wrapped — PE has an 86 MB section with zero raw size. On launch it spawns a child `FEAR.exe`, and the child loads `C:\WINDOWS\SYSTEM32\d3d9.dll` instead of the game-folder local `d3d9.dll`. Result: neither our proxy nor the rtx-remix bridge ever inject into the rendering process. The dirty install's `FEAR.exe` (1626112 B, sha256 `D9E5F716…`) is SecuROM-stripped (single-process), which is why it works. CLEAN's `FEAR.exe.bak` byte-for-byte matches CLEAN's `FEAR.exe`, confirming the dirty exe is the modified variant.

`NvRemixLauncher32.exe` — NVIDIA's official launcher (CLI: `[-w workdir] [-i] <full-path-to-exe>`, default uses Detours search-path mode, `-i` uses CreateRemoteThread injection) — **cannot beat SecuROM's child-respawn**. Tested both modes on CLEAN; child still loads system32 d3d9.dll because injection only reaches the SecuROM parent.

**The working configuration on CLEAN, now in place:**

- `FEAR.exe.stock.bak` ← original stock SecuROM-wrapped exe (preserved; restore at any time)
- `FEAR.exe` ← copy of dirty's SecuROM-stripped exe (sha256 `D9E5F716…`) — the only modification to CLEAN
- `d3d9.dll`, `d3d9_remix.dll`, `remix-comp-proxy.ini`, `.trex/bridge.conf`, `FEAR-comp-proxy.pdb`, `NvRemixLauncher32.exe` — all from this session's build + deploy
- `launch_remix_test.ps1` — copied from dirty (path-agnostic via `$MyInvocation`)

**Open work (carried from prior TL;DRs, still applicable):**

- Bridge SYN/ACK deadlock under driver 9636 — needs either the Frida-instrumented spawn (`scripts/spawn_gate_bridge.py`) or a bridge rebuild from source. CLEAN testing has hit the same wall as dirty, so any fix transfers.
- Verify the FFP path renders correctly under `[Remix] Enabled=0` system-d3d9 fallback on CLEAN — should reproduce the 2026-05-06 warehouse screenshot. (Not done this session — diagnostics auto-capture didn't get past the bridge hang.)
- Workspace tooling: `patches/FEAR/deploy.ps1` now accepts `-GameDir`; use `-GameDir "a:\SteamLibrary\steamapps\common\FEAR Ultimate Shooter EditionCLEAN"` for CLEAN-targeted deploys.

---

## TL;DR (2026-05-07 ~00:13 update — supersedes prior TL;DRs below)

**FFP path is shipped and working.** Screenshot evidence at 23:43 (the warehouse scene with stormy clouds, blue corrugated walls, yellow-striped bay doors, and properly lit pallets) proves the SetTransform-captured matrices + the two new fixes produce correct world rendering for sky, walls, textures, bay doors, pallets, weapon, HUD. Remaining bright blobs are additive-blend light sprites that Remix path-tracing replaces with native lights — not a blocker.

**Two fixes that took FFP from broken (white-wash + black-modulation) to correct:**

1. **Disable `D3DRS_FOGENABLE` per FFP draw**, save/restore via `dc_ctx`. ([`renderer.cpp:74-91`](src/comp/modules/renderer.cpp#L74), `:172-182`). Mechanism: FEAR's VS computes per-vertex `oFog`; with VS nulled, `oFog` is undefined → FFP rasterizer applies max fog → distant geometry washes to fog color (white). Save+disable before `engage()`, let `dc_ctx.restore_all()` put it back so shader-path draws keep the game's fog.
2. **Stage-0 `D3DTOP_SELECTARG1` instead of `D3DTOP_MODULATE`** ([`ffp_state.cpp:441-460`](src/shared/common/ffp_state.cpp#L441)). Texture-only output, no vertex-color modulation. Fixes both the white wash AND the all-black objects (decls with COLOR baked-in dark-vert lighting were modulating to 0).

**Bridge regression — root-caused.** Two compounding causes:

- **Cause A — driver upgrade.** Today the user updated NVIDIA driver 32.0.15.9621 → 32.0.15.9636. Bridge worked at 23:40 (driver 9621), now incompatible. The hang location is between server's `"Server started up..."` and `"Registering exit callback..."` log lines — the bridge calls `RegisterWaitForSingleObject(parentProcess, ...)` here, a kernel call that touches the GPU/driver via the WDDM stack. Driver 9636 changed something that makes this hang.
- **Cause B — EchoPatch.** With driver 9636 and EchoPatch's `dinput8.dll` ASI loader hooks active, the bridge hangs deterministically. Removing `dinput8.dll` (renamed to `dinput8.echopatch.bak`) lets the handshake complete: `bridge64.log` reaches `Initializing D3D9... → D3D9 interface object creation succeeded! → Sync request received...` — the canonical happy path. **HANDOFF's earlier Run 14 finding of "EchoPatch innocent" was driver-conditional and is no longer true under 9636.**
- **Cause C — leftover state across kills.** Even with EchoPatch off, a *second* launch after the first was hung in the launcher reproduced the bridge hang because the parent FEAR's named semaphores (e.g. `ModuleServer2ClientSemaphore`, `Present`) were still alive in the kernel namespace. PowerShell's `[Threading.Semaphore]::OpenExisting()` confirmed they're cleaned up after `Stop-Process`, so always kill all FEAR/NvRemixBridge before re-launching.

**Working bridge launch recipe (post-2026-05-07):**

1. `dinput8.dll` MUST be renamed aside (e.g. `dinput8.echopatch.bak`) — EchoPatch breaks bridge IPC under driver 9636
2. Kill any prior FEAR/NvRemixBridge processes; verify named semaphores `Present` and `ModuleServer2ClientSemaphore` no longer exist via `[Threading.Semaphore]::OpenExisting()`
3. `bridge.conf` keeps `disableTimeouts = False`, `infiniteRetries = False` so we get visible errors when something IS wrong (was hiding deadlocks before)
4. Launch FEAR via `Start-Process` with `__COMPAT_LAYER=RUNASINVOKER`
5. Bridge logs at `A:\SteamLibrary\steamapps\common\HEAVY RAIN\rtx-remix\logs\bridge{32,64}.log` (path inherited from `DXVK_LOG_PATH` env var; harmless cross-game co-location)

**Remaining bridge work (not blocking FFP — defer to next session if needed):**
- Validate the EchoPatch+driver hypothesis with a clean-state test (bridge handshake should now reproduce reliably)
- If bridge handshake still doesn't reach CreateDevice: instrument the 32-bit client side (FEAR.exe d3d9_remix.dll) with Frida to capture the post-handshake D3D9 caps queries
- Long-term: rebuild bridge from source against driver 9636 and submit upstream PR if NVIDIA hasn't fixed it
- Consider: enable EchoPatch only AFTER CreateDevice (impossible without bridge cooperation; would need a launcher-style intermediate)

---

---

## TL;DR (2026-05-06 evening update)

The hard-won bridge unblock from earlier today (`infiniteRetries = True` in [`assets/.trex/bridge.conf`](assets/.trex/bridge.conf)) **is no longer reliably unblocking**. Vanilla launches (no Frida) hang during the bridge IPC handshake — the 32-bit client gets through shared-memory creation, but `NvRemixBridge.exe` either never spawns or silently fails to ACK; with `infiniteRetries = True` the client waits forever instead of failing fast. The Frida-instrumented launch from earlier today (via [`scripts/spawn_gate_bridge.py`](scripts/spawn_gate_bridge.py)) was the only reliably-working configuration. **Treat the bridge as flaky again** — for proxy iteration, ship `[Remix] Enabled=0` (proxy falls back to system d3d9.dll, which is what produced the original Run 1 PASS).

The big payoff this session: a **SetTransform-based matrix capture** has replaced the abandoned `D3DXMatrixMultiply` hook idea. FEAR's renderer code at `FEAR.exe!0x004FF99C` calls `IDirect3DDevice9::SetTransform(D3DTS_WORLDMATRIX(0), …)`, `SetTransform(D3DTS_VIEW, …)`, `SetTransform(D3DTS_PROJECTION, …)` *per draw*, with clean separate matrices, for **both** FFP and shader-path geometry. The proxy's existing `D3D9Device::SetTransform` interceptor now routes those into a new `ffp_state` seam ([`src/comp/modules/d3d9ex.cpp:323-352`](src/comp/modules/d3d9ex.cpp#L323), feeds [`src/shared/common/ffp_state.cpp:on_game_view/proj/world`](src/shared/common/ffp_state.cpp)), so `apply_transforms()` can use the captured row-major matrices verbatim with no transpose (LithTech matrices are already in D3DXMATRIX layout — confirmed via `fcn.0040b170` decompile in [findings.md "Matrix hook discovery"](findings.md)). The whole "concatenated WVP at c0–c3" problem is now sidestepped — we never need to decompose anything. **Capture is confirmed working at runtime** — once FEAR progressed past the launcher in the `[Remix]=0 [FFP]=1` test, `console.log` recorded all three `[FFP] Game-supplied {World,View,Proj} matrix received from per-game hook` lines, in that order (World fires first, then View+Proj when the per-frame camera state re-uploads). What's NOT yet confirmed is that the FFP path then renders world geometry in the correct *positions* — that's a visual check ("does the world look right, or is it piled at the origin?") for the next session.

Other concrete deliverables this session:

- **Game-supplied matrix seam** ([`src/shared/common/ffp_state.hpp:64-84,162-176`](src/shared/common/ffp_state.hpp), [`.cpp`](src/shared/common/ffp_state.cpp)) — public `on_game_view/proj/world` setters, `view_proj_valid()` returns `true` once both V+P are set, `apply_transforms()` prefers game-supplied matrices over the VS-const-derived path, identity world fallback if no `on_game_world` (engine pre-multiplied W into V/P), `clear_game_matrices()` on `on_reset()`. Generic — not FEAR-specific. Builds clean.
- **Vtable-address one-shot log** in `D3D9Device::CreateDevice` ([`src/comp/modules/d3d9ex.cpp:907-916`](src/comp/modules/d3d9ex.cpp#L907) and `:1018-1026`) — proxy logs `SVSCF=0x… SetTransform=0x… DIP=0x…` to `console.log` at device creation, so the next live-trace pass starts with the breakpoint addresses already in hand. No need to chase symbols through PDB or pattern scans.
- **Live-trace evidence** of where matrices flow:
  - SVSCF caller is **always inside `d3dx9_27.dll`** (~`0x02D7xxxx` in this session's load) — FEAR makes zero direct D3D9 SVSCF calls in user code; everything goes through `ID3DXEffect`. The earlier static-analyzer finding that "FEAR has 24 SVSCF call sites" was misleading: those are all `ID3DXEffect`-related calls inside `fcn.00469D50` that go through the *LithTech renderer* vtable, not the D3D9 device.
  - SVSCF uploads `count=76` (the entire effect constant table) per draw, not the per-draw `count=4` we'd been hunting for.
  - SetTransform happens *before* SVSCF on every draw, with caller `FEAR.exe!0x004FF99C`. Three calls per draw: WORLDMATRIX(0)=256, VIEW=2, PROJECTION=3. This is the data we need.
  - LithTech matrices are row-major in memory. No transpose at the proxy seam.
- **Mistakes to skip retesting**:
  - `find_vs_constants.py`'s vtable offset `0x178 = SetVertexShaderConstantF` is **correct**, not wrong. The static-analyzer subagent miscalculated the D3D9 vtable layout (it claimed `0x184` was SVSCF, which is actually `GetVertexShaderConstantI` per [`patches/FEAR/deps/dxsdk/Include/d3d9.h:525`](deps/dxsdk/Include/d3d9.h#L525) and [`rtx_remix_tools/dx/scripts/dx9_common.py:298`](../../rtx_remix_tools/dx/scripts/dx9_common.py#L298)). **Do not patch the script.**
  - The agent's recommended Option A — "find LithTech's matrix multiply primitive via Ghidra class recovery" — is no longer needed. SetTransform capture replaces it. Pyghidra analysis of FEAR.exe still useful for other questions but not load-bearing for the matrix path.
  - The "1 SVSCF site at `0x46A016`" claim from the agent was the result of scanning the wrong vtable offset (`0x184` = `GetVertexShaderConstantI`). Real direct SVSCF count from user code is effectively zero.

Bridge regression details: with the SetTransform capture deployed but `[Remix]=1`, FEAR.exe + `d3d9_remix.dll` (b7de9a96) creates the four GUID-namespaced shared-memory channels and writes a SYN to `bridge32.log`, but `NvRemixBridge.exe` never reaches `Sync request received` in `bridge64.log`. Process state right before the kill: `NvRemixBridge.exe` running, Responding=True, but no progress past `Server started up, waiting for connection from client...`. With `infiniteRetries = True` set the client waits indefinitely — Windows shows the "F.E.A.R. is not responding" dialog because FEAR's main thread is parked inside `Direct3DCreate9` for the duration. **Same `bridge.conf` and same binaries that worked yesterday under Frida**, so the variable is something environmental — leftover semaphores from prior runs, AV/Defender intercepting `CreateProcessW`, or `DXVK_LOG_PATH` (still set at User+Machine scope to `A:\SteamLibrary\steamapps\common\HEAVY RAIN\rtx-remix\logs`) tripping a path-length / case-sensitivity issue in the bridge spawn. Worth investigating but the SetTransform track is unblocked without it.

The fastest path forward next session is **(a)** verify the SetTransform→ffp_state pipeline lights up world geometry end-to-end by getting into an actual FEAR level (the launcher menu may not exercise the per-draw transforms), then **(b)** re-engage `[Remix]=1` and either reuse Frida instrumentation or do clean-bridge-state launches to test if Remix path-traces the captured matrices correctly.

---

## Archived (2026-05-03 update — superseded but kept for context)

- **Proxy works.** [`d3d9.dll`](build/bin/release/d3d9.dll) (32-bit, our remix-comp-proxy build) is deployed at game root. Run 1 confirmed it intercepts every D3D9 call and produced a 535 KB, 3-frame, 376-draws/frame diagnostic log.
- **Static analysis is complete.** [findings.md](findings.md) and [kb.h](kb.h) (1197 entries) capture FEAR's full D3D9 architecture.
- **Two earlier proxy-side bridge bugs are now fixed:**
  1. Code 11 (`NOT_INITIALIZED`) from `remixapi_InitializeLibrary` — fixed by [deploy.ps1](deploy.ps1) step 2b pushing `assets/.trex/bridge.conf` with `exposeRemixApi = True`.
  2. Vtable-corruption crash inside `Direct3DCreate9` — fixed by staging the matching `b7de9a9` bridge client.
- **Major reframe — the 32-bit "vtable crash" was a SECONDARY failure.** PDB symbolization on 2026-05-03 (against `Downloads/remix/d3d9.pdb`) showed the 32-bit bridge **fully initialized**. The `c0000005 / 0x65 / e2a5 / bucket 108353454505` stack is `Logger::widen → ctype<char>::widen` running during `LdrShutdownProcess → DllMain(DLL_PROCESS_DETACH) → RemixDetach`, AFTER `errLogMessageBoxAndExit` was triggered by `OnServerExited(Process*)` at `d3d9_lss.cpp:153`. **The real failure is the 64-bit `NvRemixBridge.exe` server exiting first; the 32-bit client crash is just a CRT race in its own shutdown logger.**
- **Decompiled `NvRemixBridge.exe` main (`0x1400270c0`)**. It requires exactly two CLI args. argv[1] = 36-char GUID (`%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx`). argv[2] = literal version string `remix-main+b7de9a96` (hardcoded at `0x14007C6F8`). Mismatch → silent `_invalid_parameter_noinfo_noreturn` (int3 abort) BEFORE the logger initializes — explaining "no `bridge64.log` ever created."
- **Version strings are NOT the bug.** All three components hold the literal `remix-main+b7de9a96`:
  - 32-bit client `d3d9_remix.dll` @ 0xac9b8 (UTF-8 + UTF-16 forms)
  - 64-bit server `NvRemixBridge.exe` @ 0x7baf8 (`Bridge Server\n========...remix-main+b7de9a96`)
  - 64-bit runtime `.trex/d3d9.dll` @ 0x609cb8 / 0x60c695 / 0x4f8373b
- **`NvRemixBridge.exe` works fine in isolation when given valid args.** Manual launch with `NvRemixBridge.exe 12345678-1234-1234-1234-567890abcdef remix-main+b7de9a96` from `.trex/` stayed alive past 8 s waiting for client IPC connection. **Binary, GPU (RTX 5090), driver (32.0.15.9621), Vulkan loader (1.4.321), and `.trex/d3d9.dll` runtime are all fine.**
- **Latest open hypothesis**: the 32-bit bridge client is passing **wrong args** to `NvRemixBridge.exe` from inside FEAR.exe — most likely a wrong GUID, wrong version literal at runtime, or extra/missing trailing arg. Capture script [`capture_nvremix_cmdline.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/capture_nvremix_cmdline.ps1) is staged in the game dir and ready to grab the actual cmdline on next launch.
- **EchoPatch and AppCompat shims are EXONERATED** (Launches 1 & 2 today produced bit-identical crashes after their respective removals).

The fastest unblock from here is **(a) capture the actual cmdline, identify the corruption, patch around it** OR **(b) iterate the proxy in FFP-only mode** which is fully productive even without Remix engaged.

---

## Filesystem Map (where everything lives)

```text
patches/FEAR/                                  ← per-game project, fully self-contained
  src/comp/main.cpp                            ← WINDOW_CLASS_NAME = "FEAR"
  src/comp/game/                               ← per-game hook stubs (empty for now; needed for D3DXMatrixMultiply hook)
  src/shared/common/ffp_state.hpp              ← VS register layout (template defaults; wrong for FEAR but doesn't matter while FFP=0)
  assets/remix-comp-proxy.ini                  ← canonical INI (source of truth)
  deps/dxsdk/Lib/x86/d3dx9.lib                 ← d3dx9.lib extracted from DXSDK Jun 2010 (one-time setup)
  deps/remix-bridge-x86/d3d9.dll               ← 32-bit bridge client. NOW the b7de9a9 CI build copied from Downloads/remix/d3d9.dll (matches user's .trex/). MUST match the .trex/ runtime build or you get the c0000005/0x65/e2a5 vtable crash.
  deps/remix-bridge-x86/d3d9.v1.4.2.dll.bak    ← prior v1.4.2 client, kept as evidence + fallback
  deps/remix-bridge-x86/NvRemixLauncher32.exe  ← bridge launcher (32→64-bit detour helper). Not auto-deployed; user supplies their own at game root.
  assets/.trex/bridge.conf                     ← bridge config with `exposeRemixApi = True` (NEEDED for the proxy's remix_api::initialize, else Code 11). deploy.ps1 step 2b pushes this to <gameDir>/.trex/bridge.conf.
  build.bat                                    ← VS detection patched to use vswhere (handles VS18 Community)
  build/bin/release/d3d9.dll                   ← latest build artifact
  deploy.ps1                                   ← copies proxy d3d9.dll + INI (from assets/) + matching bridge as d3d9_remix.dll + bridge.conf (to .trex/) + PDB
  findings.md                                  ← static analysis + run history + blocker analysis
  kb.h                                         ← 1197 entries from bootstrap.py
  bootstrap_report.txt                         ← bootstrap details
  HANDOFF.md                                   ← this file

FEAR Ultimate Shooter Edition/                 ← game directory (deploy target)
  d3d9.dll                                     ← our proxy (32-bit, 1.1 MB)
  d3d9_remix.dll                               ← 32-bit bridge client (bridge → server)
  remix-comp-proxy.ini                         ← runtime config (mirrors assets/remix-comp-proxy.ini)
  NvRemixLauncher32.exe                        ← bridge launcher already at root (from user's install)
  .trex/                                       ← 64-bit DXVK-Remix runtime (NvRemixBridge.exe + d3d9.dll, both x64)
  rtx_comp/                                    ← proxy logs (console.log, diagnostics.log, archived runs)

rtx_remix_tools/dx/remix-comp-proxy/           ← READ-ONLY template, never edit
```

---

## Build & Deploy (one cycle)

```powershell
cd patches\FEAR
build.bat release --name FEAR
powershell -ExecutionPolicy Bypass -File deploy.ps1
```

`build.bat` handles VS detection (vswhere) and writes to `patches/FEAR/build/bin/release/`.
`deploy.ps1` copies the proxy + INI (from `assets/`, not stale `build/`) + bridge + PDB into the game dir. Don't reinvent this — it has comments explaining each step.

---

## Configuration State (deployed INI)

```ini
[Remix]   Enabled=1   DLLName=d3d9_remix.dll
[FFP]     Enabled=0   AlbedoStage=0
[Skinning] Enabled=0
[Diagnostics] Enabled=1 AutoCapture=1 DelayMs=180000 LogFrames=3
```

- `[FFP]=0` is **deliberate**. FEAR's shader path uploads concatenated WorldViewProj at register c0–c3 (confirmed in run 1 log). With template register defaults the proxy would feed Remix garbage matrices. Until a `D3DXMatrixMultiply` hook captures pre-concat W/V/P, FFP conversion stays off.
- `[Remix]=1` because the bridge is wired. Currently fails (see blocker below).
- `[Diagnostics]` 3-min delay was the user's preference — gives time to load into a level before capture.

---

## Run History (latest → oldest, in `FEAR Ultimate Shooter Edition/rtx_comp/`)

| Run | Logs | Result |
| --- | --- | --- |
| 1 | `*_run1_ffponly.log`, `diag_20260502_2007*.log` | **PASS** — proxy injects, 535 KB diag, 376 draws/frame, c0–c85 used, 32 unique textures stages 0–3. **This is the data the next iteration relies on.** |
| 2 | `*_run2_brokenbridge.log` | bridge LoadLibrary 0xC1 (had renamed 64-bit `.trex/d3d9.dll` as `d3d9_remix.dll`; wrong arch) |
| 3 | `*_run3_stale_ini.log` | build/ INI snapshot was stale; deployed wrong config |
| 4 | `*_run4_remixapi11.log` | bridge load OK, `remixapi_InitializeLibrary → 11 (NOT_INITIALIZED)`, FEAR exits before `CreateDevice` |
| 5 | `*_run5_shims_restored.log` | same as run 4; third-party shims aren't the cause |
| 6 | `*_run6_pre_exposeRemixApi.log` | one more confirmation of the Code 11 condition before applying the fix |
| 7 | `*_run7_wrong_bridge_client_crash.log` | After [deploy.ps1](deploy.ps1) was fixed to push `bridge.conf`, RemixApi initialized OK. FEAR then crashed in `Direct3DCreate9` with `0xc0000005 / fault offset 0x65 / module=unknown` — vtable corruption from version-mismatched bridge client (v1.4.2 vs `.trex/` `b7de9a9` server). |
| 8 | `*_run8_clean_exit_pre_d3d.log` | After user re-installed the bundle, FEAR exited cleanly before `Direct3DCreate9` (proxy didn't even see the FEAR window in time). One-off / unrepro after redeploy. |
| 9 | `*_run9_dialog_after_d3d_create.log` | After staging the matching `b7de9a9` bridge client, proxy log progresses through `[STATUS] [RemixApi] Initialized RemixApi` and `[d3d9] Direct3DCreate9 called` plus all module init. Then "RTX Remix Runtime Error!" dialog appears (parented to FEAR.exe). Bridge writes zero log files; `NvRemixBridge.exe` and `NvRemixLauncher32.exe` never run. |
| 10 | (no proxy log — proxy moved aside) | **Bridge-alone test** — proxy renamed to `d3d9.proxy.dll.bak`, bundle's `d3d9.dll` placed at game root directly. Same crash as run 7: `0xc0000005 / fault offset 0x65 / module=unknown / StackHash e2a5 / fault bucket 108353454505`. **Proves the bridge install is the root cause, independent of the proxy.** |
| 11 | `*_run11_no_dxwrapper_same_crash.log` | **dxwrapper.dll renamed aside.** Same bit-identical crash. Rules out dxwrapper as the trigger. |
| 12 | `*_run12_full_v142_same_crash.log` | **Full official rtx-remix v1.4.2 swap** — `.trex/`, bridge client, `NvRemixLauncher32.exe` all replaced with v1.4.2 from `tools/rtx_remix_dl/remix-release.zip`. Same bit-identical crash. **Rules out bridge build version entirely.** Restored to b7de9a9 after test. v1.4.2 stack backed up: `.trex.user_b7de9a9.bak/` (still removed, since user's b7de9a9 was restored), `deps/remix-bridge-x86/d3d9.v1.4.2.dll.bak` available. |
| 13 | `*_run13_pre_trace.log`, `*_run13_pre_launch1_h1.log` | First launches of 2026-05-03 session. Same crash. Used to establish baseline before this session's interventions. `bridge.conf logLevel = Trace` enabled (from default Info) — still produces NO `d3d9.log` / `server.log`, confirming bridge dies before logger init in the SERVER (32-bit client init was always fine). |
| 14 | `*_run14_h1_no_echopatch_same_crash.log` | **Launch 1 / H1 test** — `dinput8.dll` (EchoPatch ASI loader, 1.5 MB) renamed aside. Same bit-identical `c0000005 / 0x65 / e2a5 / bucket 108353454505` crash. **Rules out EchoPatch / kernel32 hook interference.** dinput8.dll restored. |
| 15 | `*_run15_h2_no_appcompat_same_crash.log` | **Launch 2 / H2 test** — `HKCU\...\AppCompatFlags\Layers` entry for `FEAR.exe` (was `HIGHDPIAWARE`) deleted; launched via [`launch_remix_test.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/launch_remix_test.ps1) which sets `__COMPAT_LAYER=RUNASINVOKER` for the spawned process tree. Same bit-identical crash. **Rules out Windows AppCompat shimming.** |
| 16 | (pending) | **Launch 3 / capture run** — paired with [`capture_nvremix_cmdline.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/capture_nvremix_cmdline.ps1) running in a separate window. Goal: capture the exact `CommandLine` `NvRemixBridge.exe` is invoked with from inside FEAR.exe via `Win32_Process` polling at 30 ms. Compare against the known-good manual invocation: `NvRemixBridge.exe <36-char GUID> remix-main+b7de9a96`. Any deviation (bad GUID, different version literal, extra trailing arg) is the smoking gun. |

The latest `console.log` / `diagnostics.log` in `rtx_comp/` are from the most recent failed run.

### What we now know is invariant

The `c0000005 / 0x65 / unknown / e2a5 / bucket 108353454505` crash signature is **bit-identical** across:

- With proxy in chain (run 9, 11, 13, 14, 15) and without proxy (run 10)
- b7de9a9 CI build bridge (runs 9, 11, 13–15) and official v1.4.2 release bridge (run 12)
- With `dxwrapper.dll` (runs 9, 12, 13–15) and without (run 11)
- With `exposeRemixApi=True` (runs 7–15) and earlier `False` runs that exited differently but always died before `CreateDevice`
- With EchoPatch's `dinput8.dll` (runs 7–13, 15) and without (run 14)
- With `HIGHDPIAWARE` AppCompat shim active (runs 7–14) and with shim cleared + `RUNASINVOKER` (run 15)
- With `bridge.conf logLevel = Info` (runs 7–12) and `Trace` (runs 13–15)

**Run 1's "PASS" was achieved without the bridge loaded** — `console_run1_ffponly.log:3` shows `[Proxy] Loaded system d3d9` and `console_run1_ffponly.log:12` shows `[WARN] Remix bridge does not export remixapi_InitializeLibrary`. The proxy fell back to system `d3d9.dll` and the game ran normally with FFP-only diagnostics.

**The 32-bit client crash signature is invariant because it's a CRT shutdown race that fires every time the bridge's `OnServerExited` watchdog → `errLogMessageBoxAndExit` → `exit()` chain runs.** It tells us nothing about WHY the server exited. The actual root-cause variable is what the 64-bit `NvRemixBridge.exe` server is doing — which is exiting silently via `_invalid_parameter_noinfo_noreturn` before its log subsystem comes up.

### Eliminated hypotheses (do not re-test)

| Hypothesis | Eliminated by | Notes |
| --- | --- | --- |
| Our remix-comp-proxy is at fault | Run 10 (bridge alone) reproduces identically | Proxy is innocent |
| Bridge build version (v1.4.2 vs b7de9a9 nightly) | Run 12 (full v1.4.2 swap) reproduces identically | Both versions fail |
| `dxwrapper.dll` interference | Run 11 (dxwrapper renamed aside) reproduces identically | dxwrapper is inert |
| `exposeRemixApi = False` | Runs 4–6 had a different earlier failure (Code 11); all post-fix runs have current crash | This was the OLD bug — fixed |
| EchoPatch `dinput8.dll` ASI loader hooks | Run 14 reproduces identically with EchoPatch removed | EchoPatch is innocent |
| Windows AppCompat shims (`AcLayers.DLL`/`apphelp.dll`) | Run 15 reproduces identically with HKCU layer cleared + `__COMPAT_LAYER=RUNASINVOKER` | AppCompat shims are innocent |
| Wrong client/server version string handshake | Strings dump on 2026-05-03 confirms all 3 components hold `remix-main+b7de9a96` | Version literals match |
| Server binary itself broken | Manual launch with valid GUID + version arg keeps `NvRemixBridge.exe` alive past 8 s | Binary, GPU, driver, Vulkan all fine |
| Missing DLL dependency in `NvRemixBridge.exe` | `pefile` import scan: only standard Win DLLs; all resolve to System32 | Import table is clean |
| Missing required runtime in `.trex/d3d9.dll` | Same scan: all dependencies present in `.trex/`; `RemixParticleSystem.dll` is delay-loaded and lives in `.trex/usd/plugins/` | All deps resolved |

### Open hypotheses (live)

All three are now eliminated by the live Frida bridge trace from 2026-05-06 — see [findings.md "Bridge crash — true root cause and fix (2026-05-06)"](findings.md#bridge-crash--true-root-cause-and-fix-2026-05-06):

| # | Hypothesis | Verdict |
| --- | --- | --- |
| **A** | Wrong/corrupt argv from the 32-bit client | **Eliminated.** Run 16 captured the exact cmdline; live Frida trace confirmed argv parse passes (`wcslen(argv[0])==0x24`, `wcscmp(argv[1],"remix-main+b7de9a96")==0`) and WinMain runs to completion. |
| **B** | Static-initializer abort (NVAPI/Vulkan probe) | **Eliminated.** WinMain reaches its `ret` instruction with `eax=1`. Standard CRT path then calls `ExitProcess(1)`. No `_invalid_parameter` ever fires. |
| **C** | SecuROM blocking the bridge spawn | **Eliminated.** `NvRemixBridge.exe` spawns successfully, runs through `D3D9 init`, `RemixApi initialized`, the SYN/ACK handshake, and only exits cleanly via `ExitProcess(1)` after the bridge itself returns from WinMain. |

**Actual root cause:** the b7de9a96 server's "wait for CONTINUE" code path in WinMain does not honor `commandTimeout`/`startupTimeout`/`ackTimeout`/`disableTimeouts`; it gives up in <1 ms even when the client delivers `Continue` ~9 ms later. Setting `infiniteRetries = True` in `assets/.trex/bridge.conf` is the only documented option that makes the server actually wait. Fix is committed to `assets/.trex/bridge.conf` and pushed by `deploy.ps1`.

---

## Active Blocker — `NvRemixBridge.exe` Aborts Before Logging

The visible WER signature is the **secondary** failure (CRT shutdown race in 32-bit client locale facet during `LdrShutdownProcess → DllMain DETACH → RemixDetach → Logger::widen`). The **primary** failure is in the 64-bit server.

```text
Visible (32-bit client, secondary):
  Exception code:    0xc0000005
  Fault offset:      0x00000065   (= NULL+0x65 = std::ctype<char> destroyed locale facet vtable)
  Faulting module:   unknown      (atexit-destroyed object, no module ownership)
  StackHash:         e2a5
  Fault bucket:      108353454505

Top of bridge stack (resolved via Downloads/remix/d3d9.pdb):
  Logger::widen (inline)
  Logger::formatMessage         (log.cpp:200)
  Logger::emitMsg               (log.cpp:172)
  Logger::info                  (log.cpp:140)
  RemixDetach                   (d3d9_lss.cpp:435)
  DllMain(DLL_PROCESS_DETACH)   (d3d9_bootstrap.cpp:157)
  ...LdrShutdownProcess → ExitProcess → exit(-1)...
  Logger::errLogMessageBoxAndExit (log.cpp:154)   ← shows the dialog
  OnServerExited(Process*)      (d3d9_lss.cpp:153) ← root trigger
```

`OnServerExited` fires only when the spawned `NvRemixBridge.exe` server process actually exits (or fails to start). The 32-bit client never gets to do real D3D work.

**`NvRemixBridge.exe` then dies via `_invalid_parameter_noinfo_noreturn` (int3 abort)** in its argv-parse path BEFORE the logger initializes — that's why `bridge64.log` is never created. The argv-parse expects:

```text
argv[1] = 36-char GUID, format %08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx
argv[2] = literal string "remix-main+b7de9a96"  (hardcoded at NvRemixBridge.exe!0x14007C6F8)
```

Mismatch on either path triggers `int3` with no event-log entry, no `*.dmp`, no log. We confirmed:

- All 3 components (32-bit client, 64-bit server, 64-bit runtime) hold the literal `remix-main+b7de9a96`.
- Manual launch with valid args (`NvRemixBridge.exe 12345678-1234-1234-1234-567890abcdef remix-main+b7de9a96` from `.trex/`) keeps the server alive >8 s waiting for the client IPC handshake. **Server binary, GPU, driver, Vulkan all fine.**

So the issue is in **what arguments the 32-bit client passes to `NvRemixBridge.exe` at runtime inside the FEAR.exe process** — not in the binaries themselves.

### Recommended next steps (cheapest first, post-PDB-symbolization)

1. **Capture the actual cmdline.** [`capture_nvremix_cmdline.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/capture_nvremix_cmdline.ps1) is staged in the game dir — polls `Win32_Process` at 30 ms, logs name/PID/PPID/CommandLine of any `NvRemix*` or `FEAR.exe` to `capture_nvremix_cmdline.log`. Run it in one PowerShell window, launch FEAR via [`launch_remix_test.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/launch_remix_test.ps1) in another. Compare the captured cmdline to the known-good manual one. Any deviation (malformed GUID, extra arg, missing arg, wrong CWD-resolved path) is the smoking gun.
2. **If cmdline is correct**, attach Frida to `NvRemixBridge.exe` at spawn — the bridge probably gets past argv-parse and dies in a static initializer (likely a Vulkan/NVAPI probe that misbehaves on the RTX 5090 + driver 32.0.15.9621 combo). Symbolize via `.trex/NvRemixBridge.pdb` (already staged in `.trex/`).
3. **If cmdline is wrong**, decompile the 32-bit client's `Process::Start` (or equivalent in `d3d9_remix.dll`) and find where it builds the cmdline. May be a SecuROM-induced corruption (their hooks rewrite arg buffers in some games), or a CoCreateGuid quirk. Patch the 32-bit client's call site OR write a shim DLL that intercepts `CreateProcessW` and fixes the args.
4. **If SecuROM is suspected**, a SecuROM-stripped FEAR.exe (commonly available from preservation projects, or LAA + no-CD patches) would let the bridge spawn cleanly.

### Cheap unblock if Remix can't be revived quickly

Set `[Remix] Enabled=0` and continue iterating the proxy in FFP-only mode. Run 1's data is sufficient to drive several rounds of work:

- Hook `D3DXMatrixMultiply` (or trace it via `livetools` to find the call site) to capture W/V/P *before* concatenation. This is the canonical fix for FEAR's shader path and is the next major piece of per-game work in [`src/comp/game/game.cpp`](src/comp/game/game.cpp) (currently empty).
- Refine [`ffp_state.hpp`](src/shared/common/ffp_state.hpp) register layout so `view_proj_valid()` stays false until the matrix hook gives us real W/V/P; FFP path then engages on shader-path draws too.
- Validate the FFP path's `SetTransform`-driven matrices are reaching the chain correctly (run 1 already shows the proxy passes those through; verify in Remix once bridge is up).

### Helper scripts staged this session

| Script | Purpose |
| --- | --- |
| `FEAR Ultimate Shooter Edition/launch_remix_test.ps1` | Sets `__COMPAT_LAYER=RUNASINVOKER`, fixes CWD, launches FEAR.exe. Used in Launch 2 to test H2 (now exonerated). |
| `FEAR Ultimate Shooter Edition/capture_nvremix_cmdline.ps1` | Polls `Win32_Process` every 30 ms for `NvRemix*` and `FEAR.exe`, logs PID/PPID/CommandLine, waits for `NvRemixBridge.exe` to exit and records its exit code. Output: `capture_nvremix_cmdline.log` next to the script. |

### PDBs staged this session (in game dir, for any debugger to find automatically)

| PDB | Source | Purpose |
| --- | --- | --- |
| `FEAR Ultimate Shooter Edition/d3d9_remix.pdb` | Renamed from `Downloads/remix/d3d9.pdb` (b7de9a9, Apr 23) | Symbols for the 32-bit bridge client we deploy as `d3d9_remix.dll` |
| `FEAR Ultimate Shooter Edition/.trex/d3d9.pdb` | From `Downloads/remix/.trex/d3d9.pdb` | Symbols for the 64-bit DXVK-Remix runtime |
| `FEAR Ultimate Shooter Edition/.trex/NvRemixBridge.pdb` | From `Downloads/remix/.trex/NvRemixBridge.pdb` | Symbols for the 64-bit server (key for tracing the silent abort) |
| `FEAR Ultimate Shooter Edition/d3dx9_27.dll` | Extracted from `DirectX/Aug2005_d3dx9_27_x86.cab` | Staged in case the bridge resolves d3dx9_27 from a wrong PATH (low-priority hypothesis but free to keep) |

---

## Critical Code Pointers for the Next Iteration

- **Where to add the matrix hook:** [`src/comp/game/game.cpp`](src/comp/game/game.cpp) `init_game_addresses()` — currently empty. Use the patterns in `find_d3d_calls.py`/`find_transforms.py` results in [findings.md](findings.md) as starting addresses. The 24 indirect `SetVertexShaderConstantF` call sites listed in `find_vs_constants.py` output are the most direct callers; trace upstream via `livetools` to find the multiply.
- **Renderer routing:** [`src/comp/modules/renderer.cpp`](src/comp/modules/renderer.cpp) — default decision tree is unmodified; do not touch until log shows world geometry rejected. FEAR's heavy FFP usage means most draws should already pass through correctly.
- **Skinning:** stays off. `find_skinning.py` confirmed no FFP vertex-blend or WORLDMATRIX(n) usage. Per the skill rule, do not enable unless explicitly asked.
- **Albedo stage:** `[FFP] AlbedoStage=0` is the right starting guess from `find_texture_ops.py`. Flip to 1 only if log shows white/black geometry once FFP engages.

---

## Open Questions for the User

1. Did your RTX Remix install (the `.trex/` folder + `NvRemixLauncher32.exe`) ever launch FEAR successfully **before** I deployed our proxy? If yes, what command did you use? If no, the bridge install needs work upstream of anything we've done.
2. Is your `.trex/` folder content the same version as rtx-remix v1.4.2 (the version of the bridge client we extracted)? A mismatched server can silently fail the IPC handshake.
3. Would you prefer (a) chase the bridge issue, or (b) keep iterating the proxy in FFP-only mode? Both are productive; the proxy work transfers either way.

---

## Memory & Context References

- **Skill:** `dx9-ffp-port` — covers the full porting workflow, decision trees, and pitfalls.
- **Engineering rules:** `.claude/CLAUDE.md` (workspace), `.claude/rules/tool-dispatch.md`, `.claude/rules/subagent-workflow.md`.
- **Saved memory:** `feedback_deploy_after_every_build.md` (workspace rule: every build auto-deploys; user never copies manually).
- **Previous chat:** ran in parallel, did the bridge architecture diagnosis (bridge client = 32-bit, `.trex/d3d9.dll` = 64-bit DXVK-Remix runtime). Key edits in [deploy.ps1:31-37](deploy.ps1#L31) explain the architecture.
