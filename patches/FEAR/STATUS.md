# F.E.A.R. → RTX Remix Port — Status

**As of:** 2026-05-06 evening (SetTransform-based capture wired; bridge regressed)
**Target:** F.E.A.R. v1.08 Ultimate Shooter Edition (LithTech Jupiter EX, MSVC 7.1, x86)
**Goal:** Render FEAR through RTX Remix path-tracing via the [`remix-comp-proxy`](README.md) DX9 fixed-function pipeline framework.

This is the canonical entry point. Detailed analysis lives in [findings.md](findings.md) (D3D9 architecture, kb.h, run history, crash dump symbolizations, matrix-hook live-trace evidence) and [HANDOFF.md](HANDOFF.md) (full filesystem map, run-by-run debugging log, hypothesis matrix, current-session TL;DR).

---

## Status at a glance

| Component | State |
| --- | --- |
| Static analysis (engine ID, D3D9 architecture, VS layout, skinning) | ✅ Complete — [findings.md](findings.md), [kb.h](kb.h) (1197 entries) |
| `remix-comp-proxy` build for FEAR | ✅ Working — intercepts every D3D9 call (Run 1: 535 KB diag, 376 draws/frame) |
| Build/deploy automation (`build.bat` + `deploy.ps1`) | ✅ Working — every build auto-deploys to game dir |
| `ffp_state` game-supplied matrix seam (`on_game_view/proj/world`) | ✅ Wired — public setters, no transpose, takes priority over VS-const path |
| Proxy `SetTransform` interceptor → `ffp_state` seam | ✅ Wired — captures FEAR's per-draw W/V/P from `FEAR.exe!0x004FF99C` |
| Vtable-address logging at `CreateDevice` (live-BP target lookup) | ✅ Wired — emits `SVSCF=… SetTransform=… DIP=…` to `console.log` |
| End-to-end FFP-via-SetTransform render verification | ⏳ Next — needs an in-level launch; launcher screens don't fire the per-draw transforms enough to validate |
| RTX Remix bridge (32-bit client → 64-bit `NvRemixBridge.exe` server) | ⚠️ **Regressed** — vanilla launches hang at SYN-ACK with `infiniteRetries=True`; only Frida-instrumented launch worked yesterday |
| `D3DXMatrixMultiply` hook | 🚫 Abandoned — FEAR doesn't import D3DXMatrixMultiply; the SetTransform capture replaces it |

**Bottom line (2026-05-06 evening update):** The matrix-hook problem is solved on paper via a SetTransform-based capture (FEAR sets `WORLD/VIEW/PROJECTION` per draw with clean separate matrices via `IDirect3DDevice9::SetTransform` from `FEAR.exe!0x004FF99C`). The proxy now intercepts those and feeds them into a new `ffp_state` seam ([`src/comp/modules/d3d9ex.cpp:323-352`](src/comp/modules/d3d9ex.cpp#L323), [`src/shared/common/ffp_state.cpp:on_game_view/proj/world`](src/shared/common/ffp_state.cpp)). LithTech matrices are row-major (same layout as `D3DXMATRIX`) so they're forwarded verbatim with no transpose. The build is clean and deployed. **Verification of this end-to-end at runtime is the next-session checkbox** — the live test in this session reached the launcher main menu but didn't progress into a level, so the `[FFP] Game-supplied … matrix received from per-game hook` log lines never fired (probably because the launcher screen doesn't drive the per-draw transforms hard enough to engage the seam).

**Bridge regression (2026-05-06 evening):** The earlier "bridge unblocked" milestone (under Frida instrumentation, with `infiniteRetries = True`) does NOT reproduce on vanilla launches today. Two attempts this session both hung at the bridge IPC handshake — `bridge32.log` reaches `Sending SYN command, waiting for ACK from server...` and stops; `bridge64.log` reaches `Server started up, waiting for connection from client...` and stops. With `infiniteRetries = True` set, both sides wait forever instead of failing fast. Same `bridge.conf`, same b7de9a96 binaries that worked yesterday. Variables to investigate next session: leftover semaphore state from prior runs, `DXVK_LOG_PATH = A:\SteamLibrary\steamapps\common\HEAVY RAIN\rtx-remix\logs` (still set at User+Machine scope — bridge logs go *there*, not to the FEAR dir), antivirus/Defender intercepting `CreateProcessW` from FEAR. **For proxy iteration in the meantime, ship `[Remix] Enabled=0`** — proxy falls back to system d3d9.dll, which is what produced the original Run 1 PASS and is fine for shaking out the SetTransform→ffp_state pipeline.

---

## Toolkit / workflow

Static and dynamic toolchains live at the repo root and are shared across all patches.

**Static analysis** ([retools/](../../retools/)):
`bootstrap` (one-time KB seed), `sigdb` (compiler/library fingerprints), `context` (RAG context for decompiler), `decompiler` (pyghidra + r2ghidra hybrid, must use `--types kb.h`), `dataflow` (constants + backward slice), `cfg`, `callgraph`, `xrefs`, `datarefs`, `structrefs`, `rtti`, `throwmap`, `dumpinfo` (minidump diag), `asi_patcher`. Delegated to the `static-analyzer` subagent per [.claude/rules/tool-dispatch.md](../../.claude/rules/tool-dispatch.md).

**DX9 first-pass scripts** ([rtx_remix_tools/dx/scripts/](../../rtx_remix_tools/dx/scripts/)):
`find_d3d_calls`, `find_vs_constants`, `find_ps_constants`, `find_render_states`, `find_texture_ops`, `find_transforms`, `find_surface_formats`, `find_stateblocks`, `decode_fvf`, `decode_vtx_decls`, `find_shader_bytecode`, `classify_draws`, `find_matrix_registers`, `find_skinning`, `find_blend_states`, `scan_d3d_region`, `find_device_calls`, `find_vtable_calls`. Faster than retools for D3D9-shaped questions.

**Dynamic analysis** ([livetools/](../../livetools/)):
Frida-based attach/spawn, breakpoints, function trace, register/memory inspection, memory write, scan, write watchpoints, D3D9 dipcnt counters, module enum.

**Frame capture** ([graphics/directx/dx9/](../../graphics/directx/dx9/)):
`dx9tracer` — JSONL frame tracer with offline analyzer (summary, render-passes, shader-map, matrix flow).

**Skills / agents** ([.claude/](../../.claude/)):
`dx9-ffp-port` skill (canonical workflow for this kind of port), `dynamic-analysis` skill, `static-analyzer` and `web-researcher` subagents.

---

## What we have on FEAR

### Engine + D3D9 architecture (from [findings.md](findings.md))

- **Engine:** LithTech Jupiter EX, MSVC 7.1 (VS 2003), `ImageBase=0x00400000`. Window class match: `"LithTech"` substring.
- **Hybrid FFP + shader pipeline:** 52 `SetTransform` sites (FFP-dominant), 24 `SetVertexShaderConstantF` sites (effects).
- **Imports:** `Direct3DCreate9` (single direct), then vtable for everything else. `D3DXCreateEffect`/`D3DXCreateEffectPool` from `d3dx9_27.dll` — shaders live in external `.fx` files inside the game archives, not embedded; CTAB analysis of the EXE returns nothing.
- **Transforms (FFP path):** `D3DTS_VIEW` (1 site), `D3DTS_PROJECTION` (2), `D3DTS_WORLD` (1), `D3DTS_TEXTURE2` (2). World matrix is **not** indexed (no `WORLDMATRIX(n)` skinning palette).
- **Skinning:** `D3DRS_VERTEXBLEND` and `D3DRS_INDEXEDVERTEXBLENDENABLE` both `DISABLE`. No FFP skinning. Character rigging uses shader path (bone matrices in `.fx` constant tables).
- **Texture stages:** 17 active (0–16). Stages 0–7 are FFP, stages 8 and 16 are shader-only.
- **Surface formats:** A8R8G8B8 / A8B8G8R8 / R8G8B8 (32-bit color). No exotic formats.
- **Render states:** Standard FFP — `ZWRITEENABLE`, `ZFUNC` LESS/EQUAL/LESSEQUAL, `ALPHATESTENABLE`, `ALPHABLENDENABLE`, `CULLMODE`, `FOGENABLE`/`FOGTABLEMODE=LINEAR`, `SHADEMODE=GOURAUD`, `SPECULARENABLE=FALSE`.
- **kb.h:** 1197 entries (1051 thunk labels, 139 string labels, 6 sigdb hits, 1 RTTI). RTTI is mostly stripped — the LithTech `CRenderer`/`ILT*` hierarchy must be reconstructed by hand from vtable layout and string xrefs.

### VS register layout (from Run 1's 535 KB diagnostic capture)

| Registers | Meaning | Fits Remix? |
| --- | --- | --- |
| c0–c3 | Per-object **WorldViewProj** (already concatenated by the game) | ❌ Cannot decompose into W/V/P at the proxy layer — needs `D3DXMatrixMultiply` hook |
| c4–c7, c8–c11, c12–c15, c16–c19, c20–c23 | Per-frame camera state (frustum corners, near/far, screen size, sun, fog) | n/a (not transforms) |
| c24–c85 | Per-effect parameters (varies by `.fx`) | n/a |
| HUD | NULL VS, c0–c3 = 1920×1080 ortho | passthrough OK |

The FFP path's `SetTransform`-driven matrices reach Remix cleanly. The shader path is what needs the matrix hook before `[FFP]=1` makes sense.

### Run history (artefacts in [`FEAR Ultimate Shooter Edition/rtx_comp/`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx_comp/))

| Run | Logs | Result |
| --- | --- | --- |
| 1 | `*_run1_ffponly.log`, `diag_20260502_2007*.log` | **PASS** — proxy injects, 535 KB diagnostic dump, 3 frames, 376 draws/frame, c0–c85 used, 32 unique textures across stages 0–3 |
| 2–6 | `*_run{2..6}_*.log` | Bridge architecture/version mismatches, `remixapi_InitializeLibrary → 11`, INI staleness — all fixed |
| 7 | `*_run7_wrong_bridge_client_crash.log` | First appearance of the `c0000005 / 0x65` crash; v1.4.2 client vs `b7de9a9` `.trex/` server mismatch |
| 8 | `*_run8_clean_exit_pre_d3d.log` | One-off post-redeploy clean exit |
| 9 | `*_run9_dialog_after_d3d_create.log` | Matching `b7de9a9` client staged; proxy log shows `[STATUS] [RemixApi] Initialized RemixApi` then "RTX Remix Runtime Error!" dialog. Bridge writes zero log files |
| 10 | (proxy moved aside) | **Bridge-alone test** — same bit-identical crash. **Proxy is exonerated.** |
| 11 | `*_run11_no_dxwrapper_same_crash.log` | dxwrapper.dll renamed aside — same crash |
| 12 | `*_run12_full_v142_same_crash.log` | Full official v1.4.2 swap — same crash |
| 13–15 | `*_run{13..15}_*.log` | Trace-level bridge logging; EchoPatch dinput8 removed; AppCompat shim cleared + `__COMPAT_LAYER=RUNASINVOKER`. All same crash |
| 16 | (pending) | Will pair `capture_nvremix_cmdline.ps1` with `launch_remix_test.ps1` to capture the actual cmdline `NvRemixBridge.exe` is invoked with from inside FEAR.exe |

The crash signature is **bit-identical** across proxy/no-proxy, both bridge versions, with/without dxwrapper, with/without EchoPatch, with/without AppCompat — confirming the failure is invariant to those layers.

---

## Current rendering pipeline (what's wired today)

```
FEAR.exe
  ├─ <gameDir>/d3d9.dll                  ← our remix-comp-proxy (32-bit, intercepts every D3D9 call)
  │    └─ forwards to: d3d9_remix.dll    ← 32-bit Remix bridge client (b7de9a9, matches .trex/)
  │         └─ spawns: .trex/NvRemixBridge.exe  ← 64-bit server  ❌ ABORTS HERE
  │              └─ would load: .trex/d3d9.dll  ← DXVK-Remix 64-bit runtime
  └─ FFP path (when [FFP]=1): proxy → ffp_state → Remix
       └─ shader path: proxy → blocked at c0–c3 WVP without D3DXMatrixMultiply hook
```

**Deployed INI** (mirror of [`assets/remix-comp-proxy.ini`](assets/remix-comp-proxy.ini)):

```ini
[Remix]   Enabled=1   DLLName=d3d9_remix.dll
[FFP]     Enabled=0   AlbedoStage=0     ; deliberately off — shader-path WVP not yet decomposable
[Skinning] Enabled=0                    ; static analysis confirms no FFP skinning
[Diagnostics] Enabled=1 AutoCapture=1 DelayMs=180000 LogFrames=3
```

`[Remix]=1` is what causes the bridge spawn that currently fails. To productively iterate the proxy in the meantime, set `[Remix]=0` and the proxy falls back to the system `d3d9.dll` (this is what produced the Run 1 PASS — see `console_run1_ffponly.log:3`).

---

## Resolved blocker — bridge `infiniteRetries` flag (2026-05-06)

What actually happened, top to bottom:

1. 32-bit client `d3d9_remix.dll` initializes inside FEAR.exe (proxy log confirms `[STATUS] [RemixApi] Initialized RemixApi`).
2. Client creates the four GUID-namespaced shared-memory channels (Module/Device × Client2Server/Server2Client) and the (un-namespaced!) semaphores `Module*Server2ClientSemaphore`, `Module*Client2ServerSemaphore`, and `Present`.
3. Client spawns `NvRemixBridge.exe` with **three** CLI args (the captured cmdline contains `argv[2]` = host EXE path, ignored by the server) and waits for ACK.
4. Server runs the full WinMain prologue: `rtx_fs_init` (success), `logger_init` (success), `bridge.conf` parse (success), shared-memory open + semaphore open, `D3D9 init → LoadLibraryA(d3d9.dll)` (success), `RemixApi initialized`.
5. Server logs **`Sync request received, sending ACK response... Done! Now waiting for client to consume the response...`**.
6. Server then logs **`Timeout. Application failed to give go-ahead (CONTINUE) to operate.`** within ~1 ms — even though our 32-bit client delivers the CONTINUE command ~9 ms later. The b7de9a96 server's "wait for CONTINUE" path does not honor `commandTimeout`, `startupTimeout`, `ackTimeout`, or `disableTimeouts`.
7. Server `WinMain` returns 1, CRT teardown calls `ExitProcess(1)`.
8. Client's `OnServerExited` watchdog (`d3d9_lss.cpp:153`) fires, `errLogMessageBoxAndExit` shows the "RTX Remix Runtime Error" dialog, calls `exit(-1)`. CRT shutdown re-enters `DllMain(DETACH) → RemixDetach → Logger::info → widen(' ')` on a destroyed locale ctype facet → access violation at NULL+0x65. That's the **secondary** CRT race producing the visible WER signature, not the root cause.

**Fix:** add `infiniteRetries = True` to [`assets/.trex/bridge.conf`](assets/.trex/bridge.conf). That's the one bridge.conf option that successfully suppresses the immediate retry-bail in the "wait for CONTINUE" path. We also bump `commandTimeout`, `startupTimeout`, `ackTimeout`, and set `disableTimeouts = True`; those don't fix it on their own but are sensible alongside `infiniteRetries`.

### Original (failed) hypothesis chain

(All eliminated; kept here for context.)

### Eliminated

| Hypothesis | Eliminated by |
| --- | --- |
| Our `remix-comp-proxy` is at fault | Run 10 (bridge alone, no proxy) reproduces identically |
| Bridge build version (v1.4.2 vs `b7de9a9` nightly) | Run 12 (full v1.4.2 swap) reproduces identically |
| `dxwrapper.dll` interference | Run 11 (renamed aside) reproduces identically |
| `bridge.conf` missing `exposeRemixApi=True` | Was an earlier (Code 11) bug, fixed in Run 6 |
| EchoPatch `dinput8.dll` ASI loader | Run 14 (renamed aside) reproduces identically |
| Windows AppCompat shims | Run 15 (`HIGHDPIAWARE` cleared + `__COMPAT_LAYER=RUNASINVOKER`) reproduces identically |
| Wrong client/server version-string handshake | Strings dump confirms all three components hold `remix-main+b7de9a96` |
| `NvRemixBridge.exe` binary itself broken | Manual launch with valid GUID + version arg keeps it alive >8 s waiting for client IPC |
| Missing DLL deps | `pefile` import scan: clean, all resolve to System32 / `.trex/` |

### Live hypotheses

| # | Hypothesis | How to falsify |
| --- | --- | --- |
| **A** | Client passes corrupt args to `NvRemixBridge.exe` from inside FEAR.exe (malformed GUID, wrong CWD, extra trailing arg) | Run [`capture_nvremix_cmdline.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/capture_nvremix_cmdline.ps1) — `Win32_Process` polling at 30 ms — and compare to known-good manual invocation |
| B | Args parse fine; abort is in a static initializer (NVAPI/Vulkan probe specific to RTX 5090 + driver 32.0.15.9621) | If A shows clean cmdline, attach Frida to `NvRemixBridge.exe` at spawn (`livetools attach NvRemixBridge.exe --spawn`), trace early symbols past argv parse |
| C | SecuROM `Gam363C.tmp` blocks `CreateProcessW` from inside FEAR.exe specifically | If A shows `CreateProcessW` succeeds-then-exits, sandbox-spawn the server from a non-FEAR parent that mirrors FEAR's invocation |

---

## Next steps

The whole "decompose concatenated WVP" plan has been replaced. New plan, in order:

**1. Verify the SetTransform-based capture lights up world geometry end-to-end (no bridge needed).**

- Confirm `[Remix] Enabled=0` and `[FFP] Enabled=1` in the deployed `remix-comp-proxy.ini` (the in-game `<gameDir>/remix-comp-proxy.ini`, not the asset — `deploy.ps1` will overwrite it back to the asset's settings on next deploy).
- Launch FEAR via [`FEAR Ultimate Shooter Edition/launch_remix_test.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/launch_remix_test.ps1) (sets `__COMPAT_LAYER=RUNASINVOKER` and fixes CWD).
- **Get into an actual gameplay level**, not just the launcher main menu. The launcher splash doesn't drive enough per-draw transforms to fully exercise the seam. Once in-level, look for these `console.log` lines (they fire once, on the first capture of each):
  - `[INFO] [FFP] Game-supplied View matrix received from per-game hook`
  - `[INFO] [FFP] Game-supplied Proj matrix received from per-game hook`
  - `[INFO] [FFP] Game-supplied World matrix received from per-game hook`
- Visual: world geometry should still render (FFP path uses captured matrices to drive `SetTransform` → system d3d9.dll → GPU FFP). Some of FEAR's per-effect rendering may look different (specular/normal maps disabled in FFP mode) but world surfaces should be in the right *positions*. If you see geometry at the origin or piled up, the World matrix capture is wrong.

**2. Once the FFP path is verified, re-engage `[Remix]=1` and chase the bridge regression.**

- First, kill any leftover `NvRemixBridge.exe` orphans (`Get-Process NvRemix* | Stop-Process -Force`).
- Try clearing `DXVK_LOG_PATH` for the launch to rule out cross-game log path issues: `[Environment]::SetEnvironmentVariable('DXVK_LOG_PATH', $null, 'User')` (also `Machine` scope).
- If still hung, run [`scripts/spawn_gate_bridge.py`](scripts/spawn_gate_bridge.py) again — it was the reliably-working configuration yesterday and may give a quick view of where the new hang is.
- Goal once unhung: confirm Remix path-traces the captured FFP geometry. Capture a screenshot.

**3. ImGui overlay protection (low priority):** the proxy intercepts `SetTransform` even when ImGui is rendering its own ortho matrices. Currently the seam captures those (`shared::globals::imgui_is_rendering` is not checked in `D3D9Device::SetTransform`). Net effect: when F4 is pressed, the seam may capture ImGui's ortho V/P. Should be guarded — but only matters if the user actually opens the ImGui overlay during play.

**4. Pyghidra analyze on FEAR.exe** (`python retools/pyghidra_backend.py analyze "FEAR Ultimate Shooter Edition/FEAR.exe" --project patches/FEAR`, 5–15 min). Not needed for the matrix path anymore, but useful for any further LithTech-internal investigations (e.g., understanding what `FEAR.exe!0x004FF99C` actually is — is it the per-draw setup, the renderer dispatcher, etc.?). The earlier static-analyzer run flagged "Ghidra project not analyzed" as a gap.

---

## Pointer index

| Doc | What's in it |
| --- | --- |
| [findings.md](findings.md) | Full D3D9 architecture, kb.h summary, run history, four crash-dump symbolizations, `NvRemixBridge.exe` argv-parse re-verification |
| [HANDOFF.md](HANDOFF.md) | Filesystem map, build/deploy commands, run table 1–15, eliminated-hypothesis table, recommended next-step ladder |
| [README.md](README.md) | `remix-comp-proxy` framework overview (template-level) |
| [kb.h](kb.h) | 1197-entry knowledge base (auto-loaded by retools via `--types`) |
| [assets/remix-comp-proxy.ini](assets/remix-comp-proxy.ini) | Canonical INI source; deployed by `deploy.ps1` |
| [assets/.trex/bridge.conf](assets/.trex/bridge.conf) | Bridge config with `exposeRemixApi = True` |
| [bootstrap_report.txt](bootstrap_report.txt) | One-time `bootstrap.py` execution details |
| [`FEAR Ultimate Shooter Edition/rtx_comp/diagnostics_run1_ffponly.log`](../../FEAR%20Ultimate%20Shooter%20Edition/rtx_comp/diagnostics_run1_ffponly.log) | The 535 KB Run 1 capture — all VS reg evidence comes from here |
| [`FEAR Ultimate Shooter Edition/capture_nvremix_cmdline.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/capture_nvremix_cmdline.ps1) | Staged capture script for Run 16 |
| [`FEAR Ultimate Shooter Edition/launch_remix_test.ps1`](../../FEAR%20Ultimate%20Shooter%20Edition/launch_remix_test.ps1) | Launches FEAR with `__COMPAT_LAYER=RUNASINVOKER` and a clean CWD |
