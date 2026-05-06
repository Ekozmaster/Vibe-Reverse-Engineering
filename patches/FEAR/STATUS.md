# F.E.A.R. → RTX Remix Port — Status

**As of:** 2026-05-06
**Target:** F.E.A.R. v1.08 Ultimate Shooter Edition (LithTech Jupiter EX, MSVC 7.1, x86)
**Goal:** Render FEAR through RTX Remix path-tracing via the [`remix-comp-proxy`](README.md) DX9 fixed-function pipeline framework.

This is the canonical entry point. Detailed analysis lives in [findings.md](findings.md) (D3D9 architecture, kb.h, run history, crash dump symbolizations) and [HANDOFF.md](HANDOFF.md) (full filesystem map, run-by-run debugging log, hypothesis matrix).

---

## Status at a glance

| Component | State |
| --- | --- |
| Static analysis (engine ID, D3D9 architecture, VS layout, skinning) | ✅ Complete — [findings.md](findings.md), [kb.h](kb.h) (1197 entries) |
| `remix-comp-proxy` build for FEAR | ✅ Working — intercepts every D3D9 call (Run 1: 535 KB diag, 376 draws/frame) |
| Build/deploy automation (`build.bat` + `deploy.ps1`) | ✅ Working — every build auto-deploys to game dir |
| RTX Remix bridge (32-bit client → 64-bit `NvRemixBridge.exe` server) | ❌ **Blocked** — server exits silently before logger init |
| `D3DXMatrixMultiply` hook (decomposes shader-path WVP) | ⏳ Pending — gated on bridge unblock |
| FFP routing (`[FFP]=1`, world geometry through Remix) | ⏳ Pending — gated on matrix hook |

**Bottom line:** The proxy works and we have rich Run 1 telemetry. The blocker is upstream of our code — Nvidia's `NvRemixBridge.exe` 64-bit server aborts via `_invalid_parameter_noinfo_noreturn` (int3) before the bridge log subsystem comes up, so there is no `bridge64.log` to inspect. The visible 32-bit client crash (`0xc0000005 / 0x65 / e2a5 / bucket 108353454505`) is a secondary CRT shutdown race in the bridge's logger when its watchdog (`OnServerExited`) calls `errLogMessageBoxAndExit`.

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

## Active blocker — `NvRemixBridge.exe` aborts before logger init

The 64-bit server is what's actually dying. The full chain:

1. 32-bit client `d3d9_remix.dll` initializes cleanly inside FEAR.exe (proxy log confirms `[STATUS] [RemixApi] Initialized RemixApi`).
2. Client spawns `NvRemixBridge.exe` with two CLI args: a 36-char GUID from `CoCreateGuid` and the literal version string `remix-main+b7de9a96`.
3. Server hits `_invalid_parameter_noinfo_noreturn → swi(3)` (int3 abort) somewhere in early init **before** the logger flushes — hence no `bridge64.log` is ever created.
4. Client's watchdog `OnServerExited` (`bridge/src/client/d3d9_lss.cpp:153`) fires, calls `errLogMessageBoxAndExit`, which calls `exit(-1)`.
5. CRT teardown invokes the bridge's `DllMain(DLL_PROCESS_DETACH) → RemixDetach`, which tries to log a shutdown message via `bridge_util::Logger::info` → constructs a `std::stringstream` → calls `widen(' ')` on a locale ctype facet that has already been destroyed by atexit handlers → `call edx` with `edx=0x65` → access violation at NULL+0x65. **That visible crash signature is the secondary CRT race, not the root cause.**

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

**Bridge unblock track (preferred):**
1. Run `capture_nvremix_cmdline.ps1` paired with `launch_remix_test.ps1` to capture the exact cmdline (Run 16).
2. Compare against the known-good manual `NvRemixBridge.exe <36-char-GUID> remix-main+b7de9a96`.
3. If args are wrong → decompile the 32-bit client's `Process::Start` in `d3d9_remix.dll` to find the build site, patch or shim `CreateProcessW`.
4. If args are right → Frida-trace the server past argv parse to find the abort location (likely a static initializer hitting NVAPI/Vulkan).

**FFP-only iteration track (parallel, no bridge dependency):**
1. Set `[Remix]=0` in `remix-comp-proxy.ini`.
2. Hook `D3DXMatrixMultiply` in [`src/comp/game/game.cpp`](src/comp/game/game.cpp) (currently empty) — capture pre-concat W/V/P for the 24 shader-path call sites.
3. Refine VS register offsets in `src/shared/common/ffp_state.hpp` from the c4–c23 evidence in the Run 1 dump.
4. Set `[FFP]=1`, validate world geometry / characters / water render through the FFP conversion path against the Run 1 baseline.
5. Re-engage `[Remix]=1` once the bridge is unblocked and verify the FFP-converted draws reach Remix correctly.

The FFP track is fully productive on its own: Run 1's 535 KB diagnostic dump has everything needed to design and validate the matrix hook without Remix in the chain.

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
