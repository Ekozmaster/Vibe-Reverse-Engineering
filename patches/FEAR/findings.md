# FEAR.exe — RTX Remix Port Findings

## Binary Identification

- **File**: `FEAR Ultimate Shooter Edition\FEAR.exe`
- **Version**: F.E.A.R. v1.08 (Ultimate Shooter Edition, Aug 2009 re-release)
- **Engine**: LithTech Jupiter EX (Monolith)
- **Compiler**: MSVC 7.1 (Visual Studio 2003) — confirmed by sigdb fingerprint (CRT import: msvc-7.1)
- **ImageBase**: 0x00400000
- **Machine**: 0x014C (x86 32-bit)

## D3D9 Architecture Summary

**FEAR is a hybrid FFP + shader engine — heavily FFP, with shader effects sprinkled in.** This makes the port simpler than a pure-shader game.

### Imports

| Function | Source | Notes |
|---|---|---|
| `Direct3DCreate9` | d3d9.dll | Single direct import; everything else is via vtable |
| `D3DXCreateEffect` | d3dx9_27.dll | **Effects framework** — `.fx` shaders loaded from external files at runtime |
| `D3DXCreateEffectPool` | d3dx9_27.dll | |
| `D3DXSaveTextureToFileA` | d3dx9_27.dll | screenshot path |
| `D3DXSaveSurfaceToFileA` | d3dx9_27.dll | |
| `D3DXPlaneTransform` | d3dx9_27.dll | math helper |
| `D3DXLoadSurfaceFromMemory` | d3dx9_27.dll | |

**Implication**: shaders aren't embedded in the EXE — they live in `.fx` files in the game data archives. Static CTAB analysis returns nothing. We must rely on runtime tracing for shader register layouts.

### Call-site counts (D3D9Device vtable)

| API | Direct | Indirect | Total | Notes |
|---|---|---|---|---|
| `SetTransform` (vt+0xB0) | 2 | 50 | 52 | **FFP-heavy** — confirms hybrid pipeline |
| `GetTransform` (vt+0xB4) | 0 | 92 | 92 | game reads back transforms a lot |
| `MultiplyTransform` (vt+0xB8) | 5 | 107 | 112 | matrix stack heavily used |
| `SetRenderState` | various | various | many | standard FFP states |
| `SetTexture` (vt+0x104) | 2 | 40 | 42 | up to 17 stages used (0-16) |
| `SetTextureStageState` (vt+0x10C) | 3 | 45 | 48 | TSS configured per stage |
| `SetSamplerState` (vt+0x114) | 12 | 41 | 53 | per-sampler config |
| `SetVertexShader` (vt+0x170) | 0 | 12 | 12 | shader path entry |
| `SetVertexShaderConstantF` (vt+0x178) | 1 | 23 | 24 | matrices/effect params for shader path |
| `SetPixelShader` (vt+0x1AC) | 0 | 8 | 8 | |
| `SetPixelShaderConstantF` (vt+0x1B4) | 0 | 6 | 6 | |
| `SetPixelShaderConstantI` (vt+0x1BC) | 2 | 0 | 2 | |
| `SetPixelShaderConstantB` (vt+0x1C4) | 1 | 0 | 1 | |
| `CreatePixelShader` (vt+0x1A8) | 0 | 9 | 9 | |
| `SetFVF` (vt+0x164) | 1 | 4 | 5 | 22 GetFVF sites |
| `CreateVertexDeclaration` (vt+0x158) | 3 | 8 | 11 | |
| `SetVertexDeclaration` (vt+0x15C) | 5 | 9 | 14 | |
| `SetStreamSource` (vt+0x190) | 0 | 5 | 5 | |
| `CreateOffscreenPlainSurface` (vt+0x90) | 6 | 35 | 41 | A8R8G8B8 / A8B8G8R8 / R8G8B8 |

### Transform usage (`find_transforms.py`)

- **VIEW**: 1 site → captured by SetTransform proxy hook (no VS const interception needed for view)
- **PROJECTION**: 2 sites → captured by SetTransform
- **WORLD**: 1 site → captured by SetTransform
- **TEXTURE2**: 2 sites (scrolling UVs / projected textures)
- World matrix is **not indexed** (no FFP skinning palette via WORLDMATRIX(n))

**Key takeaway**: View / Projection / World matrices for the FFP path go through `SetTransform()` — the proxy already hooks this. The only unknowns are the shader path's VS constant register layout (24 sites, register-loaded args we couldn't decode statically).

### Skinning (`find_skinning.py`, `find_blend_states.py`)

- `D3DRS_VERTEXBLEND`: DISABLE (1 site)
- `D3DRS_INDEXEDVERTEXBLENDENABLE`: FALSE (1 site)
- No `WORLDMATRIX(n)` SetTransform calls
- No skinned vertex declarations detected
- No bone palette upload patterns

**Conclusion**: Skinning stays **disabled** (`[Skinning] Enabled=0` per skill default). Character rigging probably uses vertex shader path with bone matrices in `.fx` constant tables — but in static analysis we have no evidence of FFP-style skinning. We only enable skinning if Phase 9 reveals broken character animations.

### Render States (`find_render_states.py`)

- `ZWRITEENABLE`: TRUE/FALSE (per pass)
- `ZFUNC`: LESS / EQUAL / LESSEQUAL
- `ALPHATESTENABLE`, `ALPHABLENDENABLE`: standard
- `CULLMODE`: NONE / CW / CCW (per pass)
- `FOGENABLE`: TRUE, `FOGTABLEMODE`: LINEAR
- `SHADEMODE`: GOURAUD
- `SPECULARENABLE`: FALSE

Standard FFP render-state usage. The proxy's default FFP setup should handle all of this without per-game tweaks.

### Surface Formats

- A8R8G8B8 / A8B8G8R8 / R8G8B8 (32-bit color)
- Mostly OffscreenPlainSurface for screenshot/copy ops
- No CreateRenderTarget / CreateDepthStencilSurface direct calls visible (likely via vtable indirect or D3DX)

### Texture Stage Findings (`find_texture_ops.py`)

- 17 texture stages active (0-16) — stages 8 and 16 are clearly shader-only (FFP supports 0-7)
- Sampler 0: `ADDRESSU = 0xFF` (likely a sentinel value, real value loaded from variable)
- Sampler 1: MIRROR
- Sampler 6: MAXANISOTROPY=6
- Sampler 8: WRAP

**Albedo stage**: stage 0 is the most likely diffuse/albedo for FFP draws. We start with `[FFP] AlbedoStage=0`. Adjust to 1 if log shows the diffuse texture is on a different stage.

## Window Class Name

**Used**: `"LithTech"` (substring match in `enum_windows_proc`)

LithTech Jupiter EX games conventionally register their main window with a class containing the substring "LithTech". Static-analyzer subagent will verify the exact string. The substring match in [main.cpp:34](src/comp/main.cpp#L34) makes this robust to minor suffix variations.

## Initial remix-comp-proxy Configuration

### `ffp_state.hpp` register defaults

Left at template defaults (View=0-4, Proj=4-8, World=16-20). FEAR is FFP-dominated so VS constant layout matters only for the small shader-effect path (24 sites). Real values will surface in `diagnostics.log` after the first run, and we'll adjust if needed.

### `remix-comp-proxy.ini`

- `[Remix] Enabled=0` for first build (FFP-only smoke test, no bridge involvement)
- `[Remix] DLLName=d3d9_remix.dll` — bridge DLL will be copied from `.trex/d3d9.dll` to game-root as `d3d9_remix.dll` during deploy
- `[FFP] Enabled=1, AlbedoStage=0`
- `[Skinning] Enabled=0`
- `[Diagnostics] Enabled=1, AutoCapture=1, DelayMs=50000, LogFrames=3`

### Window class

`#define WINDOW_CLASS_NAME "LithTech"` in [src/comp/main.cpp](src/comp/main.cpp).

## Open Items After First Build

1. Verify diagnostics.log shows real per-frame draw data
2. Decompile any of the 24 SVSCF call sites to know what those constants represent (D3DXMatrix multiplications? Effect params?)
3. Run a short `livetools trace` against `SetVertexShaderConstantF` (any of the indirect sites) to see actual register values during gameplay
4. If shader-path geometry renders wrong with template defaults, adjust `vs_reg_*` in `ffp_state.hpp`
5. Confirm window class string from RegisterClass call site (subagent in flight)

## Bootstrap Results

Bootstrap (`python -m retools.bootstrap`) populated `patches/FEAR/kb.h` with **1197 KB entries** in 3594 lines. Full report at `patches/FEAR/bootstrap_report.txt`.

### Summary

| Metric | Value |
|---|---|
| Compiler ID | `msvc` (confidence 30%) |
| Functions identified by signature | **1197** |
| sigdb matches | 6 (5 CRT byte/structural, 1 CInput member) |
| RTTI classes found | 1 (`type_info` only) |
| PE imports cataloged | 312 |
| Error strings seeded | 139 |
| Propagated thunk labels | 1051 |

### Sigdb-identified functions (the 6 high-confidence matches)

| Address | Name | Source |
|---|---|---|
| 0x465730 | `CInput::ResetForceFeedbackEffects` | sigdb structural, 0.75 |
| 0x475410 | `crt_xmatch_0040D1A0` | sigdb byte, 0.70 |
| 0x475420 | `crt_xmatch_0040D1A0` | sigdb byte, 0.75 |
| 0x4833B0 | `crt_xmatch_005F9A60` | sigdb byte, 0.85 |
| 0x4FB210 | `crt_xmatch_005F9A60` | sigdb byte, 0.85 |
| 0x53E2E0 | `crt_xmatch_00EEB444` | sigdb byte, 0.70 |

### RTTI

- Only one RTTI vtable extracted: `type_info_vtable` @ `0x561ABC` (the standard MSVC `.?AVtype_info@@`).
- **No game class RTTI was recovered**, despite this being a LithTech Jupiter EX engine. Likely cause: FEAR ships built with `/GR-` (RTTI off) or RTTI was stripped in the retail build. Class hierarchies (e.g. `CRenderer`, `CMainWindow`, `ILTRenderer`, etc.) will have to be reconstructed from vtable layout + string xrefs rather than recovered automatically.

### Notable string-derived labels (engine fingerprint)

Strings strongly identify the engine and subsystems we'll be touching:

- **LithTech engine error codes** (15+ entries): `LT_ERROR`, `LT_INVALIDPARAMS`, `LT_SERVERERROR`, `LT_INVALIDWORLDFILE`, `LT_INVALIDSHELLDLL`, `LT_INVALIDOBJECTDLL`, `LT_ERRORLOADINGRENDERDLL`, `LT_INVALIDFILE`, `LT_INVALIDVERSION`, `LT_INVALIDDATA`, `LT_INVALIDNETVERSION`, `LT_ERRORCOPYINGFILE` — confirms the LithTech Jupiter EX engine fingerprint.
- **Render / D3D path**: `Couldn't find any HAL devices`, `Create failed. Attempting to fall back`, `Fall back failed`, `nVidia CPL error...`, `ScreenShot: Failed to save / copy front buffer / create offscreen surface`, `MakeCubicEnvMap: Invalid texture file / Error creating conversion / Error generating MIP map`, `Error: Unable to determine format for file`.
- **Shader / material**: `Shader %s compilation error`, `Failed re-loading shader %s`, `Failed to load compiled version`, `Failed to load source version`, `Error: Unable to open up shader file %s`, `Error: Unable to open up material file`, `Error: Failed to bind material and create...`.
- **Model / animation**: `Error loading model %s`, `Error: Unable to open up model file %s`, `Couldn't open child model`, `invalid hAnim`, `invalid model db`.
- **World / physics**: `Error: Unable to open up world file %s`, `CreateVisContainerObjects failed`, `physics recursed infinitely on a %s`, `DisablePhysicsErrors`, `DisablePhysicsWarnings`, `DisablePhysicsAsserts`.
- **Input**: `Input: Error creating buffer for device`, `Input: Warning: Buffer overflow encountered`.
- **Sound**: `Failed to initialize / instantiate / find func / load sound driver %s`, `Corrupt sound file %s`.
- **Networking (UDP)**: `WSAECONNABORTED`, `UDP: recvfrom returned status`, `UDP: Bind to port %d failed`, `UDPSimulateCorruption`.
- **Havok physics**: `Havok evaluation key has expired or is i...`, `Havok client keycode is invalid`, `MOTION_INVALID`, `DEACTIVATOR_INVALID`, `SOLVER_TYPE_INVALID`, `BROAD_PHASE_INVALID`, `RESPONSE_INVALID`, `INDICES_INVALID`, `error_hkError_cpp` — Havok 4.x physics engine confirmed.
- **PunkBuster**: `PB_Error: Server DLL Load Failure`, `PB_Error: Query Failed`, `PB_Error: Client DLL Load Failure`.
- **zlib**: `invalid distance code`, `invalid literal length code`, `invalid stored block lengths`, `invalid block type`, `invalid window size`, `buffer error`, `data error`, `stream error` — embedded zlib for resource decompression.
- **Bink video**: `Invalid Binkw32 dll, video playback disa...` — Bink decoder for cutscenes.
- **CTOR/CTORS**: `breakonerror`, `errorlogfile`, `error.log`, `ErrorLog` — global error/log infrastructure CVars.

### Top "interesting" function-name candidates recovered

`grep ^@` on kb.h gives 1197 entries, but only 1 has a real recovered name:

1. **`CInput::ResetForceFeedbackEffects`** @ `0x465730` — DirectInput force-feedback path (LithTech CInput class). Useful starting point for input subsystem reverse-engineering.

The other 1196 entries are split as:
- **1051 `_thunk_sub_*` labels** — propagated names for jump-thunks/aliases (low intrinsic value, but the propagation graph survives so subsequent decompilation will benefit).
- **139 `str_*` labels** — error/log-string symbols (excellent xref anchors; e.g., xref to `str_LT_ERRORLOADINGRENDERDLL` will land directly in the render-DLL load failure path).
- **5 `crt_xmatch_*`** — CRT helper functions identified by byte signature.

### Notable struct / class names discovered

- **None new beyond `CInput`**. No `CD3DDeviceWrapper`, `CRenderer`, `CMainWindow`, `ILTRenderer`, `ILTClient`, `ILTServer`, etc. were recovered automatically because RTTI is stripped from this build. The LithTech ILT* / CL* class hierarchy is real but invisible to RTTI scan; will need manual reconstruction via vtable analysis on the indirect-call sites already enumerated in `findings.md` (for example, `Render`, `BeginScene`, `EndScene`, `Present`, `SetTransform` indirect call sites are vtable slots into a `CRenderer`-equivalent).

### Recommended next steps for the main agent

1. The rich set of `str_LT_*`, `str_Error*`, `str_Failed_*` labels in kb.h are excellent starting points — do `xrefs.py` against them to find the corresponding subsystem entry-points (renderer load, world load, input init, sound init, model load).
2. Decompile `0x465730 CInput::ResetForceFeedbackEffects` first — it's our only sigdb-named function and likely sits inside a `CInput` vtable, giving us the full CInput layout for free.
3. Because RTTI is stripped, do **not** rely on `--rtti` heuristics during further bootstrapping. Use `bootstrap.py`-style propagation + manual vtable walks instead.
4. Subsequent decompilations must use `--types patches/FEAR/kb.h` so the labels propagate into r2ghidra/pyghidra output.

---

## Run History

| Run | INI config | Bridge state | Result |
|---|---|---|---|
| 1 | `[Remix]=0 [FFP]=1 delay=50000` | not loaded | **Pass** — proxy injects, 535 KB diagnostics captured (3 frames, 376 draws/frame, 86 VS regs c0–c85) |
| 2 | `[Remix]=1 [FFP]=1` | bridge LoadLibrary failed (0xC1, 64-bit DLL in 32-bit process) | proxy fell back to system32 d3d9 — Remix not in chain |
| 3 | stale build/ INI overrode source | bridge LoadLibrary failed | same as run 2 |
| 4 | `[Remix]=1 [FFP]=0 delay=180000` + 32-bit bridge wired | bridge LoadLibrary **OK**, `remixapi_InitializeLibrary` returned code 11 (NOT_INITIALIZED) | FEAR.exe exited mid-init, never called `CreateDevice` |
| 5 | same as run 4, third-party shims temporarily removed | same code 11 | confirms third-party shims aren't the cause |

## Current Blocker — Bridge Server Won't Spawn

`d3d9_remix.dll` (the 32-bit Remix bridge client) loads cleanly inside FEAR, but its handshake to the 64-bit server (`NvRemixBridge.exe`) never completes. `remixapi_InitializeLibrary` returns `REMIXAPI_ERROR_CODE_NOT_INITIALIZED = 11`, which means "bridge client is up, server is not responsive." After this, the next D3D call FEAR makes (`CreateDevice`) hits the bridge's IPC stub with no live server on the other end → process exits.

**This is independent of `remix-comp-proxy`.** A bridge-only test (proxy moved aside, bridge renamed to `d3d9.dll`) reproduces the exit. So the proxy port is correct; the failure is in the bridge install / environment.

### What's confirmed working

- Proxy interception of every D3D9 call (run 1).
- Window class match (`"FEAR"`).
- INI config loaded correctly (FFP=0, Remix=1, delay=180000).
- Bridge DLL is the right architecture (PE32 i386, exports `remixapi_InitializeLibrary`).
- Hardware: NVIDIA RTX 5090, driver 32.0.15.9621.

### What hasn't been verified

- Whether `NvRemixBridge.exe` (64-bit server) spawns at all when the bridge client loads. No trace of it in the process list. No bridge-side log files appear in the game directory or `.trex/`.
- Whether the user's RTX Remix install ever ran FEAR successfully before our deployment (i.e. is this a pre-existing bridge issue, or did we introduce it?).
- Whether something in `dinput8.dll` (a 1.5 MB ASI loader, much larger than stock) is intercepting `LoadLibrary` and silently blocking the bridge's `CreateProcess` for `NvRemixBridge.exe`.

### Recommended next steps for unblocking Remix path

1. **Validate the bridge install was ever functional.** Move our proxy aside, leave bridge as `d3d9.dll`, also temporarily move the user's third-party shims out (`dinput8.dll` etc.). Launch `FEAR.exe` and confirm whether `NvRemixBridge.exe` shows up in Task Manager. If not, the install needs to be replaced.
2. **Try the matching `bridge-remix` release** (pinned to the same version as `.trex/`). The bundled bridge client at `patches/FEAR/deps/remix-bridge-x86/d3d9.dll` is from the rtx-remix v1.4.2 all-in-one zip; verify it is built against the same `.trex/` runtime that the user dropped in.
3. **Check NvRemixBridge.exe's dependencies**: run with Sysinternals `procmon` or `Dependency Walker` to see if it has unmet imports (rare on an RTX 5090 system, but possible if a Vulkan layer / VC redist is missing).
4. **Stay in FFP-only mode for further proxy work.** Run 1 proved the proxy captures everything we need to iterate the FFP→Remix path mapping. We don't need Remix engaged to refine register layout, draw routing, etc.

## VS Constant Layout (refined from run 1 data)

The 535 KB diagnostics log from run 1 confirms FEAR's actual register usage in the shader path:

- **c0–c3**: per-object **WorldViewProj** (concatenated). Different translation values per draw. Cannot be decomposed into separate W/V/P at this layer.
- **c4–c7, c8–c11, c12–c15, c16–c19, c20–c23**: per-frame derived camera state (frustum corners, near/far planes, screen size, sun, fog). Not individual W/V/P matrices.
- **c24–c85**: per-effect parameters (varies by shader).
- HUD path uses NULL VS shader and uploads an ortho 1920×1080 matrix to c0–c3.
- 376 draws/frame, 1 BeginScene/frame, 32 unique textures across stages 0–3.

**Implication for Remix:** the FFP path (52 SetTransform sites) uploads clean `D3DTS_VIEW`/`D3DTS_PROJECTION`/`D3DTS_WORLD` matrices that Remix consumes directly — those draws are good. The shader path's concatenated WVP at c0–c3 means the proxy cannot reconstruct W/V/P separately without a per-game hook on `D3DXMatrixMultiply` (or equivalent) to capture the operands *before* concatenation. That's the next iteration once the bridge runs.

## Crash dump FEAR.exe.39232.dmp diagnose - 2026-05-03

### Context
Launched with remix-comp-proxy d3d9.dll, 32-bit Remix bridge d3d9_remix.dll, 64-bit Remix runtime in .trex/.
Proxy log shows clean startup through RemixApi init; never reached CreateDevice.
WER bucket 108353454505, FaultModule=StackHash_e2a5, Offset PCH_A9_FROM_ntdll+0x7978C.

### Exception
```
Code:    0xC0000005 (access violation)
Address: 0x0000000000000065  (NULL+0x65 -- vtable call through NULL pointer)
Thread:  41648 (only thread, blocked in ntdll+0x7978C -- KiUserExceptionDispatcher region)
Params:  [0]=0x0 (read), [1]=0x65 (faulting va)
```

### Faulting thread stack scan (top->bottom of return-address chain)
```
ntdll.dll+0x7978C            <-- exception dispatcher
KERNELBASE.dll+0x158EFF      <-- topmost RET (likely RaiseException)
d3dx9_27.dll +0x1EF110 (x2)  <-- D3DX exception handler frames
d3dx9_27.dll +0x1EFF98 (x2)
d3dx9_27.dll +0x94A00
Gam363C.tmp  +0x3A807 (x2)   <-- securom/protector unpacked image (FEAR launcher)
FEAR.exe     +0xC002D, +0x12002D
d3d9_remix.dll +0x1476A, +0x9E9FD, +0x100A2, +0x9E56C, +0x60E1A,
               +0xA2CF4, +0x61BC3, +0xA6788, +0xA6790, +0xA66DC,
               +0xA2F8A, +0x6169F, +0xCA6A8, +0x5F605,
               +0x8EEBB, +0xA2EAB, +0x61DFB ... (24 frames total)
DXCore.dll   +0x7489, +0x62F6, +0x23176, +0x22CD0, +0x22F4B, +0x22FFE
apphelp.dll  +0x8AFA0, +0x2C3A3, +0x2C0E0, +0x2C3BB, +0x2C3E2 (x3)
```

### Loaded modules (Remix-relevant)
```
0x500F0000  905216   d3d9_remix.dll          <- 32-bit bridge client (loaded)
0x50350000  5332992  d3d9.dll                <- 5.0 MB - this is our remix-comp-proxy at game-dir
0x603B0000  1548288  d3d9.dll                <- 1.5 MB - system d3d9.dll (System32)
0x02600000  2420736  d3dx9_27.dll            <- game's D3DX
0x77E00000  2093056  D3DX9_43.dll
0x60660000  221184   DXCore.dll              <- pulled in by bridge for adapter enum
```

Notably absent: NvRemixBridge.exe is NOT in the loaded module list. The 64-bit Remix runtime sub-process never spawned (or already exited) at the moment of the crash.

### Diagnosis

Faulting instruction is at VA 0x65 -- a NULL+0x65 dereference, classic indirect call through a NULL vtable / function-pointer field at struct offset 0x65 (or 0x64 if dword-aligned -> field at +0x64). This matches the WER "FaultModule=StackHash_e2a5" because the IP is in unmapped low memory, so WER hashes the stack instead of attributing to a module.

The deepest non-system frames are **d3d9_remix.dll (24 frames)** with FEAR.exe / D3DX above and DXCore.dll / apphelp.dll alongside. The crash is **inside the 32-bit Remix bridge client (d3d9_remix.dll)**, not in our remix-comp-proxy and not in game code. Our proxy successfully forwarded a call into the bridge, the bridge attempted to dispatch into something (most likely the NvRemixBridge.exe sub-process or a returned IRemixApi object), got back a NULL/garbage pointer where it expected a vtable, and called through it -> NULL+0x65.

The absence of NvRemixBridge.exe from the module list is consistent with a failed bridge handshake: d3d9_remix.dll tried to talk to a 64-bit sub-process that either failed to launch or failed to register an object back; the bridge then dereferenced the resulting NULL.

### Likely root causes (in priority order)
1. Version skew between 32-bit d3d9_remix.dll (bridge client) and the .trex/ runtime files -- known to crash without bridge logs (see memory: feedback_remix_bridge_client_must_match_trex).
2. NvRemixBridge.exe failed to launch (path / .trex layout / antivirus / SecuROM 'Gam363C.tmp' protector interfering).
3. bridge.conf missing 'exposeRemixApi = True' -> bridge loaded but RemixApi sub-object NULL when proxy called through it.

### Suggested live verification
- ProcMon: filter on FEAR.exe + Process Create -> confirm whether NvRemixBridge.exe is launched at all.
- Check d3d9_remix.dll + .trex/d3d9.dll file versions match (must be the same Remix release).
- Verify FEAR Ultimate Shooter Edition/.trex/ contains NvRemixBridge.exe and full runtime (d3d9.dll, dxvk_*, etc.).
- Confirm bridge.conf in game dir has 'exposeRemixApi = True' (proxy needs it).
- Re-run with bridge logging on (bridge.conf logLevel = Debug) to capture handshake failure before the crash.

## Crash Dump Symbolization (FEAR.exe.35904.dmp) — 2026-05-03

### Summary
The d3d9_remix.dll crash is **NOT** during bridge IPC, server spawn, or RemixApi init. It is during **shutdown**: the bridge's NvRemixBridge.exe child process exited unexpectedly, the watchdog `OnServerExited` callback fired, called `errLogMessageBoxAndExit`, which called CRT `exit()`. CRT `exit()` ran `LdrShutdownProcess`, which re-entered `d3d9_remix!DllMain(DLL_PROCESS_DETACH)`, which called `RemixDetach`, which tried to log a shutdown message via `bridge_util::Logger::info("...")`. The Logger constructed a `std::stringstream`, which constructed a `std::basic_ios`, whose `init()` called `widen(' ')`, which used `std::use_facet<std::ctype<char>>` to look up the locale ctype facet — and got back a **NULL or freed facet pointer**. The faulting instruction `call edx` at `+0x14768` invoked `vtable+0x20` (the `do_widen` slot of `std::ctype<char>`) on a destroyed/uninitialized facet → eip = 0x65 garbage.

In short: **the C++ locale facets had already been torn down by atexit handlers before our shutdown logger call ran.** This is a classic CRT teardown ordering bug — logging during DLL_PROCESS_DETACH after locale cleanup. The bridge SUCCESSFULLY started up, the server SUCCESSFULLY launched, then the server died, and the cleanup path crashed trying to log the failure.

### Faulting Instruction
```
50084761  push 20h                    ; pushing ' ' (space char) for widen
50084763  mov  edx,[ecx+20h]          ; edx = vtable[8] = ctype<char>::do_widen slot
50084766  mov  ecx,eax                ; this = facet ptr (=0 or destroyed)
50084768  call edx                    ; <-- crashes; edx=0x65, jumps to NULL+0x65
```
`edx = 0x65` because the destroyed facet object holds garbage in its vtable slot 8.

### Full Symbolized Stack (most recent first)
| # | Module Offset | Symbol | Source |
|---|--------------|--------|--------|
| 00 | 0x65 (NULL+0x65) | (faulting `call edx` target) | — |
| 01 | +0x14768 (inline) | std::ctype<char>::widen | xlocale:2755 |
| 02 | +0x1476A (inline) | std::basic_ios::widen | ios:113 |
| 03 | +0x1476A | std::basic_ios::init | ios:149 |
| 04 | +0x10063 (inline) | std::basic_istream::ctor | istream:50 |
| 05 | +0x100A2 | std::basic_iostream::basic_iostream | istream:759 |
| 06 | +0x60E1A | std::basic_stringstream::basic_stringstream | sstream:873 |
| 07 | +0x61BC3 | **bridge_util::Logger::formatMessage** | bridge/src/util/log/log.cpp:200 |
| 08 | +0x6169F | **bridge_util::Logger::emitMsg** | bridge/src/util/log/log.cpp:172 |
| 09 | +0x61DFB | **bridge_util::Logger::info** | bridge/src/util/log/log.cpp:140 |
| 0a | +0x45029 | **RemixDetach** | bridge/src/client/d3d9_lss.cpp:435 |
| 0b | +0x1711E | **DllMain (dwReason=DLL_PROCESS_DETACH)** | bridge/src/client/d3d9_bootstrap.cpp:157 |
| 0c | +0x7CD6F | _CRT_INIT dllmain_dispatch | dll_dllmain.cpp:281 |
| 0d | +0x7CE51 | _DllMainCRTStartup | dll_dllmain.cpp:334 |
| 0e..12 | (ntdll) | LdrShutdownProcess / RtlExitUserProcess | — |
| 13 | (kernel32) | ExitProcess | — |
| 14 | +0x85361 | exit_or_terminate_process | ucrt exit.cpp:141 |
| 15 | +0x8532E | common_exit | ucrt exit.cpp:288 |
| 16 | +0x85472 | exit(-1) | ucrt exit.cpp:301 |
| 17 | +0x61B6F | **bridge_util::Logger::errLogMessageBoxAndExit** | bridge/src/util/log/log.cpp:154 |
| 18 | +0x43DE2 | **OnServerExited(Process*)** | bridge/src/client/d3d9_lss.cpp:153 |
| 19..1a | +0x7520E | bridge_util::Process::OnExited callback | util_process.h:65/70 |
| 1b..1e | (ntdll) | TpCallbackIndependent worker thread | — |

### What this tells us
1. **The bridge fully initialized.** It got past `Logger::init`, past server spawn, past `bridge_util::Process` setup, and was running normally with the watchdog timer armed.
2. **NvRemixBridge.exe died on its own** — likely the actual root cause is in the 64-bit server (.trex/d3d9.dll), not the 32-bit client. The 32-bit client crash is a *secondary* shutdown crash hiding the real failure.
3. **The "NULL+0x65 vtable call" is the DESTROYED LOCALE FACET, not a bridge IPC vtable.** Earlier interpretation that this was `bridge_obj->vtable[+0x64]` was wrong — `+0x64`/`+0x20` here is the offset within `std::ctype<char>`'s vtable for `do_widen`, and the `0x65` is just the `' '` character (0x20) sign-extended/garbage from a destroyed object.

### Real Investigation Path
- The bridge client is healthy. **The 64-bit server (.trex/d3d9.dll → NvRemixBridge.exe) is what's crashing.**
- Need to capture **NvRemixBridge.exe**'s own crash dump or log. Check `%LOCALAPPDATA%\NVIDIA-Omniverse\logs\` or wherever Remix runtime logs.
- `OnServerExited` at d3d9_lss.cpp:153 is the entry point — it gets called whenever the server process exits, with no info about WHY. Server-side logs are required.
- Reasonable next steps: (a) launch with bridge.conf `serverLogLevel = Debug`; (b) attach a debugger to NvRemixBridge.exe before it dies (livetools `attach NvRemixBridge.exe --spawn` after FEAR launches it); (c) check if NvRemixBridge.exe has its own .dmp in CrashDumps.

### Suggested Live Verification
- `livetools attach FEAR.exe --spawn` then break on `d3d9_remix!OnServerExited` to catch the moment the watchdog fires.
- Set up Process Monitor / WER to also capture NvRemixBridge.exe crashes — that's where the truth is.
- Confirm `.trex/d3d9.dll` and `.trex/NvRemixBridge.exe` actually match the b7de9a9 bridge build (the bridge client/server version mismatch memory is exactly this scenario).


## NvRemixBridge.exe early-exit analysis — 2026-05-03

### Summary
NvRemixBridge.exe (PE x64, ImageBase=0x140000000, EntryPoint=0x140049d74, WinMain=0x1400270c0) requires TWO command-line arguments at startup. Without them it logs "Command line argument count received to launch server is not as expected (argCount >= 2)" and silently exits. With wrong args it exits via the version-mismatch path. Both paths happen BEFORE the file-backed log writer ever flushes anything, hence the missing `bridge64.log`.

### Required CLI Arguments (verified in WinMain @ 0x1400270c0)

| Pos | Type | Value | Validation |
|-----|------|-------|------------|
| argv[0] | wchar* | path to NvRemixBridge.exe (implicit) | — |
| argv[1] | wchar* GUID | `XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXX` (36 chars) | `wcslen(argv[1]) == 0x24` AND `swscanf_s(argv[1], L"%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", ...) != -1`. Used to name the IPC shared-memory mapping objects. On failure: logs "Server was invoked with invalid GUID! Unable to establish bridge, exiting...". |
| argv[2] | wchar* version | `remix-main+b7de9a96` literal | `wcscmp(argv[2], L"remix-main+b7de9a96") == 0`. On mismatch: "Client (%s) and server (%s) version numbers do not match. Mixed version runtime execution is currently not supported! Exiting..." |

`argCount < 2` (i.e. fewer than 2 entries — note the message says `>= 2` but really argv[1] is required) hits the failure log via `aiStack_1d4[0] < 2`.

### Most Likely Early-Exit Branch When Run Standalone (PID exits with code 1)
**No GUID supplied → `argCount < 2` branch fires** (WinMain, around offset +0x12C0 of fcn.1400270c0, just after `CommandLineToArgvW` call):
```
puVar15 = CommandLineToArgvW(arg1, &argc);
if (argc < 2) {
    /* construct std::string "Command line argument count received to launch server is not as expected" */
    /* construct std::string "(argCount >= 2)"  ← assertion-style log line */
    LogMessage(...);
    /* falls through to GUID parsing on argv[1] (NULL/garbage) which then double-fails */
}
uVar19 = puVar15[0];                     /* argv[1] — UB if argc<2 */
iVar16 = wcslen(uVar19);
if (iVar16 == 0x24) {                    /* must be exactly 36 chars */
    swscanf_s(...);                      /* parse GUID */
} else {
    /* "Server was invoked with invalid GUID!" → logger → exit(1) */
}
```

### Init Order Before Logger Flushes
1. CRT entry (0x140049d74) → `__scrt_common_main_seh` boilerplate → calls `WinMain(0x1400270c0)`.
2. **`fcn.14001f380` — RTX filesystem init** (returns bool). Calls `GetCurrentProcessId()` → `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` → walks for own PID → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|VM_READ)` → `QueryFullProcessImageNameW` to find the EXE path. If that fails: logs "Failed to find executable path!" and returns 0; WinMain logs "Failed to initialize rtx filesystem!" and exits.
3. **`fcn.140035880(1, 0)` — Logger init.** Same Toolhelp32 snapshot pattern but for **PARENT** PID (`GetCurrentProcessId()` then loops looking for self entry to extract `th32ParentProcessID` from `PROCESSENTRY32`'s `iStack_160` field). Then `OpenProcess` on parent + `QueryFullProcessImageNameW` to get parent's EXE name. Builds log path from parent name. **The log file `bridge64.log` is OPENED here but the Logger uses internal buffering — logs from steps 4-7 may be queued in memory, never flushed because the early-exit (step 7) calls `_invalid_parameter_noinfo_noreturn` / `swi(3)` (int3 abort) rather than `exit()`, killing the process before flush.**
4. Logs "NVIDIA RTX Remix Bridge Server" banner + version `remix-main+b7de9a96`.
5. Logs "Running in x64 mode!"
6. `CommandLineToArgvW(GetCommandLineW(), &argc)` → if `argc < 2`, logs failure but **continues** into GUID parse on uninitialized argv[1] → second failure ("invalid GUID") → exits.
7. Validates `argv[2] == L"remix-main+b7de9a96"` literal. If not equal → logs version mismatch → exit.
8. Allocates IPC shared memory (Module/Device Server2Client/Client2Server channels), then calls `func_0x14000f9f0` ("Initializing D3D9..." → `LoadLibraryA("d3d9.dll")` from current dir, then `d3d9vk_x64.dll` fallback).

### Why log file is missing
Logger init in step 3 builds an in-memory log path string but actual file creation is deferred (likely to a thread-pool flush). With process termination via `_invalid_parameter_noinfo_noreturn → swi(3)` (int3 abort) at the early-exit branches, the buffer never reaches disk. **Even successful bridge launches will only write `bridge64.log` once enough output accumulates / flush thread runs.** "No log file" is a symptom of fail-fast death, not the root cause.

### Imports — runtime LoadLibrary targets
- Static IAT: `KERNEL32`, `USER32`, `SHELL32`, `ole32`, `dbghelp` (MiniDumpWriteDump), `VERSION` (GetFileVersionInfoA — used to read d3d9.dll's version AFTER load).
- Dynamic via LoadLibrary (string evidence at 0x140077920 / 0x14007C0D8 / 0x14007C210):
  - `d3d9.dll` (the DXVK-Remix runtime — same dir as NvRemixBridge.exe = `.trex\d3d9.dll`)
  - `d3d9vk_x64.dll` (vanilla DXVK fallback)
  - GetProcAddress targets: `remixapi_InitializeLibrary` (0x140077900) and through it the full `RemixApi_*` table (CreateMaterial, DestroyMaterial, CreateMesh, DrawInstance, CreateLight, SetConfigVariable, CreateD3D9, RegisterDevice).
  - String at 0x14007C230 "Unable to resolve %s, may be the result of an outdated Remix DXVK *or* loading vanilla DXVK." logs when GetProcAddress returns NULL — well after the version-check exit.

### Environment variables checked at startup
- `DXVK_LOG_PATH` (string at 0x1400778D8, used by logger to override default log dir).
- No singleton check, no Vulkan/NVAPI/GPU probe before logger init.

### Config files read
- `bridge.conf` (string at 0x14007D808) — opened by ServerOptions (singleton at globals 0x14009ac60 / 0x14009aca0, accessed via `func_0x14001eb60`). Reader keys: `exposeRemixApi`, `useSharedHeap`, `sharedHeapDefaultSegmentSize`, `moduleClientChannelMemSize`, `moduleClientCmdQueueSize`, `clientChannelMemSize`, `logLevel`, `logApiCalls`, `logAllCalls`, `logServerCommands`. Resolved relative to the EXE's own directory (`.trex\bridge.conf`). **Read AFTER logger init but BEFORE argv parse**, so a malformed bridge.conf would also fail before anything reaches disk.

### Manual repro command
The 32-bit client builds the command line in `d3d9_lss.cpp` using a v4 GUID from `CoCreateGuid` formatted with `%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx`. To repro standalone:
```
cd .trex
NvRemixBridge.exe 12345678-1234-1234-1234-123456789012 "remix-main+b7de9a96"
```
Without the parent client creating the named shared-memory regions first, the server will time out waiting for connection (logs "Timeout. Connection not established to client application/game.") and exit with code 1 — but at least you'll get the `bridge64.log` from the connection-wait phase, which is what we currently lack.

### Key Addresses (NvRemixBridge.exe)
| Address | Description |
|---------|-------------|
| 0x140049d74 | EntryPoint (`__scrt_common_main_seh`) |
| 0x1400270c0 | WinMain — argv parse, version check, IPC init, main loop |
| 0x14001f380 | RTX filesystem init — Toolhelp32 + QueryFullProcessImageNameW for own EXE |
| 0x14001f010 | helper: get current PID via Toolhelp32 walk |
| 0x140035880 | Logger init — finds PARENT PID + parent EXE name to derive log filename |
| 0x140033bb0 | Logger path builder (combines parent-name + DXVK_LOG_PATH env / cwd) |
| 0x14001eb60 | ServerOptions singleton accessor (TLS-protected) |
| 0x14000f9f0 | D3D9 init — LoadLibraryA("d3d9.dll") then d3d9vk_x64.dll fallback |
| 0x140077900 | string "remixapi_InitializeLibrary" (GetProcAddress target) |
| 0x14007C6F8 | string "remix-main+b7de9a96" (server's hard-coded version) |
| 0x14007C7C0 | string "Server was invoked with invalid GUID! Unable to establish bridge, exiting..." |
| 0x14007C840 | string "Client (%s) and server (%s) version numbers do not match... Exiting..." |
| 0x14007C740 | string "Command line argument count received to launch server is not as expected" |
| 0x14007C790 | string "(argCount >= 2)" |
| 0x14007DCA8 | string "bridge64.log" — actual log file name |
| 0x1400778D8 | string "DXVK_LOG_PATH" — env var checked |
| 0x14007D808 | string "bridge.conf" — config file name |

### Suggested Live Verification
1. **Most diagnostic test:** Run `NvRemixBridge.exe 12345678-1234-1234-1234-123456789012 "remix-main+b7de9a96"` from `.trex\` cwd. Expected outcomes:
   - If `bridge64.log` IS created (containing "Timeout. Connection not established..."): the binary itself is fine, the issue is the bridge client's GUID/version handshake or the .trex\d3d9.dll runtime fails earlier than we think.
   - If `bridge64.log` is STILL not created: a static initializer is crashing (e.g. `dynamic initializer for ...` strings at 0x140083260 — there are C++ globals being constructed before WinMain that may be hitting a Vulkan/NVAPI probe).
2. **Attach debugger before death:** `livetools attach NvRemixBridge.exe --spawn` (after the main agent triggers FEAR to launch it) — set BP on `kernel32!ExitProcess` and `ntdll!RtlExitUserProcess`, dump call stack.
3. **Verify the bridge client passes the right version literal:** hexdump `.trex\d3d9.dll` and confirm the embedded version string is also `remix-main+b7de9a96`. Mismatched commit hashes between FEAR-comp-proxy build and `.trex\d3d9.dll` build would trigger the silent version-mismatch exit.
4. **Procmon:** filter on `ProcessName=NvRemixBridge.exe` — confirm whether it ever calls `CreateFile bridge.conf` / `CreateFile bridge64.log` before exiting. Procmon will also show if a static initializer touches `nvapi64.dll` / `vulkan-1.dll` and gets ACCESS_DENIED.

---

## Bridge argv-parse re-verification — 2026-05-03

### Summary
**The argc==4 cmdline does NOT cause the abort.** The prior conclusion ("requires exactly two CLI args / argc==3") was wrong. `main` at `0x1400270c0` uses `CommandLineToArgvW` and only checks `argCount < 2` (a soft warning that just logs and falls through). The real gating predicate is `wcslen(argv[0]) == 0x24` (GUID must be exactly 36 wchars). argv[2] (FEAR.exe path) and argv[3] are NEVER read in main. Extra arguments are tolerated.

### Verdict
- **Does extra arg cause the abort? NO.** argc==4 passes every check in main.
- The crash before logger init is **not** an argv-count issue.

### Proof — exact instructions in `main` (0x1400270c0)

| VA | Decompiled | Meaning |
|----|------------|---------|
| ~0x14002...near line 209 | `puVar15 = CommandLineToArgvW(arg1, &aiStack_1d4)` | argv built; argc stored at `aiStack_1d4[0]` |
| line 210 | `if (aiStack_1d4[0] < 2) { ...log "argCount<2"... }` | **Soft check — falls through, no abort.** Just logs `"Command line argument count received to launch server is not as expected. argCount=%d"` |
| line 242 | `iVar16 = wcslen(puVar15[0])` | strlen on argv[0] (the GUID) |
| line 243 | `if (iVar16 == 0x24)` | **Hard gate**: argv[0] must be exactly 36 wide chars. If not, the entire startup body is skipped → process exits without doing anything (and without writing log). |
| line 303-304 | `uVar19 = puVar15[1]; iVar13 = wcscmp(uVar19, L"remix-main+b7de9a96")` | argv[1] vs version literal at `0x14007C6F8` |
| line 411 | `LocalFree(puVar15)` | argv freed unconditionally inside the GUID==36 branch |

`puVar15[2]` and `puVar15[3]` are never dereferenced anywhere in main. `grep "puVar15\[" /tmp/main_decomp.txt` returns only the `[1]` access.

### Version literal location confirmed
- `L"remix-main+b7de9a96"` lives at `0x14007C6F8` (matches HANDOFF). Compared via `wcscmp` against argv[1]. Our cmdline argv[1] is the unquoted bareword `remix-main+b7de9a96` which matches byte-for-byte. **Not the bug.**

### Surprises
1. **The argc<2 branch only logs.** It does not call `_invalid_parameter_noinfo_noreturn`, does not `exit`, and does not skip subsequent logic. Control falls into the strlen(argv[0])==0x24 check regardless. (A malformed cmdline with only argv[0]=GUID would still proceed.)
2. **`_invalid_parameter_noinfo_noreturn` (`func_0x14004f474`) IS called from main**, but only inside `std::string` destructor invariant-violation paths (the `(0xfff < uStack_X + 1) && (0x1f < ...)` patterns are MSVC SSO sanity checks). These fire only on heap corruption — they cannot trigger from a valid argv.
3. **argv[2] (FEAR.exe path) is dead code from main's perspective.** main never opens or validates it. If the bridge uses it for parent-process tracking, that happens in a later subsystem (likely the IPC handshake or exit-callback registration around `func_0x000140019b90`).
4. **argv[0] = GUID, NOT exe path.** Unlike standard CRT `argv`, `CommandLineToArgvW` includes the exe path as `argv[0]` ONLY if you pass `GetCommandLineW()`. Here `arg1` is `lpCmdLine` from WinMain — which **excludes** the exe path. So the bridge's argv[0] is the GUID, argv[1] is the version, argv[2] is the host exe path. argCount==3 from CommandLineToArgvW means the cmdline as we send it produces 3 tokens — which the bridge already expects and tolerates.

### Implication for the crash
Since argv parsing is fine, the abort happens elsewhere. Candidates (in main's order):
- `func_0x000140020260` / `func_0x00014001f380` (very early init, before any logging) — runs unconditionally before the GUID branch
- `func_0x000140035880(1, 0)` and `func_0x00014001f6e0(0x14009ad00)` (logger init?) — runs only if `func_0x00014001f380` returned non-zero
- `func_0x000140043000()` (called immediately after logger init)
- A C++ static initializer firing before `main` even runs (probable: no `bridge64.log` ever created suggests the logger never reached its first flush)

### Suggested Live Verification
1. **Set BP at the start of main itself (`0x1400270c0`)** — if it never hits, the abort is in a static initializer (CRT `__scrt_common_main` or a `.CRT$XCU` ctor).
2. **If main is reached, BP at `0x140020260` (first call) and step over each pre-CommandLineToArgvW call** to find which one fails. The early branch `if (cVar5 == '\0')` (failed `func_0x14001f380`) emits `"Failed to initialize rtx filesystem."` and then dies — but via a `swi(3)` inside std::string cleanup. That string ("Failed to initialize rtx filesystem.") would appear in stderr if logger isn't up.
3. **The argv-related abort theory is dead — drop it.** Focus instrumentation on early init: rtx filesystem init, NVAPI probe in `.CRT$XCU`, or a missing `.trex\bridge.conf` causing `func_0x140043000` to fault.
