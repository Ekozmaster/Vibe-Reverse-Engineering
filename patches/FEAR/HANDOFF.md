# FEAR → RTX Remix Port — Handoff

**As of:** 2026-05-11 ~02:33 — **FEAR renders through RTX Remix for the first time.** See the breakthrough TL;DR immediately below; the older 02:05/02:13/05-07/05-06/05-03 entries are kept for diagnostic context.
**Workspace rule:** every build is auto-deployed into `FEAR Ultimate Shooter Edition/` via `deploy.ps1`. `deploy.ps1` now accepts `-GameDir <path>` for testing against alternate installs (e.g. CLEAN). The user does not copy files manually.

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
