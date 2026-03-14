# DX9 FFP Template

A modifiable DX9 proxy DLL that converts shader-based rendering to the fixed-function pipeline (FFP) for RTX Remix compatibility. This is **not** a drag-and-drop solution — it's a starting codebase you adapt per-game using the Vibe RE tools and AI chat.

## Getting Started with Copilot

A prompt file is included at `.github/copilot-prompts/dx9-ffp-port.prompt.md`. In VS Code Copilot chat, type `#dx9-ffp-port` to load it as context. This gives Copilot full knowledge of the template architecture, porting workflow, and common pitfalls — so you can work through the port conversationally without re-explaining the codebase each time.

## How It Works

The proxy replaces the game's `d3d9.dll`, intercepts `IDirect3DDevice9` calls, and:

1. **Captures** vertex shader constants (View, Projection, World matrices)
2. **NULLs** both vertex and pixel shaders on draw calls
3. **Applies** captured matrices via `SetTransform` (FFP)
4. **Sets up** texture stages and lighting for FFP rendering
5. **Chain-loads** RTX Remix (`d3d9_remix.dll`) so Remix sees FFP geometry

## Project Structure

```
dx9_ffp_template/
├── proxy/
│   ├── d3d9_main.c       # DLL entry, logging, chain loading
│   ├── d3d9_wrapper.c    # IDirect3D9 wrapper (17 methods)
│   ├── d3d9_device.c     # IDirect3DDevice9 wrapper (119 methods) — core FFP conversion
│   ├── build.bat         # MSVC x86 build script
│   ├── d3d9.def          # Export definition
│   └── proxy.ini         # Runtime config (chain loading, albedo stage)
├── scripts/
│   ├── find_d3d_calls.py      # Find D3D9/D3DX imports and call sites
│   ├── find_device_calls.py   # Find device vtable calls + device pointer refs
│   ├── find_vs_constants.py   # Find SetVertexShaderConstantF sites + args
│   ├── find_vtable_calls.py   # Find D3DX constant table + D3D9 vtable calls
│   ├── decode_vtx_decls.py    # Decode vertex declarations (auto-scan or manual)
│   └── scan_d3d_region.py     # Map all D3D9 vtable calls in a code region
├── kb.h                       # Knowledge base (accumulate RE discoveries)
└── README.md
```

## Porting Workflow

### Step 1: Initial Analysis

Run the analysis scripts against your game binary to understand its D3D9 usage:

```bash
# Find DirectX imports and call sites
python scripts/find_d3d_calls.py "C:\Games\YourGame\game.exe"

# Find device pointer and vtable call patterns
python scripts/find_device_calls.py "C:\Games\YourGame\game.exe" --device-addr 0xADDRESS

# Find SetVertexShaderConstantF call sites and their arguments
python scripts/find_vs_constants.py "C:\Games\YourGame\game.exe"

# Find D3DX constant table usage
python scripts/find_vtable_calls.py "C:\Games\YourGame\game.exe"

# Decode vertex declarations (auto-scan for them)
python scripts/decode_vtx_decls.py "C:\Games\YourGame\game.exe" --scan

# Map all D3D9 calls in the engine's rendering code region
python scripts/scan_d3d_region.py "C:\Games\YourGame\game.exe" 0xSTART 0xEND
```

### Step 2: Discover VS Constant Layout

The most important thing to discover is which VS constant registers hold the View, Projection, and World matrices. Use the Vibe RE tools:

```bash
# Decompile the function that calls SetVertexShaderConstantF
python -m retools.decompiler game.exe 0xCALL_SITE_ADDR --types kb.h

# Trace live to see actual register values
python -m livetools trace 0xSetVSConstF_addr --count 50 \
    --read "[esp+4]:4:uint32; [esp+8]:4:uint32; [esp+c]:64:float32"
```

Common patterns:
- **Registers 0-3**: View matrix (4 vec4 = 16 floats)
- **Registers 4-7**: Projection matrix
- **Registers 16-19**: World matrix
- **Registers 20+**: Bone palette (3 regs/bone for 4x3 matrices)

### Step 3: Update the Defines

Edit the `GAME-SPECIFIC` section at the top of `d3d9_device.c`:

```c
#define VS_REG_VIEW_START       0   // Your game's view matrix start register
#define VS_REG_VIEW_END         4
#define VS_REG_PROJ_START       4   // Your game's projection matrix start register
#define VS_REG_PROJ_END         8
#define VS_REG_WORLD_START     16   // Your game's world matrix start register
#define VS_REG_WORLD_END       20
```

### Step 4: Build and Test

```bash
cd proxy
build.bat
```

Deploy `d3d9.dll` + `proxy.ini` to the game directory. If using Remix, also place `d3d9_remix.dll` there.

Check `ffp_proxy.log` in the game directory for diagnostic output. The proxy logs detailed draw call information for the first few frames after a configurable delay (default 50 seconds).

### Step 5: Iterate

Use the diagnostic log to understand what's happening:
- **VS regs written**: Which constant registers the game actually uses
- **Vertex declarations**: What vertex formats the game uses
- **Draw calls**: DIP vs DP, vertex counts, textures per stage
- **Matrices**: The actual View/Proj/World values being captured

Common adjustments:
- **Wrong matrices**: Re-check register mapping with live tracing
- **Missing textures**: Adjust `AlbedoStage` in `proxy.ini`
- **Skinned meshes**: Currently passed through with shaders; modify `WD_DrawIndexedPrimitive` to route differently
- **UI/particles broken**: Adjust `WD_DrawPrimitive` pass-through logic

## Build Requirements

- **MSVC x86** (Visual Studio with C++ desktop workload)
- Run from a **VS Developer Command Prompt (x86)**
- No external dependencies (no CRT, no SDK headers)

## Configuration (proxy.ini)

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `[Remix]` | `Enabled` | `1` | Chain-load RTX Remix DLL |
| `[Remix]` | `DLLName` | `d3d9_remix.dll` | Name of Remix DLL |
| `[Preload]` | `DLL` | *(empty)* | Side-effect DLL to load at startup |
| `[FFP]` | `AlbedoStage` | `0` | Which texture stage has the albedo texture |

## Architecture Notes

- **No CRT**: The proxy uses no C runtime. Hand-rolled `memcpy`, `HeapAlloc`, `WriteFile` logging. Links only `kernel32.lib`.
- **COM vtable replacement**: `WrappedDevice` is a C struct with a manually-built vtable. 104 non-intercepted methods use `__declspec(naked)` relay thunks (zero overhead).
- **FFP Engage/Disengage**: The proxy tracks whether it's in FFP mode and avoids redundant state switches between consecutive draw calls.
- **Skinning**: Behind `#ifdef ENABLE_SKINNING`. Detects bone palettes from large VS constant writes. FFP indexed vertex blending supports max ~48 bones.
