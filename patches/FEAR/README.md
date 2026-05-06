# remix-comp-proxy

A DX9 proxy framework for RTX Remix compatibility mods, with built-in fixed-function pipeline (FFP) conversion. Part of the [Vibe Reverse Engineering](https://github.com/Ekozmaster/Vibe-Reverse-Engineering) toolkit.

## What It Does

Legacy DX9 games use vertex/pixel shaders that RTX Remix can't inject ray-traced lighting into. This proxy sits between the game and Remix, intercepting D3D9 calls and converting shader-based rendering to fixed-function pipeline calls that Remix understands.

### Core Features

- **Full D3D9 proxy** — d3d9.dll proxy with every IDirect3DDevice9 method intercepted
- **FFP conversion** — captures VS constants, parses vertex declarations, transposes matrices, and routes draw calls through the D3D9 fixed-function pipeline
- **Draw routing** — configurable decision trees that classify each draw call (3D geometry, HUD, skinned mesh) and decide whether to convert or pass through
- **Integrated frame tracer** — captures all D3D9 API calls to JSONL with category filtering, delayed capture, and external trigger support
- **INI configuration** — game-specific register layouts, albedo stage, skinning toggle, and diagnostics settings in `remix-comp-proxy.ini` (no recompile needed)
- **ImGui debug overlay** (F4) — live VS constant heatmap, matrix viewer, texture stage bindings, draw stats, FFP enable/disable toggle, tracer controls
- **Diagnostic logging** — timed frame dump to `rtx_comp\diagnostics.log` for debugging VS register layouts, vertex declarations, and draw call routing
- **Optional skinning module** — runtime-toggled vertex skinning with bone matrix upload, vertex buffer expansion, and compressed format decoding
- **DLL chain loading** — pre-load and post-load DLL/ASI injection for additional mods
- **Component module system** — `shared/` (game-agnostic static lib) + `comp/` (game-specific DLL) with clean separation
- **Per-game build split** — shared library stays in the base, only `comp/` is copied per game project

### Architecture

```
src/
  shared/              Game-agnostic static library
    common/
      config.hpp/cpp     INI config reader
      ffp_state.hpp/cpp  FFP state tracking, transforms, lighting, texture stages
      ...
    utils/               Hooking, memory, general utilities
  comp/                Game-specific DLL (copy this per game)
    main.cpp             DLL entry, window finding, config loading
    comp.cpp             Module registration
    d3d9_proxy.cpp       d3d9.dll export forwarding
    game/                Game-specific patterns and structs
    modules/
      d3d9ex.cpp         D3D9 proxy with FFP + tracer interceptions
      renderer.cpp       Draw routing decision trees
      imgui.cpp          Debug overlay with FFP tab
      tracer.cpp         Integrated frame tracer
      diagnostics.cpp    Frame logging
      skinning.cpp       Optional skinning
```

## Building

1. Run `build.bat` (requires Visual Studio 2022)
2. Output: `build/bin/release/d3d9.dll`

For per-game projects: `build.bat release --name GameName --comp path/to/comp`

## Deploying

1. Copy `d3d9.dll` to the game directory
2. Copy `remix-comp-proxy.ini` to the game directory
3. Edit `remix-comp-proxy.ini` with game-specific settings
4. Place `d3d9_remix.dll` (RTX Remix) in the game directory

## Contributors

| Who | What | Support |
|-----|------|---------|
| [xoxor4d](https://github.com/xoxor4d) | Original [remix-comp-base](https://github.com/xoxor4d/remix-comp-base) framework, D3D9 proxy architecture, ImGui integration, module system | [Ko-Fi](https://ko-fi.com/xoxor4d) / [Patreon](https://patreon.com/xoxor4d) |
| [kim2091](https://github.com/kim2091) | FFP conversion system, skinning module, diagnostic logging, tracer integration, INI config, toolkit integration | [Ko-Fi](https://ko-fi.com/kim20913944) |
| [momo5502](https://github.com/momo5502) | Initial codebase that remix-comp-base was built on | |

## Dependencies

- [Dear ImGui](https://github.com/ocornut/imgui) — debug overlay
- [MinHook](https://github.com/TsudaKageyu/minhook) — function hooking
- [RTX Remix Bridge API](https://github.com/NVIDIAGameWorks/rtx-remix) — Remix integration

## License

MIT. See [LICENSE](LICENSE).
