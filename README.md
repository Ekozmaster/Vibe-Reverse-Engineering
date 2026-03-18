# Vibe Reverse Engineering

LLM-friendly static and dynamic analysis tools for **x86/x64 PE binaries**, designed for agentic coding tools. Point an agent at an `.exe`, describe what you want, and let it work.

No reverse engineering experience required -- just good prompting. Although some basic knowledge of programming and RE can go a long way.

## Requirements

- A supported agentic coding tool:
  - [Cursor IDE](https://cursor.sh)
  - [VSCode](https://code.visualstudio.com/) + [Copilot](https://github.com/features/copilot)
  - [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
  - [Kiro](https://kiro.dev)
- Python 3.10+
- Visual Studio 2022+ with C++ Desktop workload (only needed to build ASI patches)

Radare2 (used by the decompiler) is bundled in `tools/` for Windows -- no separate install needed.

### Python setup

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Tools

**Static analysis** (`retools/`) works directly on PE files on disk: disassembly, decompilation, cross-references, call graphs, vtable analysis, byte pattern search, and more.

**Dynamic analysis** (`livetools/`) attaches to a running process via Frida: breakpoints, register/memory inspection, function tracing, instruction-level stepping, and live memory patching.

**Game window automation** (`livetools/gamectl.py`) sends keystrokes and mouse clicks to a game window without Frida. Uses `SendInput` with `AttachThreadInput` focus management — works with DirectInput/RawInput games that ignore `PostMessage`. Target by process exe name:

```bash
python -m livetools gamectl --exe game.exe info
python -m livetools gamectl --exe game.exe keys "DOWN DOWN RETURN"
python -m livetools gamectl --exe game.exe macro --macro-file patches/MyGame/macros.json navigate_menu
```

**D3D9 frame tracer** (`graphics/directx/dx9/tracer/`) captures every `IDirect3DDevice9` call with arguments, backtraces, shader bytecodes, and matrix data. Outputs JSONL for offline analysis.

**RTX Remix FFP template** (`rtx_remix_tools/dx/dx9_ffp_template/`) is a D3D9 proxy DLL that converts shader-based games to fixed-function pipeline for RTX Remix compatibility.

## How it works

The project ships with agent instructions tailored to each supported environment:

| Tool | Instructions |
|------|-------------|
| Cursor | `.cursor/rules/` |
| Copilot | `.github/copilot-instructions.md` |
| Claude Code | `CLAUDE.md` |
| Kiro | `.kiro/steering/` + `.kiro/powers/` |

Each teaches the agent the full tool catalog — which tool to reach for, when, and why. The agent picks the right tool automatically based on your question.

### Kiro

Kiro loads context automatically via steering files and exposes deep skill knowledge via powers:

| Steering file | Loaded | Purpose |
|---------------|--------|---------|
| `tool-catalog.md` | Always | Complete reference for all tools |
| `engineering-standards.md` | Always | Code quality and comment standards |
| `dx9-ffp-port.md` | On proxy/patch files | RTX Remix FFP porting workflow |

| Power | Purpose |
|-------|---------|
| `dx9-ffp-port` | DX9 fixed-function pipeline porting knowledge base |
| `dynamic-analysis` | Frida-based dynamic analysis patterns and workflows |

Kiro also has agent hooks that enforce the workflow: research the game/API online and write a spec before touching code, verify fixes actually work after the agent stops, and keep the KB updated with game-specific findings.

## Usage

Open this directory in your agentic coding tool and describe what you're after:

> Disable frustum culling in "D:/Games/MyGame/AwesomeGame.exe" -- I'm modding raytracing and need geometry to render behind the camera for reflections/mirrors.

Be descriptive about the feature or bug, the expected behavior, and your goal. The agent will plan and execute from there.

## Important

Some processes (especially games) require their window to be focused for dynamic analysis to capture data -- breakpoints won't hit and traces won't register otherwise. Follow the agent's instructions and watch what it is doing.

## License

[MIT](LICENSE)
