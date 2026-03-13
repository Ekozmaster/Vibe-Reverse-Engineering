# Vibe Reverse Engineering

LLM-friendly static and dynamic analysis tools for **x86/x64 PE binaries**, designed for Cursor IDE. Point an agent at an `.exe`, describe what you want, and let it work.

No reverse engineering experience required -- just good prompting. Although some basic knowledge of programming and RE can go a long way.

## Requirements

- [Cursor IDE](https://cursor.sh)
OR
- [VSCode](https://code.visualstudio.com/) + [Copilot](https://github.com/features/copilot)
- Python 3.10+
- Visual Studio 2022+ with C++ Desktop workload (only needed to build ASI patches)

Radare2 (used by the decompiler) is bundled in `tools/` for Windows -- no separate install needed.

### Python setup

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## How it works

The project ships with Cursor rules (`.cursor/rules/`) that teach the agent a full tool catalog -- which tool to reach for, when, and why. The agent picks the right tool automatically based on your question.

**Static analysis** (`retools/`) works directly on PE files on disk: disassembly, decompilation, cross-references, call graphs, vtable analysis, byte pattern search, and more.

**Dynamic analysis** (`livetools/`) attaches to a running process via Frida: breakpoints, register/memory inspection, function tracing, instruction-level stepping, and live memory patching.

## Usage

Start a new chat in Cursor, point it at the target binary, and describe what you're after:

> Disable frustum culling in "D:/Games/MyGame/AwesomeGame.exe" -- I'm modding raytracing and need geometry to render behind the camera for reflections/mirrors.

Be descriptive about the feature or bug, the expected behavior, and your goal. The agent will plan and execute from there.

## Important

Some processes (especially games) require their window to be focused for dynamic analysis to capture data -- breakpoints won't hit and traces won't register otherwise. Follow the agent's instructions and watch what it is doing.

## License

[MIT](LICENSE)
