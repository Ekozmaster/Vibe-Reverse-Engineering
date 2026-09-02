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

**Indexed queries** (`retools/index.py` + `retools/query.py`) cache analyzed facts (functions, names, cross-references, strings, imports) into a per-game SQLite file (`patches/<Game>/index.db`), so the agent can answer "who calls this" or "find all strings matching X" with a local SQL query instead of re-scanning the binary. Bootstrap and Ghidra analysis both feed it; Ghidra-sourced facts win over provisional ones.

**Ghidra server** (`retools/ghidra_server.py`) keeps one Ghidra program warm per game project so repeat decompilations return in well under a second instead of paying Ghidra's analysis cost on every call.

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

Agent instructions are **single-sourced** — edit once, every harness picks it up:

- **`AGENTS.md`** (repo root) — canonical instructions: project conventions, engineering standards, and pointers to the tool catalog. Read natively by Cursor, Kiro, Codex, and most agents. VS Code Copilot loads it via the shipped `.vscode/settings.json` (`chat.useAgentsMdFile`); Claude Code imports it from `.claude/CLAUDE.md`.
- **`.claude/`** — the maintained tree for everything deeper: skills (`.claude/skills/`), tool catalog (`.claude/references/`), workflow rules (`.claude/rules/`), and subagent definitions (`.claude/agents/`). These files are plain Markdown any agent can read by path.

Skills install themselves: Claude Code reads `.claude/skills/` natively, and AGENTS.md instructs every other agent to install the skills into its own skills directory on first use (via the [skills CLI](https://github.com/vercel-labs/skills) or a manual copy). Normally you don't need to do anything — open the repo and start working.

To install manually instead, or to consume the skills from another project:

```bash
# Inside this repo (pick your agent):
npx skills add ./.claude/skills -a cursor -y     # or -a copilot, -a kiro-cli, ...

# From anywhere else:
npx skills add Ekozmaster/Vibe-Reverse-Engineering
```

Inside the repo, point the source at `./.claude/skills` explicitly — with a bare `.` the CLI skips the current project's own agent directories and finds nothing. Installed copies live in git-ignored locations (`.agents/`, `.cursor/skills/`, `skills-lock.json`, …); the canonical, editable copies stay in `.claude/skills/`.

## Usage

Open this directory in your agentic coding tool and describe what you're after:

> Disable frustum culling in "D:/Games/MyGame/AwesomeGame.exe" -- I'm modding raytracing and need geometry to render behind the camera for reflections/mirrors.

Be descriptive about the feature or bug, the expected behavior, and your goal. The agent will plan and execute from there.

## Important

Some processes (especially games) require their window to be focused for dynamic analysis to capture data -- breakpoints won't hit and traces won't register otherwise. Follow the agent's instructions and watch what it is doing.

## License

[MIT](LICENSE)

# Contributors
- E-man (aka Ekozmaster, Project Lead)
- Kim2091
  - [Consider supporting!](https://ko-fi.com/kim20913944)
- Night1099
