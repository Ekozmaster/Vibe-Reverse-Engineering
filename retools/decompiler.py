#!/usr/bin/env python3
"""Decompile a function from a PE binary.

Uses pyghidra (headless Ghidra) when a Ghidra project exists, falling back
to radare2 + r2ghidra/pdc. pyghidra runs Ghidra's full analysis pipeline
for richer type/calling convention recovery, but requires a one-time
analysis pass via pyghidra_backend.py.

Supports loading type/function/global metadata via ``--types`` to produce
richer decompiled output (named structs, function names, enum values).

Prerequisites:
    pip install r2pipe
    radare2 portable in  tools/radare2-*/bin  (auto-detected)

Usage:
    python -m retools.decompiler <binary> <va>
    python -m retools.decompiler <binary> <va> --types kb.h
    python -m retools.decompiler <binary> <va> --backend pdc
    python -m retools.decompiler <binary> <va> --project patches/MyGame --backend ghidra

Knowledge base format (``--types`` input):
    // C type definitions (struct, enum, typedef) -- no prefix
    struct Foo { int x; float y; };
    enum Mode { MODE_A=0, MODE_B=1 };

    // Function signatures at addresses -- @ prefix
    @ 0x401000 void __cdecl ProcessInput(int key);

    // Global variables at addresses -- $ prefix
    $ 0x7C5548 Foo* g_mainObject

Examples:
    python -m retools.decompiler binary.exe 0x401000
    python -m retools.decompiler binary.exe 0x401000 --types project/kb.h
    python -m retools.decompiler binary.exe 0x401000 --project patches/MyGame --backend ghidra
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import r2pipe
except ImportError:
    sys.exit("r2pipe not installed. Run: pip install r2pipe")

_HERE = Path(__file__).resolve().parent
_PROJECT = _HERE.parent

_BACKEND_CMDS = {
    "pdg": "pdg",    # r2ghidra – best quality
    "pdc": "pdc",    # r2 built-in pseudo-C
    "pdd": "pdd",    # r2dec (JS-based)
}


def _find_r2_bin() -> str | None:
    """Locate the radare2 binary, preferring the project-local portable install."""
    tools_dir = _PROJECT / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            candidate = child / "bin" / "radare2.exe"
            if candidate.is_file():
                return str(candidate)
            candidate = child / "bin" / "radare2"
            if candidate.is_file():
                return str(candidate)
    import shutil
    return shutil.which("radare2") or shutil.which("r2")


def _find_sleigh_home() -> str | None:
    """Locate the r2ghidra_sleigh directory containing flattened .ldefs/.sla files."""
    tools_dir = _PROJECT / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            candidate = child / "share" / "r2ghidra_sleigh"
            if candidate.is_dir() and any(candidate.glob("*.ldefs")):
                return str(candidate)
    xdg = Path.home() / ".local" / "share" / "radare2" / "plugins" / "r2ghidra_sleigh"
    if xdg.is_dir() and any(xdg.glob("*.ldefs")):
        return str(xdg)
    return None


def _ensure_r2_in_path(r2_bin: str) -> None:
    """Add radare2's bin dir to PATH so DLL deps resolve."""
    bin_dir = str(Path(r2_bin).parent)
    if bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")


def _load_types(r2, types_arg: str) -> None:
    """Parse a knowledge-base string and send type/function/global commands to r2."""
    if types_arg == "-":
        text = sys.stdin.read()
    elif os.path.isfile(types_arg):
        text = Path(types_arg).read_text(encoding="utf-8")
    else:
        text = types_arg

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        if line.startswith("@ "):
            rest = line[2:]
            addr_str, sig = rest.split(None, 1)
            addr = int(addr_str, 16)
            name = sig.rstrip(";").split("(")[0].split()[-1]
            r2.cmd(f"af @ {addr:#x}")
            r2.cmd(f"afn {name} @ {addr:#x}")
            r2.cmd(f"afs {sig.rstrip(';')} @ {addr:#x}")
        elif line.startswith("$ "):
            parts = line[2:].split()
            addr = int(parts[0], 16)
            name = parts[-1]
            r2.cmd(f"f {name} @ {addr:#x}")
            if len(parts) > 2:
                type_name = " ".join(parts[1:-1])
                r2.cmd(f"tl {type_name} @ {addr:#x}")
        else:
            r2.cmd(f"td {line}")


def decompile(binary: str, va: int, *, backend: str = "auto",
              full_analysis: bool = False, types: str | None = None,
              project_dir: str | None = None) -> str:
    """Decompile the function at *va* and return pseudo-C as a string.

    Args:
        binary: Path to PE file.
        va: Virtual address of the function.
        backend: Decompiler backend ("auto", "ghidra", "pyhidra", "pdg", "pdc", "pdd").
        full_analysis: If True, run ``aaa`` before decompiling.
        types: Knowledge-base string, stdin marker (``-``), or file path.
        project_dir: Project directory (e.g. ``patches/MyGame``). Enables
            pyghidra backend when a Ghidra project exists at ``<project_dir>/ghidra/``.
    """
    # -- pyghidra backend routing --
    if backend in ("ghidra", "pyhidra"):
        if not project_dir:
            return "[error] --project required with --backend ghidra"
        from retools.pyghidra_backend import decompile as ghidra_decompile
        ghidra_dir = str(Path(project_dir) / "ghidra")
        return ghidra_decompile(ghidra_dir, binary, va)

    if backend == "auto" and project_dir:
        from retools.pyghidra_backend import is_analyzed, decompile as ghidra_decompile
        bin_name = Path(binary).stem
        ghidra_dir = str(Path(project_dir) / "ghidra")
        if is_analyzed(ghidra_dir, bin_name):
            result = ghidra_decompile(ghidra_dir, binary, va)
            if not result.startswith("[error]"):
                return result
            # pyghidra error in auto mode -- fall through to r2ghidra
    # -- end pyghidra routing (fall through to r2ghidra) --

    r2_bin = _find_r2_bin()
    if r2_bin is None:
        raise FileNotFoundError(
            "radare2 not found. Install to tools/radare2-*/bin or add to PATH.")
    _ensure_r2_in_path(r2_bin)

    r2 = r2pipe.open(binary, flags=["-2"])
    try:
        r2.cmd("e scr.color=0")
        r2.cmd("e log.level=0")
        r2.cmd("e asm.lines=false")

        sleigh = _find_sleigh_home()
        if sleigh:
            r2.cmd(f"e r2ghidra.sleighhome={sleigh}")

        if types:
            _load_types(r2, types)

        if full_analysis:
            r2.cmd("aaa")
        else:
            r2.cmd(f"af @ {va:#x}")

        if backend == "auto":
            for try_be in ("pdg", "pdc"):
                out = r2.cmd(f"{_BACKEND_CMDS[try_be]} @ {va:#x}").strip()
                if out and "install" not in out.lower():
                    return out
            return f"[error] No decompiler backend produced output at {va:#x}"

        cmd = _BACKEND_CMDS.get(backend)
        if cmd is None:
            return f"[error] Unknown backend '{backend}'. Choose from: {', '.join(_BACKEND_CMDS)}"
        out = r2.cmd(f"{cmd} @ {va:#x}").strip()
        return out if out else f"[error] {backend} produced no output at {va:#x}"
    finally:
        r2.quit()


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Function virtual address in hex (e.g. 0x401000)")
    p.add_argument(
        "-b", "--backend",
        choices=["auto", "ghidra", "pyhidra", *_BACKEND_CMDS],
        default="auto",
        help="Decompiler backend (default: auto – tries pdg then pdc)",
    )
    p.add_argument(
        "-A", "--full-analysis",
        action="store_true",
        help="Run full r2 analysis (aaa) before decompiling – slower but better names",
    )
    p.add_argument(
        "-t", "--types",
        help="Knowledge base: inline types string, '-' for stdin, "
             "or path to .h file with structs/functions/globals",
    )
    p.add_argument(
        "-p", "--project",
        help="Project directory (e.g. patches/MyGame). "
             "Enables pyghidra backend when Ghidra project exists at <project>/ghidra/",
    )
    args = p.parse_args()
    if not args.types:
        print("hint: use --types kb.h to load a knowledge base for richer output", file=sys.stderr)
    print("KB workflow: decompile -> learn -> update kb.h with new types/functions/globals → decompile again",
          file=sys.stderr)
    print(decompile(args.binary, int(args.va, 16),
                    backend=args.backend, full_analysis=args.full_analysis,
                    types=args.types, project_dir=args.project))


if __name__ == "__main__":
    main()
