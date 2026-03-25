"""Pyghidra (headless Ghidra) decompiler backend.

Provides one-time analysis of PE binaries and on-demand decompilation
using Ghidra's DecompInterface via the pyghidra bridge.
"""

import argparse
import os
import shutil
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# is_analyzed
# ---------------------------------------------------------------------------

def is_analyzed(project_dir: str, binary_name: str) -> bool:
    """Check whether a Ghidra project with completed analysis exists.

    Args:
        project_dir: Path to the directory containing the .gpr and .rep.
        binary_name: Original binary filename (e.g. ``game.exe``).

    Returns:
        True if a .gpr file and a non-empty .rep directory exist.
    """
    base = Path(project_dir)
    stem = Path(binary_name).stem
    # pyghidra.open_program() nests the project: project_dir/stem/stem.gpr
    nested = base / stem
    gpr = nested / f"{stem}.gpr"
    rep = nested / f"{stem}.rep"
    if not gpr.exists():
        return False
    if not rep.is_dir():
        return False
    if not any(rep.iterdir()):
        return False
    return True


# ---------------------------------------------------------------------------
# _import_pyghidra
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_TOOLS = _HERE.parent / "tools"


def _ensure_java_env():
    """Set JAVA_HOME and PATH from portable JDK in tools/ if needed."""
    if os.environ.get("JAVA_HOME") or shutil.which("java"):
        return
    for d in sorted(_TOOLS.glob("jdk-*"), reverse=True):
        java_bin = d / "bin" / "java.exe"
        if not java_bin.exists():
            java_bin = d / "bin" / "java"
        if java_bin.exists():
            os.environ["JAVA_HOME"] = str(d)
            os.environ["PATH"] = str(d / "bin") + os.pathsep + os.environ.get("PATH", "")
            return


def _ensure_ghidra_env():
    """Set GHIDRA_INSTALL_DIR from tools/ if not already set."""
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        return
    for d in sorted(_TOOLS.glob("ghidra_*"), reverse=True):
        if d.is_dir() and (d / "ghidraRun.bat").exists():
            os.environ["GHIDRA_INSTALL_DIR"] = str(d)
            return


def _import_pyghidra():
    """Lazily import pyghidra, returning None if not installed."""
    _ensure_java_env()
    _ensure_ghidra_env()
    try:
        import pyghidra
        return pyghidra
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def analyze(binary: str, project_dir: str) -> str:
    """Run Ghidra auto-analysis on a binary and save the project.

    Args:
        binary: Path to the PE binary to analyze.
        project_dir: Directory to store the Ghidra project files.

    Returns:
        Summary string on success, or ``[error] ...`` on failure.
    """
    pyghidra = _import_pyghidra()
    if pyghidra is None:
        return "[error] pyghidra is not installed"

    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        return "[error] GHIDRA_INSTALL_DIR environment variable not set"

    binary_path = Path(binary)
    proj_dir = Path(project_dir)
    proj_dir.mkdir(parents=True, exist_ok=True)
    project_name = binary_path.stem

    pyghidra.start()

    t0 = time.time()
    with pyghidra.open_program(
        binary,
        project_location=str(proj_dir),
        project_name=project_name,
        analyze=True,
    ):
        elapsed = time.time() - t0

    return f"Analysis complete: {binary_path.name} ({elapsed:.1f}s), project saved to {proj_dir}"


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------

def decompile(project_dir: str, binary: str, va: int) -> str:
    """Decompile a function at the given virtual address.

    Opens a previously-analyzed Ghidra project and uses DecompInterface
    to produce C output for the function containing ``va``.

    Args:
        project_dir: Path to the Ghidra project directory.
        binary: Path to the original PE binary.
        va: Virtual address inside the target function.

    Returns:
        Decompiled C string, or ``[error] ...`` on failure.
    """
    binary_path = Path(binary)
    binary_name = binary_path.name

    if not is_analyzed(project_dir, binary_name):
        return f"[error] no analyzed project for {binary_name} in {project_dir}"

    pyghidra = _import_pyghidra()
    if pyghidra is None:
        return "[error] pyghidra is not installed"

    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        return "[error] GHIDRA_INSTALL_DIR environment variable not set"

    project_name = binary_path.stem

    pyghidra.start()

    with pyghidra.open_program(
        binary,
        project_location=str(project_dir),
        project_name=project_name,
        analyze=False,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(program)

        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(va)
        func = program.getListing().getFunctionContaining(addr)
        if func is None:
            return f"[error] no function found at 0x{va:X}"

        monitor = ConsoleTaskMonitor()
        result = ifc.decompileFunction(func, 60, monitor)
        return result.getDecompiledFunction().getC()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """CLI entry point with analyze, decompile, and status subcommands."""
    parser = argparse.ArgumentParser(
        prog="pyghidra_backend",
        description="Pyghidra headless Ghidra backend",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- analyze ---
    p_analyze = sub.add_parser("analyze", help="Run Ghidra auto-analysis on a binary")
    p_analyze.add_argument("binary", help="Path to PE binary")
    p_analyze.add_argument("--project", required=True, help="Project directory")

    # --- decompile ---
    p_decompile = sub.add_parser("decompile", help="Decompile a function")
    p_decompile.add_argument("binary", help="Path to PE binary")
    p_decompile.add_argument("va", help="Virtual address (hex)")
    p_decompile.add_argument("--project", required=True, help="Project directory")

    # --- status ---
    p_status = sub.add_parser("status", help="Check analysis status")
    p_status.add_argument("binary", help="Path to PE binary")
    p_status.add_argument("--project", required=True, help="Project directory")

    args = parser.parse_args()
    ghidra_dir = str(Path(args.project) / "ghidra")
    binary_name = Path(args.binary).name

    if args.command == "status":
        if is_analyzed(ghidra_dir, binary_name):
            print(f"Analyzed: {binary_name}")
        else:
            print(f"Not analyzed: {binary_name}")
        raise SystemExit(0)

    if args.command == "analyze":
        result = analyze(args.binary, ghidra_dir)
        print(result)
        raise SystemExit(0)

    if args.command == "decompile":
        va = int(args.va, 16) if args.va.startswith("0x") else int(args.va)
        result = decompile(ghidra_dir, args.binary, va)
        print(result)
        raise SystemExit(0)


if __name__ == "__main__":
    main()
