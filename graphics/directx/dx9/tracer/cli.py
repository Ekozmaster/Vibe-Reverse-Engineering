"""D3D9 frame trace tool -- capture and analyze complete D3D9 call sequences.

Subcommands:
    codegen   Generate d3d9_trace_hooks.inc from the method database
    trigger   Signal the trace proxy to capture N frames
    analyze   Offline analysis of captured JSONL trace files

Usage:
    python -m graphics.directx.dx9.tracer codegen [--output PATH]
    python -m graphics.directx.dx9.tracer trigger [--game-dir PATH] [--frames 2] [--delay 3] [--wait]
    python -m graphics.directx.dx9.tracer analyze <file.jsonl> [options]

Examples:
    # Generate C hooks header
    python -m graphics.directx.dx9.tracer codegen -o src/d3d9_trace_hooks.inc

    # Trigger a 2-frame capture with 5s delay
    python -m graphics.directx.dx9.tracer trigger --game-dir "C:/Games/MyGame" --delay 5

    # Analyze the captured trace
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --summary
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --hotpaths --top 20
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --matrix-flow
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --draw-calls --filter "frame==0"
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --render-passes
    python -m graphics.directx.dx9.tracer analyze dxtrace_frame.jsonl --resolve-addrs app.exe --hotpaths
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import NamedTuple


def cmd_codegen(args: argparse.Namespace) -> None:
    from .d3d9_methods import generate_hooks_inc, generate_cpp_dispatch_inc, SLOT_COUNT, max_argc

    if args.format == "cpp":
        code = generate_cpp_dispatch_inc()
        label = "C++ dispatch"
    else:
        code = generate_hooks_inc()
        label = "C hooks"

    if args.output:
        Path(args.output).write_text(code)
        print(f"Generated {args.output} ({label}, {SLOT_COUNT} methods, max {max_argc()} args)")
    else:
        sys.stdout.write(code)


_WAIT_TIMEOUT_SECONDS = 120.0
_POLL_SECONDS = 0.3
# A tracer writes its first progress line as it takes the trigger
_PROGRESS_GRACE_SECONDS = 2.0


class _Progress(NamedTuple):
    """The one line of the tracer's progress file.

    "<frame> <calls>" while capturing, then " done" on the last write; or
    "0 0 failed <reason>" from a tracer that could not start the capture.

    Attributes:
        frame: Frames the capture has finished.
        calls: Calls it has recorded.
        done: The capture is over and every recorded call is in the JSONL file.
        failure: Why the tracer could not start the capture; None when it could.
    """
    frame: int
    calls: int
    done: bool = False
    failure: str | None = None


def _read_progress(path: Path) -> _Progress | None:
    """The tracer's progress; None while there is no whole line to read.

    The tracer rewrites the file in place, so a line without its newline is
    one it is still writing.
    """
    try:
        # A failure names a path, in the ANSI code page of the game's machine
        line = path.read_text(errors="replace")
        if not line.endswith("\n"):
            return None
        frame, calls, *outcome = line.split(maxsplit=3)
        progress = _Progress(int(frame), int(calls))
    except (OSError, ValueError):
        return None
    if outcome[:1] == ["failed"]:
        return progress._replace(failure=" ".join(outcome[1:]).strip() or "no reason given")
    return progress._replace(done=outcome == ["done"])


def _frames_short(progress: _Progress, frames: int) -> str:
    return f"the capture stopped at frame {progress.frame} of {frames}"


def _wait_for_capture(trigger_path: Path, progress_path: Path, frames: int) -> str | None:
    """Follow a capture until the tracer reports it written in full.

    Returns:
        None once the tracer reports the capture done at frame *frames* or
        later; otherwise the reason the capture was not seen to finish.
    """
    start = time.time()
    taken_at = None
    progress = None
    while time.time() - start < _WAIT_TIMEOUT_SECONDS:
        time.sleep(_POLL_SECONDS)
        seen = _read_progress(progress_path)
        if seen is not None and seen.failure is not None:
            return f"the tracer could not start the capture: {seen.failure}"
        if seen is not None and seen != progress:
            progress = seen
            print(f"\r  [frame {seen.frame}] {seen.calls} calls captured ({time.time() - start:.1f}s)  ",
                  end="", flush=True)
        if progress is not None and progress.done:
            return None if progress.frame >= frames else _frames_short(progress, frames)
        if taken_at is None and not trigger_path.exists():
            taken_at = time.time()
        if taken_at is not None and progress is None and time.time() - taken_at > _PROGRESS_GRACE_SECONDS:
            return (f"a tracer took the trigger but reported no progress. Either it could not write "
                    f"{progress_path} or start the capture (dxtrace_proxy.log, or the remix-comp-proxy log, "
                    f"says which), or it predates progress reports: then copy the current "
                    f"graphics/directx/dx9/tracer/bin/d3d9.dll, or a current remix-comp-proxy build, "
                    f"to {trigger_path.parent}")

    if progress is None:
        return (f"no tracer took the trigger within {_WAIT_TIMEOUT_SECONDS:.0f}s. Is the game running, "
                f"with the tracer's d3d9.dll in {trigger_path.parent}?")
    if progress.frame >= frames:
        return (f"the tracer reached frame {progress.frame} but never reported the capture file written in full. "
                f"Most likely it predates that report: copy the current graphics/directx/dx9/tracer/bin/d3d9.dll, "
                f"or a current remix-comp-proxy build, to {trigger_path.parent}")
    return _frames_short(progress, frames)


def _modified_at(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def _write_trigger(trigger_path: Path, frames: int) -> None:
    """Write the trigger file whole, so a tracer polling for it never reads it empty."""
    staging = trigger_path.with_suffix(".tmp")
    staging.write_text(f"frames={frames}\n")
    os.replace(staging, trigger_path)


def cmd_trigger(args: argparse.Namespace) -> None:
    game_dir = Path(args.game_dir) if args.game_dir else Path(".")
    trigger_path = game_dir / "dxtrace_capture.trigger"
    progress_path = game_dir / "dxtrace_progress.txt"
    jsonl_path = game_dir / "dxtrace_frame.jsonl"

    if not game_dir.is_dir():
        print(f"[error] Directory not found: {game_dir}")
        sys.exit(1)

    delay = args.delay
    if delay > 0:
        for remaining in range(delay, 0, -1):
            print(f"\r  Triggering capture in {remaining}s... (alt-tab to game now) ", end="", flush=True)
            time.sleep(1)
        print("\r  Triggering capture NOW                                        ")

    # Progress left by an earlier capture would read as progress of this one
    progress_path.unlink(missing_ok=True)
    earlier_capture = _modified_at(jsonl_path)
    _write_trigger(trigger_path, args.frames)
    print(f"  Trigger file created: {trigger_path}")

    if not args.wait:
        print("  Use --wait to monitor progress, or run analyze when done.")
        return

    print("  Waiting for capture to complete...")
    try:
        problem = _wait_for_capture(trigger_path, progress_path, args.frames)
    finally:
        # Left behind, the trigger would start a capture the next time the game runs
        try:
            trigger_path.unlink()
        except FileNotFoundError:
            pass  # the tracer took it
        else:
            print(f"\n  Trigger file removed: {trigger_path}")
    print()

    if problem is not None:
        print(f"  [error] {problem}")
        sys.exit(1)

    if _modified_at(jsonl_path) in (None, earlier_capture):
        # The remix-comp-proxy tracer names each capture after the time it started
        print(f"  Capture complete, in the [Tracer] OutputDir folder under {game_dir} (captures by default)")
        return
    size_kb = jsonl_path.stat().st_size / 1024
    print(f"  Capture complete: {jsonl_path} ({size_kb:.1f} KB)")
    print(f"  Run: python -m graphics.directx.dx9.tracer analyze \"{jsonl_path}\" --summary")


def cmd_analyze(args: argparse.Namespace) -> None:
    from .analyze import run_analysis
    run_analysis(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dx9tracer",
        description="D3D9 frame trace: capture and analyze complete API call sequences.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # codegen
    cg = sub.add_parser("codegen", help="Generate d3d9_trace_hooks.inc")
    cg.add_argument("--output", "-o", default=None, help="Output path (default: stdout)")
    cg.add_argument("--format", "-f", choices=["c", "cpp"], default="c",
                    help="Output format: c (standalone proxy) or cpp (remix-comp-proxy module)")
    cg.set_defaults(func=cmd_codegen)

    # trigger
    tr = sub.add_parser("trigger", help="Signal trace proxy to capture frames")
    tr.add_argument("--game-dir", "-d", default=None, help="Target directory (default: cwd)")
    tr.add_argument("--frames", "-n", type=int, default=2, help="Number of frames to capture")
    tr.add_argument("--delay", type=int, default=3, help="Countdown seconds before trigger")
    tr.add_argument("--wait", "-w", action="store_true",
                    help="Follow the capture until the tracer reports it written in full; "
                         "exit 1 when it was not seen to get there")
    tr.set_defaults(func=cmd_trigger)

    # analyze
    an = sub.add_parser("analyze", help="Analyze captured JSONL trace")
    an.add_argument("file", help="Path to dxtrace_frame.jsonl")
    an.add_argument("--summary", action="store_true", help="Overview: calls per frame/method")
    an.add_argument("--draw-calls", action="store_true", help="List draws with state deltas")
    an.add_argument("--callers", metavar="METHOD", help="Caller histogram for a method")
    an.add_argument("--hotpaths", action="store_true", help="Frequency-sorted call paths")
    an.add_argument("--top", type=int, default=20, help="Number of results for ranked output")
    an.add_argument("--state-at", type=int, metavar="SEQ", help="Reconstruct state at sequence N")
    an.add_argument("--render-loop", action="store_true", help="Detect render loop entry point")
    an.add_argument("--render-passes", action="store_true", help="Group draws by render target")
    an.add_argument("--matrix-flow", action="store_true", help="Track constant matrix uploads")
    an.add_argument("--shader-map", action="store_true", help="Disassemble shaders, show register map")
    an.add_argument("--fxc", metavar="PATH", help="Path to fxc.exe (fallback for shader disasm)")
    an.add_argument("--diff-draws", nargs=2, type=int, metavar=("A", "B"), help="State diff between draws")
    an.add_argument("--diff-frames", nargs=2, type=int, metavar=("A", "B"), help="Compare two frames")
    an.add_argument("--rt-graph", action="store_true", help="Render target dependency graph")
    an.add_argument("--classify-draws", action="store_true", help="Auto-tag draws by render state")
    an.add_argument("--vtx-formats", action="store_true", help="Group draws by vertex declaration")
    an.add_argument("--redundant", action="store_true", help="Find redundant state-set calls")
    an.add_argument("--texture-freq", action="store_true", help="Texture binding frequency")
    an.add_argument("--const-provenance", action="store_true",
                    help="Show which seq# set each constant register at draw time")
    an.add_argument("--const-provenance-draw", type=int, metavar="DRAW#",
                    help="Detailed constant provenance for a single draw index")
    an.add_argument("--const-evolution", metavar="RANGE",
                    help="Track register changes across draws (e.g. vs:c0-c6, ps:c0-c3, c4-c6)")
    an.add_argument("--state-snapshot", type=int, metavar="DRAW#",
                    help="Full state dump at a specific draw index")
    an.add_argument("--transform-calls", action="store_true",
                    help="Analyze SetTransform/SetViewport usage and timing")
    an.add_argument("--animate-constants", action="store_true", help="Cross-frame constant tracking")
    an.add_argument("--pipeline-diagram", action="store_true", help="Auto-generate mermaid render pipeline")
    an.add_argument("--resolve-addrs", metavar="BINARY", help="Resolve backtrace addrs via retools")
    an.add_argument("--filter", metavar="EXPR", help="Filter records (field==value)")
    an.add_argument("--export-csv", metavar="FILE", help="Export to CSV")
    an.set_defaults(func=cmd_analyze)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
