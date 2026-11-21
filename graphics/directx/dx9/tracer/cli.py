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
import secrets
import sys
import time
from enum import Enum, auto
from functools import partial
from pathlib import Path
from typing import Callable, NamedTuple


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


# How long the capture may go without reporting anything new
_WAIT_TIMEOUT_SECONDS = 120.0
_POLL_SECONDS = 0.3
# The tracers clamp the frame count of a trigger file to the same limit
MAX_CAPTURE_FRAMES = 100000


class _Progress(NamedTuple):
    """A progress line the tracer wrote about one capture.

    "<frame> <calls> <id>" while capturing, then " done" on the last write; or
    "0 0 <id> failed <reason>" from a tracer that could not start the capture.
    <id> is the id in the trigger file that started the capture.

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


class _NoProgress(Enum):
    """Why the progress file says nothing about a capture."""
    # The tracer rewrites the file in place, so a line without its newline is one it is still writing
    BEING_WRITTEN = auto()
    # No file, or a whole line about another capture
    NOT_REPORTED = auto()


def _read_progress(path: Path, capture_id: str) -> _Progress | _NoProgress:
    """What the progress file says about the capture started by the trigger carrying *capture_id*."""
    try:
        # A failure names a path, in the ANSI code page of the game's machine
        line = path.read_text(errors="replace")
    except FileNotFoundError:
        return _NoProgress.NOT_REPORTED
    if not line.endswith("\n"):
        return _NoProgress.BEING_WRITTEN
    fields = line.split(maxsplit=4)
    if len(fields) < 3 or fields[2] != capture_id:
        return _NoProgress.NOT_REPORTED
    try:
        progress = _Progress(int(fields[0]), int(fields[1]))
    except ValueError:
        return _NoProgress.NOT_REPORTED
    outcome = fields[3:]
    if outcome[:1] == ["failed"]:
        return progress._replace(failure=" ".join(outcome[1:]).strip() or "no reason given")
    return progress._replace(done=outcome == ["done"])


def _frames_short(progress: _Progress, frames: int) -> str:
    return f"the capture stopped at frame {progress.frame} of {frames}"


def _taken_without_report(trigger_path: Path, progress_path: Path) -> str:
    return (f"a tracer took the trigger but reported no progress for it. Either it could not write "
            f"{progress_path} (dxtrace_proxy.log, or the remix-comp-proxy log, says so), or it predates "
            f"progress reports that name their trigger: then copy the current "
            f"graphics/directx/dx9/tracer/bin/d3d9.dll, or a current remix-comp-proxy build, "
            f"to {trigger_path.parent}")


def _wait_for_capture(trigger_path: Path, progress_path: Path, frames: int, capture_id: str) -> str | None:
    """Follow the capture started by the trigger carrying *capture_id* until the tracer reports it written in full.

    Returns:
        None once the tracer reports the capture done at frame *frames* or
        later; otherwise the reason the capture was not seen to finish.
    """
    start = last_change = time.monotonic()
    progress = None
    while time.monotonic() - last_change < _WAIT_TIMEOUT_SECONDS:
        time.sleep(_POLL_SECONDS)
        # The tracer writes its first progress line before it takes the trigger: a progress
        # file read after the trigger is seen gone holds that line or a later one
        taken = not trigger_path.exists()
        seen = _read_progress(progress_path, capture_id)
        if seen is _NoProgress.NOT_REPORTED and taken and progress is None:
            return _taken_without_report(trigger_path, progress_path)
        if not isinstance(seen, _Progress):
            continue
        if seen.failure is not None:
            return f"the tracer could not start the capture: {seen.failure}"
        if seen != progress:
            progress = seen
            last_change = time.monotonic()
            print(f"\r  [frame {seen.frame}] {seen.calls} calls captured ({last_change - start:.1f}s)  ",
                  end="", flush=True)
        if progress.done:
            return None if progress.frame >= frames else _frames_short(progress, frames)

    if progress is None and trigger_path.exists():
        return (f"no tracer took the trigger within {_WAIT_TIMEOUT_SECONDS:.0f}s. Is the game running, "
                f"with the tracer's d3d9.dll in {trigger_path.parent}, and not still writing an earlier capture?")
    if progress is None:
        return _taken_without_report(trigger_path, progress_path)
    if progress.frame >= frames:
        return (f"the tracer reached frame {progress.frame} but never reported the capture file written in full. "
                f"Most likely it predates that report: copy the current graphics/directx/dx9/tracer/bin/d3d9.dll, "
                f"or a current remix-comp-proxy build, to {trigger_path.parent}")
    return f"{_frames_short(progress, frames)} and reported nothing new for {_WAIT_TIMEOUT_SECONDS:.0f}s"


def _modified_at(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def _when_released(operation: Callable[[], None]) -> None:
    """Run a file *operation*, again at each poll for as long as another process holds the file open.

    A tracer reading the trigger file holds it without sharing deletion, which
    Windows reports to a rename or a removal as a permission error.

    Raises:
        PermissionError: The file was still held after _WAIT_TIMEOUT_SECONDS.
    """
    deadline = time.monotonic() + _WAIT_TIMEOUT_SECONDS
    while True:
        try:
            return operation()
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(_POLL_SECONDS)


def _place_trigger(trigger_path: Path, frames: int, capture_id: str, wait_for_release: bool) -> None:
    """Put the trigger file in place whole, so a tracer polling for it never reads it empty.

    Args:
        wait_for_release: Wait for a tracer that holds an earlier trigger file open to let go of it.

    Raises:
        PermissionError: The folder cannot be written, or an earlier trigger file is held open.
    """
    staging = trigger_path.with_suffix(".tmp")
    try:
        staging.write_text(f"frames={frames}\nid={capture_id}\n")
        replace = partial(os.replace, staging, trigger_path)
        if wait_for_release:
            _when_released(replace)
        else:
            replace()
    finally:
        staging.unlink(missing_ok=True)


def _take_back_trigger(trigger_path: Path) -> bool:
    """Remove the trigger file, unless a tracer has taken it.

    Returns:
        Whether the file was there to remove.

    Raises:
        PermissionError: The file was still held open after _WAIT_TIMEOUT_SECONDS.
    """
    try:
        _when_released(trigger_path.unlink)
    except FileNotFoundError:
        return False
    return True


def _trigger_capture(game_dir: Path, frames: int, wait: bool) -> None:
    trigger_path = game_dir / "dxtrace_capture.trigger"
    progress_path = game_dir / "dxtrace_progress.txt"
    jsonl_path = game_dir / "dxtrace_frame.jsonl"

    earlier_capture = _modified_at(jsonl_path)
    capture_id = secrets.token_hex(8)
    _place_trigger(trigger_path, frames, capture_id, wait_for_release=wait)
    print(f"  Trigger file created: {trigger_path}")

    if not wait:
        print("  Use --wait to monitor progress, or run analyze when done.")
        return

    print("  Waiting for capture to complete...")
    try:
        problem = _wait_for_capture(trigger_path, progress_path, frames, capture_id)
    finally:
        # Left behind, the trigger would start a capture the next time the game runs
        if _take_back_trigger(trigger_path):
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


def cmd_trigger(args: argparse.Namespace) -> None:
    game_dir = Path(args.game_dir) if args.game_dir else Path(".")
    if not game_dir.is_dir():
        print(f"[error] Directory not found: {game_dir}")
        sys.exit(1)

    delay = args.delay
    if delay > 0:
        for remaining in range(delay, 0, -1):
            print(f"\r  Triggering capture in {remaining}s... (alt-tab to game now) ", end="", flush=True)
            time.sleep(1)
        print("\r  Triggering capture NOW                                        ")

    try:
        _trigger_capture(game_dir, args.frames, args.wait)
    except PermissionError as error:
        print(f"\n  [error] a tracer file in {game_dir} is not accessible: {error}")
        sys.exit(1)


def _capture_frames(text: str) -> int:
    """The --frames value: a count the tracers capture as asked."""
    try:
        frames = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not 1 <= frames <= MAX_CAPTURE_FRAMES:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_CAPTURE_FRAMES}")
    return frames


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
    tr.add_argument("--frames", "-n", type=_capture_frames, default=2,
                    help=f"Number of frames to capture, 1 to {MAX_CAPTURE_FRAMES}")
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
