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

    trigger_path.write_text(f"frames={args.frames}\n")
    print(f"  Trigger file created: {trigger_path}")

    if not args.wait:
        print("  Use --wait to monitor progress, or run analyze when done.")
        return

    print("  Waiting for capture to complete...")
    last_frame = -1
    last_seq = -1
    start = time.time()

    while True:
        time.sleep(0.3)

        if progress_path.exists():
            try:
                parts = progress_path.read_text().strip().split()
                frame, seq = int(parts[0]), int(parts[1])
                if frame != last_frame or seq != last_seq:
                    elapsed = time.time() - start
                    print(f"\r  [frame {frame}] {seq} calls captured ({elapsed:.1f}s)  ", end="", flush=True)
                    last_frame, last_seq = frame, seq

                if frame >= args.frames:
                    break
            except (ValueError, IndexError):
                pass

        if not trigger_path.exists() and last_frame < 0:
            time.sleep(0.5)
            if not trigger_path.exists():
                break

        if time.time() - start > 120:
            print("\n  [timeout] Capture did not complete within 120s")
            break

    print()
    if jsonl_path.exists():
        size_kb = jsonl_path.stat().st_size / 1024
        print(f"  Capture complete: {jsonl_path} ({size_kb:.1f} KB)")
        print(f"  Run: python -m graphics.directx.dx9.tracer analyze \"{jsonl_path}\" --summary")
    else:
        print(f"  [warning] Expected output not found: {jsonl_path}")


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
                    help="Output format: c (standalone proxy) or cpp (remix-comp module)")
    cg.set_defaults(func=cmd_codegen)

    # trigger
    tr = sub.add_parser("trigger", help="Signal trace proxy to capture frames")
    tr.add_argument("--game-dir", "-d", default=None, help="Target directory (default: cwd)")
    tr.add_argument("--frames", "-n", type=int, default=2, help="Number of frames to capture")
    tr.add_argument("--delay", type=int, default=3, help="Countdown seconds before trigger")
    tr.add_argument("--wait", "-w", action="store_true", help="Wait and show progress")
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
