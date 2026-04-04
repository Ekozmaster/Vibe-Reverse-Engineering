"""CLI entry point for renderdoctools -- RenderDoc capture analysis toolkit.

Usage:  python -m renderdoctools <command> <capture.rdc> [args]

Event browser:
    python -m renderdoctools events <capture.rdc> [--draws-only] [--filter TEXT]

Pipeline state:
    python -m renderdoctools pipeline <capture.rdc> --event <EID> [--stage STAGE]

Textures:
    python -m renderdoctools textures <capture.rdc> --event <EID> [--save-all DIR]

Shaders:
    python -m renderdoctools shaders <capture.rdc> --event <EID> [--stage STAGE]

Mesh data:
    python -m renderdoctools mesh <capture.rdc> --event <EID> [--post-vs]

GPU counters:
    python -m renderdoctools counters <capture.rdc> [--fetch NAME] [--zero-samples]

Analysis:
    python -m renderdoctools analyze <capture.rdc> [--summary] [--biggest-draws N]

Utilities:
    python -m renderdoctools open <capture.rdc>
    python -m renderdoctools capture <exe> [--output FILE]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import core


def cmd_events(args: argparse.Namespace) -> None:
    config = {
        "draws_only": args.draws_only,
        "filter": args.filter or "",
    }
    result = core.run_script("events", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    events = result["events"]
    print("=== %d events ===" % result["total"])

    for ev in events:
        indent = "  " * ev["depth"]
        tag = ""
        if ev["draw"]:
            tag = " [DRAW idx=%d inst=%d]" % (ev["numIndices"], ev["numInstances"])
        elif ev["clear"]:
            tag = " [CLEAR]"
        print("%s%d: %s%s" % (indent, ev["eid"], ev["name"], tag))


def cmd_open(args: argparse.Namespace) -> None:
    qrd = core.find_renderdoc()
    capture = str(Path(args.capture).resolve())
    subprocess.Popen([str(qrd), capture])
    print("Opened %s in RenderDoc." % capture)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="renderdoctools",
        description="RenderDoc capture analysis toolkit",
    )
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    # events
    p_events = sub.add_parser("events", help="List events and draw calls")
    p_events.add_argument("capture", help="Path to .rdc capture file")
    p_events.add_argument("--draws-only", action="store_true", help="Only show draw calls")
    p_events.add_argument("--filter", type=str, default="", help="Filter events by name")
    p_events.add_argument("--json", action="store_true", help="Output raw JSON")
    p_events.add_argument("--output", type=str, help="Write output to file")
    p_events.set_defaults(func=cmd_events)

    # open
    p_open = sub.add_parser("open", help="Launch RenderDoc GUI with capture")
    p_open.add_argument("capture", help="Path to .rdc capture file")
    p_open.set_defaults(func=cmd_open)

    args = parser.parse_args()

    # Handle --output redirect
    if hasattr(args, "output") and args.output:
        with open(args.output, "w") as f:
            old_stdout = sys.stdout
            sys.stdout = f
            args.func(args)
            sys.stdout = old_stdout
    else:
        args.func(args)


if __name__ == "__main__":
    main()
