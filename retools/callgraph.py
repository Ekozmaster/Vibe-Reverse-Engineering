#!/usr/bin/env python3
"""Build multi-level caller or callee trees for a function.

Recursively finds callers (--up) or callees (--down) to the specified
depth.  Default output is an indented tree; --flat gives a sorted list
of unique addresses.

Modes:
    --up N    Walk UP the call chain: who calls this function? (N levels)
    --down N  Walk DOWN the call chain: what does this function call? (N levels)

Usage:
    python retools/callgraph.py <binary> <target> --up N   [--flat]
    python retools/callgraph.py <binary> <target> --down N [--flat]

Examples:
    python retools/callgraph.py binary.exe 0x401000 --up 3
    python retools/callgraph.py binary.exe 0x401000 --down 2
    python retools/callgraph.py binary.exe 0x401000 --up 4 --flat
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from xrefs import scan_refs
from funcinfo import find_start, analyze


def _find_callers(b: Binary, target: int) -> list[int]:
    """Return deduplicated sorted caller function addresses."""
    refs = []
    for va_start, raw_off, size in b.exec_ranges():
        refs.extend(scan_refs(b.raw, va_start, raw_off, size, target, "call"))
    funcs = set()
    for _, va in refs:
        start = find_start(b, va)
        funcs.add(start if start else va)
    return sorted(funcs)


def _find_callees(b: Binary, func_va: int) -> list[int]:
    """Return deduplicated sorted direct callee addresses."""
    _, calls, _ = analyze(b, func_va, 0x4000)
    targets = set()
    for _, t in calls:
        if isinstance(t, int):
            targets.add(t)
    return sorted(targets)


def _build_tree(b: Binary, va: int, depth: int, direction: str,
                cache: dict, visited: set) -> dict:
    if depth <= 0 or va in visited:
        return {"va": va, "children": []}
    visited.add(va)

    if va in cache:
        children_vas = cache[va]
    else:
        children_vas = (_find_callers(b, va) if direction == "up"
                        else _find_callees(b, va))
        cache[va] = children_vas

    children = [
        _build_tree(b, c, depth - 1, direction, cache, visited)
        for c in children_vas
    ]
    visited.discard(va)
    return {"va": va, "children": children}


def _print_tree(node: dict, indent: int = 0):
    prefix = "  " * indent + ("+-" if indent else "")
    n_children = len(node["children"])
    suffix = f"  ({n_children} children)" if n_children and indent == 0 else ""
    print(f"{prefix}0x{node['va']:08X}{suffix}")
    for child in node["children"]:
        _print_tree(child, indent + 1)


def _flatten(node: dict, result: set):
    result.add(node["va"])
    for child in node["children"]:
        _flatten(child, result)


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("target",
                   help="Target function address in hex (e.g. 0x401000)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--up", type=int, metavar="N",
                   help="Trace callers N levels up the call chain")
    g.add_argument("--down", type=int, metavar="N",
                   help="Trace callees N levels down the call chain")
    p.add_argument("--flat", action="store_true",
                   help="Output a flat sorted address list instead of a tree")
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.target, 16)
    direction = "up" if args.up else "down"
    depth = args.up or args.down

    if direction == "up":
        start = find_start(b, va)
        va = start if start else va

    tree = _build_tree(b, va, depth, direction, {}, set())

    if args.flat:
        addrs = set()
        _flatten(tree, addrs)
        addrs.discard(va)
        for a in sorted(addrs):
            print(f"0x{a:08X}")
        print(f"\n{len(addrs)} unique {'callers' if direction == 'up' else 'callees'}")
    else:
        _print_tree(tree)


if __name__ == "__main__":
    main()
