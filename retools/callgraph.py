#!/usr/bin/env python3
"""Build multi-level caller or callee trees for a function.

Recursively finds callers (--up) or callees (--down) to the specified
depth.  Default output is an indented tree; --flat gives a sorted list
of unique addresses.

Modes:
    --up N    Walk UP the call chain: who calls this function? (N levels)
    --down N  Walk DOWN the call chain: what does this function call? (N levels)

Usage:
    python retools/callgraph.py <binary> <target> --up N   [--flat] [--indirect]
    python retools/callgraph.py <binary> <target> --down N [--flat] [--indirect]

Examples:
    python retools/callgraph.py binary.exe 0x401000 --up 3
    python retools/callgraph.py binary.exe 0x401000 --down 2 --indirect
    python retools/callgraph.py binary.exe 0x401000 --up 4 --flat
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from xrefs import scan_refs, scan_indirect_refs, IndirectRef
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


def _find_callees(b: Binary, func_va: int) -> tuple[list[int], list[IndirectRef]]:
    """Return (direct_targets, indirect_refs) for the function at func_va.

    Args:
        b: Loaded PE binary.
        func_va: Function start address.

    Returns:
        Tuple of (sorted direct callee addresses, list of IndirectRef for
        indirect calls within the function).
    """
    _, calls, end_va = analyze(b, func_va, 0x4000)
    direct = set()
    for _, t in calls:
        if isinstance(t, int):
            direct.add(t)

    # Scan function body for indirect calls
    func_size = end_va - func_va if end_va > func_va else 0x2000
    func_code = b.read_va(func_va, func_size)
    indirect_refs = scan_indirect_refs(
        func_code, [(func_va, 0, len(func_code))], b.base, is_64=b.is_64
    )
    return sorted(direct), indirect_refs


def _build_tree(b: Binary, va: int, depth: int, direction: str,
                cache: dict, visited: set, indirect: bool = False) -> dict:
    if depth <= 0 or va in visited:
        return {"va": va, "children": [], "indirect": []}
    visited.add(va)

    if va in cache:
        children_vas, indirect_refs = cache[va]
    else:
        if direction == "up":
            children_vas = _find_callers(b, va)
            indirect_refs = []
        else:
            children_vas, indirect_refs = _find_callees(b, va)
        cache[va] = (children_vas, indirect_refs)

    children = [
        _build_tree(b, c, depth - 1, direction, cache, visited, indirect)
        for c in children_vas
    ]
    visited.discard(va)
    return {"va": va, "children": children,
            "indirect": indirect_refs if indirect else []}


def _print_tree(node: dict, indent: int = 0, show_indirect: bool = False):
    prefix = "  " * indent + ("+-" if indent else "")
    n_children = len(node["children"])
    suffix = f"  ({n_children} children)" if n_children and indent == 0 else ""
    print(f"{prefix}0x{node['va']:08X}{suffix}")
    if show_indirect and node.get("indirect"):
        for ref in node["indirect"]:
            disp_str = f"+0x{ref.disp:X}" if ref.disp else ""
            iprefix = "  " * (indent + 1) + "  "
            print(f"{iprefix}~ {ref.mnemonic} [{ref.base}{disp_str}] ({ref.target_type})")
    for child in node["children"]:
        _print_tree(child, indent + 1, show_indirect)


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
    p.add_argument("--indirect", action="store_true",
                   help="Include indirect calls in --down mode (vtable dispatch, "
                        "function pointers)")
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.target, 16)
    direction = "up" if args.up else "down"
    depth = args.up or args.down

    if direction == "up":
        start = find_start(b, va)
        va = start if start else va

    tree = _build_tree(b, va, depth, direction, {}, set(), indirect=args.indirect)

    if args.flat:
        addrs = set()
        _flatten(tree, addrs)
        addrs.discard(va)
        for a in sorted(addrs):
            print(f"0x{a:08X}")
        print(f"\n{len(addrs)} unique {'callers' if direction == 'up' else 'callees'}")
    else:
        _print_tree(tree, show_indirect=args.indirect)


if __name__ == "__main__":
    main()
