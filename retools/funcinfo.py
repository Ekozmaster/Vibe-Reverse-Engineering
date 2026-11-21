#!/usr/bin/env python3
"""Analyze a function: find start, all return instructions, and callees.

Given any address inside a function, walks backward to find the prologue,
then forward-scans to collect every RET (with stack cleanup size and
inferred calling convention) and every direct CALL target.

Output:
    Function: 0xSTART .. 0xEND  (N bytes)
    Returns (N):  address, ret imm, calling convention guess
    Callees (N):  unique direct call targets with call count

Usage:
    python retools/funcinfo.py <binary> <va> [--max-size BYTES]

Examples:
    python retools/funcinfo.py binary.exe 0x401000
    python retools/funcinfo.py binary.exe 0x401000 --max-size 0x4000
"""

import argparse
import bisect
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

_MAX_FUNCTION_INSNS = 5000

def find_start(b: Binary, va: int, **_kw) -> int | None:
    """Find the function entry point containing *va*.

    Delegates to ``Binary.find_func_start``: the x64 exception table where
    it covers *va*, else the nearest known entry point before it.
    """
    return b.find_func_start(va)


def _branch_target(insn) -> int | None:
    """Immediate target of a jump or loop instruction; None for anything else."""
    if not insn.mnemonic.startswith(("j", "loop")):
        return None
    try:
        return int(insn.op_str, 16)
    except ValueError:
        return None


def _function_starts_after(b: Binary, start: int, end: int) -> list[int]:
    """The known function entry points in (*start*, *end*), in address order."""
    table = b.func_table
    return table[bisect.bisect_right(table, start):bisect.bisect_left(table, end)]


def _follows_a_function_end(b: Binary, va: int) -> bool:
    """Whether the bytes before *va* end a function: padding, a return or an unconditional jump.

    A known entry point reached that way starts a function of its own; one in
    the middle of straight-line code is a call target inside a function.
    """
    before = b.read_va(va - 6, 6)
    if len(before) < 6:
        return True
    return (before[-1] in (0xCC, 0x90, 0xC3) or before[-3] == 0xC2 or before[-2] == 0xEB
            or before[-5] == 0xE9 or before[-6:-4] == b"\xFF\x25")


def analyze(b: Binary, start: int, max_size: int):
    """Return (rets, callees, end_va) for the function at *start*.

    The scan ends at a known function start that this function's code does not
    run into, or at padding: three nops after a return, or an int3. A known
    start that live code falls through to, or that a branch of this function
    jumps past, lies inside the function (a call target in its body, or bytes
    that only look like one) and does not end the scan. Compilers also put an
    int3 after a call that does not return; such an int3 ends the scan only
    when no branch seen so far jumps past it to a label of this function. A
    ``jmp`` to the next function or beyond is a tail call and does not carry
    the scan over an int3; the next function is the nearest known start that
    follows a function end (padding, a return or a jump).

    *end_va* is the end of the last return scanned, or of a later instruction
    that is live and not padding (nop or int3), so a function without a return
    still has an extent. The bytes behind a return or an unconditional jump are
    alignment or a jump table unless a branch reaches them: instructions are
    live from the function's start, stop being live behind a return or jump,
    and are live again from the first address at or below the furthest branch
    target seen before it. Only a live instruction's branch target counts.
    """
    rets: list[tuple[int, int]] = []
    calls: list[tuple[int, int | str]] = []
    end_va = start
    nop_run = 0
    furthest_branch = start
    later_starts = _function_starts_after(b, start, start + max_size)
    next_function = next((va for va in later_starts if _follows_a_function_end(b, va)), None)
    previous = None
    live = True

    window = b.iter_disasm(start, max_bytes=max_size)
    for insn in itertools.islice(window, _MAX_FUNCTION_INSNS):
        live = live or insn.address <= furthest_branch
        ahead = bisect.bisect_left(later_starts, insn.address)
        if not live and ahead < len(later_starts) and later_starts[ahead] < insn.address + insn.size:
            break
        is_ret = insn.mnemonic in ("ret", "retn")
        if is_ret:
            cleanup = int(insn.op_str, 0) if insn.op_str else 0
            rets.append((insn.address, cleanup))
        elif insn.mnemonic == "call":
            try:
                target: int | str = int(insn.op_str, 16)
            except ValueError:
                target = insn.op_str
            calls.append((insn.address, target))
        else:
            branch = _branch_target(insn) if live else None
            is_tail_call = insn.mnemonic == "jmp" and next_function is not None and branch is not None \
                and branch >= next_function
            if branch is not None and not is_tail_call and branch < start + max_size:
                furthest_branch = max(furthest_branch, branch)

        if is_ret or (live and insn.mnemonic not in ("nop", "int3")):
            end_va = insn.address + insn.size
        if is_ret or insn.mnemonic == "jmp":
            live = False
        nop_run = nop_run + 1 if insn.mnemonic == "nop" else 0
        if nop_run >= 3 and rets:
            break
        if insn.mnemonic == "int3" and (previous in ("ret", "retn", "jmp") or insn.address >= furthest_branch):
            break
        previous = insn.mnemonic

    return rets, calls, end_va


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Any address inside the target function (hex, "
                   "e.g. 0x401000)")
    p.add_argument(
        "--max-size", type=lambda x: int(x, 0), default=0x2000,
        help="Max forward-scan window in bytes (default: 0x2000)",
    )
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.va, 16)
    start = find_start(b, va) or va
    rets, calls, end_va = analyze(b, start, args.max_size)
    w = 16 if b.is_64 else 8

    print(f"Function: 0x{start:0{w}X} .. 0x{end_va:0{w}X}  ({end_va - start} bytes)")
    if not start <= va < max(end_va, start + 1):
        print(f"[warning] 0x{va:0{w}X} is not inside this range. Its function is reached "
              f"only through a pointer, so its start is not known; this is the "
              f"nearest known start before the address.")
    print()

    print(f"Returns ({len(rets)}):")
    for addr, cleanup in rets:
        if cleanup:
            desc = f"stdcall/thiscall  {cleanup} bytes = {cleanup // 4} stack args"
        else:
            desc = "cdecl/thiscall  0 stack args"
        print(f"  0x{addr:0{w}X}: ret {f'0x{cleanup:X}':6s}  {desc}")

    print(f"\nCallees ({len(set(t for _, t in calls))}):")
    seen: set = set()
    for _, target in calls:
        if target in seen:
            continue
        seen.add(target)
        n = sum(1 for _, t in calls if t == target)
        label = target if isinstance(target, str) else f"0x{target:0{w}X}"
        print(f"  {label}{f'  ({n}x)' if n > 1 else ''}")


if __name__ == "__main__":
    main()
