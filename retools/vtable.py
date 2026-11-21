#!/usr/bin/env python3
"""Analyze C++ virtual tables in a PE binary.

Two sub-commands:

  dump    Read sequential function pointers from a vtable address and
          preview the first 3 instructions of each slot.
  calls   Scan all code for indirect calls through [reg+OFFSET], useful
          for finding every callsite of a specific vtable slot.

Usage:
    python retools/vtable.py <binary> dump  <vtable_addr> [--slots N]
    python retools/vtable.py <binary> calls <offset>

Examples:
    python retools/vtable.py binary.exe dump 0x6A0000 --slots 30
    python retools/vtable.py binary.exe calls 0xB0
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary


def cmd_dump(b: Binary, args):
    """Read sequential function pointers from a vtable address."""
    va = int(args.address, 16)
    for i in range(args.slots):
        slot_va = va + i * b.ptr_size
        target = b.read_ptr(slot_va)
        if target is None:
            break
        valid = b.in_exec(target)
        line = f"  [{i:3d}] +0x{i * b.ptr_size:04X}  -> 0x{target:08X}"
        if valid:
            insns = b.disasm(target, count=3)
            preview = "; ".join(f"{ins.mnemonic} {ins.op_str}" for ins in insns)
            print(f"{line}  {preview}")
        else:
            print(f"{line}  (not code)")
            if i > 0:
                break


def cmd_calls(b: Binary, args):
    """Find all indirect calls through [reg+offset]."""
    offset = int(args.offset, 16)
    hits = []
    for insn in b.sweep():
        if insn.mnemonic != "call":
            continue
        for mop in b.mem_operands(insn):
            if mop.base and not mop.index and mop.disp == offset:
                hits.append((insn.address, mop.base, insn.op_str))

    print(f"{len(hits)} indirect calls through [reg+0x{offset:X}]\n")
    for va, base, op_str in hits:
        print(f"  0x{va:08X}  {base:5s}  call {op_str}")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("dump",
                       help="Read function pointers from a vtable address")
    s.add_argument("address",
                   help="Vtable start address in hex (e.g. 0x6A0000)")
    s.add_argument("--slots", type=int, default=30,
                   help="Max number of slots to read (default: 30)")

    s = sub.add_parser("calls",
                       help="Find all indirect call [reg+offset] sites")
    s.add_argument("offset",
                   help="Vtable slot offset in hex (e.g. 0xB0)")

    args = p.parse_args()
    b = Binary(args.binary)
    {"dump": cmd_dump, "calls": cmd_calls}[args.command](b, args)


if __name__ == "__main__":
    main()
