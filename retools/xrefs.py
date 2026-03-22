#!/usr/bin/env python3
"""Find cross-references (calls and/or jumps) to a target virtual address.

Scans all executable sections for E8 (call), E9/EB (jmp), and 0F 8x (jcc)
instructions whose resolved target matches the given address.  Shows
disassembly context around each hit.

Output:  N xrefs to 0xTARGET, then each hit with surrounding disassembly.

Usage:
    python retools/xrefs.py <binary> <target> [-t call|jump|any] [-c N]

Examples:
    python retools/xrefs.py binary.exe 0x401000
    python retools/xrefs.py binary.exe 0x401000 -t call
    python retools/xrefs.py binary.exe 0x401000 -t jump -c 10
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary


def scan_refs(raw: bytes, sec_va: int, sec_off: int, sec_size: int,
              target: int, kind: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for i in range(sec_size - 6):
        b = raw[sec_off + i]
        va = sec_va + i

        if kind in ("call", "any") and b == 0xE8:
            rel = struct.unpack_from("<i", raw, sec_off + i + 1)[0]
            if va + 5 + rel == target:
                results.append(("call", va))
            continue

        if kind not in ("jump", "any"):
            continue

        if b == 0xE9:
            rel = struct.unpack_from("<i", raw, sec_off + i + 1)[0]
            if va + 5 + rel == target:
                results.append(("jmp", va))
        elif b == 0x0F and 0x80 <= raw[sec_off + i + 1] <= 0x8F:
            rel = struct.unpack_from("<i", raw, sec_off + i + 2)[0]
            if va + 6 + rel == target:
                results.append(("jcc", va))
        elif 0x70 <= b <= 0x7F:
            rel = struct.unpack_from("<b", raw, sec_off + i + 1)[0]
            if va + 2 + rel == target:
                results.append(("jcc.s", va))
        elif b == 0xEB:
            rel = struct.unpack_from("<b", raw, sec_off + i + 1)[0]
            if va + 2 + rel == target:
                results.append(("jmp.s", va))
    return results


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("target", help="Target virtual address in hex (e.g. 0x401000)")
    p.add_argument("-t", "--type", choices=["call", "jump", "any"], default="any",
                   help="Filter: 'call' (E8 only), 'jump' (jmp/jcc), "
                        "or 'any' (default: any)")
    p.add_argument("-c", "--context", type=int, default=5,
                   help="Instructions of disasm context around each xref "
                        "(default: 5)")
    args = p.parse_args()

    b = Binary(args.binary)
    target = int(args.target, 16)

    refs: list[tuple[str, int]] = []
    for va_start, raw_off, size in b.exec_ranges():
        refs.extend(scan_refs(b.raw, va_start, raw_off, size, target, args.type))
    refs.sort(key=lambda r: r[1])

    print(f"{len(refs)} xrefs to 0x{target:X}\n")
    for kind, va in refs:
        print(f"--- {kind} at 0x{va:08X} ---")
        for insn in b.disasm(va - args.context * 8, args.context * 4):
            if insn.address > va + args.context * 8:
                break
            marker = " <<<" if insn.address == va else ""
            raw_hex = " ".join(f"{x:02X}" for x in insn.bytes)
            print(f"  0x{insn.address:08X}: {raw_hex:30s} {insn.mnemonic:8s} {insn.op_str}{marker}")
        print()


if __name__ == "__main__":
    main()
