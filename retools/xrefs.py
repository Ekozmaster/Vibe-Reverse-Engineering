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
from collections import namedtuple
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

IndirectRef = namedtuple(
    "IndirectRef", ["va", "mnemonic", "base", "index", "scale", "disp", "target_type"]
)


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


def scan_indirect_refs(
    code: bytes,
    sections: list[tuple[int, int, int]],
    imagebase: int,
    is_64: bool = False,
) -> list[IndirectRef]:
    """Scan code for indirect call/jump instructions.

    Args:
        code: Raw bytes of the binary.
        sections: List of (va_start, raw_offset, raw_size) for executable sections.
        imagebase: PE image base address.
        is_64: If True, disassemble as x64. Defaults to x86 (32-bit).

    Returns:
        List of IndirectRef for each indirect call/jump found.
    """
    cs = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    cs.detail = True
    results: list[IndirectRef] = []

    for sec_va, sec_off, sec_size in sections:
        chunk = code[sec_off : sec_off + sec_size]
        for insn in cs.disasm(chunk, sec_va):
            if insn.mnemonic not in ("call", "jmp"):
                continue
            for mop in Binary.mem_operands(insn):
                if mop.base and mop.disp and not mop.index:
                    # call [reg+offset] — vtable dispatch
                    results.append(IndirectRef(
                        va=insn.address, mnemonic=insn.mnemonic,
                        base=mop.base, index="", scale=0,
                        disp=mop.disp, target_type="vtable",
                    ))
                elif mop.base and not mop.disp and not mop.index:
                    # call [reg] — function pointer
                    results.append(IndirectRef(
                        va=insn.address, mnemonic=insn.mnemonic,
                        base=mop.base, index="", scale=0,
                        disp=0, target_type="fptr",
                    ))
                elif not mop.base and not mop.index and mop.disp:
                    # call [addr] — IAT / global function pointer
                    results.append(IndirectRef(
                        va=insn.address, mnemonic=insn.mnemonic,
                        base="", index="", scale=0,
                        disp=mop.disp, target_type="iat",
                    ))
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
    p.add_argument("--indirect", action="store_true",
                   help="Also scan for indirect calls/jumps (vtable dispatch, "
                        "function pointers, IAT calls)")
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

    if args.indirect:
        sections = b.exec_ranges()
        indirect = scan_indirect_refs(b.raw, sections, b.base, is_64=b.is_64)
        print(f"{len(indirect)} indirect call/jump sites\n")
        for ref in indirect:
            disp_str = f"+0x{ref.disp:X}" if ref.disp else ""
            print(f"  0x{ref.va:08X}: {ref.mnemonic:4s} [{ref.base}{disp_str}]  ({ref.target_type})")


if __name__ == "__main__":
    main()
