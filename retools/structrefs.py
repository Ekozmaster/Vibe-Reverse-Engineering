#!/usr/bin/env python3
"""Find all instructions that access [register + offset] for a given offset.

Useful for mapping struct field usage across a binary -- e.g. finding every
piece of code that touches ``obj+0x54`` to understand a struct layout.
Classifies each hit as read (r), write (w), or both (rw).

With ``--aggregate``, scans a function for ALL ``[base+disp]`` accesses and
outputs a reconstructed C struct definition.

Output (default):
    N refs to [reg+0xOFFSET]
      0xVA  base  [rw]  mnemonic  operand

Output (--aggregate):
    struct Unknown {
      /* +0x000 */ void*    field_0;     // read  at 0x401012, 0x401034
      /* +0x008 */ uint32_t field_8;     // write at 0x401020
    };

Usage:
    python retools/structrefs.py <binary> <offset> [--base REG] [--fn VA]
    python retools/structrefs.py <binary> --aggregate --fn <VA> [--base REG]

Examples:
    python retools/structrefs.py binary.exe 0x54
    python retools/structrefs.py binary.exe 0x54 --base esi
    python retools/structrefs.py binary.exe 0x54 --fn 0x401000 --fn-size 0x200
    python retools/structrefs.py binary.exe --aggregate --fn 0x401000 --base esi
"""

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

CHUNK = 0x10000


@dataclass
class FieldAccess:
    offset: int
    type_name: str
    size: int
    access: str
    refs: list[int] = field(default_factory=list)

_TYPE_MAP = {
    ("fld", 4): "float", ("fld", 8): "double",
    ("fst", 4): "float", ("fst", 8): "double",
    ("fstp", 4): "float", ("fstp", 8): "double",
    ("fsub", 4): "float", ("fsub", 8): "double",
    ("fadd", 4): "float", ("fadd", 8): "double",
    ("fmul", 4): "float", ("fmul", 8): "double",
    ("fdiv", 4): "float", ("fdiv", 8): "double",
    ("fcomp", 4): "float", ("fcomp", 8): "double",
    ("movss", 4): "float",
    ("movsd", 8): "double",
}


def _infer_type(mnemonic: str, size: int, is_64: bool) -> str:
    key = (mnemonic, size)
    if key in _TYPE_MAP:
        return _TYPE_MAP[key]
    if mnemonic == "movzx":
        return {1: "uint8_t", 2: "uint16_t"}.get(size, f"uint{size * 8}_t")
    if mnemonic == "movsx" or mnemonic == "movsxd":
        return {1: "int8_t", 2: "int16_t"}.get(size, f"int{size * 8}_t")
    ptr_size = 8 if is_64 else 4
    if size == ptr_size:
        return "void*"
    return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(
        size, f"byte[{size}]")


def scan(b: Binary, offset: int, base_filter: str | None,
         fn_start: int | None, fn_size: int):
    """Yield (va, base_reg, access, mnemonic, op_str) for matching accesses."""
    if fn_start is not None:
        ranges = [(fn_start, b.va_to_offset(fn_start) or 0, fn_size)]
    else:
        ranges = b.exec_ranges()

    for sec_va, sec_off, sec_size in ranges:
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                for mop in b.mem_operands(insn):
                    if mop.disp != offset:
                        continue
                    if not mop.base or mop.index:
                        continue
                    if base_filter and mop.base != base_filter:
                        continue
                    yield (insn.address, mop.base, mop.access,
                           insn.mnemonic, insn.op_str)


_CODE_REL_REGS = frozenset(("rip", "eip"))


def scan_all_fields(b: Binary, base_filter: str | None,
                    fn_start: int, fn_size: int):
    """Yield (disp, va, base_reg, access, mnemonic, op_str, mem_size)."""
    ranges = [(fn_start, b.va_to_offset(fn_start) or 0, fn_size)]
    for sec_va, sec_off, sec_size in ranges:
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                for mop in b.mem_operands(insn):
                    if not mop.base or mop.index:
                        continue
                    if mop.base in _CODE_REL_REGS:
                        continue
                    if mop.disp < 0:
                        continue
                    if base_filter and mop.base != base_filter:
                        continue
                    yield (mop.disp, insn.address, mop.base, mop.access,
                           insn.mnemonic, insn.op_str, mop.size)


def _aggregate(b: Binary, base_filter: str | None,
               fn_start: int, fn_size: int):
    """Print reconstructed C struct from all field accesses."""
    fields = aggregate_struct(b, fn_start, base_reg=base_filter, fn_size=fn_size)
    if not fields:
        print("No field accesses found.")
        return

    w = 16 if b.is_64 else 8
    print("struct Unknown {")
    for fa in fields:
        refs = ", ".join(f"0x{va:0{w}X}" for va in fa.refs[:4])
        if len(fa.refs) > 4:
            refs += ", ..."
        pad = max(1, 9 - len(fa.type_name))
        field_name = f"field_{fa.offset:X}"
        print(f"    /* +0x{fa.offset:03X} */ {fa.type_name}{' ' * pad}"
              f"{field_name};{' ' * max(1, 6 - len(field_name))}"
              f"// {fa.access:4s} at {refs}")
    print("};")


def aggregate_struct(b: Binary, fn_va: int, base_reg=None,
                     fn_size=0x2000) -> list[FieldAccess]:
    """Reconstruct struct fields from all [base+disp] accesses in a function.

    Args:
        b: Loaded PE binary.
        fn_va: Virtual address of the function to analyze.
        base_reg: Optional base register filter (e.g. "esi").
        fn_size: Maximum function size to scan.

    Returns:
        List of FieldAccess objects sorted by offset.
    """
    raw_fields: dict[int, dict] = defaultdict(
        lambda: {"accesses": [], "types": set(), "size": 0})

    for disp, va, base, acc, mn, ops, mem_size in scan_all_fields(
            b, base_reg, fn_va, fn_size):
        f = raw_fields[disp]
        f["accesses"].append((va, acc))
        f["types"].add(_infer_type(mn, mem_size, b.is_64))
        f["size"] = max(f["size"], mem_size)

    results: list[FieldAccess] = []
    for offset in sorted(raw_fields):
        f = raw_fields[offset]
        type_name = sorted(f["types"])[0] if f["types"] else "uint32_t"
        all_acc: set[str] = set()
        for _, acc in f["accesses"]:
            all_acc.update(acc)
        acc_label = "rw" if {"r", "w"} <= all_acc else (
            "w" if "w" in all_acc else "r")
        refs = [va for va, _ in f["accesses"]]
        results.append(FieldAccess(
            offset=offset,
            type_name=type_name,
            size=f["size"],
            access=acc_label,
            refs=refs,
        ))
    return results


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("offset", nargs="?",
                   help="Struct field offset in hex (e.g. 0x54). "
                        "Not needed with --aggregate.")
    p.add_argument("--base",
                   help="Only show accesses with this base register "
                        "(e.g. esi, edi, ecx)")
    p.add_argument("--fn",
                   help="Restrict scan to a single function at this VA (hex)")
    p.add_argument("--fn-size", type=lambda x: int(x, 0), default=0x2000,
                   help="Max function size when using --fn (default: 0x2000)")
    p.add_argument("--aggregate", action="store_true",
                   help="Scan all [base+disp] in --fn and output a C struct")
    args = p.parse_args()

    b = Binary(args.binary)
    fn_start = int(args.fn, 16) if args.fn else None

    if args.aggregate:
        if fn_start is None:
            p.error("--aggregate requires --fn")
        _aggregate(b, args.base, fn_start, args.fn_size)
        return

    if args.offset is None:
        p.error("offset is required (unless using --aggregate)")

    offset = int(args.offset, 16)
    hits = list(scan(b, offset, args.base, fn_start, args.fn_size))
    w = 16 if b.is_64 else 8
    print(f"{len(hits)} refs to [reg+0x{offset:X}]\n")
    for va, base, acc, mnemonic, op_str in hits:
        print(f"  0x{va:0{w}X}  {base:5s} [{acc:2s}]  {mnemonic:8s} {op_str}")


if __name__ == "__main__":
    main()
