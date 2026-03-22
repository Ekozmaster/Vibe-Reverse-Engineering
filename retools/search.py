#!/usr/bin/env python3
"""Search a PE binary for strings, byte patterns, imports, exports, or instructions.

Sub-commands:

  strings   Extract printable ASCII strings (keyword filter, optional --xrefs)
  pattern   Find exact byte sequences (hex, spaces optional)
  imports   List PE import table entries (optional DLL name filter)
  exports   List PE export table entries (optional keyword filter)
  insn      Find instructions by mnemonic/operand pattern (optional --near)

Usage:
    python retools/search.py <binary> strings [-f KEYWORDS] [-m MIN_LEN] [--xrefs]
    python retools/search.py <binary> pattern <hex_bytes>
    python retools/search.py <binary> imports [-d DLL_NAME]
    python retools/search.py <binary> exports [-f KEYWORDS]
    python retools/search.py <binary> insn <pattern> [--near <pattern2>] [--range N]

Examples:
    python retools/search.py binary.exe strings -f render,draw
    python retools/search.py binary.exe strings -f "error" --xrefs
    python retools/search.py binary.exe pattern "D9 56 54 D8 1D"
    python retools/search.py binary.exe imports -d kernel32
    python retools/search.py binary.dll exports -f Create
    python retools/search.py binary.dll insn "mov *,0x10000"
    python retools/search.py binary.dll insn "mov *,0x10000" --near "cmp *,0x10000" --range 0x400
"""

import argparse
import fnmatch
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

CHUNK = 0x10000


@dataclass(frozen=True, slots=True)
class StringRef:
    va: int | None
    offset: int
    value: str


@dataclass(frozen=True, slots=True)
class ImportEntry:
    dll: str
    name: str


def find_strings(b: Binary, filter_keywords=None, min_len=4) -> list[StringRef]:
    """Extract printable ASCII strings from the binary.

    Args:
        b: Loaded PE binary.
        filter_keywords: List of keywords to match (case-insensitive), or None for all.
        min_len: Minimum string length.

    Returns:
        List of StringRef with VA, file offset, and string value.
    """
    results: list[StringRef] = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, b.raw):
        s = m.group().decode("ascii", errors="ignore")
        if filter_keywords and not any(
            f.lower() in s.lower() for f in filter_keywords
        ):
            continue
        va = b.offset_to_va(m.start())
        results.append(StringRef(va=va, offset=m.start(), value=s))
    return results


def find_imports(b: Binary) -> list[ImportEntry]:
    """Extract PE import table entries.

    Returns:
        List of ImportEntry with DLL name and function name.
    """
    results: list[ImportEntry] = []
    if not hasattr(b.pe, "DIRECTORY_ENTRY_IMPORT"):
        return results
    for entry in b.pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("ascii", errors="ignore")
        for imp in entry.imports:
            name = (
                imp.name.decode("ascii", errors="ignore")
                if imp.name
                else f"ordinal_{imp.ordinal}"
            )
            results.append(ImportEntry(dll=dll, name=name))
    return results


def _match_insn(mnemonic: str, op_str: str, pattern: str) -> bool:
    """Match an instruction against a glob pattern like ``mov *,0x10000``."""
    parts = pattern.split(None, 1)
    mn_pat = parts[0]
    if not fnmatch.fnmatch(mnemonic, mn_pat):
        return False
    if len(parts) < 2:
        return True
    return fnmatch.fnmatch(op_str.replace(" ", ""), parts[1].replace(" ", ""))


def _scan_insn_pattern(b: Binary, pattern: str):
    """Yield (va, mnemonic, op_str) for instructions matching *pattern*."""
    for sec_va, sec_off, sec_size in b.exec_ranges():
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                if _match_insn(insn.mnemonic, insn.op_str, pattern):
                    yield insn.address, insn.mnemonic, insn.op_str


def _find_xrefs_for_va(b: Binary, target_va: int) -> list[tuple[int, str, str]]:
    """Find code locations referencing *target_va* (push/mov imm or lea rip+disp)."""
    hits = []
    for sec_va, sec_off, sec_size in b.exec_ranges():
        for chunk_start in range(0, sec_size, CHUNK):
            chunk_end = min(chunk_start + CHUNK + 32, sec_size)
            code = b.raw[sec_off + chunk_start : sec_off + chunk_end]
            va = sec_va + chunk_start
            for insn in b._cs.disasm(code, va):
                if target_va in b.abs_imm_refs(insn):
                    hits.append((insn.address, insn.mnemonic, insn.op_str))
                elif target_va in b.rip_rel_refs(insn):
                    hits.append((insn.address, insn.mnemonic, insn.op_str))
    return hits


def cmd_strings(b: Binary, args):
    w = 16 if b.is_64 else 8
    filters = [f.strip() for f in args.filter.split(",")] if args.filter else None
    for sref in find_strings(b, filter_keywords=filters, min_len=args.min_len):
        loc = f"0x{sref.va:0{w}X}" if sref.va else f"off:{sref.offset:08X}"
        print(f"{loc}: {sref.value}")
        if args.xrefs and sref.va:
            for xva, mn, ops in _find_xrefs_for_va(b, sref.va):
                print(f"  xref: 0x{xva:0{w}X} ({mn} {ops})")


def cmd_pattern(b: Binary, args):
    w = 16 if b.is_64 else 8
    needle = bytes.fromhex(args.hex.replace(" ", ""))
    pos = 0
    while True:
        idx = b.raw.find(needle, pos)
        if idx == -1:
            break
        va = b.offset_to_va(idx)
        loc = f"0x{va:0{w}X}" if va else f"off:{idx:08X}"
        print(loc)
        pos = idx + 1


def cmd_imports(b: Binary, args):
    for imp in find_imports(b):
        if args.dll and args.dll.lower() not in imp.dll.lower():
            continue
        print(f"{imp.dll:30s} {imp.name}")


def cmd_exports(b: Binary, args):
    if not hasattr(b.pe, "DIRECTORY_ENTRY_EXPORT"):
        print("No export table found.")
        return
    w = 16 if b.is_64 else 8
    filters = [f.strip() for f in args.filter.split(",")] if args.filter else None
    for exp in b.pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode("ascii", errors="ignore") if exp.name else ""
        if filters and not any(f.lower() in name.lower() for f in filters):
            continue
        rva = exp.address
        ordinal = exp.ordinal
        print(f"  {ordinal:5d}  0x{rva:0{w}X}  {name}")


def cmd_insn(b: Binary, args):
    w = 16 if b.is_64 else 8
    primary_hits = list(_scan_insn_pattern(b, args.pattern))

    if not args.near:
        for va, mn, ops in primary_hits:
            print(f"  0x{va:0{w}X}  {mn:8s} {ops}")
        print(f"\n{len(primary_hits)} matches")
        return

    scan_range = int(args.range, 0) if args.range else 0x200
    near_index: dict[int, tuple[str, str]] = {}
    for va, mn, ops in _scan_insn_pattern(b, args.near):
        near_index[va] = (mn, ops)

    results = []
    for va, mn, ops in primary_hits:
        for near_va in near_index:
            if abs(near_va - va) <= scan_range:
                results.append((va, mn, ops, near_va, *near_index[near_va]))
                break

    for va, mn, ops, nva, nmn, nops in results:
        print(f"  0x{va:0{w}X}  {mn:8s} {ops}")
        print(f"    near 0x{nva:0{w}X}  {nmn:8s} {nops}  "
              f"(delta {nva - va:+d})")
    print(f"\n{len(results)} matches (of {len(primary_hits)} primary, "
          f"filtered by --near within {scan_range} bytes)")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("strings", help="Extract printable ASCII strings")
    s.add_argument("-f", "--filter",
                   help="Comma-separated keywords to match (case-insensitive)")
    s.add_argument("-m", "--min-len", type=int, default=4,
                   help="Minimum string length (default: 4)")
    s.add_argument("--xrefs", action="store_true",
                   help="Also show code locations referencing each string")

    s = sub.add_parser("pattern", help="Find exact byte pattern in the binary")
    s.add_argument("hex",
                   help="Hex bytes to search for, e.g. 'D9 56 54 D8 1D'")

    s = sub.add_parser("imports", help="List PE import table entries")
    s.add_argument("-d", "--dll",
                   help="Show only imports from DLLs matching this substring")

    s = sub.add_parser("exports", help="List PE export table entries")
    s.add_argument("-f", "--filter",
                   help="Comma-separated keywords to match (case-insensitive)")

    s = sub.add_parser("insn",
                       help="Find instructions by mnemonic/operand pattern")
    s.add_argument("pattern",
                   help="Glob pattern: 'mov *,0x10000', 'lea *,[rip+*]', etc.")
    s.add_argument("--near",
                   help="Secondary pattern that must appear within --range bytes")
    s.add_argument("--range", default="0x200",
                   help="Max distance for --near filter (default: 0x200)")

    args = p.parse_args()
    b = Binary(args.binary)
    {"strings": cmd_strings, "pattern": cmd_pattern, "imports": cmd_imports,
     "exports": cmd_exports, "insn": cmd_insn}[args.command](b, args)


if __name__ == "__main__":
    main()
