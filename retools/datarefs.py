#!/usr/bin/env python3
"""Find all instructions that reference a global memory address.

Scans executable sections for instructions whose operands encode an
absolute address (no base/index register), e.g. ``fsub [0x7A0000]``
or ``mov [0x7A0000], eax``.  Classifies each hit as read (r), write (w),
or read-write (rw).

With ``--imm``, also finds instructions that use the address as an
immediate constant (e.g. ``push 0x7A0000``, ``mov ecx, 0x7A0000``).
These are labelled ``[imm]`` in the output.

With ``--indirect``, performs a two-phase scan to find register-indirect
references via base+offset patterns (e.g. ``mov ecx, 0x7AD000`` near
``mov eax, [ecx+0xB4]`` when target is 0x7AD0B4).  Also resolves
single-level pointer chains from static PE data.

Output:  N data refs to 0xADDR..0xADDR+RANGE
           0xVA  [r ]  mnemonic  operand

Usage:
    python retools/datarefs.py <binary> <address> [--range N] [--access r|w|rw] [--imm]
    python retools/datarefs.py <binary> <address> --indirect [--max-offset N] [--window N]

Examples:
    python retools/datarefs.py binary.exe 0x7A0000
    python retools/datarefs.py binary.exe 0x7A0000 --range 12
    python retools/datarefs.py binary.exe 0x7A0000 --access w
    python retools/datarefs.py binary.exe 0x7A0000 --imm
    python retools/datarefs.py binary.exe 0x7AD0B4 --indirect
    python retools/datarefs.py binary.exe 0x7AD0B4 --indirect --max-offset 8192
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary


def _access_for(b, insn, addr_lo, addr_hi):
    """How *insn* uses its memory operands that lie in the target range: "r", "w" or "rw"."""
    mask = 0xFFFFFFFFFFFFFFFF if b.is_64 else 0xFFFFFFFF
    acc = set()
    for mop in b.mem_operands(insn):
        if mop.index:
            continue
        if mop.base == "rip":
            ea = insn.address + insn.size + mop.disp
        elif mop.base:
            continue
        else:
            ea = mop.disp & mask
        if addr_lo <= ea < addr_hi:
            acc.update(mop.access)
    return "rw" if {"r", "w"} <= acc else ("w" if "w" in acc else "r")


def scan(b: Binary, addr: int, size: int, access_filter: str | None,
         include_imm: bool = False):
    """Yield (va, mnemonic, op_str, access) for matching instructions."""
    addr_hi = addr + size
    for insn in b.sweep():
        mem_hit = any(addr <= r < addr_hi for r in b.abs_mem_refs(insn))
        rip_hit = any(addr <= r < addr_hi for r in b.rip_rel_refs(insn))
        imm_hit = include_imm and any(
            addr <= r < addr_hi for r in b.abs_imm_refs(insn)
        )
        if not mem_hit and not rip_hit and not imm_hit:
            continue
        if rip_hit and not mem_hit:
            mem_hit = True
        if mem_hit:
            acc = _access_for(b, insn, addr, addr_hi)
            if access_filter and not set(access_filter) <= set(acc):
                if not imm_hit:
                    continue
                acc = "imm"
        else:
            acc = "imm"
        yield insn.address, insn.mnemonic, insn.op_str, acc


def scan_indirect(b: Binary, target: int, max_offset: int = 4096,
                  scan_window: int = 256):
    """Find indirect references to *target* via [reg + displacement].

    Phase 1 — single pass over executable sections collecting instructions
    whose immediate operand falls in [target - max_offset, target].  Also
    resolves one-level pointer chains: ``mov reg, [global]`` where the
    static value at *global* falls in the same range.

    Phase 2 — for each candidate base-load, scans *scan_window* bytes
    forward for a ``[reg + disp]`` memory operand where
    ``disp == target - base``.  Two-factor match (base literal + matching
    displacement nearby) keeps false-positive rate low.

    Yields dicts:
        base_va       – address of the base-loading instruction
        base_val      – the resolved base value
        offset        – target - base_val
        source        – how the base was loaded ("imm" or "ptr@0xADDR")
        base_insn     – disassembly of the base-loading instruction
        access_va     – address of the [reg+disp] instruction
        access_insn   – disassembly of the access instruction
        access        – "r", "w", or "rw"
        reg           – base register used in the access
        func          – enclosing function entry (or None)
    """
    target_lo = target - max_offset

    # -- Phase 1: collect candidate base-loading instructions ---------------
    candidates = []
    n_insns = 0

    for insn in b.sweep():
        n_insns += 1
        for val in b.abs_imm_refs(insn):
            if target_lo <= val <= target:
                candidates.append((
                    insn.address, val, "imm",
                    insn.mnemonic, insn.op_str,
                ))
        for ref in b.abs_mem_refs(insn):
            ptr = b.read_ptr(ref)
            if ptr is not None and target_lo <= ptr <= target:
                candidates.append((
                    insn.address, ptr, f"ptr@0x{ref:X}",
                    insn.mnemonic, insn.op_str,
                ))

    print(f"Phase 1: scanned {n_insns:,} instructions, "
          f"found {len(candidates)} base candidates", file=sys.stderr)

    # -- Phase 2: verify displacement match in nearby code ------------------
    seen = set()
    for cand_va, base_val, src_type, cand_mn, cand_ops in candidates:
        needed = target - base_val
        code = b.read_va(cand_va, scan_window)
        if not code:
            continue
        for insn in b._cs.disasm(code, cand_va):
            if insn.address == cand_va:
                continue
            for mop in Binary.mem_operands(insn):
                if not mop.base:
                    continue
                if mop.disp == needed:
                    key = (cand_va, insn.address)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield {
                        "base_va": cand_va,
                        "base_val": base_val,
                        "offset": needed,
                        "source": src_type,
                        "base_insn": f"{cand_mn} {cand_ops}",
                        "access_va": insn.address,
                        "access_insn": f"{insn.mnemonic} {insn.op_str}",
                        "access": mop.access,
                        "reg": mop.base,
                        "func": b.find_func_start(cand_va),
                    }


def _print_indirect(hits, target, max_offset, is_64):
    """Pretty-print indirect-ref results grouped by (base, offset)."""
    w = 16 if is_64 else 8
    groups = defaultdict(list)
    for h in hits:
        groups[(h["base_val"], h["offset"])].append(h)

    total = sum(len(v) for v in groups.values())
    print(f"\n{total} indirect refs to 0x{target:X} "
          f"(max offset: {max_offset})\n")

    for (base_val, offset), group in sorted(groups.items()):
        print(f"  Base 0x{base_val:X} + 0x{offset:X} = 0x{target:X}")
        for h in group:
            fn = f"  fn:0x{h['func']:X}" if h["func"] else ""
            src_tag = f"  ({h['source']})" if h["source"] != "imm" else ""
            print(f"    0x{h['base_va']:0{w}X}       {h['base_insn']}{src_tag}")
            print(f"    0x{h['access_va']:0{w}X}  "
                  f"[{h['access']:2s}]  {h['access_insn']}"
                  f"  via {h['reg']}{fn}")
        print()


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("address",
                   help="Target global address in hex (e.g. 0x7A0000)")
    p.add_argument("--range", type=int, default=4,
                   help="Byte range: match refs to "
                        "[address, address+range) (default: 4)")
    p.add_argument("--access", choices=["r", "w", "rw"],
                   help="Only show instructions that read (r) or write (w) the "
                        "address; rw keeps the ones that do both")
    p.add_argument("--imm", action="store_true",
                   help="Also find immediate-value references "
                        "(push/mov of the address as a constant)")
    p.add_argument("--indirect", action="store_true",
                   help="Find indirect [reg+offset] references by matching "
                        "nearby base-loading instructions with displacement "
                        "operands that sum to the target address")
    p.add_argument("--max-offset", type=int, default=4096,
                   help="Max displacement for --indirect scan (default: 4096)")
    p.add_argument("--window", type=int, default=256,
                   help="Forward scan window in bytes for --indirect "
                        "displacement verification (default: 256)")
    args = p.parse_args()

    b = Binary(args.binary)
    addr = int(args.address, 16)

    if args.indirect:
        hits = list(scan_indirect(b, addr, args.max_offset, args.window))
        _print_indirect(hits, addr, args.max_offset, b.is_64)
    else:
        hits = list(scan(b, addr, args.range, args.access,
                         include_imm=args.imm))
        w = 16 if b.is_64 else 8
        print(f"{len(hits)} data refs to "
              f"0x{addr:X}..0x{addr + args.range - 1:X}\n")
        for va, mnemonic, op_str, acc in hits:
            print(f"  0x{va:0{w}X}  [{acc:2s}]  {mnemonic:8s} {op_str}")


if __name__ == "__main__":
    main()
