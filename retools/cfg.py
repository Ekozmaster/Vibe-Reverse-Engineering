#!/usr/bin/env python3
"""Decompose a function into basic blocks and show control flow edges.

Finds the function prologue from a given VA, splits it into basic blocks
(leader = branch target or fall-through after branch), and shows edges
(conditional, unconditional, fall-through).

Output (text mode):
    === Block 0xADDR (N insns)  -> 0xTARGET (label), ... ===
      disassembly lines

Output (mermaid mode):
    Mermaid graph TD suitable for rendering in Markdown.

Usage:
    python retools/cfg.py <binary> <va> [--format text|mermaid] [--max-size N]

Examples:
    python retools/cfg.py binary.exe 0x401000
    python retools/cfg.py binary.exe 0x401000 --format mermaid
    python retools/cfg.py binary.exe 0x401000 --max-size 0x8000
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary
from funcinfo import find_start

_UNCOND_JUMPS = {"jmp", "ret", "retn"}
_COND_JUMPS = {
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp",
}


def _resolve_target(insn) -> int | None:
    try:
        return int(insn.op_str, 16)
    except ValueError:
        return None


def _resolve_switch(
    b: Binary, jmp_insn, preceding_insns: list
) -> list[int] | None:
    """Attempt to resolve a switch/jump table from an indirect jmp.

    Detects MSVC patterns: cmp reg,N / ja default / jmp [table + reg*4].

    Args:
        b: Loaded PE binary.
        jmp_insn: The indirect jmp instruction (Capstone CsInsn).
        preceding_insns: Instructions in the same block, ending with jmp_insn.

    Returns:
        List of resolved target VAs, or None if not a recognized switch pattern.
    """
    mops = Binary.mem_operands(jmp_insn)
    if not mops:
        return None
    mop = mops[0]
    if not mop.index or mop.scale != 4:
        return None

    table_base = mop.disp
    if not table_base:
        return None

    # Walk backward looking for cmp reg, N / ja pattern
    jmp_idx = None
    for i, insn in enumerate(preceding_insns):
        if insn.address == jmp_insn.address:
            jmp_idx = i
            break

    if jmp_idx is None or jmp_idx < 2:
        return None

    case_count = None
    for i in range(jmp_idx - 1, max(jmp_idx - 10, -1), -1):
        insn = preceding_insns[i]
        if insn.mnemonic == "cmp" and hasattr(insn, "operands") and len(insn.operands) == 2:
            from capstone import x86_const as x86
            op = insn.operands[1]
            if op.type == x86.X86_OP_IMM:
                case_count = op.imm & 0xFFFFFFFF
                break

    if case_count is None or case_count > 1024:
        return None

    # Read table entries
    ptr_fmt = "<Q" if b.is_64 else "<I"
    ptr_size = b.ptr_size
    targets = []
    for i in range(case_count + 1):
        entry_data = b.read_va(table_base + i * ptr_size, ptr_size)
        if len(entry_data) < ptr_size:
            return None
        target = struct.unpack(ptr_fmt, entry_data)[0]
        if not b.in_exec(target):
            return None
        targets.append(target)

    return targets


def _find_func_end(insns):
    """Detect function boundary: stop after ret + NOP padding or int3."""
    last_ret = None
    nop_run = 0
    for i, insn in enumerate(insns):
        if insn.mnemonic in ("ret", "retn"):
            last_ret = i
            nop_run = 0
        elif last_ret is not None:
            if insn.mnemonic == "nop":
                nop_run += 1
                if nop_run >= 2:
                    return last_ret + 1
            elif insn.mnemonic == "int3":
                return last_ret + 1
            else:
                last_ret = None
                nop_run = 0
    return len(insns)


def build_cfg(b: Binary, start: int, max_size: int = 0x4000):
    """Return (blocks, edges) where blocks maps block_va -> [insns]."""
    raw_insns = b.disasm(start, count=5000, max_bytes=max_size)
    if not raw_insns:
        return {}, []
    insns = raw_insns[:_find_func_end(raw_insns)]
    if not insns:
        return {}, []

    # Collect block-start addresses
    leaders = {start}
    for insn in insns:
        mn = insn.mnemonic
        if mn in _UNCOND_JUMPS | _COND_JUMPS:
            target = _resolve_target(insn)
            if target is not None:
                leaders.add(target)
            if mn in _COND_JUMPS:
                leaders.add(insn.address + insn.size)
            if mn in _UNCOND_JUMPS and mn not in ("ret", "retn"):
                leaders.add(insn.address + insn.size)

    leaders = sorted(leaders)
    leader_set = set(leaders)

    # Partition instructions into blocks
    blocks: dict[int, list] = {}
    current_leader = None
    for insn in insns:
        if insn.address in leader_set:
            current_leader = insn.address
            blocks[current_leader] = []
        if current_leader is not None:
            blocks[current_leader].append(insn)
            mn = insn.mnemonic
            if mn in _UNCOND_JUMPS or mn in _COND_JUMPS:
                current_leader = None

    # Build edges
    edges = []
    for block_va, block_insns in blocks.items():
        if not block_insns:
            continue
        last = block_insns[-1]
        mn = last.mnemonic
        if mn in ("ret", "retn"):
            continue
        target = _resolve_target(last)
        fallthrough = last.address + last.size
        if mn in _COND_JUMPS:
            if target and target in blocks:
                edges.append((block_va, target, mn))
            if fallthrough in blocks:
                edges.append((block_va, fallthrough, "fall"))
        elif mn in _UNCOND_JUMPS:
            if target and target in blocks:
                edges.append((block_va, target, "jmp"))
            elif target is None and mn == "jmp":
                # Attempt switch table resolution
                switch_targets = _resolve_switch(b, last, block_insns)
                if switch_targets:
                    for i, st in enumerate(switch_targets):
                        if st not in blocks:
                            blocks[st] = []
                        edges.append((block_va, st, f"case {i}"))
        else:
            if fallthrough in blocks:
                edges.append((block_va, fallthrough, "fall"))

    return blocks, edges


def _fmt_text(blocks, edges, b):
    sorted_blocks = sorted(blocks.items())
    for block_va, insns in sorted_blocks:
        out_edges = [(dst, label) for src, dst, label in edges if src == block_va]
        edge_str = "  -> " + ", ".join(
            f"0x{dst:08X} ({label})" for dst, label in out_edges
        ) if out_edges else ""
        print(f"\n=== Block 0x{block_va:08X} ({len(insns)} insns){edge_str} ===")
        for insn in insns:
            print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")


def _fmt_mermaid(blocks, edges, start):
    print("```mermaid")
    print("graph TD")
    for block_va, insns in sorted(blocks.items()):
        first = insns[0] if insns else None
        last = insns[-1] if insns else None
        label = f"0x{block_va:08X}"
        if last:
            label += f"..0x{last.address:08X}"
        label += f" ({len(insns)} insns)"
        node_id = f"B_{block_va:08X}"
        print(f'    {node_id}["{label}"]')
    for src, dst, label in edges:
        src_id = f"B_{src:08X}"
        dst_id = f"B_{dst:08X}"
        print(f'    {src_id} -->|"{label}"| {dst_id}')
    print("```")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Any address inside the target function (hex, "
                   "e.g. 0x401000)")
    p.add_argument("--format", choices=["text", "mermaid"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--max-size", type=lambda x: int(x, 0), default=0x4000,
                   help="Max forward-scan window in bytes (default: 0x4000)")
    p.add_argument("--switch-details", action="store_true",
                   help="Show switch table addresses and entry counts")
    args = p.parse_args()

    b = Binary(args.binary)
    va = int(args.va, 16)
    start = find_start(b, va) or va
    blocks, edges = build_cfg(b, start, args.max_size)

    print(f"Function 0x{start:08X}: {len(blocks)} blocks, {len(edges)} edges\n")
    if args.switch_details:
        switch_blocks = [(va, insns) for va, insns in blocks.items()
                         if any(src == va and "case" in label
                                for src, _, label in edges)]
        if switch_blocks:
            print(f"Switch tables detected: {len(switch_blocks)}")
            for sva, _ in switch_blocks:
                cases = [(dst, label) for src, dst, label in edges
                         if src == sva and "case" in label]
                print(f"  0x{sva:08X}: {len(cases)} cases")
            print()
    if args.format == "mermaid":
        _fmt_mermaid(blocks, edges, start)
    else:
        _fmt_text(blocks, edges, b)


if __name__ == "__main__":
    main()
