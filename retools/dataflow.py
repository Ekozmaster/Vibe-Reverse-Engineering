#!/usr/bin/env python3
"""Intraprocedural data flow analysis: forward constant propagation and backward slicing.

Operates on a single function's CFG. Tracks x86 general-purpose registers
through basic blocks, propagating constants and building value expressions.

Usage:
    python -m retools.dataflow <binary> <va> --constants
    python -m retools.dataflow <binary> <va> --slice <target_va>:<reg>
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capstone import x86_const as x86
from common import Binary
from cfg import build_cfg


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Const:
    """Resolved constant value."""
    value: int
    def __str__(self):
        return f"0x{self.value & 0xFFFFFFFF:x}"

@dataclass(frozen=True)
class Unknown:
    """Unresolvable value."""
    def __str__(self):
        return "?"

@dataclass(frozen=True)
class BinOp:
    """Binary operation on two values."""
    op: str
    left: object   # Value
    right: object  # Value
    def __str__(self):
        return f"({self.left} {self.op} {self.right})"

@dataclass(frozen=True)
class Load:
    """Memory load: [base + offset]."""
    base: object   # Value
    offset: int
    def __str__(self):
        return f"[{self.base}+0x{self.offset:x}]" if self.offset else f"[{self.base}]"

@dataclass(frozen=True)
class Arg:
    """Function argument."""
    index: int
    def __str__(self):
        return f"arg{self.index}"


# ---------------------------------------------------------------------------
# Forward constant propagation
# ---------------------------------------------------------------------------

# Caller-saved registers clobbered by call instructions
_CALLER_SAVED = frozenset(("eax", "ecx", "edx"))

# Registers tracked for 32-bit
_GPR_32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _init_state() -> dict[str, object]:
    """Initialize register state: all Unknown."""
    return {r: Unknown() for r in _GPR_32}


def _get_imm(insn, idx: int) -> int | None:
    """Extract immediate operand at position idx, or None."""
    if not hasattr(insn, "operands") or idx >= len(insn.operands):
        return None
    op = insn.operands[idx]
    if op.type == x86.X86_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def _get_reg(insn, idx: int) -> str | None:
    """Extract register name at position idx, or None."""
    if not hasattr(insn, "operands") or idx >= len(insn.operands):
        return None
    op = insn.operands[idx]
    if op.type == x86.X86_OP_REG:
        return insn.reg_name(op.reg)
    return None


def _get_mem(insn, idx: int) -> tuple[str, int] | None:
    """Extract (base_reg, disp) from memory operand at idx, or None."""
    if not hasattr(insn, "operands") or idx >= len(insn.operands):
        return None
    op = insn.operands[idx]
    if op.type == x86.X86_OP_MEM:
        base = insn.reg_name(op.mem.base) if op.mem.base else ""
        return (base, op.mem.disp)
    return None


def _apply_insn(state: dict, insn, push_stack: list) -> None:
    """Update register state for a single instruction."""
    mn = insn.mnemonic
    nops = len(insn.operands) if hasattr(insn, "operands") else 0

    if mn == "mov" and nops == 2:
        dst_reg = _get_reg(insn, 0)
        if dst_reg:
            # mov reg, imm
            imm = _get_imm(insn, 1)
            if imm is not None:
                state[dst_reg] = Const(imm)
                return
            # mov reg, reg
            src_reg = _get_reg(insn, 1)
            if src_reg and src_reg in state:
                state[dst_reg] = state[src_reg]
                return
            # mov reg, [base+disp]
            mem = _get_mem(insn, 1)
            if mem is not None:
                base_reg, disp = mem
                base_val = state.get(base_reg, Unknown()) if base_reg else Const(0)
                state[dst_reg] = Load(base_val, disp)
                return
            state[dst_reg] = Unknown()

    elif mn in ("add", "sub") and nops == 2:
        dst_reg = _get_reg(insn, 0)
        if dst_reg and dst_reg in state:
            imm = _get_imm(insn, 1)
            src_reg = _get_reg(insn, 1)
            if imm is not None:
                left = state[dst_reg]
                right = Const(imm)
            elif src_reg and src_reg in state:
                left = state[dst_reg]
                right = state[src_reg]
            else:
                state[dst_reg] = Unknown()
                return
            # Fold constants
            if isinstance(left, Const) and isinstance(right, Const):
                if mn == "add":
                    state[dst_reg] = Const((left.value + right.value) & 0xFFFFFFFF)
                else:
                    state[dst_reg] = Const((left.value - right.value) & 0xFFFFFFFF)
            else:
                state[dst_reg] = BinOp("+" if mn == "add" else "-", left, right)

    elif mn == "xor" and nops == 2:
        dst_reg = _get_reg(insn, 0)
        src_reg = _get_reg(insn, 1)
        if dst_reg and src_reg and dst_reg == src_reg:
            state[dst_reg] = Const(0)
        elif dst_reg:
            state[dst_reg] = Unknown()

    elif mn == "lea" and nops == 2:
        dst_reg = _get_reg(insn, 0)
        mem = _get_mem(insn, 1)
        if dst_reg and mem:
            base_reg, disp = mem
            base_val = state.get(base_reg, Unknown()) if base_reg else Const(0)
            if isinstance(base_val, Const):
                state[dst_reg] = Const((base_val.value + disp) & 0xFFFFFFFF)
            else:
                state[dst_reg] = BinOp("+", base_val, Const(disp)) if disp else base_val

    elif mn == "push" and nops == 1:
        reg = _get_reg(insn, 0)
        if reg and reg in state:
            push_stack.append(state[reg])
        else:
            imm = _get_imm(insn, 0)
            push_stack.append(Const(imm) if imm is not None else Unknown())

    elif mn == "pop" and nops == 1:
        reg = _get_reg(insn, 0)
        if reg and push_stack:
            state[reg] = push_stack.pop()
        elif reg:
            state[reg] = Unknown()

    elif mn == "call":
        for r in _CALLER_SAVED:
            if r in state:
                state[r] = Unknown()

    elif mn in ("cdq", "cwd"):
        state["edx"] = Unknown()


def propagate_forward(insns: list, init: dict[str, object] | None = None) -> dict[str, object]:
    """Propagate constants forward through a linear sequence of instructions.

    Args:
        insns: List of Capstone instructions (linear block, no branches).
        init: Optional initial register state. Defaults to all Unknown.

    Returns:
        Register state dict mapping register names to Value objects.
    """
    state = init if init is not None else _init_state()
    push_stack: list = []
    for insn in insns:
        _apply_insn(state, insn, push_stack)
    return state


# ---------------------------------------------------------------------------
# CFG-aware forward propagation
# ---------------------------------------------------------------------------

def _merge_states(states: list[dict]) -> dict[str, object]:
    """Merge register states from multiple predecessor blocks.

    If all predecessors agree on a register's value, keep it.
    Otherwise, set to Unknown.
    """
    if not states:
        return _init_state()
    if len(states) == 1:
        return dict(states[0])
    merged = {}
    for reg in _GPR_32:
        values = [s.get(reg, Unknown()) for s in states]
        first = values[0]
        if all(v == first for v in values):
            merged[reg] = first
        else:
            merged[reg] = Unknown()
    return merged


def propagate_cfg(
    b: Binary, func_va: int, max_size: int = 0x4000, max_iterations: int = 3
) -> dict[int, dict[str, object]]:
    """Forward constant propagation across a function's CFG.

    Args:
        b: Loaded PE binary.
        func_va: Function start address.
        max_size: Max scan window for CFG construction.
        max_iterations: Fixed-point iteration limit for loops.

    Returns:
        Dict mapping block start VA to register state at block exit.
    """
    if b.is_64:
        raise NotImplementedError("x64 dataflow not yet supported — only x86 registers are tracked")
    blocks, edges = build_cfg(b, func_va, max_size)
    if not blocks:
        return {}

    # Build predecessor map
    preds: dict[int, list[int]] = {bva: [] for bva in blocks}
    for src, dst, _ in edges:
        if dst in preds:
            preds[dst].append(src)

    # Topological-ish order: entry block first, then by address
    entry = func_va
    ordered = sorted(blocks.keys())
    if entry in ordered:
        ordered.remove(entry)
        ordered.insert(0, entry)

    # Iterate to fixed point
    block_exit: dict[int, dict[str, object]] = {}
    for _ in range(max_iterations):
        changed = False
        for bva in ordered:
            # Merge predecessor exit states
            pred_states = [block_exit[p] for p in preds.get(bva, []) if p in block_exit]
            if bva == entry:
                entry_state = _init_state()
                if pred_states:
                    entry_state = _merge_states([entry_state] + pred_states)
                init = entry_state
            else:
                init = _merge_states(pred_states) if pred_states else _init_state()

            new_exit = propagate_forward(blocks[bva], dict(init))
            if bva not in block_exit or new_exit != block_exit[bva]:
                block_exit[bva] = new_exit
                changed = True

        if not changed:
            break

    return block_exit


# ---------------------------------------------------------------------------
# Backward slicing
# ---------------------------------------------------------------------------

def _insn_reads(insn) -> set[str]:
    """Return set of register names read by this instruction."""
    regs = set()
    if not hasattr(insn, "operands"):
        return regs
    for i, op in enumerate(insn.operands):
        if op.type == x86.X86_OP_REG:
            if i == 0 and insn.mnemonic in ("mov", "lea", "movzx", "movsxd", "pop"):
                continue  # destination only, not read
            regs.add(insn.reg_name(op.reg))
        elif op.type == x86.X86_OP_MEM:
            if op.mem.base:
                regs.add(insn.reg_name(op.mem.base))
            if op.mem.index:
                regs.add(insn.reg_name(op.mem.index))
    return regs


def _insn_writes(insn) -> set[str]:
    """Return set of register names written by this instruction."""
    regs = set()
    if not hasattr(insn, "operands"):
        return regs
    if insn.mnemonic in ("push", "cmp", "test"):
        return regs  # these don't write to register operands
    if insn.operands and insn.operands[0].type == x86.X86_OP_REG:
        regs.add(insn.reg_name(insn.operands[0].reg))
    if insn.mnemonic == "call":
        regs.update(_CALLER_SAVED)
    if insn.mnemonic in ("cdq", "cwd"):
        regs.add("edx")
    if insn.mnemonic == "pop" and insn.operands:
        if insn.operands[0].type == x86.X86_OP_REG:
            regs.add(insn.reg_name(insn.operands[0].reg))
    return regs


def backward_slice(
    insns: list, target_va: int, target_reg: str, max_depth: int = 50
) -> list[tuple[int, str, str]]:
    """Backward slice: find instructions contributing to target_reg at target_va.

    Args:
        insns: Instruction list (single basic block or linear sequence).
        target_va: Address of the instruction where we want the value.
        target_reg: Register name to trace (e.g., "eax").
        max_depth: Max instructions to walk backward.

    Returns:
        List of (va, register, description) for each contributing instruction,
        ordered from earliest to latest.
    """
    if not insns:
        return []

    # Find target instruction index
    target_idx = None
    for i, insn in enumerate(insns):
        if insn.address == target_va:
            target_idx = i
            break
    if target_idx is None:
        target_idx = len(insns) - 1

    # Walk backward, tracking which registers we need
    needed: set[str] = {target_reg}
    result: list[tuple[int, str, str]] = []
    steps = 0

    for i in range(target_idx, -1, -1):
        if not needed or steps >= max_depth:
            break
        insn = insns[i]
        writes = _insn_writes(insn)
        overlap = writes & needed
        if overlap:
            desc = f"{insn.mnemonic} {insn.op_str}"
            for reg in overlap:
                result.append((insn.address, reg, desc))
            needed -= overlap
            needed |= _insn_reads(insn)
        steps += 1

    result.reverse()
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("va", help="Function virtual address (hex)")
    p.add_argument("--constants", action="store_true",
                   help="Show all resolved constants in the function")
    p.add_argument("--slice", metavar="VA:REG",
                   help="Backward slice: trace REG at VA (e.g. 0x401080:eax)")
    p.add_argument("--max-size", type=lambda x: int(x, 0), default=0x4000,
                   help="Max function scan window (default: 0x4000)")
    args = p.parse_args(argv)

    b = Binary(args.binary)
    func_va = int(args.va, 16)
    start = b.find_func_start(func_va) or func_va
    w = 16 if b.is_64 else 8

    if args.constants:
        block_states = propagate_cfg(b, start, max_size=args.max_size)
        print(f"Forward propagation for 0x{start:0{w}X}: {len(block_states)} blocks\n")
        for bva in sorted(block_states):
            state = block_states[bva]
            resolved = {r: v for r, v in state.items() if not isinstance(v, Unknown)}
            if resolved:
                print(f"  Block 0x{bva:0{w}X}:")
                for reg, val in sorted(resolved.items()):
                    print(f"    {reg} = {val}")

    elif args.slice:
        parts = args.slice.split(":")
        if len(parts) != 2:
            print("Error: --slice format is VA:REG (e.g. 0x401080:eax)", file=sys.stderr)
            sys.exit(1)
        target_va = int(parts[0], 16)
        target_reg = parts[1]
        from funcinfo import analyze
        _, _, end_va = analyze(b, start, args.max_size)
        func_size = end_va - start if end_va > start else args.max_size
        insns = b.disasm(start, count=5000, max_bytes=func_size)
        result = backward_slice(insns, target_va, target_reg)
        print(f"Backward slice for {target_reg} at 0x{target_va:0{w}X}:\n")
        for va, reg, desc in result:
            print(f"  0x{va:0{w}X}: {reg} <- {desc}")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
