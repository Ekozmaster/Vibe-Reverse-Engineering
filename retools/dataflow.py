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
    """Extract (base_reg, disp) from memory operand at idx, or None.

    Returns None when an index register is present (scaled index addressing)
    since the displacement alone doesn't represent the full address.
    """
    if not hasattr(insn, "operands") or idx >= len(insn.operands):
        return None
    op = insn.operands[idx]
    if op.type == x86.X86_OP_MEM:
        if op.mem.index:
            return None
        base = insn.reg_name(op.mem.base) if op.mem.base else ""
        return (base, op.mem.disp)
    return None


# The tracked register each register name is the whole or a part of
_TRACKED_REGISTER = {
    part: whole
    for whole, parts in {
        "eax": ("eax", "ax", "ah", "al"), "ebx": ("ebx", "bx", "bh", "bl"),
        "ecx": ("ecx", "cx", "ch", "cl"), "edx": ("edx", "dx", "dh", "dl"),
        "esi": ("esi", "si"), "edi": ("edi", "di"), "ebp": ("ebp", "bp"), "esp": ("esp", "sp"),
    }.items()
    for part in parts
}


def _registers_written(insn) -> set[str]:
    """Tracked registers *insn* writes, in whole or in part, as operands or implicitly."""
    _read, written = insn.regs_access()
    names = (insn.reg_name(reg) for reg in written)
    return {_TRACKED_REGISTER[name] for name in names if name in _TRACKED_REGISTER}


def _apply_modelled(state: dict, insn, push_stack: list) -> set[str]:
    """Give the registers of an instruction this module models their new values.

    Returns:
        The registers that were given a value. Empty for an instruction, or a
        form of one, that is not modelled.
    """
    mn = insn.mnemonic
    nops = len(insn.operands)

    if mn == "mov" and nops == 2:
        dst = _get_reg(insn, 0)
        if dst not in state:
            return set()
        imm = _get_imm(insn, 1)
        src = _get_reg(insn, 1)
        mem = _get_mem(insn, 1)
        if imm is not None:
            state[dst] = Const(imm)
        elif src in state:
            state[dst] = state[src]
        elif mem is not None:
            base_reg, disp = mem
            state[dst] = Load(state.get(base_reg, Unknown()) if base_reg else Const(0), disp)
        else:
            return set()
        return {dst}

    if mn in ("add", "sub") and nops == 2:
        dst = _get_reg(insn, 0)
        if dst not in state:
            return set()
        imm = _get_imm(insn, 1)
        src = _get_reg(insn, 1)
        if imm is not None:
            right = Const(imm)
        elif src in state:
            right = state[src]
        else:
            return set()
        left = state[dst]
        if isinstance(left, Const) and isinstance(right, Const):
            value = left.value + right.value if mn == "add" else left.value - right.value
            state[dst] = Const(value & 0xFFFFFFFF)
        else:
            state[dst] = BinOp("+" if mn == "add" else "-", left, right)
        return {dst}

    if mn == "xor" and nops == 2:
        dst = _get_reg(insn, 0)
        if dst in state and _get_reg(insn, 1) == dst:
            state[dst] = Const(0)
            return {dst}
        return set()

    if mn == "lea" and nops == 2:
        dst = _get_reg(insn, 0)
        mem = _get_mem(insn, 1)
        if dst not in state or mem is None:
            return set()
        base_reg, disp = mem
        base_val = state.get(base_reg, Unknown()) if base_reg else Const(0)
        if isinstance(base_val, Const):
            state[dst] = Const((base_val.value + disp) & 0xFFFFFFFF)
        else:
            state[dst] = BinOp("+", base_val, Const(disp)) if disp else base_val
        return {dst}

    if mn == "push" and nops == 1:
        reg = _get_reg(insn, 0)
        imm = _get_imm(insn, 0)
        if reg in state:
            push_stack.append(state[reg])
        else:
            push_stack.append(Const(imm) if imm is not None else Unknown())
        return set()

    if mn == "pop" and nops == 1:
        reg = _get_reg(insn, 0)
        if reg in state and push_stack:
            state[reg] = push_stack.pop()
            return {reg}
        return set()

    if mn == "call":
        for reg in _CALLER_SAVED:
            state[reg] = Unknown()
        return set(_CALLER_SAVED)

    if mn in ("cdq", "cwd"):
        # Sign-extends eax into edx; capstone lists eax as written too, but it keeps its value
        state["edx"] = Unknown()
        return {"eax", "edx"}

    return set()


def _apply_insn(state: dict, insn, push_stack: list) -> None:
    """Update register state for a single instruction.

    A register the instruction writes without a value being modelled for it
    becomes Unknown: a value from before the instruction no longer holds.
    """
    given_a_value = _apply_modelled(state, insn, push_stack)
    for reg in _registers_written(insn) - given_a_value:
        state[reg] = Unknown()


def propagate_forward(insns: list, init: dict[str, object] | None = None) -> dict[str, object]:
    """Propagate constants forward through a linear sequence of instructions.

    Args:
        insns: List of Capstone instructions (linear block, no branches).
        init: Initial values of some registers; every register it leaves
            out starts Unknown. Not modified.

    Returns:
        Register state dict mapping register names to Value objects.
    """
    state = {**_init_state(), **(init or {})}
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

            new_exit = propagate_forward(blocks[bva], init)
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

    Walks backward linearly from target_va, ignoring control flow. Results are
    exact for straight-line code but approximate when the instruction list spans
    multiple basic blocks (branch targets and merge points are not tracked).

    Args:
        insns: Instruction list (may span multiple basic blocks).
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


def backward_slice_cfg(
    b: Binary, func_va: int, target_va: int, target_reg: str,
    max_depth: int = 50, max_size: int = 0x4000,
) -> list[tuple[int, str, str]]:
    """CFG-aware backward slice: trace register contributions respecting control flow.

    Walks backward from target_va through the function's CFG, following
    predecessor edges at block boundaries.

    Args:
        b: Loaded PE binary.
        func_va: Function start address.
        target_va: Address where we want the register value.
        target_reg: Register name to trace (e.g., "eax").
        max_depth: Max instructions to walk backward per path.
        max_size: Max scan window for CFG construction.

    Returns:
        List of (va, register, description) for each contributing instruction,
        ordered by address.
    """
    blocks, edges = build_cfg(b, func_va, max_size)
    if not blocks:
        return []

    preds: dict[int, list[int]] = {bva: [] for bva in blocks}
    for src, dst, _ in edges:
        if dst in preds:
            preds[dst].append(src)

    # Find which block contains target_va
    target_block = None
    target_idx = None
    for bva, insns in blocks.items():
        for i, insn in enumerate(insns):
            if insn.address == target_va:
                target_block = bva
                target_idx = i
                break
        if target_block is not None:
            break
    if target_block is None:
        return []

    result: list[tuple[int, str, str]] = []
    visited: set[tuple[int, frozenset[str]]] = set()

    def _walk(bva: int, end_idx: int, needed: set[str], depth: int):
        key = (bva, frozenset(needed))
        if key in visited or not needed or depth >= max_depth:
            return
        visited.add(key)

        for i in range(end_idx, -1, -1):
            if not needed or depth >= max_depth:
                break
            insn = blocks[bva][i]
            writes = _insn_writes(insn)
            overlap = writes & needed
            if overlap:
                desc = f"{insn.mnemonic} {insn.op_str}"
                for reg in overlap:
                    result.append((insn.address, reg, desc))
                needed = needed - overlap | _insn_reads(insn)
            depth += 1

        if needed:
            for pred_va in preds.get(bva, []):
                if pred_va in blocks and blocks[pred_va]:
                    _walk(pred_va, len(blocks[pred_va]) - 1, set(needed), depth)

    _walk(target_block, target_idx, {target_reg}, 0)

    # Deduplicate and sort by address
    seen: set[tuple[int, str]] = set()
    unique: list[tuple[int, str, str]] = []
    for va, reg, desc in sorted(result):
        if (va, reg) not in seen:
            seen.add((va, reg))
            unique.append((va, reg, desc))
    return unique


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
    if b.is_64:
        sys.exit("[error] dataflow tracks x86 registers only and this is a 64-bit "
                 "binary. Use the decompiler for x64 constant and value-origin questions.")
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
        result = backward_slice_cfg(b, start, target_va, target_reg, max_size=args.max_size)
        print(f"Backward slice for {target_reg} at 0x{target_va:0{w}X}:\n")
        for va, reg, desc in result:
            print(f"  0x{va:0{w}X}: {reg} <- {desc}")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
