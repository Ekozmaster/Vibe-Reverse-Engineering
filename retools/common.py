"""Core utilities for PE binary reverse engineering."""

from __future__ import annotations

import bisect
import functools
import struct
from dataclasses import dataclass
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone import x86_const as x86


_EXCEPTION_DIRECTORY = 3
_UNW_FLAG_CHAININFO = 0x4
_MAX_UNWIND_CHAIN = 32  # a chain longer than this is a loop in a damaged file

_MAX_INSN_LEN = 15
# Capstone decodes everything one disasm call asks for before handing back the
# first instruction, at about 1 KB per instruction with details on, so the
# instructions decoded per call are capped.
_SWEEP_BATCH_INSNS = 4096
_ITER_BATCH_INSNS = 16


def _disasm_batches(cs: Cs, code: bytes, va: int, batch_insns: int):
    """Decode *code* with *cs*, at most *batch_insns* instructions per capstone call.

    Each call gets ``batch_insns * 15`` bytes, so every instruction it may
    return lies whole inside them, and the next call starts where the last
    returned instruction ends. The result is the same as one call over all of
    *code*. Decoding stops where *cs* stops: at the end of *code*, or at the
    first byte that is no instruction unless *cs* skips data.

    Args:
        cs: Capstone handle with the mode, detail and skipdata settings to decode with.
        code: Bytes to decode.
        va: Virtual address of the first byte.
        batch_insns: Most instructions decoded per capstone call.
    """
    pos = 0
    while pos < len(code):
        decoded = 0
        for insn in cs.disasm(code[pos : pos + batch_insns * _MAX_INSN_LEN], va + pos, batch_insns):
            decoded += 1
            yield insn
        if decoded < batch_insns:
            return
        pos = insn.address + insn.size - va


def sweep_code(code: bytes, va: int, is_64: bool):
    """Linear-sweep *code*, yielding every instruction that decodes.

    Bytes that are not instructions (jump tables and other data embedded in
    code) are stepped over one at a time. Without that, decoding ends at the
    first such byte and the rest of the buffer is never looked at.

    Args:
        code: Raw bytes of an executable region.
        va: Virtual address of the first byte.
        is_64: Decode as x64 instead of x86.
    """
    cs = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    cs.detail = True
    cs.skipdata = True
    for insn in _disasm_batches(cs, code, va, _SWEEP_BATCH_INSNS):
        if insn.id:  # id 0 marks a skipped data byte, which has no operands
            yield insn


@dataclass(frozen=True, slots=True)
class MemOp:
    """A decoded memory operand from an x86 instruction."""
    base: str
    index: str
    scale: int
    disp: int
    size: int
    access: str  # "r", "w", or "rw"


class Binary:
    """Loaded PE binary with section-aware memory access and disassembly.

    Args:
        path: Filesystem path to a PE (.exe / .dll) file.
    """

    # The only data directories any tool reads. Parsing every directory
    # (relocations above all) costs seconds on a large binary.
    _PARSED_DIRECTORIES = [
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
    ]

    def __init__(self, path: str):
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories(directories=self._PARSED_DIRECTORIES)
        self.raw = Path(path).read_bytes()
        self.base: int = self.pe.OPTIONAL_HEADER.ImageBase
        self.is_64: bool = self.pe.OPTIONAL_HEADER.Magic == 0x20B
        self.ptr_size: int = 8 if self.is_64 else 4
        self._cs = Cs(CS_ARCH_X86, CS_MODE_64 if self.is_64 else CS_MODE_32)
        self._cs.detail = True

    # ── Address translation ──────────────────────────────────────────

    def va_to_offset(self, va: int) -> int | None:
        """Virtual address -> raw file offset (None if unmapped)."""
        rva = va - self.base
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                return rva - s.VirtualAddress + s.PointerToRawData
        return None

    def offset_to_va(self, offset: int) -> int | None:
        """Raw file offset -> virtual address (None if outside any section)."""
        for s in self.pe.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return self.base + offset - s.PointerToRawData + s.VirtualAddress
        return None

    def in_exec(self, va: int) -> bool:
        """True if *va* falls inside an executable section."""
        return any(
            start <= va < start + size
            for start, _, size in self.exec_ranges()
        )

    # ── Raw memory access ────────────────────────────────────────────

    def read_va(self, va: int, size: int) -> bytes:
        """Read up to *size* bytes starting at virtual address *va*.

        A section's memory can be larger than what the file stores for it;
        the loader zero-fills the rest, so that part reads as zeros here
        too. The read ends at the section's last byte.
        """
        rva = va - self.base
        for s in self.pe.sections:
            offset = rva - s.VirtualAddress
            if not 0 <= offset < s.Misc_VirtualSize:
                continue
            stored = s.SizeOfRawData - offset
            start = s.PointerToRawData + offset
            if stored >= size:
                return self.raw[start : start + size]
            data = self.raw[start : start + stored] if stored > 0 else b""
            zero_filled = min(size, s.Misc_VirtualSize - offset) - len(data)
            return data + bytes(max(zero_filled, 0))
        return b""

    def read_struct(self, va: int, fmt: str) -> tuple:
        """Unpack a struct format at *va* (little-endian assumed in *fmt*)."""
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.read_va(va, size))

    def read_ptr(self, va: int) -> int | None:
        """Dereference a pointer at *va*. Returns the target VA or None."""
        fmt = "<Q" if self.is_64 else "<I"
        data = self.read_va(va, self.ptr_size)
        if len(data) < self.ptr_size:
            return None
        return struct.unpack(fmt, data)[0]

    # ── Disassembly ──────────────────────────────────────────────────

    def disasm(self, va: int, count: int = 30, max_bytes: int = 0x800) -> list:
        """Disassemble up to *count* instructions starting at *va*."""
        if count <= 0:
            return []
        return list(self._cs.disasm(self.read_va(va, max_bytes), va, count))

    def iter_disasm(self, va: int, max_bytes: int = 0x800):
        """Lazily decode instructions starting at *va*, up to the first byte that is no instruction.

        Capstone is handed a few instructions' worth at a time as the iterator
        is consumed, so a caller that stops at a function's end does not pay
        for the rest of the *max_bytes* window.
        """
        return _disasm_batches(self._cs, self.read_va(va, max_bytes), va, _ITER_BATCH_INSNS)

    def sweep(self, ranges: list[tuple[int, int, int]] | None = None):
        """Yield every instruction of a linear sweep over executable code.

        The sweep continues past data embedded in code (see ``sweep_code``),
        so a whole-binary scan covers each section to its end.

        Args:
            ranges: (va_start, raw_offset, raw_size) regions to sweep. All
                executable sections when omitted.
        """
        for start_va, raw_off, raw_size in (self.exec_ranges() if ranges is None else ranges):
            yield from sweep_code(self.raw[raw_off : raw_off + raw_size], start_va, self.is_64)

    def exec_ranges(self) -> list[tuple[int, int, int]]:
        """Return (va_start, raw_offset, raw_size) for each executable section."""
        return [
            (self.base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData)
            for s in self.pe.sections
            if s.Characteristics & 0x20000000
        ]

    # ── Function entry-point table ────────────────────────────────────

    @functools.cached_property
    def _exception_chunks(self) -> list[tuple[int, int, int]]:
        """(begin, end, function start) of each x64 exception table entry, sorted by begin.

        The table has an entry for every function with unwind information,
        which is every function but the leaf ones. A function the linker split
        up has one entry per chunk, and the later chunks name the first through
        chained unwind information.
        """
        if not self.is_64:
            return []
        directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= _EXCEPTION_DIRECTORY:
            return []
        directory = directories[_EXCEPTION_DIRECTORY]
        table = self.read_va(self.base + directory.VirtualAddress, directory.Size)
        chunks = []
        for begin, end, unwind in struct.iter_unpack("<III", table[: len(table) - len(table) % 12]):
            if end > begin:
                chunks.append((self.base + begin, self.base + end, self.base + self._first_chunk(begin, unwind)))
        return sorted(chunks)

    @functools.cached_property
    def _chunk_begins(self) -> list[int]:
        return [begin for begin, _end, _start in self._exception_chunks]

    def _first_chunk(self, begin: int, unwind: int) -> int:
        """RVA where the function starts whose chunk at RVA *begin* has unwind information at RVA *unwind*."""
        for _ in range(_MAX_UNWIND_CHAIN):
            if unwind & 1:
                # Not unwind information but another table entry that this one stands for
                entry = self.read_va(self.base + unwind - 1, 12)
            else:
                header = self.read_va(self.base + unwind, 4)
                if len(header) < 4 or not (header[0] >> 3) & _UNW_FLAG_CHAININFO:
                    return begin
                unwind_codes = (header[2] + 1) & ~1  # padded to an even count
                entry = self.read_va(self.base + unwind + 4 + unwind_codes * 2, 12)
            if len(entry) < 12:
                return begin
            begin, _end, unwind = struct.unpack("<III", entry)
        return begin

    def _chunk_at(self, va: int) -> tuple[int, int, int] | None:
        """The exception table chunk that holds *va*."""
        idx = bisect.bisect_right(self._chunk_begins, va) - 1
        if idx >= 0 and va < self._exception_chunks[idx][1]:
            return self._exception_chunks[idx]
        return None

    def _follows_end_of_code(self, va: int) -> bool:
        """True when the bytes before *va* are padding, a return or an unconditional jump."""
        before = self.read_va(va - 5, 5)
        return len(before) == 5 and (
            before[4] in (0xCC, 0x90, 0xC3)                 # int3, nop, ret
            or before[2] == 0xC2                            # ret imm16
            or before[0] == 0xE9 or before[3] == 0xEB)      # jmp rel32, jmp rel8

    @property
    def func_table(self) -> list[int]:
        """Sorted list of known function entry points (lazily built).

        Entry points come from the x64 exception table, the targets of direct
        ``call rel32`` instructions and the exports. A ``jmp rel32`` target is
        one only where a function can start, behind padding, a return or
        another jump: that is a function reached by tail calls, while any other
        jump target is a label inside a function. On x64 nothing inside a
        function of the exception table is an entry point.

        Both tests are byte heuristics, not decoded instructions: every
        ``E8``/``E9`` byte counts as a call or jump, and "behind padding, a
        return or a jump" only looks at the raw bytes before the target. An
        operand or data byte that happens to match can add a false entry point.
        """
        if hasattr(self, "_func_table"):
            return self._func_table
        called: set[int] = set()
        jumped_to: set[int] = set()
        for va_start, raw_off, raw_size in self.exec_ranges():
            data = self.raw[raw_off : raw_off + raw_size]
            for i in range(len(data) - 4):
                if data[i] in (0xE8, 0xE9):
                    rel = int.from_bytes(data[i + 1 : i + 5], "little", signed=True)
                    dest = va_start + i + 5 + rel
                    if self.in_exec(dest):
                        (called if data[i] == 0xE8 else jumped_to).add(dest)
        starts = called | {va for va in jumped_to if self._follows_end_of_code(va)}
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address:
                    starts.add(self.base + exp.address)
        starts = {va for va in starts if self._chunk_at(va) is None}
        starts.update(start for _begin, _end, start in self._exception_chunks)
        self._func_table = sorted(starts)
        return self._func_table

    def find_func_start(self, va: int) -> int | None:
        """Entry point of the function that holds *va*, or None when no known function does.

        On x64 the exception table gives each function's extent, so an address
        behind the end of such a function is not counted as part of it. For
        every other function only the start is known, and the nearest start at
        or before *va* is returned however far back it lies.
        """
        chunk = self._chunk_at(va)
        if chunk is not None:
            return chunk[2]
        idx = bisect.bisect_right(self.func_table, va) - 1
        if idx < 0:
            return None
        start = self.func_table[idx]
        # A function of the exception table would hold *va* in one of its chunks
        return None if self._chunk_at(start) is not None else start

    # ── Instruction analysis ─────────────────────────────────────────

    @staticmethod
    def is_call(insn) -> bool:
        return insn.mnemonic == "call"

    @staticmethod
    def is_jump(insn) -> bool:
        return insn.mnemonic.startswith("j")

    @staticmethod
    def is_ret(insn) -> bool:
        return insn.mnemonic in ("ret", "retn")

    @staticmethod
    def is_nop(insn) -> bool:
        return insn.mnemonic == "nop"

    @staticmethod
    def call_target(insn) -> int | str | None:
        """Resolve the target of a call/jmp instruction.

        Returns:
            int for direct targets, operand string for indirect, None otherwise.
        """
        if insn.mnemonic not in ("call", "jmp"):
            return None
        try:
            return int(insn.op_str, 16)
        except ValueError:
            return insn.op_str

    # FPU/SSE mnemonics where operand 0 is a memory destination
    _STORE_MNEMONICS = frozenset((
        "fstp", "fst", "fistp", "fist", "fisttp", "fbstp",
        "fstcw", "fnstcw", "fstenv", "fnstenv", "fstsw", "fnstsw",
        "movss", "movsd", "movaps", "movups", "movdqa", "movdqu",
        "movntps", "movntpd", "movnti",
    ))

    @classmethod
    def mem_operands(cls, insn) -> list[MemOp]:
        """Extract structured memory operands from an instruction."""
        if not hasattr(insn, "operands"):
            return []
        reg_name = insn.reg_name
        results = []
        for i, op in enumerate(insn.operands):
            if op.type != x86.X86_OP_MEM:
                continue
            if i == 0 and insn.mnemonic in cls._STORE_MNEMONICS:
                acc = "w"
            elif (op.access & 3) == 3:
                acc = "rw"
            elif op.access & 2:
                acc = "w"
            elif op.access & 1:
                acc = "r"
            else:
                acc = "r"
            results.append(MemOp(
                base=reg_name(op.mem.base) if op.mem.base else "",
                index=reg_name(op.mem.index) if op.mem.index else "",
                scale=op.mem.scale,
                disp=op.mem.disp,
                size=op.size,
                access=acc,
            ))
        return results

    def abs_mem_refs(self, insn) -> list[int]:
        """Absolute memory addresses referenced by this instruction.

        Extracts addresses from operands like ``[0x7A0000]`` (no base/index
        register). Works for ``mov``, ``fld``, ``fsub``, ``cmp``, etc.
        """
        if not hasattr(insn, "operands"):
            return []
        mask = 0xFFFFFFFFFFFFFFFF if self.is_64 else 0xFFFFFFFF
        refs = []
        for op in insn.operands:
            if op.type != x86.X86_OP_MEM:
                continue
            if op.mem.base == 0 and op.mem.index == 0 and op.mem.disp != 0:
                refs.append(op.mem.disp & mask)
        return refs

    def rip_rel_refs(self, insn) -> list[int]:
        """Resolved RIP-relative addresses (64-bit only).

        For instructions like ``lea rax, [rip + 0x1234]``, resolves to
        the absolute target: ``insn.address + insn.size + disp``.
        """
        if not self.is_64 or not hasattr(insn, "operands"):
            return []
        refs = []
        for op in insn.operands:
            if op.type != x86.X86_OP_MEM:
                continue
            if op.mem.base == x86.X86_REG_RIP and op.mem.index == 0:
                refs.append(insn.address + insn.size + op.mem.disp)
        return refs

    def abs_imm_refs(self, insn) -> list[int]:
        """Immediate operand values that look like virtual addresses.

        Extracts values from ``push 0x7C540C``, ``mov ecx, 0x7C540C``,
        etc.  Skips small constants (< 0x10000) that are unlikely to be
        addresses.
        """
        if not hasattr(insn, "operands"):
            return []
        mask = 0xFFFFFFFFFFFFFFFF if self.is_64 else 0xFFFFFFFF
        refs = []
        for op in insn.operands:
            if op.type != x86.X86_OP_IMM:
                continue
            val = op.imm & mask
            if val > 0x10000:
                refs.append(val)
        return refs
