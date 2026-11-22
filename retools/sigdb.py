#!/usr/bin/env python3
"""Signature database for function identification in PE binaries.

Provides a SQLite-backed signature database with:
- Byte-pattern signatures (FLIRT-style, with relocation wildcards)
- Structural signatures (CFG shape + mnemonic hash)
- Compiler fingerprinting (Rich header, CRT imports, marker patterns)
- Multi-tier matching: byte-exact -> structural fallback
- Build pipeline from JSON manifest + CSV address maps, or FLIRT .pat files
- CLI with build, import-pat, scan, identify, fingerprint, pull subcommands

Usage:
    python retools/sigdb.py build manifest.json -o sigs.db
    python retools/sigdb.py import-pat VisualStudio2008.pat -d sigs.db --compiler msvc2008 --source rizin_vs2008
    python retools/sigdb.py scan binary.exe -d sigs.db
    python retools/sigdb.py identify binary.exe 0x401000 -d sigs.db
    python retools/sigdb.py fingerprint binary.exe
    python retools/sigdb.py pull
"""

from __future__ import annotations

import argparse
import bisect
import collections
import csv
import itertools
import json
import os
import re
import sqlite3
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capstone import x86_const as x86
from cfg import SHAPE_VERSION, build_cfg
from common import Binary

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "signatures.db"

_HF_REPO_DEFAULT = "RTX-Remix/Vibe-Reverse-Engineering-Signature-DB"
_HF_REVISION_DEFAULT = "main"
_HF_URL_TEMPLATE = "https://huggingface.co/{repo}/resolve/{revision}/{path}"


def _hf_url(repo: str, revision: str, path: str) -> str:
    """URL of *path* in the HF *repo* at *revision*, a branch (which may hold "/"), tag or commit."""
    return _HF_URL_TEMPLATE.format(repo=repo, revision=urllib.parse.quote(revision, safe=""), path=path)


SCHEMA_VERSION = 2

# Columns schema version 2 added to version 1.
_V2_BYTE_COLUMNS = ("crc_len", "crc16")
_V2_STRUCTURAL_COLUMN = "shape_version"
# The shape version of a structural row stored before rows carried one.
_FIRST_SHAPE_VERSION = 1

# Longest run of bytes after the 32-byte prefix a FLIRT CRC16 can cover.
_MAX_CRC_LEN = 0xFF

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS byte_sigs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    pattern   BLOB    NOT NULL,
    mask      BLOB    NOT NULL,
    func_size INTEGER NOT NULL,
    tail_crc  INTEGER NOT NULL DEFAULT 0,
    crc_len   INTEGER NOT NULL DEFAULT 0,
    crc16     INTEGER NOT NULL DEFAULT 0,
    compiler  TEXT    NOT NULL DEFAULT '',
    source    TEXT    NOT NULL DEFAULT '',
    category  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS structural_sigs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    block_count   INTEGER NOT NULL,
    edge_count    INTEGER NOT NULL,
    call_count    INTEGER NOT NULL,
    mnemonic_hash INTEGER NOT NULL,
    constants     TEXT    NOT NULL DEFAULT '',
    compiler      TEXT    NOT NULL DEFAULT '',
    source        TEXT    NOT NULL DEFAULT '',
    category      TEXT    NOT NULL DEFAULT '',
    shape_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS compiler_fingerprints (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,
    pattern  BLOB NOT NULL,
    mask     BLOB NOT NULL DEFAULT x'',
    compiler TEXT NOT NULL,
    label    TEXT NOT NULL DEFAULT ''
);
"""

_TABLES = tuple(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _SCHEMA_SQL))

# CRT DLLs that identify the compiler / runtime version
_CRT_DLLS: dict[str, str] = {
    "msvcrt.dll": "msvc-generic",
    "msvcr70.dll": "msvc-7.0",
    "msvcr71.dll": "msvc-7.1",
    "msvcr80.dll": "msvc-8.0",
    "msvcr90.dll": "msvc-9.0",
    "msvcr100.dll": "msvc-10.0",
    "msvcr110.dll": "msvc-11.0",
    "msvcr120.dll": "msvc-12.0",
    "ucrtbase.dll": "msvc-14+",
    "vcruntime140.dll": "msvc-14.0+",
    "vcruntime140d.dll": "msvc-14.0+-debug",
    "libgcc_s_dw2-1.dll": "gcc-mingw",
    "libstdc++-6.dll": "gcc-mingw",
    "cygwin1.dll": "gcc-cygwin",
}

# Heuristic patterns for _categorize_name
_CRT_PREFIXES = (
    "_security", "__security", "_malloc", "_free", "_realloc", "_calloc",
    "_msize", "__acrt", "_atexit", "__dllonexit", "_onexit",
    "_initterm", "__initterm", "_cexit", "__cexit", "_exit",
    "__crt", "_crt", "__scrt", "_amsg_exit", "_invalid_parameter",
    "__report_gsfailure", "_except_handler", "__except_handler",
    "_SEH_", "__SEH_", "__C_specific_handler",
    "__GSHandlerCheck", "_guard_", "__guard_",
    "_chkstk", "__chkstk", "_alloca_probe",
    "_purecall", "__purecall",
    "___report_rangecheckfailure",
)

_MATH_NAMES = frozenset((
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "sinf", "cosf", "tanf", "asinf", "acosf", "atanf", "atan2f",
    "sqrt", "sqrtf", "pow", "powf", "exp", "expf", "log", "logf",
    "log10", "log10f", "ceil", "ceilf", "floor", "floorf",
    "fabs", "fabsf", "fmod", "fmodf",
    "_CIsin", "_CIcos", "_CItan", "_CIasin", "_CIacos", "_CIatan",
    "_CIatan2", "_CIsqrt", "_CIpow", "_CIexp", "_CIlog", "_CIlog10",
    "_CIfmod", "_ftol", "_ftol2", "_ftol2_sse", "_dtol2", "_dtol2_sse",
))


@dataclass(frozen=True, slots=True)
class Match:
    """Result of a signature lookup."""
    name: str
    confidence: float
    tier: str           # "byte" or "structural"
    compiler: str = ""
    source: str = ""
    category: str = ""


# ---------------------------------------------------------------------------
# Signature extraction
# ---------------------------------------------------------------------------

def extract_byte_sig(
    b: Binary, va: int, func_size: int | None = None,
) -> tuple[bytes, bytes, int, int] | None:
    """Extract a 32-byte pattern + mask from the function at *va*.

    Wildcards bytes 1-4 after E8 (CALL rel32) and E9 (JMP rel32) opcodes
    since the rel32 operand is position-dependent, and every byte past the
    end of a function shorter than 32 bytes, which belongs to whatever the
    linker placed next. Computes a tail CRC32 over the last 32 bytes.

    Args:
        func_size: The function's size when known (from a map); estimated
            from the disassembly otherwise.

    Returns:
        (pattern, mask, tail_crc, func_size) or None if unreadable.
    """
    code = b.read_va(va, 64)
    if len(code) < 32:
        return None

    pattern = bytearray(code[:32])
    mask = bytearray(b"\xff" * 32)

    _wildcard_rel32(pattern, mask)

    if func_size is None:
        func_size = _estimate_func_size(b, va)
    for i in range(max(func_size, 0), 32):
        mask[i] = 0x00
        pattern[i] = 0x00

    # Tail CRC: CRC32 of last 32 bytes (or whatever is available)
    tail_offset = max(0, func_size - 32)
    tail_bytes = b.read_va(va + tail_offset, 32)
    tail_crc = zlib.crc32(tail_bytes) & 0xFFFFFFFF if tail_bytes else 0

    return bytes(pattern), bytes(mask), tail_crc, func_size


def extract_flirt_crc(b: Binary, va: int, func_size: int) -> tuple[int, int]:
    """FLIRT CRC16 span for the function at *va*: (crc_len, crc16).

    The span starts after the 32-byte prefix and ends at the function's end,
    after 255 bytes, or at the first instruction whose bytes depend on where
    the code was linked: a call, a branch leaving the function, a
    RIP-relative operand, or an immediate or displacement that is an address
    inside the image. The same library function linked into another game at
    another address still passes, as FLIRT's relocation-masked CRC does.

    Returns:
        (0, 0) when no byte after the prefix qualifies. A span running past
        the end of its section ends there.
    """
    stop = min(func_size, 32 + _MAX_CRC_LEN)
    if stop <= 32:
        return 0, 0
    image = _image_range(b)
    for insn in b.iter_disasm(va, max_bytes=stop):
        offset = insn.address - va
        if offset >= stop:
            break
        if offset + insn.size > 32 and _depends_on_layout(b, insn, range(va, va + func_size), image):
            stop = offset
            break
    if stop <= 32:
        return 0, 0
    data = b.read_va(va + 32, stop - 32)
    if not data:
        return 0, 0
    return len(data), flirt_crc16(data)


def _wildcard_rel32(pattern: bytearray, mask: bytearray) -> None:
    """Wildcard the rel32 operand bytes of every fixed E8/E9 (call/jmp) in a 32-byte prefix.

    An opcode near the end of the prefix has only part of its operand inside
    it; that part is wildcarded too.
    """
    i = 0
    while i < 32:
        if mask[i] and pattern[i] in (0xE8, 0xE9):
            end = min(i + 5, 32)
            pattern[i + 1:end] = bytes(end - i - 1)
            mask[i + 1:end] = bytes(end - i - 1)
            i += 5
        else:
            i += 1


def _image_range(b: Binary) -> range:
    """Virtual addresses from the image base to the end of its last section."""
    size = max((s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in b.pe.sections), default=0)
    return range(b.base, b.base + size)


def _depends_on_layout(b: Binary, insn, func: range, image: range) -> bool:
    """Whether *insn*'s bytes change when its function is linked at another address.

    Only a value inside *image* is taken for an address: -1, a stack
    adjustment, an alignment mask or a segment-relative offset such as
    fs:[0] is the same wherever the code lands.
    """
    if insn.group(x86.X86_GRP_CALL):
        return True
    pointer_mask = (1 << 8 * b.ptr_size) - 1
    for op in insn.operands:
        if op.type == x86.X86_OP_IMM:
            if insn.group(x86.X86_GRP_JUMP):
                if op.imm not in func:
                    return True
            elif op.imm & pointer_mask in image:
                return True
        elif op.type == x86.X86_OP_MEM:
            if op.mem.base in (x86.X86_REG_RIP, x86.X86_REG_EIP) or op.mem.disp & pointer_mask in image:
                return True
    return False


def _estimate_func_size(b: Binary, va: int) -> int:
    """Estimate function size by scanning for ret + padding.

    Instructions are decoded one at a time, so the scan costs about the
    function's own length, not the whole 16 KB window.
    """
    last_ret_end = 0
    decoded_end = 0
    nop_run = 0
    for insn in itertools.islice(b.iter_disasm(va, max_bytes=0x4000), 500):
        decoded_end = insn.address + insn.size - va
        if insn.mnemonic in ("ret", "retn"):
            last_ret_end = decoded_end
            nop_run = 0
        elif last_ret_end > 0:
            if insn.mnemonic == "nop":
                nop_run += 1
                if nop_run >= 2:
                    return last_ret_end
            elif insn.mnemonic == "int3":
                return last_ret_end
            else:
                nop_run = 0
    return last_ret_end if last_ret_end > 0 else decoded_end


def _end_in_prefix(b: Binary, va: int, func_size: int) -> int | None:
    """Size of the function at *va* when it ends inside its 32-byte prefix.

    The end is the first return, unconditional jump, or call with a
    breakpoint after it (one that does not return) that no branch before it
    lands past, so it is found whether or not padding follows. An
    unconditional jump is a branch, not an end, when it stays in the
    function (_stays_in_function).

    Args:
        func_size: Estimated size of the function (_estimate_func_size).

    Returns:
        None for a function that runs past the prefix.
    """
    furthest_target = 0
    after_call = False
    for insn in b.iter_disasm(va, max_bytes=32):
        start = insn.address - va
        end = start + insn.size
        if after_call and insn.id == x86.X86_INS_INT3 and furthest_target < start:
            return start
        after_call = insn.group(x86.X86_GRP_CALL)
        is_jmp = insn.id == x86.X86_INS_JMP
        if insn.group(x86.X86_GRP_JUMP) and insn.operands[0].type == x86.X86_OP_IMM:
            target = insn.operands[0].imm - va
            if not is_jmp or _stays_in_function(b, va, target, func_size):
                furthest_target = max(furthest_target, target)
        if (is_jmp or insn.group(x86.X86_GRP_RET)) and furthest_target < end:
            return end
    return None


def _stays_in_function(b: Binary, va: int, target: int, func_size: int) -> bool:
    """Whether a jump to offset *target* of the function at *va* lands in that function.

    It does when the target lies in the 32-byte prefix or the *func_size*
    estimate and no known function starts between *va* and it. The estimate
    runs on into the next function after a tail jump, so a tail call to a
    function placed that near which *b*'s function table does not hold counts
    as staying; where the estimate stops short at an early return, a jump to
    the function's own code past it counts as leaving, as does a jump over a
    label the function table takes for a function start.
    """
    if target not in range(max(func_size, 32)):
        return False
    starts = b.func_table
    following = bisect.bisect_right(starts, va)
    return following == len(starts) or va + target < starts[following]


def _stops_at_function_end(mask: bytes, func_size: int) -> bool:
    """Whether a signature pins no byte after the end of its *func_size*-byte function."""
    return func_size < 32 and not any(mask[func_size:])


_FILLER_BYTES = frozenset(b"\xcc\x90")


def _ends_where_sig_does(code32: bytes, sig_size: int, func_size: int, prefix_end: int | None) -> bool:
    """Whether the function starting with *code32* ends where a signature of *sig_size* bytes does.

    It does when it measures that size by the estimate (*func_size*) or by
    its end in the prefix (*prefix_end*), or ends in the prefix before it
    with only breakpoints and nops up to it: a .pat length and a map size
    count the filler the compiler or the linker put after the last
    instruction.
    """
    if sig_size in (func_size, prefix_end):
        return True
    return prefix_end is not None and prefix_end < sig_size and _FILLER_BYTES.issuperset(code32[prefix_end:sig_size])


def extract_structural_sig(b: Binary, va: int) -> dict | None:
    """Extract structural (CFG-based) signature for the function at *va*.

    Returns:
        Dict with shape_version, block_count, edge_count, call_count,
        mnemonic_hash, constants -- or None if the function can't be analyzed.
    """
    blocks, edges = build_cfg(b, va)
    if not blocks:
        return None

    # Count calls and collect mnemonics + constants
    call_count = 0
    mnemonics: list[str] = []
    constants: set[int] = set()

    for block_insns in blocks.values():
        for insn in block_insns:
            mnemonics.append(insn.mnemonic)
            if insn.mnemonic == "call":
                call_count += 1
            # Collect interesting immediate constants
            for ref in b.abs_imm_refs(insn):
                if 0x100 <= ref <= 0xFFFFFFFF:
                    constants.add(ref)

    mnemonic_str = ",".join(mnemonics)
    mnemonic_hash = zlib.crc32(mnemonic_str.encode()) & 0xFFFFFFFF

    sorted_consts = sorted(constants)[:16]  # cap to avoid huge strings
    const_str = ",".join(f"0x{c:X}" for c in sorted_consts)

    return {
        "shape_version": SHAPE_VERSION,
        "block_count": len(blocks),
        "edge_count": len(edges),
        "call_count": call_count,
        "mnemonic_hash": mnemonic_hash,
        "constants": const_str,
    }


# ---------------------------------------------------------------------------
# Compiler fingerprinting
# ---------------------------------------------------------------------------

def parse_rich_header(b: Binary) -> list[dict]:
    """Parse the PE Rich header for comp.id entries.

    The Rich header sits between the DOS stub and the PE signature,
    XOR-encrypted with a checksum key. Each entry encodes a tool ID
    (linker, compiler, etc.) and a use count.

    Returns:
        List of dicts with comp_id, tool_id, minor_version, count.
    """
    raw = b.raw
    # Find "Rich" signature
    rich_pos = raw.find(b"Rich")
    if rich_pos == -1 or rich_pos < 0x40:
        return []

    # The 4 bytes after "Rich" are the XOR key
    key = struct.unpack_from("<I", raw, rich_pos + 4)[0]

    # Find "DanS" marker (XOR-encrypted) scanning backward from Rich
    dans_enc = struct.pack("<I", 0x536E6144 ^ key)  # "DanS" ^ key
    dans_pos = raw.rfind(dans_enc, 0, rich_pos)
    if dans_pos == -1:
        return []

    # Entries start after DanS + 12 bytes of padding (3 x key), end at Rich
    data_start = dans_pos + 16  # DanS + 3 padding DWORDs
    entries = []
    for off in range(data_start, rich_pos, 8):
        if off + 8 > len(raw):
            break
        val1 = struct.unpack_from("<I", raw, off)[0] ^ key
        val2 = struct.unpack_from("<I", raw, off + 4)[0] ^ key
        tool_id = (val1 >> 16) & 0xFFFF
        minor_version = val1 & 0xFFFF
        count = val2
        entries.append({
            "comp_id": val1,
            "tool_id": tool_id,
            "minor_version": minor_version,
            "count": count,
        })

    return entries


def detect_crt_import(b: Binary) -> str | None:
    """Check PE imports for known CRT DLLs.

    Returns:
        Compiler/runtime identifier string, or None.
    """
    if not hasattr(b.pe, "DIRECTORY_ENTRY_IMPORT"):
        return None
    for entry in b.pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("ascii", errors="ignore").lower()
        for crt_dll, compiler_id in _CRT_DLLS.items():
            if dll_name == crt_dll.lower():
                return compiler_id
    return None


# Rich header product id of each C and C++ compiler -> MSVC toolchain version, from
# https://github.com/dishather/richprint/blob/master/comp_id.txt
_RICH_COMPILER_TOOLCHAIN: dict[int, str] = {
    0x0A: "6.0", 0x0B: "6.0", 0x15: "6.0", 0x16: "6.0", 0x17: "6.0", 0x18: "6.0", 0x30: "6.0", 0x31: "6.0",
    0x1C: "7.0", 0x1D: "7.0",
    0x5F: "7.1", 0x60: "7.1",
    0x6D: "8.0", 0x6E: "8.0",
    0x83: "9.0", 0x84: "9.0",
    0xAA: "10.0", 0xAB: "10.0",
    0xCE: "11.0", 0xCF: "11.0",
    0xE0: "12.0", 0xE1: "12.0",
    0x104: "14+", 0x105: "14+",
}

_LABEL_YEAR_TOOLCHAIN = {
    "2002": "7.0", "2003": "7.1", "2005": "8.0", "2008": "9.0", "2010": "10.0",
    "2012": "11.0", "2013": "12.0", "2015": "14+", "2017": "14+", "2019": "14+", "2022": "14+",
}
_LABEL_VERSION_RE = re.compile(r"^\d+\.\d+$")


def msvc_toolchains(b: Binary) -> frozenset[str]:
    """MSVC versions whose compiler built objects of *b*, from its Rich header.

    Statically linked library code can only come from a toolchain listed here,
    so signatures labelled with any other MSVC version cannot match correctly.
    Only C and C++ compiler entries count: import library, linker, assembler
    and resource entries can come from another toolchain than the code's.

    Returns:
        Versions such as {"9.0", "8.0"}; empty when the binary has no Rich
        header or no entry from a compiler in _RICH_COMPILER_TOOLCHAIN.
    """
    return frozenset(
        _RICH_COMPILER_TOOLCHAIN[entry["tool_id"]]
        for entry in parse_rich_header(b)
        if entry["tool_id"] in _RICH_COMPILER_TOOLCHAIN
    )


def label_toolchains(compiler: str) -> frozenset[str]:
    """MSVC versions named by a signature's compiler label.

    Understands ``msvc2008``, ``msvc6.0`` and ``_``-joined lists such as
    ``msvc2003_2005``. A version is written as msvc_toolchains writes it:
    ``msvc7.10`` names 7.1, and every version from 14.0 up is ``14+``, the
    one name for VS2015 and later.

    Returns:
        The named versions, or an empty set when the label names no specific
        MSVC version (``msvc``, ``gcc``, ``""``).
    """
    if not compiler.startswith("msvc"):
        return frozenset()
    found: set[str] = set()
    for part in compiler[4:].lstrip("-").split("_"):
        if part in _LABEL_YEAR_TOOLCHAIN:
            found.add(_LABEL_YEAR_TOOLCHAIN[part])
        elif _LABEL_VERSION_RE.match(part):
            major, minor = part.split(".")
            found.add("14+" if int(major) >= 14 else f"{int(major)}.{minor.rstrip('0') or '0'}")
        else:
            return frozenset()
    return frozenset(found)


def _toolchain_allows(compiler: str, toolchains: frozenset[str]) -> bool:
    named = label_toolchains(compiler)
    return not (named and toolchains) or bool(named & toolchains)


class RefusedInput(ValueError):
    """Input a command will not act on: a compiler label, a manifest entry or a binary."""


def check_compiler_label(compiler: str) -> None:
    """Refuse an MSVC label that label_toolchains reads no version from.

    Such a label would be matched against every binary, as bare ``msvc`` is,
    although it was written to name one toolchain.

    Raises:
        RefusedInput: *compiler* starts with "msvc" in any letter case, is not
            exactly ``msvc`` and names no version.
    """
    if compiler.lower().startswith("msvc") and compiler != "msvc" and not label_toolchains(compiler):
        raise RefusedInput(
            f"compiler label {compiler!r} names no MSVC version: write msvc2008, msvc6.0 or a "
            "_-joined list such as msvc2003_2005, or msvc alone for any version")


def flirt_crc16(data: bytes) -> int:
    """CRC16 as stored in FLIRT .pat lines (CRC-16/X-25, byte-swapped)."""
    crc = 0xFFFF
    for byte in data:
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc ^ byte) & 1 else crc >> 1
            byte >>= 1
    crc = ~crc & 0xFFFF
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


def _categorize_name(name: str) -> str:
    """Heuristic category from a function name.

    Returns one of: "crt", "math", "stl", "exception", "security", "unknown".
    """
    lower = name.lower()

    # CRT / startup
    for prefix in _CRT_PREFIXES:
        if lower.startswith(prefix.lower()):
            return "crt"

    # Math
    # Strip leading underscore(s) for matching
    stripped = name.lstrip("_")
    if stripped in _MATH_NAMES or name in _MATH_NAMES:
        return "math"

    # STL
    if "std::" in name or "basic_string" in name or "allocator" in name:
        return "stl"

    # Exception handling
    if any(kw in lower for kw in ("throw", "catch", "unwind", "except", "eh_")):
        return "exception"

    # Security
    if "security" in lower or "guard" in lower or "gsfailure" in lower:
        return "security"

    return "unknown"


# ---------------------------------------------------------------------------
# SignatureDB
# ---------------------------------------------------------------------------

_INDEX_KEY_LEN = 4


class _ByteIndex:
    """In-memory byte_sigs rows bucketed by their first four pattern bytes.

    A signature whose first four bytes are all fixed can only match code that
    starts with exactly those bytes, so a lookup reads one bucket plus the
    signatures that wildcard any of those bytes.
    """

    def __init__(self, rows):
        self._buckets: dict[bytes, list[tuple]] = collections.defaultdict(list)
        self._wildcard_start: list[tuple] = []
        full = b"\xff" * _INDEX_KEY_LEN
        for row in rows:
            pattern, mask = row[1], row[2]
            if mask[:_INDEX_KEY_LEN] == full:
                self._buckets[pattern[:_INDEX_KEY_LEN]].append(row)
            else:
                self._wildcard_start.append(row)

    def candidates(self, code32: bytes):
        yield from self._buckets.get(code32[:_INDEX_KEY_LEN], ())
        yield from self._wildcard_start


class NotASignatureDB(sqlite3.DatabaseError):
    """The file holds something other than a signature database."""


class SchemaTooNew(sqlite3.DatabaseError):
    """The signature database was written by newer code than this."""


# (pattern, mask, crc_len, crc16): everything match_bytes compares, so two
# functions that differ only after the 32-byte prefix get separate keys.
_SigKey = tuple[bytes, bytes, int, int]


def _byte_row_key(row: tuple) -> _SigKey:
    """Key of a byte_sigs row in insertion column order."""
    return row[1], row[2], row[5], row[6]


def _byte_row_identity(row: tuple) -> tuple:
    """What makes a byte_sigs row in insertion column order the same signature as another.

    Every column but the category, which is derived from the name.
    """
    return row[:9]


# A byte signature that fits a function: its match, score in percent points, and key.
_ScoredSig = tuple[Match, int, _SigKey]


def _agreed_matches(candidates: Collection[_ScoredSig]) -> list[Match]:
    """The matches among *candidates* that name the function, best first.

    Equally scored matches are ordered by their own fields, so the result
    does not depend on the order the signatures were stored in.

    Returns:
        An empty list when the best-scored candidates carry several names:
        those of one key held under several names, or those of several keys.
        Candidates of a key held under several names are never returned.
    """
    if not candidates:
        return []
    names_by_key: dict[_SigKey, set[str]] = collections.defaultdict(set)
    for match, _, key in candidates:
        names_by_key[key].add(match.name)
    best_score = max(score for _, score, _ in candidates)
    if len({name for _, score, key in candidates if score == best_score for name in names_by_key[key]}) > 1:
        return []
    ranked = sorted(
        (c for c in candidates if len(names_by_key[c[2]]) == 1),
        key=lambda c: (-c[1], c[0].name, c[0].compiler, c[0].source, c[0].category))
    return [match for match, _, _ in ranked]


def _names_meet(holders: Collection[tuple[str, str]]) -> bool:
    """Whether two of the (name, compiler) *holders* differ in name and their labels share a version.

    A label naming no MSVC version shares one with every label.
    """
    return any(
        name != other_name and _toolchain_allows(compiler, label_toolchains(other_compiler))
        for (name, compiler), (other_name, other_compiler) in itertools.combinations(holders, 2))


class SignatureDB:
    """SQLite-backed signature database, opened for writing.

    A schema is created only in a new or empty file. Opening an existing
    signature database does not write to it, so a read-only or older-schema
    file can be scanned as it is; the first write switches the file to WAL
    and migrates it to the current schema. open_existing gives a connection
    that cannot write at all.

    Args:
        path: Filesystem path to the database file, or ":memory:".

    Raises:
        NotASignatureDB: *path* holds anything but a signature database.
        SchemaTooNew: The database's schema is newer than this code.
    """

    def __init__(self, path: str = ":memory:"):
        self._open(path, read_only=False)

    @classmethod
    def open_existing(cls, path: str) -> "SignatureDB":
        """Open a database file that is already there for reading only.

        The file is never created, migrated or otherwise written: the
        connection refuses every write.

        Raises:
            FileNotFoundError: No file at *path*.
            NotASignatureDB: The file is not a signature database.
            SchemaTooNew: The database's schema is newer than this code.
        """
        if not Path(path).is_file():
            raise FileNotFoundError(
                f"no signature database at {path} (download one with: python -m retools.sigdb pull)")
        db = cls.__new__(cls)
        db._open(path, read_only=True)
        return db

    def _open(self, path: str, read_only: bool) -> None:
        self._conn = sqlite3.connect(path)
        self._byte_index: _ByteIndex | None = None
        self._schema_writable = False
        self._read_only = read_only
        try:
            if read_only:
                self._conn.execute("PRAGMA query_only=ON")
            self._init_schema(path)
        except BaseException:
            self.close()
            raise

    def _table_names(self, path: str) -> set[str]:
        try:
            return {row[0] for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.OperationalError:
            raise
        except sqlite3.DatabaseError as e:
            raise NotASignatureDB(f"{path} is not a signature database: {e}") from e

    def _init_schema(self, path: str) -> None:
        tables = self._table_names(path)
        if "schema_version" in tables:
            row = self._conn.execute("SELECT version FROM schema_version").fetchone()
            if row and not isinstance(row[0], int):
                raise NotASignatureDB(f"{path} is not a signature database: its schema version is {row[0]!r}")
            if row and row[0] > SCHEMA_VERSION:
                raise SchemaTooNew(
                    f"{path} has schema version {row[0]}, newer than the version {SCHEMA_VERSION} "
                    "this code reads: update the tools")
            missing = [table for table in _TABLES if table not in tables]
            if missing:
                raise NotASignatureDB(f"{path} is not a signature database: it has no {', '.join(missing)} table")
            return
        if tables or self._read_only:
            raise NotASignatureDB(f"{path} is not a signature database")

        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        self._conn.commit()
        self._schema_writable = True

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- Insertion ---------------------------------------------------------

    def _byte_columns(self) -> set[str]:
        return {row[1] for row in self._conn.execute("PRAGMA table_info(byte_sigs)")}

    def _has_shape_versions(self) -> bool:
        return any(row[1] == _V2_STRUCTURAL_COLUMN for row in self._conn.execute("PRAGMA table_info(structural_sigs)"))

    def _ensure_writable_schema(self) -> None:
        """Before the first write: switch to WAL and migrate to the current schema.

        The migration adds whichever schema-2 columns are missing in one
        transaction, so a file left half-migrated is finished, not rejected.
        Statements still pending on the connection are committed first: neither
        a journal mode change nor BEGIN can run inside an open transaction.

        Raises:
            sqlite3.OperationalError: The database was opened for reading.
                Checked here because a journal mode change is the one write
                that query_only lets through.
        """
        if self._read_only:
            raise sqlite3.OperationalError("attempt to write a signature database opened for reading")
        if self._schema_writable:
            return
        self._conn.commit()
        self._conn.execute("PRAGMA journal_mode=WAL")
        missing = [col for col in _V2_BYTE_COLUMNS if col not in self._byte_columns()]
        with self._conn:
            self._conn.execute("BEGIN")
            for col in missing:
                self._conn.execute(f"ALTER TABLE byte_sigs ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
            if not self._has_shape_versions():
                self._conn.execute(f"ALTER TABLE structural_sigs ADD COLUMN {_V2_STRUCTURAL_COLUMN} "
                                   f"INTEGER NOT NULL DEFAULT {_FIRST_SHAPE_VERSION}")
            self._conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
        self._schema_writable = True

    def add_byte_sig(
        self, *, name: str, pattern: bytes, mask: bytes,
        func_size: int, tail_crc: int, crc_len: int = 0, crc16: int = 0,
        compiler: str = "", source: str = "", category: str = "",
    ) -> None:
        """Store one byte signature.

        Args:
            crc_len: Number of bytes after the 32-byte prefix covered by
                *crc16*; 0 when the signature carries no FLIRT CRC.
            crc16: FLIRT CRC16 of those bytes (see flirt_crc16).
        """
        self._write_sigs(byte_rows=[
            (name, pattern, mask, func_size, tail_crc, crc_len, crc16, compiler, source, category),
        ])

    def add_structural_sig(
        self, *, name: str, block_count: int, edge_count: int,
        call_count: int, mnemonic_hash: int, constants: str = "",
        compiler: str = "", source: str = "", category: str = "",
    ) -> None:
        self._write_sigs(structural_rows=[
            (name, block_count, edge_count, call_count, mnemonic_hash, constants, compiler, source, category,
             SHAPE_VERSION),
        ])

    def add_new_sigs(
        self, byte_rows: Iterable[tuple], structural_rows: Collection[tuple] = (),
    ) -> collections.Counter:
        """Add the rows the database does not hold yet, in one transaction.

        No held row is changed or removed, so the same sources leave the same
        signatures whatever order they are added in, and adding them again
        adds nothing.

        A byte row is held when a row with its key, name, size, tail CRC,
        compiler label and source is, so one function measured two ways or
        taken from two sources keeps a row for each. A key may end up under
        several names: match_bytes is what refuses it then. A structural row
        is held when every column is.

        Args:
            byte_rows: byte_sigs rows in insertion column order.
            structural_rows: structural_sigs rows in insertion column order.

        Returns:
            ``added`` and ``already_in_db`` byte rows, the same for structural
            rows under a ``structural_`` prefix, and ``ambiguous_prefix``:
            keys among *byte_rows* that the database now holds under more
            than one name for compiler labels that share a version or name
            none.
        """
        self._ensure_writable_schema()
        stats: collections.Counter = collections.Counter()
        holders: dict[_SigKey, set[tuple[str, str]]] = collections.defaultdict(set)
        held = set()
        for row in self._conn.execute(
                "SELECT name, pattern, mask, func_size, tail_crc, crc_len, crc16, compiler, source FROM byte_sigs"):
            held.add(_byte_row_identity(row))
            holders[_byte_row_key(row)].add((row[0], row[7]))
        new_byte_rows = []
        batch_keys = set()
        for row in byte_rows:
            key, identity = _byte_row_key(row), _byte_row_identity(row)
            batch_keys.add(key)
            if identity in held:
                stats["already_in_db"] += 1
            else:
                held.add(identity)
                holders[key].add((row[0], row[7]))
                new_byte_rows.append(row)
        stats["added"] = len(new_byte_rows)
        stats["ambiguous_prefix"] = sum(1 for key in batch_keys if _names_meet(holders[key]))

        held_structural = set(self._conn.execute(
            "SELECT name, block_count, edge_count, call_count, mnemonic_hash, "
            "constants, compiler, source, category, shape_version FROM structural_sigs")) if structural_rows else set()
        new_structural_rows = list(dict.fromkeys(row for row in structural_rows if row not in held_structural))
        stats["structural_added"] = len(new_structural_rows)
        stats["structural_already_in_db"] = len(structural_rows) - len(new_structural_rows)

        self._write_sigs(new_byte_rows, new_structural_rows)
        return +stats

    def sig_counts(self) -> tuple[int, int]:
        """Number of byte signatures and of structural signatures held."""
        return tuple(self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("byte_sigs", "structural_sigs"))

    def outdated_structural_count(self) -> int:
        """Number of structural signatures counted by another shape version than cfg's, which match nothing."""
        if not self._has_shape_versions():
            return self.sig_counts()[1]
        return self._conn.execute(
            "SELECT COUNT(*) FROM structural_sigs WHERE shape_version != ?", (SHAPE_VERSION,)).fetchone()[0]

    def _write_sigs(
        self, byte_rows: Collection[tuple] = (),
        structural_rows: Collection[tuple] = (),
    ) -> None:
        """Insert one batch of rows into both tables: all of it, or none on an error."""
        self._ensure_writable_schema()
        with self._conn:
            if byte_rows:
                self._conn.executemany(
                    "INSERT INTO byte_sigs "
                    "(name, pattern, mask, func_size, tail_crc, crc_len, crc16, compiler, source, category) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    byte_rows,
                )
            if structural_rows:
                self._conn.executemany(
                    "INSERT INTO structural_sigs "
                    "(name, block_count, edge_count, call_count, mnemonic_hash, "
                    "constants, compiler, source, category, shape_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    structural_rows,
                )
        self._byte_index = None

    # -- Byte matching -----------------------------------------------------

    def match_bytes(
        self, code: bytes, func_size: int,
        preferred_compiler: str, func_tail_crc: int,
        toolchains: frozenset[str] = frozenset(), prefix_end: int | None = None,
    ) -> list[Match]:
        """Find byte-pattern matches for the function starting with *code*.

        Args:
            code: The function's first bytes: 32 for the prefix, plus the
                bytes after it that signatures with a FLIRT CRC16 verify.
            func_size: Estimated size of the function.
            preferred_compiler: Compiler label that earns a small boost.
            func_tail_crc: CRC32 of the function's last 32 bytes.
            toolchains: MSVC versions in the binary (msvc_toolchains); a
                signature labelled with only other versions is skipped.
            prefix_end: The function's size when it ends inside the prefix
                (_end_in_prefix); None when it runs past it.

        Matching tiers:
          1. Masked comparison of the 32-byte prefix.
          2. End of a short function: a signature that pins no byte after
             its function's end is rejected unless the function measures
             that size too. *func_size* is the measure a build without map
             sizes stored, *prefix_end* the one a map or a .pat file gives,
             less the breakpoints and nops such a size counts after the
             last instruction (_ends_where_sig_does).
          3. FLIRT CRC16 over the following bytes, when the signature has
             one: a mismatch rejects, a match scores higher.
          4. Size disambiguation: exact size match scores higher.
          5. Tail CRC disambiguation: matching tail_crc scores higher.
          6. Preferred compiler boost.

        A key (prefix, mask and CRC16) that the signatures passing tiers 1
        to 3 hold under more than one name cannot tell those functions
        apart, so none of its signatures is a match: size and tail CRC only
        order the matches of a key. The function matches nothing when the
        best-scored signatures are of such a key, or carry more than one
        name between them, so a weaker signature never names a function
        that better ones disagree on.

        Returns:
            Matches, best first. Scores are whole percent points, so equal
            sums reached by different boosts tie exactly.
        """
        return _agreed_matches(self._byte_candidates(
            code, func_size, preferred_compiler, func_tail_crc, toolchains, prefix_end))

    def _byte_candidates(
        self, code: bytes, func_size: int,
        preferred_compiler: str, func_tail_crc: int,
        toolchains: frozenset[str], prefix_end: int | None,
    ) -> list[_ScoredSig]:
        """Every signature that passes tiers 1 to 3 of match_bytes, scored by tiers 3 to 6.

        An empty list means no signature fits the function's bytes; a list
        _agreed_matches empties means signatures fit and disagree on its name.
        """
        if len(code) < 32:
            return []
        code32 = code[:32]

        if self._byte_index is None:
            crc_columns = ("crc_len, crc16" if set(_V2_BYTE_COLUMNS) <= self._byte_columns()
                           else "0, 0")  # schema 1: no signature carries a CRC
            self._byte_index = _ByteIndex(self._conn.execute(
                f"SELECT name, pattern, mask, func_size, tail_crc, {crc_columns}, "
                "compiler, source, category FROM byte_sigs"
            ))
        candidates: list[_ScoredSig] = []

        for (name, pattern, mask, db_size, db_tail_crc, crc_len, crc16,
             compiler, source, category) in self._byte_index.candidates(code32):
            if not _toolchain_allows(compiler, toolchains):
                continue
            if not _masked_eq(code32, pattern, mask):
                continue
            if _stops_at_function_end(mask, db_size) and not _ends_where_sig_does(
                    code32, db_size, func_size, prefix_end):
                continue
            score = 70  # base confidence for byte match
            if crc_len:
                following = code[32:32 + crc_len]
                if len(following) < crc_len or flirt_crc16(following) != crc16:
                    continue
                score += 15
            if db_size == func_size:
                score += 15
            elif db_size > 0 and abs(db_size - func_size) / max(db_size, func_size) < 0.1:
                score += 5
            if db_tail_crc != 0 and func_tail_crc != 0 and db_tail_crc == func_tail_crc:
                score += 10
            if preferred_compiler and compiler == preferred_compiler:
                score += 5
            candidates.append((
                Match(
                    name=name, confidence=min(score, 100) / 100, tier="byte",
                    compiler=compiler, source=source, category=category,
                ),
                score,
                (pattern, mask, crc_len, crc16),
            ))
        return candidates

    # -- Structural matching -----------------------------------------------

    def match_structural(
        self, block_count: int, edge_count: int, call_count: int,
        mnemonic_hash: int, constants: str,
        toolchains: frozenset[str] = frozenset(),
    ) -> list[Match]:
        """Find structural matches by CFG shape and mnemonic hash.

        Requires exact mnemonic_hash match plus CFG shape (block_count,
        edge_count). call_count and constants refine the score. Signatures
        labelled with MSVC versions absent from *toolchains* are skipped, and
        so are those whose shape was counted by another version of cfg than
        the current one (cfg.SHAPE_VERSION), which counted the arguments.

        A shape that the remaining signatures hold under more than one name
        cannot tell those functions apart, so it matches nothing.

        Skips trivially small functions (< 3 blocks) -- their structural
        signatures are too generic to produce meaningful matches.
        """
        if block_count < 3 or not self._has_shape_versions():
            return []

        cur = self._conn.execute(
            "SELECT name, block_count, edge_count, call_count, "
            "mnemonic_hash, constants, compiler, source, category "
            "FROM structural_sigs "
            "WHERE mnemonic_hash = ? AND block_count = ? AND edge_count = ? AND shape_version = ?",
            (mnemonic_hash, block_count, edge_count, SHAPE_VERSION),
        )
        candidates: list[tuple[Match, float]] = []
        for (name, db_bc, db_ec, db_cc, db_mh, db_consts,
             compiler, source, category) in cur:
            if not _toolchain_allows(compiler, toolchains):
                continue
            score = 0.6  # base for structural match
            if db_cc == call_count:
                score += 0.15
            if db_consts == constants:
                score += 0.15
            elif constants and db_consts and set(db_consts.split(",")) & set(constants.split(",")):
                score += 0.05
            candidates.append((
                Match(
                    name=name, confidence=min(score, 1.0), tier="structural",
                    compiler=compiler, source=source, category=category,
                ),
                score,
            ))

        if len({m.name for m, _ in candidates}) > 1:
            return []
        candidates.sort(key=lambda c: c[1], reverse=True)
        return [m for m, _ in candidates]

    # -- High-level identification -----------------------------------------

    def identify(
        self, b: Binary, va: int, preferred_compiler: str = "",
        toolchains: frozenset[str] | None = None,
    ) -> Match | None:
        """Identify a function by its bytes, or by its structure when no byte signature fits it.

        Byte signatures that fit the function and disagree on its name
        (match_bytes) leave it unnamed: a structural signature is coarser
        than the bytes, so it cannot settle which of them is right.

        Args:
            toolchains: MSVC versions in *b*; read from its Rich header
                when None.

        Returns the best Match, or None.
        """
        if toolchains is None:
            toolchains = msvc_toolchains(b)

        # Tier 1: byte signature
        code = b.read_va(va, 32 + _MAX_CRC_LEN)
        if len(code) >= 32:
            func_size = _estimate_func_size(b, va)
            tail_offset = max(0, func_size - 32)
            tail_bytes = b.read_va(va + tail_offset, 32)
            tail_crc = zlib.crc32(tail_bytes) & 0xFFFFFFFF if tail_bytes else 0
            candidates = self._byte_candidates(
                code, func_size, preferred_compiler, tail_crc, toolchains, _end_in_prefix(b, va, func_size))
            if candidates:
                return next(iter(_agreed_matches(candidates)), None)

        # Tier 2: structural signature
        sig = extract_structural_sig(b, va)
        if sig is not None:
            matches = self.match_structural(
                sig["block_count"], sig["edge_count"], sig["call_count"],
                sig["mnemonic_hash"], sig["constants"], toolchains,
            )
            if matches:
                return matches[0]

        return None

    def scan(
        self, b: Binary, preferred_compiler: str = "",
    ) -> dict[int, Match]:
        """Bulk-scan all functions in the binary.

        A name that is the best match at more than one address is dropped
        everywhere: one library function links once, so repeats mean the
        signature is too generic to tell those functions apart.

        Returns:
            Dict mapping function VA to best Match.
        """
        toolchains = msvc_toolchains(b)
        results: dict[int, Match] = {}
        for va in b.func_table:
            m = self.identify(b, va, preferred_compiler, toolchains)
            if m is not None:
                results[va] = m
        hits_per_name = collections.Counter(m.name for m in results.values())
        return {va: m for va, m in results.items() if hits_per_name[m.name] == 1}

    # -- Compiler fingerprinting -------------------------------------------

    def fingerprint(self, b: Binary) -> dict:
        """Three-signal compiler detection.

        Signals:
          1. Rich header comp.id entries
          2. Marker byte patterns from compiler_fingerprints table
          3. CRT import DLL names

        Returns:
            Dict with compiler, confidence (0-1), evidence (list of strings).
        """
        evidence: list[str] = []
        votes: dict[str, float] = {}

        # Signal 1: Rich header
        rich = parse_rich_header(b)
        if rich:
            evidence.append(f"Rich header: {len(rich)} comp.id entries")
            # Rich header implies MSVC toolchain
            votes["msvc"] = votes.get("msvc", 0) + 0.4

        # Signal 2: Marker patterns from DB
        cur = self._conn.execute(
            "SELECT pattern, mask, compiler, label FROM compiler_fingerprints "
            "WHERE kind = 'marker'"
        )
        for pattern, mask, compiler, label in cur:
            # Scan first executable section for marker
            for sec_va, sec_off, sec_size in b.exec_ranges():
                chunk = b.raw[sec_off:sec_off + min(sec_size, 0x10000)]
                if _scan_for_pattern(chunk, pattern, mask):
                    evidence.append(f"Marker: {label} -> {compiler}")
                    votes[compiler] = votes.get(compiler, 0) + 0.3
                    break

        # Signal 3: CRT import
        crt = detect_crt_import(b)
        if crt:
            evidence.append(f"CRT import: {crt}")
            base = crt.split("-")[0] if "-" in crt else crt
            votes[base] = votes.get(base, 0) + 0.3

        if not votes:
            return {"compiler": "unknown", "confidence": 0.0, "evidence": evidence}

        best = max(votes, key=votes.get)
        confidence = min(votes[best], 1.0)
        return {"compiler": best, "confidence": confidence, "evidence": evidence}


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------

_MIN_SIG_FUNC_SIZE = 16
_MIN_FIXED_BYTES = 12


@dataclass
class NewSigs:
    """Signatures read from a build's or an import's sources, before a database takes them."""
    byte_rows: list[tuple] = field(default_factory=list)
    structural_rows: list[tuple] = field(default_factory=list)
    skipped: collections.Counter = field(default_factory=collections.Counter)

    def add_to(self, db: SignatureDB) -> collections.Counter:
        """Add them to *db* (SignatureDB.add_new_sigs).

        Returns:
            Counts of added and skipped signatures by reason.
        """
        return self.skipped + db.add_new_sigs(self.byte_rows, self.structural_rows)


def read_manifest_sigs(manifest: dict) -> NewSigs:
    """Extract the signatures of every ``binary_with_map`` source of a JSON manifest.

    Manifest format::

        {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": "path/to/file.dll",
                    "map": "path/to/map.csv",
                    "compiler": "msvc2008"
                }
            ]
        }

    The CSV must have ``address`` and ``name`` columns; an optional ``size``
    column replaces the estimated function size. Functions under 16 bytes
    and prefixes with fewer than 12 fixed bytes get no byte signature. Byte
    signatures carry a FLIRT CRC16 (extract_flirt_crc).

    Raises:
        RefusedInput: A compiler label names no MSVC version
            (check_compiler_label), or a binary is not a PE image.
        FileNotFoundError: A binary or a map is missing.
        ValueError: A map row's address or size is not a number.
    """
    sources = [source for source in manifest.get("sources", []) if source.get("type") == "binary_with_map"]
    for source in sources:
        check_compiler_label(source.get("compiler", ""))
    sigs = NewSigs()
    for source in sources:
        _read_binary_with_map(source["binary"], source["map"], source.get("compiler", ""), sigs)
    return sigs


def _read_binary_with_map(binary_path: str, map_path: str, compiler: str, sigs: NewSigs) -> None:
    try:
        b = Binary(binary_path)
    except pefile.PEFormatError as e:
        raise RefusedInput(f"cannot load {binary_path}: {e.value}") from e

    source_name = Path(binary_path).name
    with open(map_path, newline="") as f:
        for row in csv.DictReader(f):
            va = int(row["address"], 0)
            name = row["name"]
            category = _categorize_name(name)
            size = int(row["size"], 0) if row.get("size") else None

            bsig = extract_byte_sig(b, va, size)
            if bsig is None:
                sigs.skipped["unreadable"] += 1
                continue
            pattern, mask, tail_crc, func_size = bsig
            if func_size < _MIN_SIG_FUNC_SIZE:
                sigs.skipped["too_small"] += 1
                continue
            if sum(1 for m in mask if m) < _MIN_FIXED_BYTES:
                sigs.skipped["too_few_fixed_bytes"] += 1
            else:
                crc_len, crc16 = extract_flirt_crc(b, va, func_size)
                sigs.byte_rows.append((
                    name, pattern, mask, func_size, tail_crc, crc_len, crc16,
                    compiler, source_name, category,
                ))

            ssig = extract_structural_sig(b, va)
            if ssig is not None:
                sigs.structural_rows.append((
                    name, ssig["block_count"], ssig["edge_count"], ssig["call_count"],
                    ssig["mnemonic_hash"], ssig["constants"], compiler, source_name, category,
                    ssig["shape_version"],
                ))


# ":OFFSET name" is a public; ":OFFSET@ name" a local label. "?" stands for a function with no name.
_PAT_SYMBOL_RE = re.compile(r":([0-9A-Fa-f]{4,8})(@?) (\S+)")
_PAT_UNNAMED = "?"
_PAT_LOCAL_NAME_RE = re.compile(r"^(\.|\$|_LN\d+$)")


_PAT_PREFIX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}|\.\.){32}")
_PAT_HEX_RE = re.compile(r"[0-9A-Fa-f]+")


@dataclass(frozen=True, slots=True)
class PatSig:
    """The offset-0 function of one FLIRT .pat line.

    Attributes:
        length: Bytes from offset 0 to the next public, or to the end of the
            module when no public follows.
        crc_len: Bytes after the prefix that *crc16* covers. They are the
            module's, so they can run past *length*.
    """
    name: str
    is_local: bool
    pattern: bytes
    mask: bytes
    length: int
    crc_len: int
    crc16: int


def parse_pat_line(line: str) -> PatSig | None:
    """Parse a FLIRT .pat line into the signature of its offset-0 public.

    A line is: 64 hex chars for the first 32 bytes ("..": relocated byte),
    CRC16 length, CRC16, module length, then ":OFFSET name" publics. Only the
    public at offset 0 starts at the prefix, so the others are ignored; a
    local label there (":0000@ name") is taken when no public is. The sigdb
    E8/E9 rel32 wildcards are applied on top of the relocation ones.

    A module with several publics holds several functions: the one at offset
    0 ends where the next public starts. Prefix bytes past the end of a
    function shorter than 32 bytes are wildcards, as extract_byte_sig makes
    them.

    Returns:
        The parsed signature, or None for "---", lines with no named symbol
        at offset 0 and malformed lines: a prefix pair that is neither two
        hex digits nor "..", a field with anything but hex digits in it, a
        CRC16 length over 255 or a CRC16 over 16 bits.
    """
    parts = line.split(" ", 4)
    if len(parts) < 5:
        return None
    hexpat, crc_len_hex, crc_hex, length_hex, rest = parts
    if not _PAT_PREFIX_RE.fullmatch(hexpat):
        return None
    if not all(_PAT_HEX_RE.fullmatch(number) for number in (crc_len_hex, crc_hex, length_hex)):
        return None
    crc_len, crc16, module_length = int(crc_len_hex, 16), int(crc_hex, 16), int(length_hex, 16)
    if crc_len > _MAX_CRC_LEN or crc16 > 0xFFFF:
        return None

    symbols = [(int(off, 16), bool(local), sym) for off, local, sym in _PAT_SYMBOL_RE.findall(rest.split(" ^", 1)[0])]
    at_start = [(local, sym) for off, local, sym in symbols if off == 0 and sym != _PAT_UNNAMED]
    if not at_start:
        return None
    is_local, name = min(at_start, key=lambda symbol: symbol[0])
    later_publics = [off for off, local, _ in symbols if off > 0 and not local]
    length = min([*later_publics, module_length])

    pattern = bytearray(32)
    mask = bytearray(32)
    for i in range(min(32, length)):
        pair = hexpat[2 * i:2 * i + 2]
        if pair != "..":
            pattern[i] = int(pair, 16)
            mask[i] = 0xFF
    _wildcard_rel32(pattern, mask)
    return PatSig(name, is_local, bytes(pattern), bytes(mask), length, crc_len, crc16)


def _pat_skip_reason(sig: PatSig) -> str | None:
    if sig.is_local or _PAT_LOCAL_NAME_RE.match(sig.name) or "CrtImplementationDetails" in sig.name:
        return "local_or_managed"
    if sig.length < _MIN_SIG_FUNC_SIZE:
        return "too_small"
    if sum(1 for i in range(min(32, sig.length)) if sig.mask[i]) < _MIN_FIXED_BYTES:
        return "too_few_fixed_bytes"
    return None


def read_pat_sigs(path: str, compiler: str, source: str) -> NewSigs:
    """Read the byte signatures of a FLIRT .pat file.

    Skips local labels, unnamed functions, functions under 16 bytes and
    prefixes with fewer than 12 fixed bytes.

    Raises:
        RefusedInput: *compiler* names no MSVC version (check_compiler_label).
    """
    check_compiler_label(compiler)
    sigs = NewSigs()
    with open(path, errors="replace") as f:
        for line in f:
            sig = parse_pat_line(line.rstrip("\n"))
            if sig is None:
                sigs.skipped["unparsed"] += 1
                continue
            reason = _pat_skip_reason(sig)
            if reason:
                sigs.skipped[reason] += 1
                continue
            sigs.byte_rows.append((
                sig.name, sig.pattern, sig.mask, sig.length, 0, sig.crc_len, sig.crc16,
                compiler, source, _categorize_name(sig.name),
            ))
    return sigs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _masked_eq(code: bytes, pattern: bytes, mask: bytes) -> bool:
    """Compare code against pattern with mask (0xFF = must match, 0x00 = wildcard)."""
    for c, p, m in zip(code, pattern, mask):
        if (c & m) != (p & m):
            return False
    return True


def _scan_for_pattern(data: bytes, pattern: bytes, mask: bytes) -> bool:
    """Scan *data* for *pattern* with *mask*. Returns True on first hit."""
    plen = len(pattern)
    if not mask:
        return pattern in data
    for i in range(len(data) - plen + 1):
        if _masked_eq(data[i:i + plen], pattern, mask):
            return True
    return False


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url), timeout=60) as resp:
        return resp.read()


def _download_file(url: str, dest: str) -> None:
    """Download a file from *url* to *dest* with progress."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    data = _fetch(url)
    dest_path.write_bytes(data)
    print(f"  {dest_path.name} ({len(data):,} bytes)")


def download_signature_db(url: str, dest: str) -> None:
    """Replace the signature database at *dest* with the one at *url*.

    The download lands beside *dest* and takes its place only once it opens
    as a signature database this code reads, so a refused download leaves
    *dest* as it was. A write-ahead log left beside *dest* by a writer that
    never closed it goes with the database it belongs to
    (_replace_database): SQLite would replay it over the download.

    Raises:
        sqlite3.DatabaseError: The download is not a signature database, or
            its schema is newer than this code.
        PermissionError: *dest* or its log cannot be replaced; on Windows,
            because a program holds it open. The database and its log are as
            they were.
    """
    dest_path = Path(dest)
    part = dest_path.with_name(dest_path.name + ".part")
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    data = _fetch(url)
    try:
        part.write_bytes(data)
        try:
            SignatureDB.open_existing(str(part)).close()
        except sqlite3.DatabaseError as e:
            raise sqlite3.DatabaseError(f"download from {url} refused, {dest} left as it was: {e}") from e
        try:
            _replace_database(part, dest_path)
        except PermissionError as e:
            raise PermissionError(
                f"cannot replace {dest} with the download (is it open in another program?): {e}") from e
    finally:
        part.unlink(missing_ok=True)
    print(f"  {dest_path.name} ({len(data):,} bytes)")


def _replace_database(new: Path, dest: Path) -> None:
    """Move the database file *new* over *dest*, dropping the write-ahead log and shared memory files of *dest*.

    Those files hold the rows the old database has not checkpointed, so they
    are set aside under another name until *new* is in place and put back if
    it cannot be: a refusal leaves the old database whole.

    Raises:
        OSError: One of the files cannot be moved; all are as they were.
    """
    set_aside: list[tuple[Path, Path]] = []
    try:
        for suffix in ("-wal", "-shm"):
            sidecar = dest.with_name(dest.name + suffix)
            if sidecar.exists():
                aside = sidecar.with_name(sidecar.name + ".replaced")
                os.replace(sidecar, aside)
                set_aside.append((sidecar, aside))
        os.replace(new, dest)
    except OSError:
        for sidecar, aside in reversed(set_aside):
            os.replace(aside, sidecar)
        raise
    for _, aside in set_aside:
        aside.unlink()


def _source_dest(dest_dir: Path, rel_path: str) -> Path:
    """Where a manifest source path lands under *dest_dir*.

    Raises:
        RefusedInput: The path is absolute on Windows or POSIX, carries a
            drive, leads out of *dest_dir*, or names a folder that is there
            already: *dest_dir* itself, or the folder before a part of only
            dots and spaces, which Windows drops.
    """
    below_sources = rel_path.removeprefix("sources/")
    dest = (dest_dir / below_sources).resolve()
    as_windows = PureWindowsPath(below_sources)
    dropped_by_windows = any(part != ".." and not part.rstrip(". ") for part in as_windows.parts)
    if as_windows.anchor or dropped_by_windows or dest_dir.resolve() not in dest.parents:
        raise RefusedInput(f"manifest source path {rel_path!r} names no file inside {dest_dir}")
    return dest


def _manifest_sources(manifest_json: bytes, repo: str) -> list[str]:
    """The source paths listed by the manifest.json of the HF *repo*.

    Raises:
        RefusedInput: See _pull_sources.
    """
    try:
        manifest = json.loads(manifest_json)
    except ValueError as e:
        raise RefusedInput(f"manifest.json of {repo} is not JSON: {e}") from e
    sources = manifest.get("sources", []) if isinstance(manifest, dict) else None
    if not isinstance(sources, list) or not all(isinstance(rel_path, str) for rel_path in sources):
        raise RefusedInput(f"manifest.json of {repo} is not an object whose \"sources\" is a list of paths")
    return sources


def _pull_sources(repo: str, dest_dir: str, revision: str = _HF_REVISION_DEFAULT) -> None:
    """Download source files listed in the HF repo's manifest.json at *revision*.

    Raises:
        RefusedInput: The manifest is not a JSON object whose ``sources``, if
            any, is a list of paths, or a listed path names no file inside
            *dest_dir*; nothing is downloaded then.
    """
    dests = {rel_path: _source_dest(Path(dest_dir), rel_path)
             for rel_path in _manifest_sources(_fetch(_hf_url(repo, revision, "manifest.json")), repo)}
    for rel_path, dest in dests.items():
        try:
            _download_file(_hf_url(repo, revision, rel_path), str(dest))
        except urllib.error.HTTPError as e:
            print(f"  WARNING: {rel_path}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # -- build -------------------------------------------------------------
    s = sub.add_parser("build", help="Build signature DB from manifest")
    s.add_argument("manifest", help="JSON manifest file")
    s.add_argument("-o", "--output", default="sigs.db",
                   help="Output database path (default: sigs.db)")

    # -- import-pat --------------------------------------------------------
    s = sub.add_parser("import-pat", help="Add a FLIRT .pat file to a signature DB")
    s.add_argument("pat", help="FLIRT .pat file")
    s.add_argument("-d", "--db", required=True,
                   help="Signature DB path (created if missing; refused if it holds something else)")
    s.add_argument("--compiler", required=True,
                   help="Compiler label for every signature, e.g. msvc2008 or msvc6.0")
    s.add_argument("--source", required=True, help="Source label, e.g. rizin_vs2008")

    # -- scan --------------------------------------------------------------
    s = sub.add_parser("scan", help="Scan a binary for known functions")
    s.add_argument("binary", help="PE binary path")
    s.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH),
                   help="Signature DB path (default: %(default)s)")
    s.add_argument("--compiler", default="",
                   help="Preferred compiler hint")

    # -- identify ----------------------------------------------------------
    s = sub.add_parser("identify", help="Identify a single function")
    s.add_argument("binary", help="PE binary path")
    s.add_argument("va", help="Function virtual address (hex)")
    s.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH),
                   help="Signature DB path (default: %(default)s)")
    s.add_argument("--compiler", default="",
                   help="Preferred compiler hint")

    # -- fingerprint -------------------------------------------------------
    s = sub.add_parser("fingerprint",
                       help="Detect compiler from binary metadata")
    s.add_argument("binary", help="PE binary path")

    # -- pull ---------------------------------------------------------------
    s = sub.add_parser("pull", help="Download signature DB from HuggingFace")
    s.add_argument("--sources", action="store_true",
                   help="Also download source CSVs/TOMLs")
    s.add_argument("--repo", default=_HF_REPO_DEFAULT,
                   help=f"HuggingFace repo (default: {_HF_REPO_DEFAULT})")
    s.add_argument("--revision", default=_HF_REVISION_DEFAULT,
                   help="Branch, tag or commit to download (default: %(default)s)")

    args = p.parse_args(argv)

    try:
        _dispatch(args)
    except (OSError, sqlite3.DatabaseError, RefusedInput) as e:
        print(f"sigdb: {e}", file=sys.stderr)
        sys.exit(1)


def _print_outdated_structural_sigs(db: SignatureDB) -> None:
    outdated = db.outdated_structural_count()
    if outdated:
        print(f"  {outdated} structural sigs were built with an older CFG shape and match nothing until they are "
              "rebuilt from their binaries (sigdb build)")


def _dispatch(args: argparse.Namespace) -> None:
    if args.command == "build":
        with open(args.manifest) as f:
            manifest = json.load(f)
        sigs = read_manifest_sigs(manifest)
        db = SignatureDB(args.output)
        stats = sigs.add_to(db)
        byte_count, structural_count = db.sig_counts()
        print(f"Built {args.output}: {byte_count} byte sigs, {structural_count} structural sigs")
        for reason, count in sorted(stats.items()):
            print(f"  {reason}: {count}")
        _print_outdated_structural_sigs(db)
        db.close()

    elif args.command == "import-pat":
        sigs = read_pat_sigs(args.pat, args.compiler, args.source)
        db = SignatureDB(args.db)
        stats = sigs.add_to(db)
        db.close()
        for reason, count in sorted(stats.items()):
            print(f"  {reason}: {count}")

    elif args.command == "scan":
        db = SignatureDB.open_existing(args.db)
        b = Binary(args.binary)
        results = db.scan(b, args.compiler)
        w = 16 if b.is_64 else 8
        for va, m in sorted(results.items()):
            print(f"  0x{va:0{w}X}  {m.name:40s} "
                  f"{m.confidence:.0%} ({m.tier}) [{m.category}]")
        print(f"\n{len(results)} / {len(b.func_table)} functions identified")
        _print_outdated_structural_sigs(db)
        db.close()

    elif args.command == "identify":
        db = SignatureDB.open_existing(args.db)
        b = Binary(args.binary)
        va = int(args.va, 16)
        m = db.identify(b, va, args.compiler)
        if m:
            print(f"  {m.name}")
            print(f"  confidence: {m.confidence:.0%}")
            print(f"  tier:       {m.tier}")
            print(f"  compiler:   {m.compiler}")
            print(f"  source:     {m.source}")
            print(f"  category:   {m.category}")
        else:
            print("  No match")
        db.close()

    elif args.command == "fingerprint":
        b = Binary(args.binary)
        db = SignatureDB(":memory:")
        result = db.fingerprint(b)
        print(f"  Compiler:   {result['compiler']}")
        print(f"  Confidence: {result['confidence']:.0%}")
        for ev in result["evidence"]:
            print(f"    - {ev}")
        db.close()

    elif args.command == "pull":
        data_dir = DEFAULT_DB_PATH.parent
        db_url = _hf_url(args.repo, args.revision, "signatures.db")
        print(f"Downloading from {args.repo}@{args.revision}...")
        download_signature_db(db_url, str(data_dir / "signatures.db"))
        if args.sources:
            _pull_sources(args.repo, str(data_dir / "sources"), args.revision)
        print("Done.")


if __name__ == "__main__":
    main()
