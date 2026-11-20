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
import collections
import csv
import itertools
import json
import re
import sqlite3
import struct
import sys
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capstone import x86_const as x86
from common import MIN_ABS_ADDRESS, Binary

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "signatures.db"

_HF_REPO_DEFAULT = "RTX-Remix/Vibe-Reverse-Engineering-Signature-DB"
_HF_REVISION_DEFAULT = "main"
_HF_URL_TEMPLATE = "https://huggingface.co/{repo}/resolve/{revision}/{path}"

SCHEMA_VERSION = 2

# byte_sigs columns schema version 2 added to version 1.
_V2_BYTE_COLUMNS = ("crc_len", "crc16")

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
    category      TEXT    NOT NULL DEFAULT ''
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
    the code was linked: a call, a branch leaving the function, an absolute
    memory operand, or an immediate that looks like an address. The same
    library function linked into another game at another address still
    passes, as FLIRT's relocation-masked CRC does.

    Returns:
        (0, 0) when no byte after the prefix qualifies. A span running past
        the end of its section ends there.
    """
    stop = min(func_size, 32 + _MAX_CRC_LEN)
    if stop <= 32:
        return 0, 0
    for insn in b.iter_disasm(va, max_bytes=stop):
        offset = insn.address - va
        if offset >= stop:
            break
        if offset + insn.size > 32 and _depends_on_layout(b, insn, va, func_size):
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


def _depends_on_layout(b: Binary, insn, va: int, func_size: int) -> bool:
    if insn.group(x86.X86_GRP_CALL):
        return True
    for op in insn.operands:
        if op.type == x86.X86_OP_IMM:
            if insn.group(x86.X86_GRP_JUMP):
                if not va <= op.imm < va + func_size:
                    return True
            elif b.abs_imm_refs(insn):
                return True
        elif op.type == x86.X86_OP_MEM:
            mem = op.mem
            if mem.base in (0, x86.X86_REG_RIP, x86.X86_REG_EIP) and mem.index == 0:
                return True
            # x86 has no RIP-relative form: a switch table or global array is
            # reached through [index*scale + abs32] or [reg + abs32].
            if not b.is_64 and (mem.base == 0 or abs(mem.disp) > MIN_ABS_ADDRESS):
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


def extract_structural_sig(b: Binary, va: int) -> dict | None:
    """Extract structural (CFG-based) signature for the function at *va*.

    Returns:
        Dict with block_count, edge_count, call_count, mnemonic_hash,
        constants -- or None if the function can't be analyzed.
    """
    try:
        from cfg import build_cfg
    except ImportError:
        return None

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


# Rich header build number -> MSVC toolchain version. Build 50727 is shared by
# VS2005 (8.0) and VS2012 (11.0); the product id tells them apart.
_RICH_BUILD_TOOLCHAIN: dict[int, str] = {
    8168: "6.0", 8447: "6.0", 8797: "6.0", 8799: "6.0", 8804: "6.0", 8966: "6.0", 9044: "6.0",
    9466: "7.0", 9955: "7.0",
    3052: "7.1", 3077: "7.1", 4035: "7.1", 6030: "7.1",
    21022: "9.0", 30729: "9.0",
    30319: "10.0", 40219: "10.0",
    51025: "11.0", 51106: "11.0", 60315: "11.0", 60610: "11.0", 61030: "11.0",
    21005: "12.0", 30501: "12.0", 31101: "12.0", 40629: "12.0",
}
_VS2012_FIRST_PRODID = 0xC7
_VS2015_FIRST_PRODID = 0x100

_LABEL_YEAR_TOOLCHAIN = {
    "2002": "7.0", "2003": "7.1", "2005": "8.0", "2008": "9.0", "2010": "10.0",
    "2012": "11.0", "2013": "12.0", "2015": "14+", "2017": "14+", "2019": "14+", "2022": "14+",
}
_LABEL_VERSION_RE = re.compile(r"^\d+\.\d+$")


def msvc_toolchains(b: Binary) -> frozenset[str]:
    """MSVC versions that contributed objects to *b*, from its Rich header.

    Statically linked library code can only come from a toolchain listed here,
    so signatures labelled with any other MSVC version cannot match correctly.

    Returns:
        Versions such as {"9.0", "8.0"}; empty when the binary has no Rich
        header or none of its build numbers is known.
    """
    found: set[str] = set()
    for entry in parse_rich_header(b):
        tool_id, build = entry["tool_id"], entry["minor_version"]
        if tool_id >= _VS2015_FIRST_PRODID:
            found.add("14+")
        elif build == 50727:
            found.add("11.0" if tool_id >= _VS2012_FIRST_PRODID else "8.0")
        elif build in _RICH_BUILD_TOOLCHAIN:
            found.add(_RICH_BUILD_TOOLCHAIN[build])
    return frozenset(found)


def label_toolchains(compiler: str) -> frozenset[str]:
    """MSVC versions named by a signature's compiler label.

    Understands ``msvc2008``, ``msvc6.0`` and ``_``-joined lists such as
    ``msvc2003_2005``.

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
            found.add(part)
        else:
            return frozenset()
    return frozenset(found)


def _toolchain_allows(compiler: str, toolchains: frozenset[str]) -> bool:
    named = label_toolchains(compiler)
    return not (named and toolchains) or bool(named & toolchains)


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


class SignatureDB:
    """SQLite-backed signature database.

    Opening an existing database does not write to it, so a read-only or
    older-schema file can be scanned as it is. The first write switches the
    file to WAL and migrates it to the current schema.

    Args:
        path: Filesystem path to the database file, or ":memory:".
    """

    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path)
        self._byte_index: _ByteIndex | None = None
        self._schema_writable = False
        self._init_schema()

    @classmethod
    def open_existing(cls, path: str) -> "SignatureDB":
        """Open a database file that is already there, never creating one.

        Raises:
            FileNotFoundError: No file at *path*.
        """
        if not Path(path).is_file():
            raise FileNotFoundError(
                f"no signature database at {path} (download one with: python -m retools.sigdb pull)")
        return cls(path)

    def _init_schema(self) -> None:
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='schema_version'"
        )
        if cur.fetchone() is not None:
            row = self._conn.execute(
                "SELECT version FROM schema_version"
            ).fetchone()
            if row and row[0] > SCHEMA_VERSION:
                self._conn.close()
                self._conn = None
                raise RuntimeError(
                    f"Database schema version {row[0]} is newer than "
                    f"code version {SCHEMA_VERSION}. Update the code."
                )
            return

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

    def _ensure_writable_schema(self) -> None:
        """Before the first write: switch to WAL and migrate to the current schema.

        The migration adds whichever schema-2 columns are missing in one
        transaction, so a file left half-migrated is finished, not rejected.
        Statements still pending on the connection are committed first: neither
        a journal mode change nor BEGIN can run inside an open transaction.
        """
        if self._schema_writable:
            return
        self._conn.commit()
        self._conn.execute("PRAGMA journal_mode=WAL")
        missing = [col for col in _V2_BYTE_COLUMNS if col not in self._byte_columns()]
        with self._conn:
            self._conn.execute("BEGIN")
            for col in missing:
                self._conn.execute(f"ALTER TABLE byte_sigs ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
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
        self._insert_byte_sigs([
            (name, pattern, mask, func_size, tail_crc, crc_len, crc16, compiler, source, category),
        ])

    def _insert_byte_sigs(self, rows: list[tuple]) -> None:
        self._ensure_writable_schema()
        self._conn.executemany(
            "INSERT INTO byte_sigs "
            "(name, pattern, mask, func_size, tail_crc, crc_len, crc16, compiler, source, category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        self._byte_index = None

    def add_structural_sig(
        self, *, name: str, block_count: int, edge_count: int,
        call_count: int, mnemonic_hash: int, constants: str = "",
        compiler: str = "", source: str = "", category: str = "",
    ) -> None:
        self._ensure_writable_schema()
        self._conn.execute(
            "INSERT INTO structural_sigs "
            "(name, block_count, edge_count, call_count, mnemonic_hash, "
            "constants, compiler, source, category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, block_count, edge_count, call_count, mnemonic_hash,
             constants, compiler, source, category),
        )
        self._conn.commit()

    # -- Byte matching -----------------------------------------------------

    def match_bytes(
        self, code: bytes, func_size: int,
        preferred_compiler: str, func_tail_crc: int,
        toolchains: frozenset[str] = frozenset(),
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

        Matching tiers:
          1. Masked comparison of the 32-byte prefix.
          2. FLIRT CRC16 over the following bytes, when the signature has
             one: a mismatch rejects, a match scores higher.
          3. Size disambiguation: exact size match scores higher.
          4. Tail CRC disambiguation: matching tail_crc scores higher.
          5. Preferred compiler boost.
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
        candidates: list[tuple[Match, float]] = []

        for (name, pattern, mask, db_size, db_tail_crc, crc_len, crc16,
             compiler, source, category) in self._byte_index.candidates(code32):
            if not _toolchain_allows(compiler, toolchains):
                continue
            if not _masked_eq(code32, pattern, mask):
                continue
            score = 0.7  # base confidence for byte match
            if crc_len:
                following = code[32:32 + crc_len]
                if len(following) < crc_len or flirt_crc16(following) != crc16:
                    continue
                score += 0.15
            if db_size == func_size:
                score += 0.15
            elif db_size > 0 and abs(db_size - func_size) / max(db_size, func_size) < 0.1:
                score += 0.05
            if db_tail_crc != 0 and func_tail_crc != 0 and db_tail_crc == func_tail_crc:
                score += 0.10
            if preferred_compiler and compiler == preferred_compiler:
                score += 0.05
            candidates.append((
                Match(
                    name=name, confidence=min(score, 1.0), tier="byte",
                    compiler=compiler, source=source, category=category,
                ),
                score,
            ))

        candidates.sort(key=lambda c: c[1], reverse=True)
        return [m for m, _ in candidates]

    # -- Structural matching -----------------------------------------------

    def match_structural(
        self, block_count: int, edge_count: int, call_count: int,
        mnemonic_hash: int, constants: str,
        toolchains: frozenset[str] = frozenset(),
    ) -> list[Match]:
        """Find structural matches by CFG shape and mnemonic hash.

        Requires exact mnemonic_hash match plus CFG shape (block_count,
        edge_count). call_count and constants refine the score. Signatures
        labelled with MSVC versions absent from *toolchains* are skipped.

        Skips trivially small functions (< 3 blocks) -- their structural
        signatures are too generic to produce meaningful matches.
        """
        if block_count < 3:
            return []

        cur = self._conn.execute(
            "SELECT name, block_count, edge_count, call_count, "
            "mnemonic_hash, constants, compiler, source, category "
            "FROM structural_sigs "
            "WHERE mnemonic_hash = ? AND block_count = ? AND edge_count = ?",
            (mnemonic_hash, block_count, edge_count),
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

        candidates.sort(key=lambda c: c[1], reverse=True)
        return [m for m, _ in candidates]

    # -- High-level identification -----------------------------------------

    def identify(
        self, b: Binary, va: int, preferred_compiler: str = "",
        toolchains: frozenset[str] | None = None,
    ) -> Match | None:
        """Identify a function by trying byte-exact, then structural fallback.

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
            matches = self.match_bytes(code, func_size, preferred_compiler, tail_crc, toolchains)
            if matches:
                return matches[0]

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

# (pattern, mask, crc_len, crc16): everything match_bytes compares, so two
# functions that differ only after the 32-byte prefix get separate keys.
_SigKey = tuple[bytes, bytes, int, int]


def build_from_manifest(db: SignatureDB, manifest: dict) -> collections.Counter:
    """Ingest signatures from a JSON manifest.

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
    are skipped. Byte signatures carry a FLIRT CRC16 (extract_flirt_crc) and
    go through the same prefix checks as import_pat.

    Returns:
        Counts of added and skipped byte signatures by reason.
    """
    stats: collections.Counter = collections.Counter()
    by_key: dict[_SigKey, list[tuple]] = collections.defaultdict(list)
    for source in manifest.get("sources", []):
        if source.get("type") != "binary_with_map":
            continue
        binary_path = source["binary"]
        map_path = source["map"]
        compiler = source.get("compiler", "")

        if not Path(binary_path).is_file():
            print(f"sigdb: skipping missing binary: {binary_path}", file=sys.stderr)
            continue

        try:
            b = Binary(binary_path)
        except Exception as e:
            print(f"sigdb: failed to load {binary_path}: {e}", file=sys.stderr)
            continue

        source_name = Path(binary_path).name
        with open(map_path, newline="") as f:
            for row in csv.DictReader(f):
                va = int(row["address"], 0)
                name = row["name"]
                category = _categorize_name(name)
                size = int(row["size"], 0) if row.get("size") else None

                bsig = extract_byte_sig(b, va, size)
                if bsig is None:
                    stats["unreadable"] += 1
                    continue
                pattern, mask, tail_crc, func_size = bsig
                if func_size < _MIN_SIG_FUNC_SIZE:
                    stats["too_small"] += 1
                    continue
                if sum(1 for m in mask if m) < _MIN_FIXED_BYTES:
                    stats["too_few_fixed_bytes"] += 1
                else:
                    crc_len, crc16 = extract_flirt_crc(b, va, func_size)
                    by_key[(pattern, mask, crc_len, crc16)].append((
                        name, pattern, mask, func_size, tail_crc, crc_len, crc16,
                        compiler, source_name, category,
                    ))

                ssig = extract_structural_sig(b, va)
                if ssig is not None:
                    db.add_structural_sig(
                        name=name, compiler=compiler,
                        source=source_name, category=category,
                        **ssig,
                    )

    _insert_unique_byte_sigs(db, by_key, stats)
    return stats


def _insert_unique_byte_sigs(
    db: SignatureDB, by_key: dict[_SigKey, list[tuple]],
    stats: collections.Counter,
) -> None:
    """Insert the byte_sigs rows of every signature key that names exactly one function.

    A key given more than one name cannot tell those functions apart. A row
    whose key is already held under a compiler label that can match the same
    binaries would only repeat it; one held for other MSVC versions only is
    added, since matching skips each row on the other's binaries.
    """
    db._ensure_writable_schema()
    held: dict[_SigKey, list[str]] = collections.defaultdict(list)
    for pattern, mask, crc_len, crc16, compiler in db._conn.execute(
            "SELECT pattern, mask, crc_len, crc16, compiler FROM byte_sigs"):
        held[(pattern, mask, crc_len, crc16)].append(compiler)
    rows = []
    for key, candidates in by_key.items():
        if len({row[0] for row in candidates}) > 1:
            stats["ambiguous_prefix"] += 1
            continue
        for row in candidates:
            toolchains = label_toolchains(row[7])
            if any(_toolchain_allows(compiler, toolchains) for compiler in held[key]):
                stats["already_in_db"] += 1
            else:
                rows.append(row)
                held[key].append(row[7])
    db._insert_byte_sigs(rows)
    stats["added"] += len(rows)


_PAT_PUBLIC_RE = re.compile(r":([0-9A-Fa-f]{4,8})@? (\S+)")
_PAT_LOCAL_NAME_RE = re.compile(r"^(\.|\$|_LN\d+$)")


@dataclass(frozen=True, slots=True)
class PatSig:
    """The offset-0 function of one FLIRT .pat line."""
    name: str
    pattern: bytes
    mask: bytes
    length: int
    crc_len: int
    crc16: int


def parse_pat_line(line: str) -> PatSig | None:
    """Parse a FLIRT .pat line into the signature of its offset-0 public.

    A line is: 64 hex chars for the first 32 bytes ("..": relocated byte),
    CRC16 length, CRC16, module length, then ":OFFSET name" publics. Only the
    public at offset 0 starts at the prefix, so the others are ignored. The
    sigdb E8/E9 rel32 wildcards are applied on top of the relocation ones.

    Prefix bytes past the end of a function shorter than 32 bytes are
    wildcards, as extract_byte_sig makes them.

    Returns:
        The parsed signature, or None for "---", malformed lines and lines
        with no public at offset 0.
    """
    parts = line.split(" ", 4)
    if len(parts) < 5 or len(parts[0]) != 64:
        return None
    hexpat, crc_len_hex, crc_hex, length_hex, rest = parts
    publics = rest.split(" ^", 1)[0]
    name = next((sym for off, sym in _PAT_PUBLIC_RE.findall(publics) if int(off, 16) == 0), None)
    if name is None:
        return None
    pattern = bytearray(32)
    mask = bytearray(32)
    try:
        for i in range(32):
            pair = hexpat[2 * i:2 * i + 2]
            if pair != "..":
                pattern[i] = int(pair, 16)
                mask[i] = 0xFF
        length, crc_len, crc16 = int(length_hex, 16), int(crc_len_hex, 16), int(crc_hex, 16)
    except ValueError:
        return None
    if length < 32:
        pattern[length:] = bytes(32 - length)
        mask[length:] = bytes(32 - length)
    _wildcard_rel32(pattern, mask)
    return PatSig(name, bytes(pattern), bytes(mask), length, crc_len, crc16)


def _pat_skip_reason(sig: PatSig) -> str | None:
    if _PAT_LOCAL_NAME_RE.match(sig.name) or "CrtImplementationDetails" in sig.name:
        return "local_or_managed"
    if sig.length < _MIN_SIG_FUNC_SIZE:
        return "too_small"
    if sum(1 for i in range(min(32, sig.length)) if sig.mask[i]) < _MIN_FIXED_BYTES:
        return "too_few_fixed_bytes"
    return None


def import_pat(db: SignatureDB, path: str, compiler: str, source: str) -> collections.Counter:
    """Add the byte signatures of a FLIRT .pat file to *db*.

    Skips local labels, functions under 16 bytes, prefixes with fewer than 12
    fixed bytes, signatures (prefix plus CRC16) the file gives more than one
    name, and signatures the database already holds for an overlapping
    compiler label (see _insert_unique_byte_sigs).

    Returns:
        Counts of added and skipped lines by reason.
    """
    stats: collections.Counter = collections.Counter()
    by_key: dict[_SigKey, list[tuple]] = collections.defaultdict(list)
    with open(path, errors="replace") as f:
        for line in f:
            sig = parse_pat_line(line.rstrip("\n"))
            if sig is None:
                stats["unparsed"] += 1
                continue
            reason = _pat_skip_reason(sig)
            if reason:
                stats[reason] += 1
                continue
            by_key[(sig.pattern, sig.mask, sig.crc_len, sig.crc16)].append((
                sig.name, sig.pattern, sig.mask, sig.length, 0, sig.crc_len, sig.crc16,
                compiler, source, _categorize_name(sig.name),
            ))
    _insert_unique_byte_sigs(db, by_key, stats)
    return stats


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

def _download_file(url: str, dest: str) -> None:
    """Download a file from *url* to *dest* with progress."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    dest_path.write_bytes(data)
    print(f"  {dest_path.name} ({len(data):,} bytes)")


def _pull_sources(repo: str, dest_dir: str, revision: str = _HF_REVISION_DEFAULT) -> None:
    """Download source files listed in the HF repo's manifest.json at *revision*."""
    manifest_url = _HF_URL_TEMPLATE.format(repo=repo, revision=revision, path="manifest.json")
    req = urllib.request.Request(manifest_url)
    with urllib.request.urlopen(req, timeout=60) as resp:
        manifest = json.loads(resp.read())

    for rel_path in manifest.get("sources", []):
        url = _HF_URL_TEMPLATE.format(repo=repo, revision=revision, path=rel_path)
        dest = Path(dest_dir) / rel_path.removeprefix("sources/")
        try:
            _download_file(url, str(dest))
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
    s.add_argument("-d", "--db", required=True, help="Signature DB path (created if missing)")
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
    except (FileNotFoundError, OSError) as e:
        print(f"sigdb: {e}", file=sys.stderr)
        sys.exit(1)


def _dispatch(args: argparse.Namespace) -> None:
    if args.command == "build":
        with open(args.manifest) as f:
            manifest = json.load(f)
        db = SignatureDB(args.output)
        stats = build_from_manifest(db, manifest)
        cur = db._conn.execute("SELECT COUNT(*) FROM byte_sigs")
        bc = cur.fetchone()[0]
        cur = db._conn.execute("SELECT COUNT(*) FROM structural_sigs")
        sc = cur.fetchone()[0]
        print(f"Built {args.output}: {bc} byte sigs, {sc} structural sigs")
        for reason, count in sorted(stats.items()):
            print(f"  {reason}: {count}")
        db.close()

    elif args.command == "import-pat":
        db = SignatureDB(args.db)
        stats = import_pat(db, args.pat, args.compiler, args.source)
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
        db_url = _HF_URL_TEMPLATE.format(repo=args.repo, revision=args.revision, path="signatures.db")
        print(f"Downloading from {args.repo}@{args.revision}...")
        _download_file(db_url, str(data_dir / "signatures.db"))
        if args.sources:
            _pull_sources(args.repo, str(data_dir / "sources"), args.revision)
        print("Done.")


if __name__ == "__main__":
    main()
