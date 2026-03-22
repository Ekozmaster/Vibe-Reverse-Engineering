#!/usr/bin/env python3
"""Signature database for function identification in PE binaries.

Provides a SQLite-backed signature database with:
- Byte-pattern signatures (FLIRT-style, with relocation wildcards)
- Structural signatures (CFG shape + mnemonic hash)
- Compiler fingerprinting (Rich header, CRT imports, marker patterns)
- Multi-tier matching: byte-exact -> structural fallback
- Build pipeline from JSON manifest + CSV address maps
- CLI with build, scan, identify, fingerprint subcommands

Usage:
    python retools/sigdb.py build manifest.json -o sigs.db
    python retools/sigdb.py scan binary.exe -d sigs.db
    python retools/sigdb.py identify binary.exe 0x401000 -d sigs.db
    python retools/sigdb.py fingerprint binary.exe
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import struct
import sys
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Binary

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "signatures.db"

_HF_REPO_DEFAULT = "RTX-Remix/Vibe-Reverse-Engineering-Signature-DB"
_HF_URL_TEMPLATE = "https://huggingface.co/{repo}/resolve/main/{path}"

SCHEMA_VERSION = 1

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

def extract_byte_sig(b: Binary, va: int) -> tuple[bytes, bytes, int, int] | None:
    """Extract a 32-byte pattern + mask from the function at *va*.

    Wildcards bytes 1-4 after E8 (CALL rel32) and E9 (JMP rel32) opcodes
    since the rel32 operand is position-dependent. Computes a FLIRT-style
    tail CRC over the last 32 bytes, and estimates function size.

    Returns:
        (pattern, mask, tail_crc, func_size) or None if unreadable.
    """
    code = b.read_va(va, 64)
    if len(code) < 32:
        return None

    pattern = bytearray(code[:32])
    mask = bytearray(b"\xff" * 32)

    # Wildcard E8/E9 rel32 operands
    i = 0
    while i < 28:  # need room for 5 bytes
        if pattern[i] in (0xE8, 0xE9):
            for j in range(1, 5):
                mask[i + j] = 0x00
                pattern[i + j] = 0x00
            i += 5
        else:
            i += 1

    # Estimate function size from disassembly
    func_size = _estimate_func_size(b, va)

    # Tail CRC: CRC32 of last 32 bytes (or whatever is available)
    tail_offset = max(0, func_size - 32)
    tail_bytes = b.read_va(va + tail_offset, 32)
    tail_crc = zlib.crc32(tail_bytes) & 0xFFFFFFFF if tail_bytes else 0

    return bytes(pattern), bytes(mask), tail_crc, func_size


def _estimate_func_size(b: Binary, va: int) -> int:
    """Estimate function size by scanning for ret + padding."""
    insns = b.disasm(va, count=500, max_bytes=0x4000)
    if not insns:
        return 0
    last_ret_end = 0
    nop_run = 0
    for insn in insns:
        if insn.mnemonic in ("ret", "retn"):
            last_ret_end = insn.address + insn.size - va
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
    return last_ret_end if last_ret_end > 0 else (insns[-1].address + insns[-1].size - va)


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

class SignatureDB:
    """SQLite-backed signature database.

    Args:
        path: Filesystem path to the database file, or ":memory:".
    """

    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

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
            # Existing DB with compatible version -- nothing to create
            return

        self._conn.executescript(_SCHEMA_SQL)
        self._conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # -- Insertion ---------------------------------------------------------

    def add_byte_sig(
        self, *, name: str, pattern: bytes, mask: bytes,
        func_size: int, tail_crc: int,
        compiler: str = "", source: str = "", category: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO byte_sigs "
            "(name, pattern, mask, func_size, tail_crc, compiler, source, category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, pattern, mask, func_size, tail_crc, compiler, source, category),
        )
        self._conn.commit()

    def add_structural_sig(
        self, *, name: str, block_count: int, edge_count: int,
        call_count: int, mnemonic_hash: int, constants: str = "",
        compiler: str = "", source: str = "", category: str = "",
    ) -> None:
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
    ) -> list[Match]:
        """Find byte-pattern matches for *code* (first 32 bytes of function).

        Matching tiers:
          1. Masked byte comparison against all stored patterns.
          2. Size disambiguation: exact size match scores higher.
          3. Tail CRC disambiguation: matching tail_crc scores higher.
          4. Preferred compiler boost.
        """
        if len(code) < 32:
            return []
        code32 = code[:32]

        # TODO: Full-table scan. Add prefix index on first non-wildcarded
        # bytes when the database grows large enough to matter.
        cur = self._conn.execute(
            "SELECT name, pattern, mask, func_size, tail_crc, "
            "compiler, source, category FROM byte_sigs"
        )
        candidates: list[tuple[Match, float]] = []

        for name, pattern, mask, db_size, db_tail_crc, compiler, source, category in cur:
            if not _masked_eq(code32, pattern, mask):
                continue
            score = 0.7  # base confidence for byte match
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
    ) -> list[Match]:
        """Find structural matches by CFG shape and mnemonic hash.

        Requires exact mnemonic_hash match plus CFG shape (block_count,
        edge_count). call_count and constants refine the score.

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
    ) -> Match | None:
        """Identify a function by trying byte-exact, then structural fallback.

        Returns the best Match, or None.
        """
        # Tier 1: byte signature
        code = b.read_va(va, 64)
        if len(code) >= 32:
            func_size = _estimate_func_size(b, va)
            tail_offset = max(0, func_size - 32)
            tail_bytes = b.read_va(va + tail_offset, 32)
            tail_crc = zlib.crc32(tail_bytes) & 0xFFFFFFFF if tail_bytes else 0
            matches = self.match_bytes(code[:32], func_size, preferred_compiler, tail_crc)
            if matches:
                return matches[0]

        # Tier 2: structural signature
        sig = extract_structural_sig(b, va)
        if sig is not None:
            matches = self.match_structural(
                sig["block_count"], sig["edge_count"], sig["call_count"],
                sig["mnemonic_hash"], sig["constants"],
            )
            if matches:
                return matches[0]

        return None

    def scan(
        self, b: Binary, preferred_compiler: str = "",
    ) -> dict[int, Match]:
        """Bulk-scan all functions in the binary.

        Returns:
            Dict mapping function VA to best Match.
        """
        results: dict[int, Match] = {}
        for va in b.func_table:
            m = self.identify(b, va, preferred_compiler)
            if m is not None:
                results[va] = m
        return results

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

def build_from_manifest(db: SignatureDB, manifest: dict) -> None:
    """Ingest signatures from a JSON manifest.

    Manifest format::

        {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": "path/to/file.dll",
                    "map": "path/to/map.csv",
                    "compiler": "msvc"
                }
            ]
        }

    The CSV must have ``address`` and ``name`` columns.
    """
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

        with open(map_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                va = int(row["address"], 0)
                name = row["name"]
                category = _categorize_name(name)
                source_name = Path(binary_path).name

                # Byte sig
                bsig = extract_byte_sig(b, va)
                if bsig is not None:
                    pattern, mask, tail_crc, func_size = bsig
                    db.add_byte_sig(
                        name=name, pattern=pattern, mask=mask,
                        func_size=func_size, tail_crc=tail_crc,
                        compiler=compiler, source=source_name,
                        category=category,
                    )

                # Structural sig
                ssig = extract_structural_sig(b, va)
                if ssig is not None:
                    db.add_structural_sig(
                        name=name, compiler=compiler,
                        source=source_name, category=category,
                        **ssig,
                    )


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


def _pull_sources(repo: str, dest_dir: str) -> None:
    """Download source files listed in the HF repo's manifest.json."""
    manifest_url = _HF_URL_TEMPLATE.format(repo=repo, path="manifest.json")
    req = urllib.request.Request(manifest_url)
    with urllib.request.urlopen(req, timeout=60) as resp:
        manifest = json.loads(resp.read())

    for rel_path in manifest.get("sources", []):
        url = _HF_URL_TEMPLATE.format(repo=repo, path=rel_path)
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
                   help=f"HuggingFace dataset repo (default: {_HF_REPO_DEFAULT})")

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
        build_from_manifest(db, manifest)
        cur = db._conn.execute("SELECT COUNT(*) FROM byte_sigs")
        bc = cur.fetchone()[0]
        cur = db._conn.execute("SELECT COUNT(*) FROM structural_sigs")
        sc = cur.fetchone()[0]
        print(f"Built {args.output}: {bc} byte sigs, {sc} structural sigs")
        db.close()

    elif args.command == "scan":
        db = SignatureDB(args.db)
        b = Binary(args.binary)
        results = db.scan(b, args.compiler)
        w = 16 if b.is_64 else 8
        for va, m in sorted(results.items()):
            print(f"  0x{va:0{w}X}  {m.name:40s} "
                  f"{m.confidence:.0%} ({m.tier}) [{m.category}]")
        print(f"\n{len(results)} / {len(b.func_table)} functions identified")
        db.close()

    elif args.command == "identify":
        db = SignatureDB(args.db)
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
        db_url = _HF_URL_TEMPLATE.format(repo=args.repo, path="signatures.db")
        print(f"Downloading from {args.repo}...")
        _download_file(db_url, str(data_dir / "signatures.db"))
        if args.sources:
            _pull_sources(args.repo, str(data_dir / "sources"))
        print("Done.")


if __name__ == "__main__":
    main()
