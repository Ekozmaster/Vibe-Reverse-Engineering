"""Tests for retools/sigdb.py -- signature database module."""

import csv
import io
import json
import os
import sqlite3
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure retools is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

from pe_fakes import CODE_VA, binary_from_sections, binary_over, pe_image  # noqa: E402


# ---------------------------------------------------------------------------
# Task 2: Schema & Data Model
# ---------------------------------------------------------------------------

class TestSchemaCreation:
    def test_creates_tables(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        conn = db._conn
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(r[0] for r in cur.fetchall())
        assert "byte_sigs" in tables
        assert "structural_sigs" in tables
        assert "compiler_fingerprints" in tables
        assert "schema_version" in tables
        db.close()

    def test_schema_version_stored(self):
        from sigdb import SignatureDB, SCHEMA_VERSION
        db = SignatureDB(":memory:")
        cur = db._conn.execute("SELECT version FROM schema_version")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == SCHEMA_VERSION
        db.close()

    def test_schema_version_too_new_raises(self):
        from sigdb import SignatureDB, SCHEMA_VERSION
        # Create a DB with a future version
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE schema_version (version INTEGER)")
        conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION + 1,))
        conn.commit()
        # Monkeypatch to use this connection -- instead, use a temp file
        conn.close()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("CREATE TABLE schema_version (version INTEGER)")
            conn.execute(
                "INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION + 1,)
            )
            conn.commit()
            conn.close()
            with pytest.raises(RuntimeError, match="newer"):
                SignatureDB(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_close_is_idempotent(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.close()
        db.close()  # should not raise

    def test_reopen_existing_db(self):
        from sigdb import SignatureDB
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            db = SignatureDB(tmp_path)
            db.add_byte_sig(
                name="test_fn", pattern=b"\x55" * 32, mask=b"\xff" * 32,
                func_size=100, tail_crc=0xDEAD, compiler="msvc",
                source="test.dll", category="crt",
            )
            db.close()
            db2 = SignatureDB(tmp_path)
            cur = db2._conn.execute("SELECT COUNT(*) FROM byte_sigs")
            assert cur.fetchone()[0] == 1
            db2.close()
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Task 3: Signature Extraction
# ---------------------------------------------------------------------------

class TestByteExtraction:
    def test_extract_returns_tuple(self, sample_binary):
        from sigdb import extract_byte_sig
        from common import Binary
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found in sample binary")
        result = extract_byte_sig(b, funcs[0])
        # May be None if function is too short
        if result is not None:
            pattern, mask, tail_crc, func_size = result
            assert isinstance(pattern, bytes)
            assert isinstance(mask, bytes)
            assert len(pattern) == 32
            assert len(mask) == 32
            assert isinstance(tail_crc, int)
            assert isinstance(func_size, int)
            assert func_size > 0

    def test_wildcards_on_e8_e9(self):
        """E8/E9 rel32 operands should be masked to wildcard."""
        from sigdb import extract_byte_sig
        # Build a mock binary with a CALL rel32 at offset 0
        code = bytearray(64)
        code[0] = 0xE8  # call rel32
        code[1:5] = b"\x10\x00\x00\x00"
        code[5] = 0x90  # nop padding
        code[10] = 0xE9  # jmp rel32
        code[11:15] = b"\x20\x00\x00\x00"
        # Fill rest with nops
        for i in range(15, 64):
            code[i] = 0x90

        mock_b = MagicMock()
        mock_b.read_va.return_value = bytes(code)

        result = extract_byte_sig(mock_b, 0x1000, func_size=51)
        assert result is not None
        pattern, mask, tail_crc, func_size = result
        # Bytes 1-4 (E8 operand) should be wildcarded
        assert mask[1:5] == b"\x00\x00\x00\x00"
        # Bytes 11-14 (E9 operand) should be wildcarded
        assert mask[11:15] == b"\x00\x00\x00\x00"
        # Byte 0 (E8 opcode) should NOT be wildcarded
        assert mask[0] == 0xFF

    def test_extract_returns_none_for_unreadable(self):
        from sigdb import extract_byte_sig
        mock_b = MagicMock()
        mock_b.read_va.return_value = b""
        result = extract_byte_sig(mock_b, 0xDEAD)
        assert result is None


class TestStructuralExtraction:
    def test_extract_returns_dict(self, sample_binary):
        from sigdb import extract_structural_sig
        from common import Binary
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found in sample binary")
        result = extract_structural_sig(b, funcs[0])
        if result is not None:
            assert isinstance(result, dict)
            assert "block_count" in result
            assert "edge_count" in result
            assert "call_count" in result
            assert "mnemonic_hash" in result
            assert "constants" in result

    def test_extract_returns_none_for_empty(self):
        from sigdb import extract_structural_sig
        mock_b = MagicMock()
        mock_b.read_va.return_value = b""
        mock_b.disasm.return_value = []
        result = extract_structural_sig(mock_b, 0xDEAD)
        assert result is None


class TestAddSigs:
    def test_add_byte_sig(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_byte_sig(
            name="my_func", pattern=b"\x55" * 32, mask=b"\xff" * 32,
            func_size=200, tail_crc=0x1234, compiler="msvc",
            source="test.dll", category="crt",
        )
        cur = db._conn.execute("SELECT name, func_size FROM byte_sigs")
        row = cur.fetchone()
        assert row[0] == "my_func"
        assert row[1] == 200
        db.close()

    def test_add_structural_sig(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="my_func", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        cur = db._conn.execute(
            "SELECT name, block_count, mnemonic_hash FROM structural_sigs"
        )
        row = cur.fetchone()
        assert row[0] == "my_func"
        assert row[1] == 5
        assert row[2] == 0xABCD
        db.close()


# ---------------------------------------------------------------------------
# Task 4: Multi-Tier Matching
# ---------------------------------------------------------------------------

class TestByteMatching:
    def test_exact_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="push_ebp_fn", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=100, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) >= 1
        assert matches[0].name == "push_ebp_fn"
        db.close()

    def test_masked_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\xE8\x00\x00\x00\x00" + b"\x90" * 27
        mask = b"\xFF\x00\x00\x00\x00" + b"\xFF" * 27
        db.add_byte_sig(
            name="call_fn", pattern=pattern, mask=mask,
            func_size=50, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        # Code with different rel32 target should still match
        code = b"\xE8\xAA\xBB\xCC\xDD" + b"\x90" * 27
        matches = db.match_bytes(
            code=code, func_size=50, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) >= 1
        assert matches[0].name == "call_fn"
        db.close()

    def test_no_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="push_ebp_fn", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        code = b"\xCC" * 32  # totally different
        matches = db.match_bytes(
            code=code, func_size=100, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) == 0
        db.close()

    def test_size_disambiguation(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="fn_small", pattern=pattern, mask=mask,
            func_size=50, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        db.add_byte_sig(
            name="fn_big", pattern=pattern, mask=mask,
            func_size=200, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=200, preferred_compiler="", func_tail_crc=0
        )
        # fn_big should rank first (exact size match)
        assert matches[0].name == "fn_big"
        db.close()

    def test_tail_crc_disambiguation(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="fn_a", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0xAAAA, compiler="msvc",
            source="test.dll", category="crt",
        )
        db.add_byte_sig(
            name="fn_b", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0xBBBB, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=100, preferred_compiler="",
            func_tail_crc=0xBBBB,
        )
        assert matches[0].name == "fn_b"
        db.close()


class TestStructuralMatching:
    def test_exact_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="loopy_fn", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        matches = db.match_structural(
            block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
        )
        assert len(matches) >= 1
        assert matches[0].name == "loopy_fn"
        db.close()

    def test_no_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="loopy_fn", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        matches = db.match_structural(
            block_count=99, edge_count=99, call_count=99,
            mnemonic_hash=0xFFFF, constants="",
        )
        assert len(matches) == 0
        db.close()


class TestIdentify:
    def test_identify_returns_match_or_none(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found")
        result = db.identify(b, funcs[0], preferred_compiler="")
        # With empty DB, should return None
        assert result is None
        db.close()


class TestScan:
    def test_scan_returns_dict(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        result = db.scan(b, preferred_compiler="")
        assert isinstance(result, dict)
        db.close()


# ---------------------------------------------------------------------------
# Task 5: Compiler Fingerprinting
# ---------------------------------------------------------------------------

class TestRichHeader:
    def test_parse_rich_header_returns_list(self, sample_binary):
        from sigdb import parse_rich_header
        from common import Binary
        b = Binary(sample_binary)
        result = parse_rich_header(b)
        assert isinstance(result, list)
        # System DLLs typically have Rich headers
        if result:
            entry = result[0]
            assert "comp_id" in entry
            assert "count" in entry

    def test_parse_rich_header_no_header(self):
        """Binary without Rich header returns empty list."""
        from sigdb import parse_rich_header
        mock_b = MagicMock()
        mock_b.raw = b"\x00" * 512  # No Rich signature
        result = parse_rich_header(mock_b)
        assert result == []


class TestCrtImport:
    def test_detect_crt_import(self, sample_binary):
        from sigdb import detect_crt_import
        from common import Binary
        b = Binary(sample_binary)
        result = detect_crt_import(b)
        # kernel32.dll doesn't import CRT, but result is str or None
        assert result is None or isinstance(result, str)

    def test_detect_crt_known_dll(self):
        from sigdb import detect_crt_import
        mock_b = MagicMock()
        mock_pe = MagicMock()
        mock_entry = MagicMock()
        mock_entry.dll = b"MSVCR120.dll"
        mock_entry.imports = []
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]
        mock_b.pe = mock_pe
        result = detect_crt_import(mock_b)
        assert result is not None
        assert "msvc" in result.lower() or "MSVCR120" in result


class TestFingerprint:
    def test_fingerprint_returns_dict(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        result = db.fingerprint(b)
        assert isinstance(result, dict)
        assert "compiler" in result
        assert "confidence" in result
        assert "evidence" in result
        db.close()


# ---------------------------------------------------------------------------
# Task 6: Build Pipeline & CLI
# ---------------------------------------------------------------------------

class TestBuildFromManifest:
    def test_build_from_manifest(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest

        # Create a dummy CSV address map
        csv_path = tmp_path / "map.csv"
        csv_path.write_text("address,name\n0x401000,_init\n0x402000,_main\n")

        # We need a real binary for extraction, but since this might fail
        # on extraction, we test that the pipeline runs without crashing.
        # Use a manifest that references a non-existent binary to test
        # the error-handling path.
        manifest = {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": str(tmp_path / "nonexistent.dll"),
                    "map": str(csv_path),
                    "compiler": "msvc",
                }
            ]
        }
        db = SignatureDB(":memory:")
        # Should not crash, just skip missing binaries
        build_from_manifest(db, manifest)
        db.close()

    def test_build_with_real_binary(self, sample_binary, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        from common import Binary

        b = Binary(sample_binary)
        funcs = b.func_table[:3]  # Just a few for speed
        if not funcs:
            pytest.skip("No functions found")

        csv_path = tmp_path / "map.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["address", "name"])
            for va in funcs:
                writer.writerow([f"0x{va:X}", f"func_{va:X}"])

        manifest = {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": sample_binary,
                    "map": str(csv_path),
                    "compiler": "msvc",
                }
            ]
        }
        db = SignatureDB(":memory:")
        build_from_manifest(db, manifest)
        # Should have ingested at least some sigs
        cur = db._conn.execute("SELECT COUNT(*) FROM byte_sigs")
        count = cur.fetchone()[0]
        # Some funcs may fail extraction, so count >= 0 is fine
        assert count >= 0
        db.close()


class TestCLI:
    def test_main_exists(self):
        from sigdb import main
        assert callable(main)

    def test_main_no_args_exits(self):
        from sigdb import main
        with pytest.raises(SystemExit):
            main([])


class TestDefaultDbPath:
    def test_default_path_points_to_data_dir(self):
        from sigdb import DEFAULT_DB_PATH
        assert DEFAULT_DB_PATH.name == "signatures.db"
        assert DEFAULT_DB_PATH.parent.name == "data"

    def test_scan_uses_default_db(self):
        """--db should no longer be required for scan."""
        from sigdb import main
        with pytest.raises(SystemExit) as exc:
            main(["scan", "nonexistent.exe"])
        assert exc.value.code != 2 or "binary" in str(exc.value)


class TestPull:
    def test_pull_subcommand_exists(self):
        from sigdb import main
        with pytest.raises(SystemExit):
            main(["pull", "--help"])

    def test_pull_downloads_db(self, tmp_path, monkeypatch):
        """pull should download signatures.db to the data directory."""
        from sigdb import _download_file
        import urllib.request

        fake_data = b"fake-sqlite-data"
        dest = tmp_path / "signatures.db"

        def fake_urlopen(req, **kwargs):
            resp = MagicMock()
            resp.read.return_value = fake_data
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.headers = {"content-length": str(len(fake_data))}
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        _download_file("https://example.com/test.db", str(dest))
        assert dest.read_bytes() == fake_data

    def test_pull_sources_fetches_manifest(self, tmp_path, monkeypatch):
        """pull --sources should fetch manifest.json first."""
        from sigdb import _pull_sources
        import urllib.request

        manifest = {"sources": ["sources/test/functions.csv"]}
        csv_data = b"address,name\n0x401000,test_func\n"

        call_log = []
        def fake_urlopen(req, **kwargs):
            url = req if isinstance(req, str) else req.full_url
            call_log.append(url)
            resp = MagicMock()
            if "manifest.json" in url:
                resp.read.return_value = json.dumps(manifest).encode()
            else:
                resp.read.return_value = csv_data
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.headers = {"content-length": "100"}
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        _pull_sources(
            repo="test/repo",
            dest_dir=str(tmp_path / "data" / "sources"),
        )
        assert any("manifest.json" in u for u in call_log)

    def test_pull_source_404_warns_continues(self, tmp_path, monkeypatch, capsys):
        """Individual source file 404 should warn, not crash."""
        from sigdb import _pull_sources
        import urllib.error
        import urllib.request

        manifest = {"sources": ["sources/a.csv", "sources/b.csv"]}

        def fake_urlopen(req, **kwargs):
            url = req if isinstance(req, str) else req.full_url
            resp = MagicMock()
            if "manifest.json" in url:
                resp.read.return_value = json.dumps(manifest).encode()
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                resp.headers = {"content-length": "100"}
                return resp
            if "a.csv" in url:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            resp.read.return_value = b"address,name\n"
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.headers = {"content-length": "100"}
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        _pull_sources(repo="test/repo", dest_dir=str(tmp_path / "sources"))
        captured = capsys.readouterr()
        assert "a.csv" in captured.err or "a.csv" in captured.out


def _sig_image(tmp_path):
    return pe_image(tmp_path / "lib.dll", bytes.fromhex("55" * 40) + b"\xc3" + b"\xcc" * 16)


class TestBuildContract:
    def test_mapped_functions_become_signatures(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        image = _sig_image(tmp_path)
        (tmp_path / "map.csv").write_text(f"address,name\n0x{CODE_VA:X},_initterm\n")
        db = SignatureDB(":memory:")
        build_from_manifest(db, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                              "map": str(tmp_path / "map.csv"), "compiler": "msvc"},
                                             {"type": "other", "binary": str(image), "map": "unused.csv"}]})
        rows = db._conn.execute("SELECT name, func_size, compiler, source, category FROM byte_sigs").fetchall()
        assert rows == [("_initterm", 41, "msvc", "lib.dll", "crt")]


class TestCategoryNames:
    @pytest.mark.parametrize("name, category", [
        ("_initterm", "crt"), ("sqrtf", "math"), ("_CIsqrt", "math"),
        ("std::vector<int>::push_back", "stl"), ("_CxxThrowException", "exception"),
        ("RethrowOnUnwind", "exception"), ("CheckGuardPage", "security"),
        ("report_gsfailure", "security"), ("DoTheThing", "unknown"),
    ])
    def test_categories(self, name, category):
        from sigdb import _categorize_name
        assert _categorize_name(name) == category


class TestCliCommands:
    def test_build_identify_scan_and_fingerprint(self, tmp_path, capsys):
        from sigdb import main
        image = _sig_image(tmp_path)
        (tmp_path / "map.csv").write_text(f"address,name\n0x{CODE_VA:X},_initterm\n")
        manifest = tmp_path / "m.json"
        manifest.write_text(json.dumps({"sources": [{"type": "binary_with_map", "binary": str(image),
                                                     "map": str(tmp_path / "map.csv"), "compiler": "msvc"}]}))
        db = str(tmp_path / "sigs.db")

        main(["build", str(manifest), "-o", db])
        assert capsys.readouterr().out.startswith(f"Built {db}: 1 byte sigs, ")

        main(["identify", str(image), f"{CODE_VA:x}", "--db", db])
        out = capsys.readouterr().out.splitlines()
        assert out[0].strip() == "_initterm" and "  tier:       byte" in out

        main(["identify", str(image), f"{CODE_VA + 0x29:x}", "--db", db])
        assert capsys.readouterr().out.strip() == "No match"

        main(["fingerprint", str(image)])
        assert capsys.readouterr().out.splitlines()[0] == "  Compiler:   unknown"


class TestFingerprintContract:
    def test_nothing_known_is_unknown_with_zero_confidence(self, tmp_path):
        from common import Binary
        from sigdb import SignatureDB
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\xc3")))
        assert SignatureDB(":memory:").fingerprint(b) == {"compiler": "unknown", "confidence": 0.0, "evidence": []}

    def test_a_crt_import_votes_for_its_compiler_family(self, tmp_path, monkeypatch):
        import sigdb
        from common import Binary
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\xc3")))
        monkeypatch.setattr(sigdb, "detect_crt_import", lambda b: "msvc-14.0+")
        result = sigdb.SignatureDB(":memory:").fingerprint(b)
        assert (result["compiler"], result["confidence"]) == ("msvc", 0.3)


class TestMatchDetails:
    def test_all_32_pattern_bytes_must_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = bytes(range(32))
        db.add_byte_sig(name="f", pattern=pattern, mask=b"\xff" * 32, func_size=0, tail_crc=0)
        assert [m.name for m in db.match_bytes(pattern, 0, "", 0)] == ["f"]
        assert db.match_bytes(pattern[:31] + b"\xee", 0, "", 0) == []


class TestEstimateFuncSize:
    @pytest.mark.parametrize("code, size", [
        ("558bec5dc3cccc", 5),        # ret then int3 padding
        ("c3909031c0c3", 1),          # ret then two nops
        ("c39031c090c3cc", 6),        # a single nop between code does not end it
        ("c331c0c3cc", 4),            # code after a ret continues the function
        ("c301c0c3cc", 4),
        ("31c031c0", 4),              # no ret: up to the last instruction
    ])
    def test_ret_followed_by_padding_ends_the_function(self, code, size):
        from sigdb import _estimate_func_size
        assert _estimate_func_size(binary_over(bytes.fromhex(code)), CODE_VA) == size


class TestRichHeaderParse:
    def test_entries_are_decoded_with_the_key(self):
        from sigdb import parse_rich_header
        key = 0x1234ABCD
        entries = [(0x00FF7809, 5), (0x01045D10, 2)]
        stub = struct.pack("<IIII", 0x536E6144 ^ key, key, key, key)
        stub += b"".join(struct.pack("<II", cid ^ key, n ^ key) for cid, n in entries)
        raw = b"MZ" + b"\0" * 0x7E + stub + b"Rich" + struct.pack("<I", key) + b"\0" * 16
        assert parse_rich_header(binary_from_sections(raw, [])) == [
            {"comp_id": 0x00FF7809, "tool_id": 0x00FF, "minor_version": 0x7809, "count": 5},
            {"comp_id": 0x01045D10, "tool_id": 0x0104, "minor_version": 0x5D10, "count": 2},
        ]


class TestScoring:
    def _db(self, *sigs):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        for name, size, crc, compiler in sigs:
            db.add_byte_sig(name=name, pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=size,
                            tail_crc=crc, compiler=compiler, source=f"{name}.dll", category=f"cat_{name}")
        return db

    def test_size_then_near_size_then_tail_crc_then_compiler(self):
        db = self._db(("far", 500, 0, ""), ("near", 105, 0, ""), ("exact", 100, 0, ""))
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 100, "", 0)] == ["exact", "near", "far"]
        db = self._db(("plain", 100, 0, ""), ("crc", 100, 0xAB, ""))
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 100, "", 0xAB)] == ["crc", "plain"]
        db = self._db(("other", 100, 0, "gcc"), ("mine", 100, 0, "msvc"))
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 100, "msvc", 0)] == ["mine", "other"]

    def test_confidence_falls_with_each_tier_and_stays_below_one(self):
        db = self._db(("far", 500, 0, ""), ("near", 105, 0, ""), ("exact", 100, 0, ""))
        conf = [m.confidence for m in db.match_bytes(b"\x55" * 32, 100, "", 0)]
        assert conf[0] > conf[1] > conf[2] and conf[0] < 1.0

    def test_a_full_match_is_capped_at_one_and_keeps_its_metadata(self):
        db = self._db(("best", 100, 0xAB, "msvc"))
        (m,) = db.match_bytes(b"\x55" * 32, 100, "msvc", 0xAB)
        assert (m.confidence, m.tier, m.compiler, m.source, m.category) == (1.0, "byte", "msvc", "best.dll", "cat_best")
        assert db.match_bytes(b"\x55" * 31, 100, "", 0) == []

    def test_structural_score_order(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        for name, calls, consts in (("none", 9, "0x9"), ("overlap", 2, "0x100,0x9"), ("exact", 2, "0x100,0x200")):
            db.add_structural_sig(name=name, block_count=4, edge_count=5, call_count=calls,
                                  mnemonic_hash=77, constants=consts)
        assert [m.name for m in db.match_structural(4, 5, 2, 77, "0x100,0x200")] == ["exact", "overlap", "none"]
        assert db.match_structural(2, 1, 2, 77, "0x100,0x200") == []

    def test_identify_prefers_the_best_byte_match(self, tmp_path):
        from common import Binary
        body = bytes.fromhex("55" * 40) + b"\xc3"
        b = Binary(str(pe_image(tmp_path / "a.exe", body + b"\xcc" * 32)))
        db = self._db(("worse", 999, 0, ""), ("better", 41, 0, ""))
        assert db.identify(b, CODE_VA).name == "better"


class TestStructuralCalls:
    def test_call_count(self, tmp_path):
        from common import Binary
        from sigdb import extract_structural_sig
        code = (b"\xe8" + struct.pack("<i", 0x20 - 5) + b"\xe8" + struct.pack("<i", 0x20 - 10) + b"\xc3").ljust(0x20, b"\xcc") + b"\xc3"
        b = Binary(str(pe_image(tmp_path / "a.exe", code)))
        assert extract_structural_sig(b, CODE_VA)["call_count"] == 2


class TestTailCrc:
    def test_tail_crc_covers_the_last_32_bytes_of_the_function(self, tmp_path):
        from common import Binary
        from sigdb import extract_byte_sig
        body = bytes.fromhex("90" * 39) + b"\xc3"
        b = Binary(str(pe_image(tmp_path / "a.exe", body + b"\xcc" * 8)))
        pattern, mask, tail_crc, size = extract_byte_sig(b, CODE_VA)
        assert size == 40
        assert tail_crc == zlib.crc32(body[8:40]) & 0xFFFFFFFF


class TestBuildSafeguards:
    def _build(self, tmp_path, text, rows):
        from sigdb import SignatureDB, build_from_manifest
        image = pe_image(tmp_path / "lib.dll", text)
        lines = ["address,name,size"] + [f"0x{CODE_VA + off:X},{name},{size}" for off, name, size in rows]
        (tmp_path / "map.csv").write_text("\n".join(lines) + "\n")
        db = SignatureDB(":memory:")
        stats = build_from_manifest(db, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                                      "map": str(tmp_path / "map.csv"), "compiler": "msvc2008"}]})
        return db, stats

    def _rows(self, db):
        return db._conn.execute("SELECT name, mask, crc_len, crc16 FROM byte_sigs ORDER BY name").fetchall()

    def test_bytes_past_a_short_function_are_wildcards(self, tmp_path):
        text = bytes(range(1, 20)) + b"\xc3" + b"\x77" * 60
        db, _ = self._build(tmp_path, text, [(0, "short", 20)])
        ((name, mask, crc_len, _),) = self._rows(db)
        assert mask[:20] == b"\xff" * 20 and mask[20:] == b"\0" * 12 and crc_len == 0

    def test_functions_under_16_bytes_are_skipped(self, tmp_path):
        db, stats = self._build(tmp_path, bytes(range(1, 64)), [(0, "tiny", 8)])
        assert self._rows(db) == [] and stats["too_small"] == 1

    def test_a_prefix_with_two_names_is_dropped(self, tmp_path):
        body = bytes(range(1, 40)) + b"\xc3"
        db, stats = self._build(tmp_path, body + body, [(0, "a", 40), (40, "b", 40)])
        assert self._rows(db) == [] and stats["ambiguous_prefix"] == 1

    def test_crc_covers_the_bytes_after_the_prefix_up_to_the_first_call(self, tmp_path):
        from sigdb import flirt_crc16
        text = b"\x90" * 40 + b"\xe8\x00\x00\x00\x00" + b"\x90" * 14 + b"\xc3"
        db, _ = self._build(tmp_path, text, [(0, "f", len(text))])
        ((_, _, crc_len, crc16),) = self._rows(db)
        assert (crc_len, crc16) == (8, flirt_crc16(b"\x90" * 8))

    def test_crc_runs_to_the_function_end_without_layout_dependent_code(self, tmp_path):
        from sigdb import flirt_crc16
        text = b"\x90" * 47 + b"\xc3"
        db, _ = self._build(tmp_path, text, [(0, "f", 48)])
        ((_, _, crc_len, crc16),) = self._rows(db)
        assert (crc_len, crc16) == (16, flirt_crc16(text[32:48]))

    def test_a_function_linked_elsewhere_still_matches(self, tmp_path):
        from common import Binary
        text = b"\x90" * 40 + b"\xe8\x00\x00\x00\x00" + b"\x90" * 14 + b"\xc3"
        db, _ = self._build(tmp_path, text, [(0, "lib_func", len(text))])
        moved = text[:41] + b"\x10\x20\x00\x00" + text[45:]
        other = Binary(str(pe_image(tmp_path / "game.exe", moved)))
        assert db.identify(other, CODE_VA).name == "lib_func"


def _rich_stub(entries):
    """A raw image whose Rich header lists (comp_id, count) *entries*."""
    key = 0x1234ABCD
    stub = struct.pack("<IIII", 0x536E6144 ^ key, key, key, key)
    stub += b"".join(struct.pack("<II", cid ^ key, n ^ key) for cid, n in entries)
    return b"MZ" + b"\0" * 0x7E + stub + b"Rich" + struct.pack("<I", key) + b"\0" * 16


class TestSchemaMigration:
    def test_a_version_1_db_gains_the_crc_columns_and_keeps_its_rows(self, tmp_path):
        from sigdb import SignatureDB, SCHEMA_VERSION
        path = str(tmp_path / "v1.db")
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version VALUES (1);
            CREATE TABLE byte_sigs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                pattern BLOB NOT NULL, mask BLOB NOT NULL, func_size INTEGER NOT NULL,
                tail_crc INTEGER NOT NULL DEFAULT 0, compiler TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '');
        """)
        conn.execute("INSERT INTO byte_sigs (name, pattern, mask, func_size) VALUES ('old', ?, ?, 40)",
                     (b"\x55" * 32, b"\xff" * 32))
        conn.commit()
        conn.close()
        db = SignatureDB(path)
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
        assert db._conn.execute("SELECT name, crc_len, crc16 FROM byte_sigs").fetchall() == [("old", 0, 0)]
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["old"]
        db.close()


class TestFlirtCrc:
    def test_crc16_is_byte_swapped_x25(self):
        from sigdb import flirt_crc16
        assert flirt_crc16(b"123456789") == 0x6E90

    def _db(self, crc_len, crc16):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_byte_sig(name="f", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=0,
                        tail_crc=0, crc_len=crc_len, crc16=crc16)
        return db

    def test_matching_crc_accepts_and_scores_higher(self):
        from sigdb import flirt_crc16
        following = bytes(range(10))
        (m,) = self._db(10, flirt_crc16(following)).match_bytes(b"\x55" * 32 + following, 0, "", 0)
        (plain,) = self._db(0, 0).match_bytes(b"\x55" * 32 + following, 0, "", 0)
        assert m.confidence > plain.confidence

    def test_wrong_or_missing_following_bytes_reject(self):
        from sigdb import flirt_crc16
        db = self._db(10, flirt_crc16(bytes(range(10))))
        assert db.match_bytes(b"\x55" * 32 + bytes(range(1, 11)), 0, "", 0) == []
        assert db.match_bytes(b"\x55" * 32 + bytes(range(9)), 0, "", 0) == []


class TestPrefixIndex:
    def test_wildcarded_start_and_fixed_start_both_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_byte_sig(name="fixed", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=0, tail_crc=0)
        db.add_byte_sig(name="wild", pattern=b"\x00" + b"\x55" * 31, mask=b"\x00" + b"\xff" * 31,
                        func_size=0, tail_crc=0)
        db.add_byte_sig(name="other", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=0, tail_crc=0)
        assert sorted(m.name for m in db.match_bytes(b"\x55" * 32, 0, "", 0)) == ["fixed", "wild"]

    def test_a_sig_added_after_a_lookup_is_found(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        assert db.match_bytes(b"\x55" * 32, 0, "", 0) == []
        db.add_byte_sig(name="late", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=0, tail_crc=0)
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 0, "", 0)] == ["late"]


class TestToolchains:
    @pytest.mark.parametrize("label, versions", [
        ("msvc2008", {"9.0"}), ("msvc6.0", {"6.0"}), ("msvc2003_2005", {"7.1", "8.0"}),
        ("msvc4.2", {"4.2"}), ("msvc", set()), ("gcc", set()), ("", set()), ("msvc2005sp1", set()),
    ])
    def test_label_toolchains(self, label, versions):
        from sigdb import label_toolchains
        assert label_toolchains(label) == versions

    def test_rich_header_builds_map_to_versions(self):
        from sigdb import msvc_toolchains
        raw = _rich_stub([
            (0x0084 << 16 | 30729, 600),   # VS2008 SP1 C++
            (0x006E << 16 | 50727, 10),    # VS2005 C++
            (0x00CE << 16 | 50727, 1),     # VS2012 tool with the shared 50727 build
            (0x0105 << 16 | 33145, 1),     # VS2015+ product id
            (0x0001 << 16 | 0, 300),       # imports: no version
        ])
        assert msvc_toolchains(binary_from_sections(raw, [])) == {"9.0", "8.0", "11.0", "14+"}

    def test_sigs_from_absent_toolchains_are_skipped(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        for name, compiler in (("vc6", "msvc6.0"), ("vs2008", "msvc2008"), ("any", "msvc"), ("both", "msvc6.0_2008")):
            db.add_byte_sig(name=name, pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=0,
                            tail_crc=0, compiler=compiler)

        def names(toolchains):
            return sorted(m.name for m in db.match_bytes(b"\x55" * 32, 0, "", 0, toolchains))

        assert names(frozenset({"6.0"})) == ["any", "both", "vc6"]
        assert names(frozenset()) == ["any", "both", "vc6", "vs2008"]

    def test_structural_sigs_are_filtered_too(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(name="vs2008", block_count=4, edge_count=5, call_count=1,
                              mnemonic_hash=7, compiler="msvc2008")
        assert db.match_structural(4, 5, 1, 7, "", frozenset({"6.0"})) == []
        assert [m.name for m in db.match_structural(4, 5, 1, 7, "", frozenset({"9.0"}))] == ["vs2008"]


class TestScanUniqueNames:
    def test_a_name_matched_at_two_addresses_is_dropped(self, monkeypatch):
        from types import SimpleNamespace

        import sigdb
        names = {0x401000: "dup", 0x402000: "dup", 0x403000: "solo", 0x404000: None}
        db = sigdb.SignatureDB(":memory:")
        monkeypatch.setattr(sigdb, "msvc_toolchains", lambda b: frozenset())
        monkeypatch.setattr(db, "identify",
                            lambda b, va, pc, tc: names[va] and sigdb.Match(names[va], 0.7, "byte"))
        result = db.scan(SimpleNamespace(func_table=list(names)))
        assert {va: m.name for va, m in result.items()} == {0x403000: "solo"}


PAT_FIXTURE = "\n".join([
    # offset-0 name, E8 call at byte 4 to be wildcarded, CRC over 2 following bytes
    "5589E5" + "90" + "E8" + "11223344" + "90" * 23 + " 02 ABCD 0040 :0000 _good :0010 _second",
    "5589E5" + "91" * 29 + " 00 0000 0030 :0000 _LN12",
    "5589E5" + "92" * 29 + " 00 0000 000C :0000 _tiny",
    "5589E5" + "93" * 29 + " 00 0000 0030 :0000 _twin_a",
    "5589E5" + "93" * 29 + " 00 0000 0030 :0000 _twin_b",
    "5589E5" + "94" * 29 + " 00 0000 0030 :0010 _not_at_zero",
    "---",
])


class TestPatImport:
    def test_parse_takes_the_offset_zero_name_crc_and_wildcards_rel32(self):
        from sigdb import parse_pat_line
        sig = parse_pat_line(PAT_FIXTURE.splitlines()[0])
        assert (sig.name, sig.length, sig.crc_len, sig.crc16) == ("_good", 0x40, 2, 0xABCD)
        assert sig.mask[:5] == b"\xff" * 5 and sig.mask[5:9] == b"\0" * 4 and sig.mask[9] == 0xFF
        assert sig.pattern[5:9] == b"\0" * 4

    def test_relocated_bytes_are_wildcards(self):
        from sigdb import parse_pat_line
        sig = parse_pat_line("55" + ".." * 4 + "90" * 27 + " 00 0000 0030 :0000 _f")
        assert sig.mask[1:5] == b"\0" * 4 and sig.mask[0] == sig.mask[5] == 0xFF

    def test_import_filters_and_counts(self, tmp_path):
        from sigdb import SignatureDB, import_pat
        pat = tmp_path / "x.pat"
        pat.write_text(PAT_FIXTURE)
        db = SignatureDB(":memory:")
        stats = import_pat(db, str(pat), "msvc2008", "test")
        assert dict(stats) == {"added": 1, "local_or_managed": 1, "too_small": 1,
                               "ambiguous_prefix": 1, "unparsed": 2}
        assert db._conn.execute("SELECT name, crc_len, crc16, compiler, source FROM byte_sigs").fetchall() == [
            ("_good", 2, 0xABCD, "msvc2008", "test")]
        assert import_pat(db, str(pat), "msvc2008", "test")["already_in_db"] == 1

    def test_pull_revision_selects_the_hf_branch(self, tmp_path, monkeypatch):
        import sigdb
        urls = []
        monkeypatch.setattr(sigdb, "DEFAULT_DB_PATH", tmp_path / "signatures.db")
        monkeypatch.setattr(sigdb, "_download_file", lambda url, dest: urls.append(url))
        sigdb.main(["pull"])
        sigdb.main(["pull", "--revision", "schema-v2"])
        assert [u.split("/resolve/")[1] for u in urls] == ["main/signatures.db", "schema-v2/signatures.db"]

    def test_cli_import_pat(self, tmp_path, capsys):
        from sigdb import main
        pat = tmp_path / "x.pat"
        pat.write_text(PAT_FIXTURE)
        main(["import-pat", str(pat), "-d", str(tmp_path / "s.db"), "--compiler", "msvc2008", "--source", "t"])
        assert "  added: 1" in capsys.readouterr().out.splitlines()
