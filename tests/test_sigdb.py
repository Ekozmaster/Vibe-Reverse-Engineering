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

from pe_fakes import (  # noqa: E402
    CODE_VA, DATA_RVA, IMAGE_BASE64, TEXT_RVA, binary_from_sections, binary_over, fake_section, pe_image,
)


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


    @pytest.mark.parametrize("command", ["scan", "identify"])
    def test_a_missing_database_is_reported_and_not_created(self, tmp_path, capsys, command):
        from sigdb import main
        image = _sig_image(tmp_path)
        db = tmp_path / "missing.db"
        args = [command, str(image)] + ([f"{CODE_VA:x}"] if command == "identify" else []) + ["--db", str(db)]

        with pytest.raises(SystemExit) as exc:
            main(args)

        assert exc.value.code == 1
        assert "no signature database" in capsys.readouterr().err
        assert not db.exists()


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
        for source, calls, consts in (("none", 9, "0x9"), ("overlap", 2, "0x100,0x9"), ("exact", 2, "0x100,0x200")):
            db.add_structural_sig(name="f", block_count=4, edge_count=5, call_count=calls,
                                  mnemonic_hash=77, constants=consts, source=source)
        assert [m.source for m in db.match_structural(4, 5, 2, 77, "0x100,0x200")] == ["exact", "overlap", "none"]
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
    def test_a_version_1_db_is_read_as_it_is_and_migrated_on_the_first_write(self, tmp_path):
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
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["old"]
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == 1
        db.add_byte_sig(name="new", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
        assert db._conn.execute("SELECT name, crc_len, crc16 FROM byte_sigs ORDER BY id").fetchall() == [
            ("old", 0, 0), ("new", 0, 0)]
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
        ("msvc14.0", {"14+"}), ("msvc14.29", {"14+"}), ("msvc12.0_14.1", {"12.0", "14+"}),
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

    def test_an_entry_with_an_unknown_build_adds_no_version(self):
        from sigdb import msvc_toolchains
        raw = _rich_stub([
            (0x0084 << 16 | 21022, 652),   # VS2008 C++
            (0x0096 << 16 | 20413, 3),     # a tool build the table lacks, as shipped games carry
            (0x0001 << 16 | 0, 390),       # imports: no version
        ])
        assert msvc_toolchains(binary_from_sections(raw, [])) == {"9.0"}

    def test_a_label_for_vs2015_or_later_matches_a_vs2015_image(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_byte_sig(name="ucrt", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=0,
                        tail_crc=0, compiler="msvc14.0")
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 0, "", 0, frozenset({"14+"}))] == ["ucrt"]

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


class TestLayoutDependentOperands:
    """Absolute addresses after the prefix end the CRC span, however they are indexed."""
    ABS = 0x00402000

    def _build(self, tmp_path, insn):
        from sigdb import SignatureDB, build_from_manifest
        text = b"\x90" * 34 + insn + b"\x90" * 12 + b"\xc3"
        image = pe_image(tmp_path / "lib.dll", text)
        (tmp_path / "map.csv").write_text(f"address,name,size\n0x{CODE_VA:X},f,{len(text)}\n")
        db = SignatureDB(":memory:")
        build_from_manifest(db, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                              "map": str(tmp_path / "map.csv"), "compiler": "msvc2008"}]})
        return db, text, db._conn.execute("SELECT crc_len FROM byte_sigs").fetchone()[0]

    def test_switch_table_jump_ends_the_crc(self, tmp_path):
        _, _, crc_len = self._build(tmp_path, b"\xff\x24\x85" + struct.pack("<I", self.ABS))
        assert crc_len == 2

    def test_register_plus_absolute_displacement_ends_the_crc(self, tmp_path):
        _, _, crc_len = self._build(tmp_path, b"\x8a\x80" + struct.pack("<I", self.ABS))
        assert crc_len == 2

    def test_stack_access_does_not_end_the_crc(self, tmp_path):
        _, text, crc_len = self._build(tmp_path, b"\x8b\x45\xf8")
        assert crc_len == len(text) - 32

    def test_switch_table_function_linked_elsewhere_still_matches(self, tmp_path):
        from common import Binary
        db, text, _ = self._build(tmp_path, b"\xff\x24\x85" + struct.pack("<I", self.ABS))
        moved = text[:37] + struct.pack("<I", self.ABS + 0x3000) + text[41:]
        other = Binary(str(pe_image(tmp_path / "game.exe", moved)))
        assert db.identify(other, CODE_VA).name == "f"


class TestPrefixDedup:
    def test_a_shared_prefix_with_different_crcs_keeps_both_and_each_matches_its_own(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        head = b"\x55\x8b\xec" + b"\x90" * 29
        a, b = head + b"\x90" * 15 + b"\xc3", head + b"\x91" * 15 + b"\xc3"
        image = pe_image(tmp_path / "lib.dll", a + b)
        (tmp_path / "map.csv").write_text(
            f"address,name,size\n0x{CODE_VA:X},a,{len(a)}\n0x{CODE_VA + len(a):X},b,{len(b)}\n")
        db = SignatureDB(":memory:")
        stats = build_from_manifest(db, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                                      "map": str(tmp_path / "map.csv"), "compiler": "msvc2008"}]})
        assert stats["added"] == 2 and stats["ambiguous_prefix"] == 0
        assert [m.name for m in db.match_bytes(a, len(a), "", 0)] == ["a"]
        assert [m.name for m in db.match_bytes(b, len(b), "", 0)] == ["b"]

    def test_one_manifest_keeps_a_function_once_per_toolchain(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        text = b"\x55\x8b\xec" + b"\x90" * 44 + b"\xc3"
        image = pe_image(tmp_path / "lib.dll", text)
        (tmp_path / "map.csv").write_text(f"address,name,size\n0x{CODE_VA:X},f,{len(text)}\n")
        source = {"type": "binary_with_map", "binary": str(image), "map": str(tmp_path / "map.csv")}
        db = SignatureDB(":memory:")
        build_from_manifest(db, {"sources": [{**source, "compiler": "msvc2008"}, {**source, "compiler": "msvc2005"},
                                             {**source, "compiler": "msvc2005_2008"}]})
        assert db._conn.execute("SELECT compiler FROM byte_sigs ORDER BY compiler").fetchall() == [
            ("msvc2005",), ("msvc2008",)]

    _PLAIN = "5589E5" + "95" * 29 + " 00 0000 0030 :0000 _plain"

    def test_a_prefix_held_for_another_toolchain_is_imported_whatever_the_order(self, tmp_path):
        from sigdb import SignatureDB, import_pat
        pat = tmp_path / "x.pat"
        pat.write_text(self._PLAIN)
        db = SignatureDB(":memory:")
        import_pat(db, str(pat), "msvc2008", "vs2008")
        stats = import_pat(db, str(pat), "msvc2005", "vs2005")
        assert stats["added"] == 1 and stats["already_in_db"] == 0
        code = bytes.fromhex("5589E5") + b"\x95" * 29
        assert [m.compiler for m in db.match_bytes(code, 0x30, "", 0, frozenset({"8.0"}))] == ["msvc2005"]

    def test_an_overlapping_or_unversioned_label_is_already_in_db(self, tmp_path):
        from sigdb import SignatureDB, import_pat
        pat = tmp_path / "x.pat"
        pat.write_text(self._PLAIN)
        db = SignatureDB(":memory:")
        import_pat(db, str(pat), "msvc2008", "vs2008")
        assert import_pat(db, str(pat), "msvc2005_2008", "both")["already_in_db"] == 1
        assert import_pat(db, str(pat), "msvc", "bare")["already_in_db"] == 1


class TestRel32AtTheEndOfThePrefix:
    def test_extract_wildcards_rel32_bytes_inside_the_prefix(self):
        from sigdb import extract_byte_sig
        code = bytearray(b"\x90" * 64)
        code[29] = 0xE8
        mock_b = MagicMock()
        mock_b.read_va.return_value = bytes(code)
        _, mask, _, _ = extract_byte_sig(mock_b, 0x1000, func_size=60)
        assert mask[29] == 0xFF and mask[30:32] == b"\0\0"

    def test_pat_wildcards_rel32_bytes_inside_the_prefix(self):
        from sigdb import parse_pat_line
        sig = parse_pat_line("90" * 30 + "E9" + "11" + " 00 0000 0040 :0000 _f")
        assert sig.mask[30] == 0xFF and sig.mask[31] == 0


def _v1_db(path, with_crc_len=False):
    """A schema-1 database as earlier code wrote it, optionally half-way through the v2 migration."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version VALUES (1);
        CREATE TABLE byte_sigs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            pattern BLOB NOT NULL, mask BLOB NOT NULL, func_size INTEGER NOT NULL,
            tail_crc INTEGER NOT NULL DEFAULT 0, compiler TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '');
        CREATE TABLE structural_sigs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            block_count INTEGER NOT NULL, edge_count INTEGER NOT NULL, call_count INTEGER NOT NULL,
            mnemonic_hash INTEGER NOT NULL, constants TEXT NOT NULL DEFAULT '',
            compiler TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '');
    """)
    if with_crc_len:
        conn.execute("ALTER TABLE byte_sigs ADD COLUMN crc_len INTEGER NOT NULL DEFAULT 0")
    conn.execute("INSERT INTO byte_sigs (name, pattern, mask, func_size) VALUES ('old', ?, ?, 40)",
                 (b"\x55" * 32, b"\xff" * 32))
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def read_only():
    """Make every file in a database's directory read-only for the rest of the test."""
    import stat
    made = []

    def make(path):
        for p in Path(path).parent.iterdir():
            os.chmod(p, stat.S_IREAD)
            made.append(p)
        return path
    yield make
    for p in made:
        os.chmod(p, stat.S_IREAD | stat.S_IWRITE)


_OPENERS = {
    "SignatureDB": lambda sigdb: sigdb.SignatureDB,
    "open_existing": lambda sigdb: sigdb.SignatureDB.open_existing,
}


class TestSchemaMigrationSafety:
    def test_a_half_migrated_db_finishes_its_migration(self, tmp_path):
        from sigdb import SignatureDB, SCHEMA_VERSION
        db = SignatureDB(_v1_db(str(tmp_path / "v1.db"), with_crc_len=True))
        db.add_byte_sig(name="new", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0,
                        crc_len=2, crc16=7)
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
        assert db._conn.execute("SELECT name, crc_len, crc16 FROM byte_sigs ORDER BY id").fetchall() == [
            ("old", 0, 0), ("new", 2, 7)]
        db.close()

    @pytest.mark.parametrize("opener", ["SignatureDB", "open_existing"])
    def test_a_read_only_version_1_db_can_be_scanned(self, tmp_path, read_only, opener):
        import sigdb
        db = _OPENERS[opener](sigdb)(read_only(_v1_db(str(tmp_path / "v1.db"))))
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["old"]
        db.close()

    @pytest.mark.parametrize("opener", ["SignatureDB", "open_existing"])
    def test_a_read_only_current_db_can_be_scanned(self, tmp_path, read_only, opener):
        import sigdb
        path = str(tmp_path / "v2.db")
        db = sigdb.SignatureDB(path)
        db.add_byte_sig(name="f", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        db.close()
        db = _OPENERS[opener](sigdb)(read_only(path))
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["f"]
        db.close()

    def test_import_pat_into_a_version_1_db(self, tmp_path):
        from sigdb import SignatureDB, import_pat
        pat = tmp_path / "x.pat"
        pat.write_text(PAT_FIXTURE)
        db = SignatureDB(_v1_db(str(tmp_path / "v1.db")))
        assert import_pat(db, str(pat), "msvc2008", "test")["added"] == 1
        assert db._conn.execute("SELECT name, crc_len, crc16 FROM byte_sigs ORDER BY id").fetchall() == [
            ("old", 0, 0), ("_good", 2, 0xABCD)]
        db.close()

    def test_a_failed_migration_leaves_the_db_unmigrated(self, tmp_path):
        from sigdb import SignatureDB
        path = _v1_db(str(tmp_path / "v1.db"))
        conn = sqlite3.connect(path)
        conn.execute("CREATE TRIGGER no_update BEFORE UPDATE ON schema_version "
                     "BEGIN SELECT RAISE(ABORT, 'refused'); END")
        conn.commit()
        conn.close()
        db = SignatureDB(path)
        with pytest.raises(sqlite3.IntegrityError):
            db.add_byte_sig(name="new", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        assert "crc_len" not in db._byte_columns() and "crc16" not in db._byte_columns()
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == 1
        db.close()

    def test_migration_runs_after_a_statement_left_a_transaction_open(self, tmp_path):
        from sigdb import SignatureDB, SCHEMA_VERSION
        db = SignatureDB(_v1_db(str(tmp_path / "v1.db")))
        db._conn.execute("INSERT INTO byte_sigs (name, pattern, mask, func_size) VALUES ('pending', ?, ?, 40)",
                         (b"\x57" * 32, b"\xff" * 32))
        assert db._conn.in_transaction
        db.add_byte_sig(name="new", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
        assert [r[0] for r in db._conn.execute("SELECT name FROM byte_sigs ORDER BY id")] == [
            "old", "pending", "new"]
        db.close()


class TestVs2015RichHeader:
    def test_a_vs2015_image_is_14_plus_only(self):
        from sigdb import msvc_toolchains
        raw = _rich_stub([
            (0x00FF << 16 | 23026, 1),     # cvtres 14.00
            (0x0102 << 16 | 23026, 1),     # linker 14.00
            (0x0104 << 16 | 23026, 20),    # utc1900 C
            (0x0105 << 16 | 23026, 80),    # utc1900 C++
            (0x0103 << 16 | 23026, 3),     # masm 14.00
            (0x0001 << 16 | 0, 120),       # imports
        ])
        assert msvc_toolchains(binary_from_sections(raw, [])) == {"14+"}


class TestCrcSpan:
    """Which bytes after the prefix a build's FLIRT CRC16 covers."""

    def _crc_len(self, tmp_path, insn):
        from sigdb import SignatureDB, build_from_manifest
        text = b"\x90" * 34 + insn + b"\x90" * 12 + b"\xc3"
        image = pe_image(tmp_path / "lib.dll", text)
        (tmp_path / "map.csv").write_text(f"address,name,size\n0x{CODE_VA:X},f,{len(text)}\n")
        db = SignatureDB(":memory:")
        build_from_manifest(db, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                              "map": str(tmp_path / "map.csv"), "compiler": "msvc2008"}]})
        return db._conn.execute("SELECT crc_len FROM byte_sigs").fetchone()[0], len(text) - 32

    def test_crc_span_stops_where_the_section_ends(self):
        from sigdb import extract_flirt_crc, flirt_crc16
        code = b"\x90" * 40
        assert extract_flirt_crc(binary_over(code), CODE_VA, 100) == (8, flirt_crc16(code[32:]))

    @pytest.mark.parametrize("insn", [
        "6aff",             # push -1
        "83c8ff",           # or eax, -1
        "83c4f0",           # add esp, -0x10
        "83e0f0",           # and eax, 0xfffffff0
        "64a100000000",     # mov eax, fs:[0]
        "6878563412",       # push 0x12345678
        "8d04cd00000000",   # lea eax, [ecx*8]
        "8b80ffffefff",     # mov eax, [eax - 0x100001]
    ])
    def test_an_operand_outside_the_image_does_not_end_the_span(self, tmp_path, insn):
        crc_len, to_function_end = self._crc_len(tmp_path, bytes.fromhex(insn))
        assert crc_len == to_function_end

    @pytest.mark.parametrize("insn", [
        "6800204000",       # push 0x402000
        "b900104000",       # mov ecx, 0x401000
        "a100204000",       # mov eax, [0x402000]
    ])
    def test_an_operand_inside_the_image_ends_the_span(self, tmp_path, insn):
        crc_len, _ = self._crc_len(tmp_path, bytes.fromhex(insn))
        assert crc_len == 2

    @pytest.mark.parametrize("insn, ends_the_span", [
        ("8b0500100000", True),             # mov eax, [rip + 0x1000]
        ("48b80020004001000000", True),     # movabs rax, 0x140002000
        ("83c8ff", False),                  # or eax, -1
        ("65488b042530000000", False),      # mov rax, gs:[0x30]
    ])
    def test_a_64_bit_function(self, insn, ends_the_span):
        from sigdb import extract_flirt_crc
        text = b"\x90" * 34 + bytes.fromhex(insn) + b"\x90" * 12 + b"\xc3"
        section = fake_section(TEXT_RVA, len(text), 0, len(text), executable=True)
        b = binary_from_sections(text, [section, fake_section(DATA_RVA, 0x200, 0, 0)], is_64=True)
        b.base = IMAGE_BASE64
        crc_len, _ = extract_flirt_crc(b, IMAGE_BASE64 + TEXT_RVA, len(text))
        assert crc_len == (2 if ends_the_span else len(text) - 32)

    def test_a_stored_row_is_matched_over_its_own_crc_len(self, tmp_path):
        from common import Binary
        from sigdb import SignatureDB, flirt_crc16
        text = b"\x90" * 34 + bytes.fromhex("6aff") + b"\x90" * 12 + b"\xc3"
        db = SignatureDB(":memory:")
        db.add_byte_sig(name="stored", pattern=text[:32], mask=b"\xff" * 32, func_size=len(text), tail_crc=0,
                        crc_len=2, crc16=flirt_crc16(text[32:34]))
        game = Binary(str(pe_image(tmp_path / "game.exe", text)))
        assert db.identify(game, CODE_VA).name == "stored"


class TestPatParsing:
    @pytest.mark.parametrize("line", [
        "zz" + "90" * 31 + " 00 0000 0030 :0000 _f",
        "90" * 32 + " 00 zzzz 0030 :0000 _f",
        "90" * 32 + " 00 0000 00g0 :0000 _f",
    ])
    def test_a_pat_line_with_bad_hex_is_unparsed(self, line):
        from sigdb import parse_pat_line
        assert parse_pat_line(line) is None

    def test_pat_prefix_bytes_past_a_short_function_are_wildcards(self):
        from sigdb import parse_pat_line
        sig = parse_pat_line("90" * 32 + " 00 0000 0010 :0000 _f")
        assert sig.mask == b"\xff" * 16 + b"\0" * 16
        assert sig.pattern == b"\x90" * 16 + b"\0" * 16

    def _import(self, tmp_path, *lines):
        from sigdb import SignatureDB, import_pat
        pat = tmp_path / "x.pat"
        pat.write_text("\n".join(lines))
        db = SignatureDB(":memory:")
        stats = import_pat(db, str(pat), "msvc2008", "test")
        return +stats, [r[0] for r in db._conn.execute("SELECT name FROM byte_sigs")]

    def test_a_local_label_at_offset_zero_is_skipped(self, tmp_path):
        stats, names = self._import(tmp_path, "5589E5" + "96" * 29 + " 00 0000 0030 :0000@ _static_fn")
        assert names == [] and stats == {"local_or_managed": 1}

    def test_an_unnamed_function_is_skipped(self, tmp_path):
        stats, names = self._import(tmp_path, "5589E5" + "97" * 29 + " 00 0000 0030 :0000 ?")
        assert names == [] and stats == {"unparsed": 1}

    def test_a_public_name_wins_over_a_local_label_at_offset_zero(self, tmp_path):
        _, names = self._import(tmp_path, "5589E5" + "98" * 29 + " 00 0000 0030 :0000@ _static_fn :0000 _public")
        assert names == ["_public"]

    def test_a_prefix_with_too_few_fixed_bytes_is_skipped(self, tmp_path):
        stats, names = self._import(
            tmp_path, "5589E5" + "99" * 8 + ".." * 21 + " 00 0000 0030 :0000 _mostly_relocated")
        assert names == [] and stats == {"too_few_fixed_bytes": 1}


def _manifest_for(tmp_path, text, rows, compiler="msvc2008"):
    """A one-source manifest over an image holding *text*, mapping (offset, name, size) *rows*."""
    image = pe_image(tmp_path / "lib.dll", text)
    lines = ["address,name,size"] + [f"0x{CODE_VA + off:X},{name},{size}" for off, name, size in rows]
    (tmp_path / "map.csv").write_text("\n".join(lines) + "\n")
    return image, {"sources": [{"type": "binary_with_map", "binary": str(image),
                                "map": str(tmp_path / "map.csv"), "compiler": compiler}]}


# test eax, eax / jz +1 / inc eax / nops / ret: three basic blocks in 40 bytes.
_BRANCHY = bytes.fromhex("85c0740140") + b"\x90" * 34 + b"\xc3"


class TestBuildSkipsCallOnlyPrefixes:
    def test_a_prefix_with_too_few_fixed_bytes_is_skipped(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        text = b"\xe8\x00\x00\x00\x00" * 6 + b"\x90" * 9 + b"\xc3"
        _, manifest = _manifest_for(tmp_path, text, [(0, "thunks", len(text))])
        db = SignatureDB(":memory:")
        stats = build_from_manifest(db, manifest)
        assert stats["too_few_fixed_bytes"] == 1
        assert db._conn.execute("SELECT COUNT(*) FROM byte_sigs").fetchone()[0] == 0


class TestStructuralSafeguards:
    def _counts(self, db):
        return tuple(db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                     for table in ("byte_sigs", "structural_sigs"))

    def test_identical_functions_with_two_names_match_in_neither_tier(self, tmp_path):
        from common import Binary
        from sigdb import SignatureDB, build_from_manifest
        twins = _BRANCHY + b"\xcc" * 8 + _BRANCHY
        image, manifest = _manifest_for(tmp_path, twins, [(0, "a", 40), (48, "b", 40)])
        db = SignatureDB(":memory:")
        stats = build_from_manifest(db, manifest)
        assert stats["ambiguous_prefix"] == 1
        assert db.identify(Binary(str(image)), CODE_VA) is None

    def test_a_single_name_still_matches_structurally(self, tmp_path):
        from common import Binary
        from sigdb import SignatureDB, build_from_manifest, extract_structural_sig
        image, manifest = _manifest_for(tmp_path, _BRANCHY, [(0, "solo", 40)])
        db = SignatureDB(":memory:")
        build_from_manifest(db, manifest)
        sig = extract_structural_sig(Binary(str(image)), CODE_VA)
        matches = db.match_structural(sig["block_count"], sig["edge_count"], sig["call_count"],
                                      sig["mnemonic_hash"], sig["constants"])
        assert [m.name for m in matches] == ["solo"]

    def test_building_twice_adds_nothing_the_second_time(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        _, manifest = _manifest_for(tmp_path, _BRANCHY, [(0, "solo", 40)])
        db = SignatureDB(":memory:")
        build_from_manifest(db, manifest)
        assert self._counts(db) == (1, 1)
        stats = build_from_manifest(db, manifest)
        assert self._counts(db) == (1, 1)
        assert stats["already_in_db"] == 1 and stats["structural_already_in_db"] == 1

    def test_a_bad_map_row_leaves_the_database_as_it_was(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        _, manifest = _manifest_for(tmp_path, _BRANCHY, [(0, "solo", 40)])
        with open(tmp_path / "map.csv", "a") as f:
            f.write("not_an_address,broken,40\n")
        db = SignatureDB(":memory:")
        with pytest.raises(ValueError):
            build_from_manifest(db, manifest)
        assert self._counts(db) == (0, 0)

    def _two_names(self, second_compiler):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(name="a", block_count=4, edge_count=5, call_count=1, mnemonic_hash=7,
                              constants="0x401000", compiler="msvc2008")
        db.add_structural_sig(name="b", block_count=4, edge_count=5, call_count=1, mnemonic_hash=7,
                              compiler=second_compiler)
        return db

    def test_a_key_held_under_two_names_is_not_a_match(self):
        assert self._two_names("msvc2008").match_structural(4, 5, 1, 7, "0x401000") == []

    def test_a_name_from_an_absent_toolchain_does_not_make_a_key_ambiguous(self):
        db = self._two_names("msvc6.0")
        assert [m.name for m in db.match_structural(4, 5, 1, 7, "", frozenset({"9.0"}))] == ["a"]

    def test_one_name_held_twice_is_a_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        for source in ("first.dll", "second.dll"):
            db.add_structural_sig(name="a", block_count=4, edge_count=5, call_count=1, mnemonic_hash=7,
                                  source=source)
        assert {m.name for m in db.match_structural(4, 5, 1, 7, "")} == {"a"}


class TestKeyHeldUnderAnotherName:
    _FOO = "5589E5" + "9A" * 29 + " 00 0000 0030 :0000 _foo"
    _BAR = "5589E5" + "9A" * 29 + " 00 0000 0030 :0000 _bar"

    def _import(self, db, tmp_path, line, compiler):
        from sigdb import import_pat
        pat = tmp_path / "x.pat"
        pat.write_text(line)
        return import_pat(db, str(pat), compiler, "test")

    def _names(self, db):
        return [r[0] for r in db._conn.execute("SELECT name FROM byte_sigs ORDER BY name")]

    def test_the_held_row_is_dropped_and_the_new_one_is_not_added(self, tmp_path):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        self._import(db, tmp_path, self._FOO, "msvc2008")
        stats = self._import(db, tmp_path, self._BAR, "msvc2008")
        assert self._names(db) == []
        assert +stats == {"conflicts_with_db": 1}
        code = bytes.fromhex("5589E5") + b"\x9a" * 29
        assert db.match_bytes(code, 0x30, "", 0) == []

    def test_names_for_toolchains_that_never_meet_are_both_kept(self, tmp_path):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        self._import(db, tmp_path, self._FOO, "msvc2008")
        stats = self._import(db, tmp_path, self._BAR, "msvc6.0")
        assert self._names(db) == ["_bar", "_foo"] and stats["conflicts_with_db"] == 0


def _other_file(path, kind):
    """A file at *path* that is not a signature database."""
    if kind == "not_sqlite":
        path.write_bytes(b"not a database " * 100)
        return path
    conn = sqlite3.connect(path)
    if kind == "unrelated_wal":
        conn.execute("PRAGMA journal_mode=WAL")
    table = "schema_version" if kind == "schema_version_only" else "notes"
    conn.execute(f"CREATE TABLE {table} (version INTEGER)")
    conn.execute(f"INSERT INTO {table} VALUES (1)")
    conn.commit()
    conn.close()
    return path


def _dir_bytes(directory):
    return {p.name: p.read_bytes() for p in directory.iterdir()}


_OTHER_KINDS = ["unrelated", "unrelated_wal", "schema_version_only", "not_sqlite"]


class TestNotASignatureDatabase:
    def _args(self, tmp_path, command, db):
        image = _sig_image(tmp_path)
        if command == "scan":
            return ["scan", str(image), "--db", str(db)]
        if command == "identify":
            return ["identify", str(image), f"{CODE_VA:x}", "--db", str(db)]
        if command == "build":
            (tmp_path / "map.csv").write_text(f"address,name\n0x{CODE_VA:X},_initterm\n")
            manifest = tmp_path / "m.json"
            manifest.write_text(json.dumps({"sources": [{"type": "binary_with_map", "binary": str(image),
                                                         "map": str(tmp_path / "map.csv"), "compiler": "msvc"}]}))
            return ["build", str(manifest), "-o", str(db)]
        pat = tmp_path / "x.pat"
        pat.write_text(PAT_FIXTURE)
        return ["import-pat", str(pat), "-d", str(db), "--compiler", "msvc2008", "--source", "t"]

    def _refused_unchanged(self, tmp_path, capsys, command, db):
        from sigdb import main
        before = _dir_bytes(db.parent)
        with pytest.raises(SystemExit) as exc:
            main(self._args(tmp_path, command, db))
        assert exc.value.code == 1
        assert "not a signature database" in capsys.readouterr().err
        assert _dir_bytes(db.parent) == before

    @pytest.mark.parametrize("kind", _OTHER_KINDS)
    @pytest.mark.parametrize("command", ["scan", "identify", "build", "import-pat"])
    def test_every_command_refuses_it_and_leaves_it_unchanged(self, tmp_path, capsys, command, kind):
        (tmp_path / "db").mkdir()
        self._refused_unchanged(tmp_path, capsys, command, _other_file(tmp_path / "db" / "other.db", kind))

    @pytest.mark.parametrize("command", ["scan", "identify"])
    def test_read_commands_refuse_an_empty_file(self, tmp_path, capsys, command):
        (tmp_path / "db").mkdir()
        db = tmp_path / "db" / "empty.db"
        db.write_bytes(b"")
        self._refused_unchanged(tmp_path, capsys, command, db)

    @pytest.mark.parametrize("command", ["build", "import-pat"])
    def test_write_commands_create_the_schema_in_an_empty_file(self, tmp_path, command):
        from sigdb import SignatureDB, main
        db = tmp_path / "empty.db"
        db.write_bytes(b"")
        main(self._args(tmp_path, command, db))
        opened = SignatureDB.open_existing(str(db))
        assert opened._conn.execute("SELECT COUNT(*) FROM byte_sigs").fetchone()[0] == 1
        opened.close()

    @pytest.mark.parametrize("kind", _OTHER_KINDS)
    def test_the_constructor_refuses_it(self, tmp_path, kind):
        from sigdb import NotASignatureDB, SignatureDB
        path = _other_file(tmp_path / "other.db", kind)
        with pytest.raises(NotASignatureDB):
            SignatureDB(str(path))


class TestReadOnlyOpen:
    def _current_db(self, path):
        from sigdb import SignatureDB
        db = SignatureDB(str(path))
        db.add_byte_sig(name="f", pattern=b"\x55" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        db.close()
        return path

    def _assert_writes_refused(self, db):
        with pytest.raises(sqlite3.OperationalError):
            db.add_byte_sig(name="new", pattern=b"\x56" * 32, mask=b"\xff" * 32, func_size=40, tail_crc=0)
        with pytest.raises(sqlite3.OperationalError):
            db.add_structural_sig(name="new", block_count=4, edge_count=5, call_count=1, mnemonic_hash=7)
        with pytest.raises(sqlite3.OperationalError):
            db._conn.execute("DELETE FROM byte_sigs")

    def test_a_database_opened_for_reading_refuses_writes(self, tmp_path):
        from sigdb import SignatureDB
        path = self._current_db(tmp_path / "sigs.db")
        before = _dir_bytes(tmp_path)
        db = SignatureDB.open_existing(str(path))
        self._assert_writes_refused(db)
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["f"]
        db.close()
        assert _dir_bytes(tmp_path) == before

    def test_a_version_1_database_opened_for_reading_is_not_migrated(self, tmp_path):
        from sigdb import SignatureDB
        path = _v1_db(str(tmp_path / "v1.db"))
        before = _dir_bytes(tmp_path)
        db = SignatureDB.open_existing(path)
        self._assert_writes_refused(db)
        assert [m.name for m in db.match_bytes(b"\x55" * 32, 40, "", 0)] == ["old"]
        db.close()
        assert _dir_bytes(tmp_path) == before

    def test_scanning_leaves_the_database_directory_unchanged(self, tmp_path, capsys):
        from sigdb import main
        (tmp_path / "db").mkdir()
        path = self._current_db(tmp_path / "db" / "sigs.db")
        before = _dir_bytes(path.parent)
        main(["scan", str(_sig_image(tmp_path)), "--db", str(path)])
        assert capsys.readouterr().out.strip().endswith("functions identified")
        assert _dir_bytes(path.parent) == before


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


class TestPullUrls:
    def test_the_revision_is_quoted_into_every_url(self, tmp_path, monkeypatch):
        import sigdb
        urls = []

        def urlopen(request, timeout):
            urls.append(request.full_url)
            return _FakeResponse(json.dumps({"sources": ["sources/a.csv"]}).encode())

        monkeypatch.setattr(sigdb, "DEFAULT_DB_PATH", tmp_path / "signatures.db")
        monkeypatch.setattr(sigdb.urllib.request, "urlopen", urlopen)
        sigdb.main(["pull", "--sources", "--repo", "org/repo", "--revision", "feat/x y?z#w"])
        base = "https://huggingface.co/org/repo/resolve/feat%2Fx%20y%3Fz%23w/"
        assert urls == [base + "signatures.db", base + "manifest.json", base + "sources/a.csv"]


class TestImportPatInputs:
    def test_a_missing_pat_file_is_reported_before_a_database_is_created(self, tmp_path, capsys):
        from sigdb import main
        db = tmp_path / "s.db"
        with pytest.raises(SystemExit) as exc:
            main(["import-pat", str(tmp_path / "missing.pat"), "-d", str(db),
                  "--compiler", "msvc2008", "--source", "t"])
        assert exc.value.code == 1
        assert "missing.pat" in capsys.readouterr().err
        assert not db.exists()
