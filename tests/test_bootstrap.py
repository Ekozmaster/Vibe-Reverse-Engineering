"""Tests for retools/bootstrap.py -- auto-KB seeding pipeline."""

import os
import struct
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure retools is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# ---------------------------------------------------------------------------
# classify_function
# ---------------------------------------------------------------------------

class TestClassifyFunction:
    def test_thunk_single_callee(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000],
            callee_names={0x401000: "_malloc"},
            is_vtable_call=False,
        )
        assert result is not None
        assert "thunk" in result["label"].lower()
        assert result["label"] == "_thunk__malloc"
        assert result["confidence"] == 0.80

    def test_thunk_unnamed_callee(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000],
            callee_names={},
            is_vtable_call=False,
        )
        assert result is not None
        assert result["label"] == "_thunk_sub_401000"
        assert result["confidence"] == 0.80

    def test_constructor_detection(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000],
            callee_names={0x401000: "operator_new"},
            is_vtable_call=True,
        )
        assert result is not None
        assert result["label"] == "constructor"
        assert result["confidence"] == 0.75

    def test_destructor_detection(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000],
            callee_names={0x401000: "operator_delete"},
            is_vtable_call=False,
        )
        assert result is not None
        assert result["label"] == "destructor"
        assert result["confidence"] == 0.70

    def test_throws_detection(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000, 0x403000],
            callee_names={0x402000: "_CxxThrowException"},
            is_vtable_call=False,
        )
        assert result is not None
        assert result["label"] == "throws"
        assert result["confidence"] == 0.85

    def test_init_global_detection(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000],
            callee_names={0x401000: "malloc"},
            is_vtable_call=False,
        )
        assert result is not None
        assert result["label"] == "init_global"
        assert result["confidence"] == 0.55

    def test_init_global_too_many_callees(self):
        """malloc with >3 callees should not match init_global."""
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000, 0x403000, 0x404000],
            callee_names={0x401000: "malloc"},
            is_vtable_call=False,
        )
        # Should not be init_global; might match something else or None
        assert result is None or result["label"] != "init_global"

    def test_no_match_returns_none(self):
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000, 0x402000, 0x403000, 0x404000, 0x405000],
            callee_names={},
            is_vtable_call=False,
        )
        assert result is None

    def test_priority_throws_over_thunk(self):
        """CxxThrowException with exactly one callee -- thunk takes priority
        since single-callee is checked first."""
        from bootstrap import classify_function
        result = classify_function(
            callees=[0x401000],
            callee_names={0x401000: "_CxxThrowException"},
            is_vtable_call=False,
        )
        assert result is not None
        # Single callee -> thunk rule fires first
        assert "thunk" in result["label"].lower()


# ---------------------------------------------------------------------------
# strings stay out of kb.h
# ---------------------------------------------------------------------------

class TestStringsNotSeededToKb:
    def test_kb_has_no_string_entries(self, tmp_path):
        """Strings belong in index.db, not kb.h: decompilers auto-resolve
        directly-referenced string literals, so kb string labels are noise."""
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        # Embed an error string in the section data so a sweep finds it.
        data = Path(pe_path).read_bytes()
        marker = b"FATAL ERROR: gamesys is corrupt\x00"
        data = data[:0x300] + marker + data[0x300 + len(marker):]
        Path(pe_path).write_bytes(data)
        project_dir = str(tmp_path / "project")

        bootstrap(pe_path, project_dir)

        content = Path(os.path.join(project_dir, "kb.h")).read_text()
        assert "str_" not in content

        import sqlite3
        con = sqlite3.connect(os.path.join(project_dir, "index.db"))
        rows = con.execute(
            "SELECT content FROM strings WHERE content LIKE '%FATAL ERROR%'"
        ).fetchall()
        con.close()
        assert rows, "string must still be indexed in index.db"


class TestUniquifyEntryNames:
    def test_duplicate_names_get_address_suffix(self):
        from bootstrap import _uniquify_entry_names
        entries = [
            "// [propagated: _thunk_sub_6B2CA8, 0.80]\n@ 0x402018 _thunk_sub_6B2CA8;",
            "// [propagated: _thunk_sub_6B2CA8, 0.80]\n@ 0x402440 _thunk_sub_6B2CA8;",
        ]
        result = _uniquify_entry_names(entries)
        assert result[0].splitlines()[1] == "@ 0x402018 _thunk_sub_6B2CA8;"
        assert result[1].splitlines()[1] == "@ 0x402440 _thunk_sub_6B2CA8_402440;"

    def test_unique_names_untouched(self):
        from bootstrap import _uniquify_entry_names
        entries = [
            "// [sigdb: byte, 0.85] crt\n@ 0x408F00 crt_strlen;",
            "@ 0x717EA4 _cSomeClass_vtable;",
        ]
        assert _uniquify_entry_names(entries) == entries

    def test_existing_kb_names_count_as_taken(self):
        from bootstrap import _uniquify_entry_names
        entries = ["@ 0x402018 _thunk_sub_6B2CA8;"]
        result = _uniquify_entry_names(entries, taken={"_thunk_sub_6B2CA8"})
        assert result[0] == "@ 0x402018 _thunk_sub_6B2CA8_402018;"

    def test_signature_lines_left_alone(self):
        """Only bare-name lines are rewritten; full signatures pass through."""
        from bootstrap import _uniquify_entry_names
        entries = [
            "@ 0x401000 void __cdecl ProcessInput(int key);",
            "@ 0x402000 void __cdecl ProcessInput(int key);",
        ]
        assert _uniquify_entry_names(entries) == entries


class TestBootstrapUniquifiesNames:
    def test_kb_function_names_unique(self, tmp_path):
        """End to end: a bootstrap run must never write two @ entries with
        the same name (r2 afn renames silently fail on collisions)."""
        from bootstrap import bootstrap
        from kb import parse_kb
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")
        bootstrap(pe_path, project_dir)
        kb = parse_kb(Path(project_dir) / "kb.h")
        names = [f.name for f in kb.functions]
        assert len(names) == len(set(names))


class TestWriteKbEntriesGlobals:
    def test_skips_known_global_addresses(self, tmp_path):
        from bootstrap import _write_kb_entries
        kb_path = str(tmp_path / "kb.h")
        entry = '// [string] "some error"\n$ 0x6FAC3C str_some_error'
        known: set = set()
        assert _write_kb_entries(kb_path, [entry], known) == 1
        assert _write_kb_entries(kb_path, [entry], known) == 0
        content = Path(kb_path).read_text()
        assert content.count("$ 0x6FAC3C") == 1


# ---------------------------------------------------------------------------
# bootstrap pipeline
# ---------------------------------------------------------------------------

def _make_minimal_pe(tmp_dir, packed=False):
    """Create a minimal valid PE file for testing.

    If packed=True, the executable section has raw_size << virtual_size
    to trigger packed binary detection.
    """
    import pefile

    # Build a minimal PE from scratch using struct packing
    # DOS header
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x14C)   # Machine: i386
    struct.pack_into("<H", coff, 2, 1)        # NumberOfSections
    struct.pack_into("<H", coff, 16, 0xE0)    # SizeOfOptionalHeader
    struct.pack_into("<H", coff, 18, 0x102)   # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    # Optional header (224 bytes for PE32)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)      # Magic: PE32
    struct.pack_into("<I", opt, 16, 0x1000)    # AddressOfEntryPoint
    struct.pack_into("<I", opt, 28, 0x400000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)    # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)     # FileAlignment
    struct.pack_into("<H", opt, 40, 4)         # MajorOSVersion
    struct.pack_into("<H", opt, 44, 4)         # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x3000)    # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)     # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)         # Subsystem: CONSOLE
    struct.pack_into("<I", opt, 76, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", opt, 80, 0x1000)    # SizeOfStackCommit
    struct.pack_into("<I", opt, 84, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", opt, 88, 0x1000)    # SizeOfHeapCommit
    struct.pack_into("<I", opt, 92, 16)        # NumberOfRvaAndSizes

    # Section header (40 bytes) - .text
    sec = bytearray(40)
    sec[0:6] = b".text\x00"

    if packed:
        # Virtual size much larger than raw size
        struct.pack_into("<I", sec, 8, 0x10000)   # VirtualSize
        struct.pack_into("<I", sec, 12, 0x1000)   # VirtualAddress
        struct.pack_into("<I", sec, 16, 0x200)    # SizeOfRawData (tiny)
        struct.pack_into("<I", sec, 20, 0x200)    # PointerToRawData
    else:
        struct.pack_into("<I", sec, 8, 0x1000)    # VirtualSize
        struct.pack_into("<I", sec, 12, 0x1000)   # VirtualAddress
        struct.pack_into("<I", sec, 16, 0x800)    # SizeOfRawData
        struct.pack_into("<I", sec, 20, 0x200)    # PointerToRawData

    # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE
    struct.pack_into("<I", sec, 36, 0x60000020)

    # Assemble headers
    headers = dos + pe_sig + coff + opt + sec

    # Pad headers to FileAlignment (0x200)
    headers += b"\x00" * (0x200 - len(headers))

    # Section data (pad to a nice size)
    if packed:
        section_data = b"\xCC" * 0x200  # Small raw data for packed
    else:
        section_data = b"\xCC" * 0x800

    pe_data = headers + section_data

    pe_path = os.path.join(tmp_dir, "test.exe")
    with open(pe_path, "wb") as f:
        f.write(pe_data)

    return pe_path


class TestBootstrapCreatesKB:
    def test_creates_kb_file(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")

        result = bootstrap(pe_path, project_dir)

        kb_path = os.path.join(project_dir, "kb.h")
        assert os.path.isfile(kb_path)
        assert isinstance(result, dict)

    def test_creates_report(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")

        result = bootstrap(pe_path, project_dir)

        report_path = os.path.join(project_dir, "bootstrap_report.txt")
        assert os.path.isfile(report_path)
        report = Path(report_path).read_text()
        assert "Compiler:" in report
        assert "Functions identified:" in report

    def test_skips_duplicate_addresses(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")

        # Run twice
        bootstrap(pe_path, project_dir)
        bootstrap(pe_path, project_dir)

        kb_path = os.path.join(project_dir, "kb.h")
        content = Path(kb_path).read_text()
        # Count lines starting with "@ 0x" -- each address should appear once
        addr_lines = [l for l in content.splitlines() if l.startswith("@ 0x")]
        addresses = [l.split()[1] for l in addr_lines]
        assert len(addresses) == len(set(addresses)), \
            f"Duplicate addresses found: {addresses}"


class TestPackedDetection:
    def test_packed_binary_early_return(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path), packed=True)
        project_dir = str(tmp_path / "project")

        result = bootstrap(pe_path, project_dir)

        assert result.get("packed") is True
        report_path = os.path.join(project_dir, "bootstrap_report.txt")
        report = Path(report_path).read_text()
        assert "packed" in report.lower() or "warning" in report.lower()


class TestBootstrapReturnDict:
    def test_returns_dict_with_stats(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")

        result = bootstrap(pe_path, project_dir)

        assert isinstance(result, dict)
        # Should have some stats keys
        assert "functions_identified" in result or "packed" in result


class TestBootstrapProjectDir:
    def test_creates_project_dir(self, tmp_path):
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "newproject" / "sub")

        bootstrap(pe_path, project_dir)

        assert os.path.isdir(project_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_module_runnable(self):
        """bootstrap should be runnable as python -m retools.bootstrap."""
        from bootstrap import main
        assert callable(main)

    def test_main_no_args_exits(self):
        from bootstrap import main
        with pytest.raises(SystemExit):
            main([])


# ---------------------------------------------------------------------------
# Index seeding
# ---------------------------------------------------------------------------

class TestStringSweepDedup:
    def test_bootstrap_scans_strings_once(self, tmp_path):
        """bootstrap must sweep the binary for strings a single time and reuse
        the result for both the error-string KB seed and the index seed."""
        import search
        from bootstrap import bootstrap

        pe_path = _make_minimal_pe(str(tmp_path))
        project_dir = str(tmp_path / "project")

        calls = {"n": 0}
        orig = search.find_strings

        def counting(b, **kw):
            calls["n"] += 1
            return orig(b, **kw)

        with patch("search.find_strings", counting):
            bootstrap(pe_path, project_dir)

        assert calls["n"] == 1


def _parsed(entries):
    """(address, name) of each KB entry, read back through the kb.h parser."""
    from kb import parse_kb
    return [(f.address, f.name) for f in parse_kb("\n".join(entries)).functions]


class TestBootstrapPipeline:
    def test_signature_db_is_downloaded_only_when_missing(self, tmp_path, monkeypatch):
        import sigdb
        from bootstrap import bootstrap
        pe_path = _make_minimal_pe(str(tmp_path))
        fetched = []
        monkeypatch.setattr(sigdb, "_download_file", lambda url, path: fetched.append(path))
        present = tmp_path / "present.db"
        present.write_bytes(b"")
        bootstrap(pe_path, str(tmp_path / "p1"), db_path=str(present))
        assert fetched == []
        missing = str(tmp_path / "missing.db")
        bootstrap(pe_path, str(tmp_path / "p2"), db_path=missing)
        assert fetched == [missing]


class TestClassifyRules:
    def test_vtable_call_without_operator_new_is_not_a_constructor(self):
        from bootstrap import classify_function
        assert classify_function([0x1000, 0x2000], {}, is_vtable_call=True) is None


class TestDetectCompiler:
    def test_crt_import_heuristic_has_low_confidence(self, monkeypatch):
        import sigdb
        from bootstrap import _detect_compiler
        monkeypatch.setattr(sigdb, "detect_crt_import", lambda b: "msvc_2019")
        assert _detect_compiler(MagicMock(), None) == {"compiler": "msvc_2019", "confidence": 0.3}
        monkeypatch.setattr(sigdb, "detect_crt_import", lambda b: None)
        assert _detect_compiler(MagicMock(), None) == {"compiler": "unknown", "confidence": 0.0}

    def test_db_fingerprint_without_confidence_reports_zero(self, tmp_path, monkeypatch):
        import sigdb
        from bootstrap import _detect_compiler
        db = tmp_path / "sigs.db"
        db.write_bytes(b"")
        fake = MagicMock()
        fake.fingerprint.return_value = {"compiler": "gcc"}
        monkeypatch.setattr(sigdb, "SignatureDB", lambda path: fake)
        assert _detect_compiler(MagicMock(), str(db)) == {"compiler": "gcc", "confidence": 0.0}


class TestMain:
    def test_main_runs_the_pipeline_and_prints_the_summary(self, tmp_path, monkeypatch, capsys):
        import bootstrap as bs
        seen = []
        monkeypatch.setattr(bs, "bootstrap", lambda binary, project, db_path=None: seen.append(
            (binary, project, db_path)) or {"compiler": "msvc", "functions_identified": 7})
        bs.main(["game.exe", "--project", str(tmp_path), "--db", "s.db"])
        assert seen == [("game.exe", str(tmp_path), "s.db")]
        assert capsys.readouterr().out.splitlines() == [
            "Compiler: msvc", "Functions identified: 7",
            f"Report written to: {os.path.join(str(tmp_path), 'bootstrap_report.txt')}"]


class TestPropagateLabels:
    def test_classifies_unseen_functions_from_their_direct_callees(self, monkeypatch):
        import funcinfo
        from bootstrap import _propagate_labels
        calls = {
            0x1000: [(0x1001, 0x9000)],                                  # thunk
            0x2000: [(0x2001, "dword ptr [eax + 4]")],                   # indirect only
            0x3000: [(0x3001, 0x9000)],                                  # known on disk
            0x4000: [(0x4001, 0x9100), (0x4002, 0x9200), (0x4003, "dword ptr [ecx]")],
        }
        monkeypatch.setattr(funcinfo, "analyze", lambda b, va, max_size: ([], calls[va], va + 0x10))
        names = {0x9000: "target", 0x9100: "operator_new", 0x9200: "other"}
        out = _propagate_labels(MagicMock(), [0x1000, 0x2000, 0x3000, 0x4000], names, {0x3000}, set())
        assert _parsed(out) == [(0x1000, "_thunk_target"), (0x4000, "constructor")]


class TestScanRtti:
    def test_classes_become_vtable_entries(self, monkeypatch):
        import rtti
        from bootstrap import _scan_rtti
        cls = MagicMock(hierarchy=["Derived", "Base"], vtable_va=0x5000)
        cls.name = ".?AVDerived@@"
        lone = MagicMock(hierarchy=[], vtable_va=0x6000)
        lone.name = ".?AVLone@@"
        monkeypatch.setattr(rtti, "scan_all_rtti", lambda pe: [cls, lone])
        count, entries = _scan_rtti(None)
        assert count == 2
        assert _parsed(entries) == [(0x5000, "Derived_vtable"), (0x6000, "Lone_vtable")]

    def test_unparseable_rtti_is_skipped(self, monkeypatch):
        import rtti
        from bootstrap import _scan_rtti

        def boom(pe):
            raise ValueError("bad rva")
        monkeypatch.setattr(rtti, "scan_all_rtti", boom)
        assert _scan_rtti(None) == (0, [])


class TestScanSignatures:
    def test_matches_become_kb_entries(self, tmp_path, monkeypatch):
        import sqlite3
        import sigdb
        from bootstrap import _scan_signatures
        db = tmp_path / "sigs.db"
        db.write_bytes(b"")
        match = MagicMock(tier="byte", confidence=0.9, category="crt")
        match.name = "_memcpy"
        fake = MagicMock()
        fake.scan.return_value = {0x401000: match}
        monkeypatch.setattr(sigdb, "SignatureDB", lambda path: fake)
        results, entries = _scan_signatures(MagicMock(), str(db), "msvc")
        assert results == {0x401000: match}
        assert _parsed(entries) == [(0x401000, "_memcpy")]
        fake.scan.assert_called_once()
        assert fake.scan.call_args.kwargs == {"preferred_compiler": "msvc"}

        fake.scan.side_effect = sqlite3.DatabaseError("corrupt")
        assert _scan_signatures(MagicMock(), str(db), "msvc") == ({}, [])


class TestSeedIndexRows:
    def test_rows_carry_ranges_modules_and_export_addresses(self, sample_binary, tmp_path):
        from bootstrap import _seed_index
        from common import Binary
        from index import GameIndex
        b = Binary(sample_binary)
        db = str(tmp_path / "index.db")
        _seed_index(b, db, strings=[])
        gi = GameIndex(db)
        segs = gi._conn.execute("SELECT start_ea, end_ea, name, source FROM segments").fetchall()
        imports = gi._conn.execute("SELECT module, source FROM imports").fetchall()
        exports = gi._conn.execute("SELECT address FROM entries").fetchall()
        gi.close()
        expected = sorted((b.base + s.VirtualAddress, b.base + s.VirtualAddress + s.Misc_VirtualSize)
                          for s in b.pe.sections)
        assert sorted((s, e) for s, e, _, _ in segs) == expected
        assert {src for *_, src in segs} == {"bootstrap"}
        assert imports and all(m and src == "bootstrap" for m, src in imports)
        assert exports and all(b.base < a < b.base + b.pe.OPTIONAL_HEADER.SizeOfImage for (a,) in exports)


class TestWriteKbEntries:
    def test_appends_new_entries_and_skips_known_addresses(self, tmp_path):
        from bootstrap import _write_kb_entries
        kb = tmp_path / "kb.h"
        kb.write_text("// head\n")
        entries = ["// [a]\n@ 0x1000 known;", "// [b]\n@ 0x2000 fresh;", "// no address line",
                   "// [c]\n@ 0xZZ bad;\n@ 0x1000 known_again;"]
        assert _write_kb_entries(str(kb), entries, {0x1000}) == 2
        assert kb.read_text() == "// head\n// [b]\n@ 0x2000 fresh;\n\n// no address line\n\n"
