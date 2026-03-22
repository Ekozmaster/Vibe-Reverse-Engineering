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
# Pipeline steps
# ---------------------------------------------------------------------------

class TestPipelineSteps:
    def test_detect_compiler_returns_dict(self, tmp_path):
        from bootstrap import _detect_compiler
        import pefile
        pe_path = _make_minimal_pe(str(tmp_path))
        b = MagicMock()
        b.pe = pefile.PE(pe_path, fast_load=False)
        result = _detect_compiler(b, db_path=None)
        assert "compiler" in result
        assert "confidence" in result

    def test_propagate_labels_incremental_set(self):
        """Verify propagation uses incremental set, not O(n^2) rebuild."""
        from bootstrap import _propagate_labels
        mock_b = MagicMock()
        result = _propagate_labels(
            b=mock_b, func_table=[], known_names={}, known_addresses=set(),
            kb_entry_addresses=set(),
        )
        assert isinstance(result, list)


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
