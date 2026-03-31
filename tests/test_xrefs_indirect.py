"""Tests for indirect call/jump scanning in xrefs.py."""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestIndirectRefType:
    def test_importable(self):
        from xrefs import IndirectRef
        ref = IndirectRef(va=0x401000, mnemonic="call", base="eax",
                          index="", scale=0, disp=0x10, target_type="vtable")
        assert ref.va == 0x401000
        assert ref.target_type == "vtable"

    def test_fields(self):
        from xrefs import IndirectRef
        ref = IndirectRef(va=0x1000, mnemonic="call", base="ecx",
                          index="", scale=0, disp=0, target_type="fptr")
        assert ref.base == "ecx"
        assert ref.disp == 0


class TestScanIndirectRefs:
    def test_importable(self):
        from xrefs import scan_indirect_refs
        assert callable(scan_indirect_refs)

    def test_finds_call_reg_plus_offset(self):
        """call [eax+0x10] should be detected as vtable type."""
        from xrefs import scan_indirect_refs
        # FF 50 10 = call [eax+0x10]
        code = b"\x90" * 8 + b"\xFF\x50\x10" + b"\x90" * 8
        sec_va = 0x401000
        results = scan_indirect_refs(code, [(sec_va, 0, len(code))], sec_va)
        vtable_hits = [r for r in results if r.target_type == "vtable"]
        assert len(vtable_hits) == 1
        assert vtable_hits[0].va == sec_va + 8
        assert vtable_hits[0].base == "eax"
        assert vtable_hits[0].disp == 0x10

    def test_finds_call_reg_no_offset(self):
        """call [ecx] (FF 11) should be detected as fptr type."""
        from xrefs import scan_indirect_refs
        # FF 11 = call [ecx]
        code = b"\x90" * 4 + b"\xFF\x11" + b"\x90" * 4
        sec_va = 0x401000
        results = scan_indirect_refs(code, [(sec_va, 0, len(code))], sec_va)
        fptr_hits = [r for r in results if r.target_type == "fptr"]
        assert len(fptr_hits) == 1
        assert fptr_hits[0].base == "ecx"
        assert fptr_hits[0].disp == 0

    def test_finds_call_absolute_mem(self):
        """call [0x7C0000] (FF 15 ...) should be detected as iat type."""
        from xrefs import scan_indirect_refs
        # FF 15 00 00 7C 00 = call dword ptr [0x7C0000]
        code = b"\x90" * 4 + b"\xFF\x15\x00\x00\x7C\x00" + b"\x90" * 4
        sec_va = 0x401000
        results = scan_indirect_refs(code, [(sec_va, 0, len(code))], sec_va)
        iat_hits = [r for r in results if r.target_type == "iat"]
        assert len(iat_hits) == 1
        assert iat_hits[0].disp == 0x7C0000

    def test_ignores_direct_calls(self):
        """E8 rel32 direct calls should not appear in indirect results."""
        from xrefs import scan_indirect_refs
        code = b"\xE8\x00\x10\x00\x00"
        sec_va = 0x401000
        results = scan_indirect_refs(code, [(sec_va, 0, len(code))], sec_va)
        assert len(results) == 0

    def test_empty_code(self):
        from xrefs import scan_indirect_refs
        results = scan_indirect_refs(b"", [], 0x400000)
        assert results == []
