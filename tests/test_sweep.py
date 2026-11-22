"""Whole-binary scans keep going past data embedded in code.

Compilers put jump tables and other data between functions. A linear sweep
that stops at the first undecodable byte silently skips everything after it,
and a scanner then reports "0 references" for code it never looked at.
"""

import struct
from types import SimpleNamespace

from pe_fakes import CODE_VA, binary_over

import datarefs
import search
import structrefs
import vtable
import xrefs

GLOBAL_VA = 0x402000

_UNDECODABLE = bytes([0xFF, 0xFF, 0xFF, 0xFF])
_RESYNC_PADDING = bytes([0x90] * 8)

_LOAD_BEFORE = bytes([0xA1]) + struct.pack("<I", GLOBAL_VA)          # mov eax, [GLOBAL_VA]
_LOAD_AFTER = bytes([0x8B, 0x0D]) + struct.pack("<I", GLOBAL_VA)     # mov ecx, [GLOBAL_VA]
_VTABLE_CALL = bytes([0xFF, 0x52, 0x10])                             # call dword ptr [edx + 0x10]

_CODE = (
    _LOAD_BEFORE
    + _UNDECODABLE + _RESYNC_PADDING
    + _LOAD_AFTER
    + _VTABLE_CALL
    + bytes([0xC3])
)
_LOAD_AFTER_VA = CODE_VA + len(_LOAD_BEFORE) + len(_UNDECODABLE) + len(_RESYNC_PADDING)
_VTABLE_CALL_VA = _LOAD_AFTER_VA + len(_LOAD_AFTER)


class TestSweep:
    def test_continues_past_undecodable_bytes(self):
        addresses = [insn.address for insn in binary_over(_CODE).sweep()]
        assert CODE_VA in addresses
        assert _LOAD_AFTER_VA in addresses

    def test_yields_only_real_instructions(self):
        for insn in binary_over(_CODE).sweep():
            assert insn.id != 0
            insn.operands  # raises on a data placeholder

    def test_each_instruction_is_reported_once(self):
        code = bytes([0x90] * 0x10040) + _LOAD_AFTER + bytes([0xC3])
        addresses = [insn.address for insn in binary_over(code).sweep()]
        assert len(addresses) == len(set(addresses))


class TestScannersSeeCodeAfterEmbeddedData:
    def test_datarefs_finds_both_references(self):
        b = binary_over(_CODE)
        hits = [va for va, *_ in datarefs.scan(b, GLOBAL_VA, 4, None)]
        assert hits == [CODE_VA, _LOAD_AFTER_VA]

    def test_string_xref_search_finds_reference_after_data(self):
        b = binary_over(
            bytes([0x68]) + struct.pack("<I", GLOBAL_VA)             # push GLOBAL_VA
            + _UNDECODABLE + _RESYNC_PADDING
            + bytes([0x68]) + struct.pack("<I", GLOBAL_VA)
            + bytes([0xC3])
        )
        hits = [va for va, *_ in search._find_xrefs_for_va(b, GLOBAL_VA)]
        assert len(hits) == 2

    def test_insn_pattern_search_finds_match_after_data(self):
        b = binary_over(_CODE)
        hits = [va for va, *_ in search._scan_insn_pattern(b, "mov ecx,*")]
        assert hits == [_LOAD_AFTER_VA]

    def test_indirect_call_scan_finds_call_after_data(self):
        b = binary_over(_CODE)
        refs = xrefs.scan_indirect_refs(b.raw, b.exec_ranges(), b.base)
        assert _VTABLE_CALL_VA in [ref.va for ref in refs]

    def test_struct_offset_scan_finds_access_after_data(self):
        b = binary_over(_CODE)
        hits = [(va, base) for va, base, *_ in structrefs.scan(b, 0x10, None, None, 0)]
        assert hits == [(_VTABLE_CALL_VA, "edx")]

    def test_struct_offset_scan_of_a_function_finds_access_after_data(self):
        b = binary_over(_CODE)
        hits = [va for va, *_ in structrefs.scan(b, 0x10, None, CODE_VA, len(_CODE))]
        assert hits == [_VTABLE_CALL_VA]

    def test_struct_field_scan_of_a_function_finds_field_after_data(self):
        b = binary_over(_CODE)
        fields = [(disp, va) for disp, va, *_ in structrefs.scan_all_fields(b, None, CODE_VA, len(_CODE))]
        assert fields == [(0x10, _VTABLE_CALL_VA)]

    def test_vtable_call_scan_finds_call_after_data(self, capsys):
        vtable.cmd_calls(binary_over(_CODE), SimpleNamespace(offset="10"))
        assert capsys.readouterr().out.splitlines() == [
            "1 indirect calls through [reg+0x10]", "",
            f"  0x{_VTABLE_CALL_VA:08X}  edx    call dword ptr [edx + 0x10]"]
