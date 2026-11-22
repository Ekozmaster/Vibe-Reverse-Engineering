"""Answers a scanner must not get silently wrong: reads of uninitialised
section tails, bracketed search patterns, addresses outside the reported
function, unsupported bitness, RTTI class names and export addresses."""

import sys
from types import SimpleNamespace

import pytest

from pe_fakes import CODE_VA, IMAGE_BASE, binary_from_sections, binary_over, fake_section

import bootstrap
import dataflow
import funcinfo
import search
from common import Binary

DATA_VA = IMAGE_BASE + 0x1000


def _binary_with_partly_stored_section() -> Binary:
    """`.data` is 0x2000 bytes in memory but only 0x10 of them are in the file;
    the next section's bytes follow directly in the file."""
    stored = bytes(range(0x10))
    next_section = bytes([0xBB] * 0x20)
    sections = [
        fake_section(0x1000, 0x2000, 0, len(stored)),
        fake_section(0x3000, len(next_section), len(stored), len(next_section)),
    ]
    return binary_from_sections(stored + next_section, sections)


class TestReadsPastStoredData:
    def test_stored_bytes_are_returned(self):
        b = _binary_with_partly_stored_section()
        assert b.read_va(DATA_VA, 4) == bytes([0, 1, 2, 3])

    def test_uninitialised_tail_reads_as_zeros(self):
        b = _binary_with_partly_stored_section()
        assert b.read_va(DATA_VA + 0x10, 4) == bytes(4)

    def test_read_across_the_end_of_stored_data_is_zero_filled(self):
        b = _binary_with_partly_stored_section()
        assert b.read_va(DATA_VA + 0x0E, 4) == bytes([0x0E, 0x0F, 0, 0])

    def test_pointer_in_the_uninitialised_tail_is_null(self):
        b = _binary_with_partly_stored_section()
        assert b.read_ptr(DATA_VA + 0x100) == 0

    def test_read_does_not_run_past_the_section(self):
        b = _binary_with_partly_stored_section()
        assert b.read_va(DATA_VA + 0x1FFE, 8) == bytes(2)


class TestInsnPattern:
    def test_square_brackets_match_literally(self):
        assert search._match_insn("lea", "rax, [rip + 0x10]", "lea *,[rip+*]")

    def test_bracketed_pattern_still_filters(self):
        assert not search._match_insn("lea", "rax, [rbx + 0x10]", "lea *,[rip+*]")

    def test_wildcards_outside_brackets(self):
        assert search._match_insn("mov", "eax, 0x10000", "mov *,0x10000")
        assert not search._match_insn("mov", "eax, 0x20000", "mov *,0x10000")


# call known; ret; then `known` and an `unreferenced` function nothing calls.
_KNOWN_VA = CODE_VA + 0x08
_UNREFERENCED_VA = CODE_VA + 0x10
_TWO_FUNCTIONS = (
    bytes([0xE8, 0x03, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC])       # call +3; ret; int3 int3
    + bytes([0x55, 0x8B, 0xEC, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC])     # known: push/mov/pop/ret
    + bytes([0x33, 0xC0, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC])     # unreferenced: xor eax,eax; ret
)


def _run_funcinfo(monkeypatch, capsys, va: int) -> str:
    monkeypatch.setattr(funcinfo, "Binary", lambda path: binary_over(_TWO_FUNCTIONS))
    monkeypatch.setattr(sys, "argv", ["funcinfo.py", "fake.exe", hex(va)])
    funcinfo.main()
    return capsys.readouterr().out


class TestFuncinfoRange:
    def test_warns_when_the_address_is_outside_the_reported_function(self, monkeypatch, capsys):
        out = _run_funcinfo(monkeypatch, capsys, _UNREFERENCED_VA)
        assert f"Function: 0x{_KNOWN_VA:08X}" in out
        assert "[warning]" in out
        assert f"0x{_UNREFERENCED_VA:08X}" in out

    def test_no_warning_when_the_address_is_inside(self, monkeypatch, capsys):
        out = _run_funcinfo(monkeypatch, capsys, _KNOWN_VA + 1)
        assert f"Function: 0x{_KNOWN_VA:08X}" in out
        assert "[warning]" not in out


class TestDataflowBitness:
    def test_64_bit_binary_is_refused_with_a_message(self, monkeypatch):
        b = binary_over(_TWO_FUNCTIONS)
        b.is_64 = True
        monkeypatch.setattr(dataflow, "Binary", lambda path: b)
        with pytest.raises(SystemExit) as exit_info:
            dataflow.main(["fake.exe", hex(CODE_VA), "--constants"])
        # A string exit code is printed to stderr and becomes exit status 1.
        assert "x86" in str(exit_info.value.code)


class TestRttiClassIdentifier:
    @pytest.mark.parametrize("mangled, identifier", [
        (".?AVActor@@", "Actor"),
        (".?AVVAArray@@", "VAArray"),
        (".?AUVertex@@", "Vertex"),
        (".?AVbad_alloc@std@@", "bad_alloc_std"),
    ])
    def test_strips_the_type_prefix_only(self, mangled, identifier):
        assert bootstrap.rtti_class_identifier(mangled) == identifier


class TestExportAddresses:
    def test_exports_are_printed_as_virtual_addresses(self, sample_binary, capsys):
        b = Binary(sample_binary)
        search.cmd_exports(b, SimpleNamespace(filter=None))
        lines = [line.split() for line in capsys.readouterr().out.splitlines() if line.strip()]
        addresses = [int(fields[1], 16) for fields in lines[:50]]
        assert addresses
        assert all(address >= b.base for address in addresses)
