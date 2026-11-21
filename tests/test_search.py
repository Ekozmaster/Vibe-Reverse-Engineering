"""Tests for retools/search.py -- strings, byte patterns, imports, exports and instruction search."""

import re
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import search  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import DATA_RAW, DATA_RVA, IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA
DATA = IMAGE_BASE + DATA_RVA


def _binary(tmp_path, text=b"\x90", data=b""):
    return Binary(str(pe_image(tmp_path / "a.exe", text, data)))


class TestFindStrings:
    def test_printable_runs_with_their_address(self, tmp_path):
        b = _binary(tmp_path, data=b"\x00\x01Hello\x00ab\x00Render error\x00")
        found = {s.value: (s.va, s.offset) for s in search.find_strings(b, min_len=4)}
        assert found["Hello"] == (DATA + 2, DATA_RAW + 2)
        assert found["Render error"] == (DATA + 11, DATA_RAW + 11)
        assert "ab" not in found

    def test_keyword_filter_is_case_insensitive(self, tmp_path):
        b = _binary(tmp_path, data=b"\x00Render error\x00draw call\x00other text\x00")
        assert [s.value for s in search.find_strings(b, filter_keywords=["ERROR", "Draw"])] == [
            "Render error", "draw call"]

    def test_min_len(self, tmp_path):
        b = _binary(tmp_path, data=b"\x00abcde\x00abcdef\x00")
        assert [s.value for s in search.find_strings(b, min_len=6) if s.va and s.va >= DATA] == ["abcdef"]

    def test_header_strings_have_no_address(self, tmp_path):
        b = _binary(tmp_path)
        dos_stub = [s for s in search.find_strings(b, min_len=4) if s.offset < 0x200]
        assert dos_stub and all(s.va is None for s in dos_stub)


class TestImports:
    def test_named_imports_of_a_system_dll(self, sample_binary):
        b = Binary(sample_binary)
        imports = search.find_imports(b)
        assert imports and all(i.dll and i.name for i in imports)
        expected = {(e.dll.decode(), (i.name or b"").decode()) for e in b.pe.DIRECTORY_ENTRY_IMPORT
                    for i in e.imports if i.name}
        assert expected <= {(i.dll, i.name) for i in imports}

    def test_an_image_without_imports(self, tmp_path):
        assert search.find_imports(_binary(tmp_path)) == []


class TestMatchInsn:
    def test_globs_on_mnemonic_and_operands_ignoring_spaces(self):
        assert search._match_insn("mov", "eax, 0x10000", "mov *,0x10000")
        assert search._match_insn("mov", "eax, 0x10000", "mov eax, 0x10000")
        assert not search._match_insn("mov", "eax, 0x20000", "mov *,0x10000")
        assert not search._match_insn("cmp", "eax, 0x10000", "mov *,0x10000")
        assert search._match_insn("jne", "0x401000", "j*")


def _export(ordinal: int, rva: int, name: bytes, forwarder: bytes | None = None) -> SimpleNamespace:
    return SimpleNamespace(ordinal=ordinal, address=rva, name=name, forwarder=forwarder)


class TestExports:
    def _exports(self, capsys, symbols, *, base=0x10000000, is_64=False, keyword=None) -> list[str]:
        b = SimpleNamespace(pe=SimpleNamespace(DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=symbols)),
                            base=base, is_64=is_64)
        search.cmd_exports(b, SimpleNamespace(filter=keyword))
        return capsys.readouterr().out.splitlines()

    def test_address_is_the_virtual_address(self, capsys):
        out = self._exports(capsys, [_export(1, 0x1234, b"Draw"), _export(2, 0x2000, b"Present")])
        assert out == ["      1  0x10001234  Draw", "      2  0x10002000  Present"]

    def test_64_bit_address_is_the_virtual_address(self, capsys):
        out = self._exports(capsys, [_export(7, 0x1234, b"Draw")], base=IMAGE_BASE64, is_64=True)
        assert out == [f"      7  0x{IMAGE_BASE64 + 0x1234:016X}  Draw"]

    def test_forwarded_export_names_its_target(self, capsys):
        out = self._exports(capsys, [_export(3, 0x5000, b"HeapAlloc", b"NTDLL.RtlAllocateHeap")])
        assert out == ["      3  0x10005000  HeapAlloc  -> NTDLL.RtlAllocateHeap"]

    def test_keyword_filter_and_unnamed_exports(self, capsys):
        symbols = [_export(1, 0x1000, b"Draw"), _export(2, 0x2000, None)]
        assert self._exports(capsys, symbols, keyword="dra") == ["      1  0x10001000  Draw"]
        assert self._exports(capsys, symbols)[1] == "      2  0x10002000  "


class TestInstructionScan:
    CODE = bytes.fromhex(
        "b800000100"                                   # +0x00 mov eax, 0x10000
        + "90" * 8                                     # +0x05 nops
        + "3d00000100"                                 # +0x0d cmp eax, 0x10000
        + "68" + struct.pack("<I", 0x402004).hex()     # +0x12 push 0x402004 (a .data address)
        + "c3")

    def test_scan_yields_every_match_with_its_address(self, tmp_path):
        b = _binary(tmp_path, text=self.CODE)
        assert list(search._scan_insn_pattern(b, "mov *,0x10000")) == [(TEXT, "mov", "eax, 0x10000")]
        assert [va for va, _, _ in search._scan_insn_pattern(b, "*")][:2] == [TEXT, TEXT + 5]

    def test_xrefs_find_the_immediate_reference(self, tmp_path):
        b = _binary(tmp_path, text=self.CODE)
        assert search._find_xrefs_for_va(b, 0x402004) == [(TEXT + 0x12, "push", "0x402004")]
        assert search._find_xrefs_for_va(b, 0x402008) == []


class TestCli:
    @pytest.fixture(autouse=True)
    def _io(self, monkeypatch, capsys):
        self._monkeypatch, self._capsys = monkeypatch, capsys

    def _main(self, capsys, path, *argv):
        self._monkeypatch.setattr(sys, "argv", ["search.py", str(path), *argv])
        search.main()
        return capsys.readouterr().out

    def test_pattern_reports_every_occurrence_including_overlaps(self, tmp_path, capsys):
        path = pe_image(tmp_path / "a.exe", b"\x90", b"\x00AAA\x00")
        out = self._main(capsys, path, "pattern", "41 41")
        assert out.splitlines() == [f"0x{DATA + 1:08X}", f"0x{DATA + 2:08X}"]

    def test_pattern_outside_sections_prints_the_file_offset(self, tmp_path, capsys):
        path = pe_image(tmp_path / "a.exe", b"\x90")
        out = self._main(capsys, path, "pattern", "4D5A")
        assert out.splitlines()[0] == "off:00000000"

    def test_strings_with_xrefs(self, tmp_path, capsys):
        code = bytes.fromhex("68" + struct.pack("<I", DATA + 1).hex() + "c3")
        path = pe_image(tmp_path / "a.exe", code, b"\x00Fatal error\x00")
        out = self._main(capsys, path, "strings", "-f", "fatal", "--xrefs").splitlines()
        assert out == [f"0x{DATA + 1:08X}: Fatal error", f"  xref: 0x{TEXT:08X} (push 0x{DATA + 1:x})"]

    def test_imports_filtered_by_dll(self, sample_binary, capsys):
        out = self._main(capsys, sample_binary, "imports", "-d", "NTDLL").splitlines()
        assert out and all(line.lower().startswith("ntdll") for line in out)

    def test_imports_unfiltered_lists_every_import(self, sample_binary, capsys):
        out = self._main(capsys, sample_binary, "imports").splitlines()
        assert len(out) == len(search.find_imports(Binary(sample_binary)))

    def test_exports_filtered_by_keyword(self, sample_binary, capsys):
        out = self._main(capsys, sample_binary, "exports", "-f", "createfilew").splitlines()
        assert out and all("createfilew" in line.lower() for line in out)

    def test_exports_without_a_table(self, tmp_path, capsys):
        assert self._main(capsys, pe_image(tmp_path / "a.exe", b"\x90"), "exports") == "No export table found.\n"

    def test_insn_near_keeps_primaries_with_a_neighbour_in_range(self, tmp_path, capsys):
        path = pe_image(tmp_path / "a.exe", TestInstructionScan.CODE)
        out = self._main(capsys, path, "insn", "mov *,0x10000", "--near", "cmp *,0x10000", "--range", "0xd")
        assert out.splitlines()[0] == f"  0x{TEXT:08X}  mov      eax, 0x10000"
        assert out.splitlines()[1].startswith(f"    near 0x{TEXT + 0xD:08X}")
        assert out.rstrip().endswith("1 matches (of 1 primary, filtered by --near within 13 bytes)")
        out = self._main(capsys, path, "insn", "mov *,0x10000", "--near", "cmp *,0x10000", "--range", "0xc")
        assert out.rstrip().endswith("0 matches (of 1 primary, filtered by --near within 12 bytes)")
        out = self._main(capsys, path, "insn", "mov *,0x10000", "--near", "cmp *,0x10000")
        assert out.rstrip().endswith("1 matches (of 1 primary, filtered by --near within 512 bytes)")

    def test_insn_lists_matches_and_a_count(self, tmp_path, capsys):
        path = pe_image(tmp_path / "a.exe", TestInstructionScan.CODE)
        out = self._main(capsys, path, "insn", "* *,0x10000").splitlines()
        assert out[:2] == [f"  0x{TEXT:08X}  mov      eax, 0x10000", f"  0x{TEXT + 0xD:08X}  cmp      eax, 0x10000"]
        assert out[-1] == "2 matches"


class TestX64:
    """PE32+: references are RIP-relative or 64-bit immediates, addresses print as 16 hex digits."""

    TEXT64, DATA64 = IMAGE_BASE64 + TEXT_RVA, IMAGE_BASE64 + DATA_RVA
    CODE = (bytes.fromhex("488d0d") + struct.pack("<i", (DATA_RVA + 1) - (TEXT_RVA + 7))  # lea rcx, [rip -> .data+1]
            + bytes.fromhex("48ba") + struct.pack("<Q", IMAGE_BASE64 + DATA_RVA + 1)          # movabs rdx, .data+1
            + b"\xc3")

    @pytest.fixture
    def image(self, tmp_path):
        return pe_image(tmp_path / "a64.exe", self.CODE, b"\x00Fatal error\x00", is_64=True)

    @pytest.fixture(autouse=True)
    def _io(self, monkeypatch, capsys):
        self._monkeypatch, self._capsys = monkeypatch, capsys

    def _main(self, path, *argv):
        self._monkeypatch.setattr(sys, "argv", ["search.py", str(path), *argv])
        search.main()
        return self._capsys.readouterr().out.splitlines()

    def test_xrefs_find_rip_relative_and_imm64_references(self, image):
        b = Binary(str(image))
        assert search._find_xrefs_for_va(b, self.DATA64 + 1) == [
            (self.TEXT64, "lea", "rcx, [rip + 0xffa]"), (self.TEXT64 + 7, "movabs", "rdx, 0x140002001")]
        assert search._find_xrefs_for_va(b, self.DATA64 + 2) == []

    def test_strings_with_xrefs(self, image):
        assert self._main(image, "strings", "-f", "fatal", "--xrefs") == [
            "0x0000000140002001: Fatal error",
            "  xref: 0x0000000140001000 (lea rcx, [rip + 0xffa])",
            "  xref: 0x0000000140001007 (movabs rdx, 0x140002001)"]

    def test_pattern(self, image):
        assert self._main(image, "pattern", "46 61 74 61 6C") == ["0x0000000140002001"]

    def test_insn(self, image):
        assert self._main(image, "insn", "lea *") == [
            "  0x0000000140001000  lea      rcx, [rip + 0xffa]", "", "1 matches"]

    def test_insn_near(self, image):
        assert self._main(image, "insn", "lea *", "--near", "movabs *") == [
            "  0x0000000140001000  lea      rcx, [rip + 0xffa]",
            "    near 0x0000000140001007  movabs   rdx, 0x140002001  (delta +7)",
            "",
            "1 matches (of 1 primary, filtered by --near within 512 bytes)"]

    def test_xrefs_come_from_executable_code_only(self, tmp_path):
        data = bytes.fromhex("48ba") + struct.pack("<Q", IMAGE_BASE64 + DATA_RVA + 11) + b"\x00Fatal error\x00"
        string = self.DATA64 + 11                         # movabs rdx, string -- in .data, not code
        lea_at = 0x40                                     # past the first 32 bytes of .text
        code = b"\x90" * lea_at + bytes.fromhex("488d0d") \
            + struct.pack("<i", (DATA_RVA + 11) - (TEXT_RVA + lea_at + 7)) + b"\xc3"
        b = Binary(str(pe_image(tmp_path / "a64.exe", code, data, is_64=True)))
        assert [va for va, _, _ in search._find_xrefs_for_va(b, string)] == [self.TEXT64 + lea_at]

    def test_strings_without_xrefs_and_outside_sections(self, image):
        assert self._main(image, "strings", "-f", "fatal") == ["0x0000000140002001: Fatal error"]
        assert self._main(image, "strings", "-f", ".text") == [f"off:{64 + 4 + 20 + 0xF0:08X}: .text"]

    def test_insn_near_reports_one_neighbour_per_match(self, tmp_path):
        code = bytes.fromhex("90" "90" "90" "c3")
        path = pe_image(tmp_path / "a64.exe", code, is_64=True)
        out = self._main(path, "insn", "ret", "--near", "nop")
        assert out[0] == "  0x0000000140001003  ret      "
        assert [line for line in out if line.startswith("    near ")] == [out[1]]
        assert out[-1] == "1 matches (of 1 primary, filtered by --near within 512 bytes)"

    def test_exports_of_a_64_bit_dll(self, sample_binary):
        b = Binary(sample_binary)
        if b.ptr_size != 8:
            pytest.skip("sample binary is not PE32+")
        names = [e.name for e in b.pe.DIRECTORY_ENTRY_EXPORT.symbols]
        out = self._main(sample_binary, "exports", "-f", "createfilew")
        assert len(out) == sum(1 for n in names if n and b"createfilew" in n.lower()) >= 2
        assert all(re.fullmatch(r"  +\d+  0x[0-9A-F]{16}  \S*CreateFileW", line) for line in out)
        assert len(self._main(sample_binary, "exports")) == len(names)

    def test_exports_of_a_32_bit_dll(self):
        dll = Path(r"C:\Windows\SysWOW64\kernel32.dll")
        if not dll.is_file():
            pytest.skip("no 32-bit system DLL")
        out = self._main(dll, "exports", "-f", "createfilew")
        assert out and all(re.fullmatch(r"  +\d+  0x[0-9A-F]{8}  \S*CreateFileW", line) for line in out)
