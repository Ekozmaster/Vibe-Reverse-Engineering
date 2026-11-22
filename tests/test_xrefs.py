"""Tests for retools/xrefs.py -- call/jump cross-references by encoding."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import xrefs  # noqa: E402
from pe_fakes import IMAGE_BASE, TEXT_RVA, pe_image  # noqa: E402

VA = 0x1000
TARGET = 0x1030


def _rel32(at, size, target=TARGET):
    return struct.pack("<i", target - (at + size))


def _code() -> bytes:
    """One reference to TARGET of every encoding the docstring lists, plus a decoy call."""
    code = bytearray(b"\x90" * 0x48)
    code[0x00:0x05] = b"\xE8" + _rel32(VA + 0x00, 5)               # call
    code[0x05:0x0A] = b"\xE9" + _rel32(VA + 0x05, 5)               # jmp rel32
    code[0x0A:0x10] = b"\x0F\x84" + _rel32(VA + 0x0A, 6)           # je rel32
    code[0x10:0x12] = b"\x74" + struct.pack("<b", TARGET - (VA + 0x12))   # je rel8
    code[0x12:0x14] = b"\xEB" + struct.pack("<b", TARGET - (VA + 0x14))   # jmp rel8
    code[0x14:0x19] = b"\xE8" + _rel32(VA + 0x14, 5, TARGET + 4)   # call elsewhere
    code[0x38:0x3A] = b"\xEB" + struct.pack("<b", TARGET - (VA + 0x3A))   # backward jmp rel8
    return bytes(code)


class TestScanRefs:
    def test_every_encoding_with_any(self):
        assert xrefs.scan_refs(_code(), VA, 0, 0x48, TARGET, "any") == [
            ("call", 0x1000), ("jmp", 0x1005), ("jcc", 0x100A), ("jcc.s", 0x1010), ("jmp.s", 0x1012),
            ("jmp.s", 0x1038)]

    def test_kind_filters(self):
        assert xrefs.scan_refs(_code(), VA, 0, 0x48, TARGET, "call") == [("call", 0x1000)]
        assert [k for k, _ in xrefs.scan_refs(_code(), VA, 0, 0x48, TARGET, "jump")] == [
            "jmp", "jcc", "jcc.s", "jmp.s", "jmp.s"]

    def test_long_jcc_is_0f_80_to_0f_8f_only(self):
        code = bytearray(b"\x90" * 0x48)
        code[0x00:0x06] = b"\x0F\x80" + _rel32(VA + 0x00, 6)             # jo
        code[0x06:0x0C] = b"\x0F\x8F" + _rel32(VA + 0x06, 6)             # jg
        code[0x0C:0x12] = b"\x0F\x10" + _rel32(VA + 0x0C, 6)             # movups: not a branch
        code[0x12:0x18] = b"\x05\x84" + _rel32(VA + 0x12, 6)             # no 0F escape
        code[0x18:0x1E] = b"\x0F\x84" + _rel32(VA + 0x18, 6, TARGET + 4)  # je elsewhere
        assert xrefs.scan_refs(bytes(code), VA, 0, 0x48, TARGET, "jump") == [("jcc", 0x1000), ("jcc", 0x1006)]

    def test_section_offset_and_address_are_applied(self):
        raw = b"\xCC" * 0x100 + _code()
        assert xrefs.scan_refs(raw, VA, 0x100, 0x48, TARGET, "call") == [("call", 0x1000)]


class TestCli:
    def test_output_lists_each_hit_with_marked_context(self, tmp_path, monkeypatch, capsys):
        text = IMAGE_BASE + TEXT_RVA
        code = bytearray(bytes.fromhex("8b442404") * 0x14)                 # mov eax, [esp + 4] filler
        code[0x30:0x35] = b"\xE8" + struct.pack("<i", 0x40 - 0x35)       # call text+0x40
        code[0x40] = 0xC3
        path = pe_image(tmp_path / "a.exe", bytes(code))
        monkeypatch.setattr(sys, "argv", ["xrefs.py", str(path), f"{text + 0x40:X}", "-t", "call"])
        xrefs.main()
        out = capsys.readouterr().out.splitlines()
        assert out[0] == f"1 xrefs to 0x{text + 0x40:X}"
        assert out[2] == f"--- call at 0x{text + 0x30:08X} ---"
        marked = [line for line in out if line.endswith(" <<<")]
        assert len(marked) == 1 and marked[0].startswith(f"  0x{text + 0x30:08X}: E8 ")
