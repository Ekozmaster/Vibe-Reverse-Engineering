"""Tests for retools/structrefs.py -- [reg+offset] field scans and struct reconstruction."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import structrefs  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA

# One function, 32-bit, accessing a struct through esi (and one field through edi).
FUNC = [
    ("0fb64601", 0x1),     # movzx eax, byte ptr [esi + 1]
    ("0fbf4602", 0x2),     # movsx eax, word ptr [esi + 2]
    ("8b4604", 0x4),       # mov eax, dword ptr [esi + 4]
    ("d94608", 0x8),       # fld dword ptr [esi + 8]
    ("89460c", 0xC),       # mov dword ptr [esi + 0xc], eax
    ("dd5e10", 0x10),      # fstp qword ptr [esi + 0x10]
    ("83461401", 0x14),    # add dword ptr [esi + 0x14], 1
    ("8b4614", 0x14),      # mov eax, dword ptr [esi + 0x14]
    ("668b4620", 0x20),    # mov ax, word ptr [esi + 0x20]
    ("8b46fc", None),      # mov eax, dword ptr [esi - 4]: negative, not a field
    ("8b44be18", None),    # mov eax, dword ptr [esi + edi*4 + 0x18]: indexed, not a field
    ("8b4f24", 0x24),      # mov ecx, dword ptr [edi + 0x24]
    ("c3", None),
]
CODE = bytes.fromhex("".join(h for h, _ in FUNC))


def _addr(i: int) -> int:
    return TEXT + sum(len(bytes.fromhex(h)) for h, _ in FUNC[:i])


@pytest.fixture
def binary(tmp_path):
    return Binary(str(pe_image(tmp_path / "a.exe", CODE)))


class TestAggregate:
    def test_fields_types_and_access(self, binary):
        fields = structrefs.aggregate_struct(binary, TEXT, base_reg="esi", fn_size=len(CODE))
        assert [(f.offset, f.type_name, f.size, f.access) for f in fields] == [
            (0x1, "uint8_t", 1, "r"),
            (0x2, "int16_t", 2, "r"),
            (0x4, "void*", 4, "r"),
            (0x8, "float", 4, "r"),
            (0xC, "void*", 4, "w"),
            (0x10, "double", 8, "w"),
            (0x14, "void*", 4, "rw"),
            (0x20, "uint16_t", 2, "r"),
        ]
        assert fields[6].refs == [_addr(6), _addr(7)]

    def test_without_a_base_filter_every_base_register_counts(self, binary):
        fields = structrefs.aggregate_struct(binary, TEXT, fn_size=len(CODE))
        assert [f.offset for f in fields] == [0x1, 0x2, 0x4, 0x8, 0xC, 0x10, 0x14, 0x20, 0x24]

    def test_a_base_filter_keeps_only_that_register(self, binary):
        fields = structrefs.aggregate_struct(binary, TEXT, base_reg="edi", fn_size=len(CODE))
        assert [f.offset for f in fields] == [0x24]

    @pytest.mark.parametrize("code, expected", [
        ("d906", "float"), ("dd06", "double"),        # fld
        ("d916", "float"), ("dd16", "double"),        # fst
        ("d91e", "float"), ("dd1e", "double"),        # fstp
        ("d826", "float"), ("dc26", "double"),        # fsub
        ("d806", "float"), ("dc06", "double"),        # fadd
        ("d80e", "float"), ("dc0e", "double"),        # fmul
        ("d836", "float"), ("dc36", "double"),        # fdiv
        ("d81e", "float"), ("dc1e", "double"),        # fcomp
        ("f30f1006", "float"),                        # movss xmm0, dword ptr [esi]
        ("f20f1006", "double"),                       # movsd xmm0, qword ptr [esi]
        ("0fb706", "uint16_t"),                       # movzx eax, word ptr [esi]
        ("0fbe06", "int8_t"),                         # movsx eax, byte ptr [esi]
        ("8a06", "uint8_t"),                          # mov al, byte ptr [esi]
    ])
    def test_the_operand_size_and_instruction_give_the_type(self, tmp_path, code, expected):
        b = Binary(str(pe_image(tmp_path / "a.exe", bytes.fromhex(code + "c3"))))
        (field,) = structrefs.aggregate_struct(b, TEXT, fn_size=len(code) // 2)
        assert (field.offset, field.type_name) == (0, expected)

    def test_a_qword_on_64_bit_is_a_pointer_and_rip_is_not_a_base(self, tmp_path):
        # mov rax, [rsi + 8]; mov rax, [rip + 0x10]; mov eax, [rsi + 0x10]
        code = bytes.fromhex("488b4608" "488b0510000000" "8b4610" "c3")
        b = Binary(str(pe_image(tmp_path / "a.exe", code, is_64=True)))
        fields = structrefs.aggregate_struct(b, IMAGE_BASE64 + TEXT_RVA, fn_size=len(code))
        assert [(f.offset, f.type_name) for f in fields] == [(8, "void*"), (0x10, "uint32_t")]


class TestScan:
    def test_finds_one_offset_with_its_access(self, binary):
        hits = list(structrefs.scan(binary, 0x14, None, None, 0))
        assert hits == [(_addr(6), "esi", "rw", "add", "dword ptr [esi + 0x14], 1"),
                        (_addr(7), "esi", "r", "mov", "eax, dword ptr [esi + 0x14]")]

    def test_base_filter_and_function_range(self, binary):
        assert list(structrefs.scan(binary, 0x24, "esi", None, 0)) == []
        assert [h[1] for h in structrefs.scan(binary, 0x24, "edi", None, 0)] == ["edi"]
        assert list(structrefs.scan(binary, 0x24, None, TEXT, _addr(11) - TEXT)) == []
        assert len(list(structrefs.scan(binary, 0x24, None, TEXT, len(CODE)))) == 1

    def test_indexed_operands_are_not_fields(self, binary):
        assert list(structrefs.scan(binary, 0x18, None, None, 0)) == []


class TestCli:
    def _main(self, monkeypatch, capsys, *argv):
        monkeypatch.setattr(sys, "argv", ["structrefs.py", *argv])
        structrefs.main()
        return capsys.readouterr().out.splitlines()

    def test_offset_scan_output(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", CODE)
        out = self._main(monkeypatch, capsys, str(path), "0x14", "--base", "esi")
        assert out[0] == "2 refs to [reg+0x14]"
        assert out[2].split() == [f"0x{_addr(6):08X}", "esi", "[rw]", "add", "dword", "ptr", "[esi", "+",
                                  "0x14],", "1"]

    def test_aggregate_output(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", CODE)
        out = self._main(monkeypatch, capsys, str(path), "--aggregate", "--fn", hex(TEXT),
                         "--fn-size", hex(len(CODE)), "--base", "esi")
        assert out[0] == "struct Unknown {" and out[-1] == "};"
        assert out[1].split() == ["/*", "+0x001", "*/", "uint8_t", "field_1;", "//", "r", "at", f"0x{_addr(0):08X}"]
        assert len(out) == 2 + 8

    def test_aggregate_needs_a_function(self, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            self._main(monkeypatch, capsys, str(pe_image(tmp_path / "a.exe", CODE)), "--aggregate")
