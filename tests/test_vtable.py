"""Tests for retools/vtable.py -- vtable slot dump and indirect call [reg+offset] sites."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import vtable  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA
DATA = IMAGE_BASE + DATA_RVA

# Three functions in .text, each longer than the three-instruction preview.
FN_A, FN_B, FN_C = TEXT + 0x00, TEXT + 0x10, TEXT + 0x20
_FUNCS = {
    0x00: bytes.fromhex("55" "8bec" "83ec08" "33c0" "c3"),   # push ebp; mov ebp, esp; sub esp, 8; xor; ret
    0x10: bytes.fromhex("b801000000" "c3" "90"),            # mov eax, 1; ret; nop
    0x20: bytes.fromhex("56" "57" "8bf1" "5f" "5e" "c3"),     # push esi; push edi; mov esi, ecx; ...
}
PREVIEW = {
    FN_A: "push ebp; mov ebp, esp; sub esp, 8",
    FN_B: "mov eax, 1; ret ; nop ",
    FN_C: "push esi; push edi; mov esi, ecx",
}


def _text() -> bytes:
    code = bytearray(b"\xCC" * 0x200)
    for off, body in _FUNCS.items():
        code[off:off + len(body)] = body
    return bytes(code)


def _ptrs(*targets) -> bytes:
    return b"".join(struct.pack("<I", t) for t in targets)


def _dump(tmp_path, monkeypatch, capsys, data: bytes, address: int, *extra) -> list[str]:
    path = pe_image(tmp_path / "a.exe", _text(), data)
    monkeypatch.setattr(sys, "argv", ["vtable.py", str(path), "dump", f"0x{address:X}", *extra])
    vtable.main()
    return capsys.readouterr().out.splitlines()


def _slot(i: int, target: int) -> str:
    head = f"  [{i:3d}] +0x{i * 4:04X}  -> 0x{target:08X}"
    return f"{head}  {PREVIEW[target]}" if target in PREVIEW else f"{head}  (not code)"


class TestDump:
    def test_slots_point_into_code_until_the_first_non_code_pointer(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(FN_A, FN_B, FN_C, 0x11111111, FN_A).ljust(0x200, b"\x11")
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA)
        assert out == [_slot(0, FN_A), _slot(1, FN_B), _slot(2, FN_C), _slot(3, 0x11111111)]

    def test_pointer_into_a_data_section_ends_the_table(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(FN_B, DATA + 0x40, FN_C).ljust(0x200, b"\x11")
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA)
        assert out == [_slot(0, FN_B), _slot(1, DATA + 0x40)]

    def test_non_code_first_slot_does_not_end_the_table(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(0, FN_C, FN_A, 0).ljust(0x200, b"\x11")
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA)
        assert out == [_slot(0, 0), _slot(1, FN_C), _slot(2, FN_A), _slot(3, 0)]

    def test_slot_offsets_count_from_the_given_address(self, tmp_path, monkeypatch, capsys):
        data = (b"\x11" * 0x40 + _ptrs(FN_C, FN_B, 7)).ljust(0x200, b"\x11")
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA + 0x40)
        assert out == [_slot(0, FN_C), _slot(1, FN_B), _slot(2, 7)]

    def test_slots_limits_the_number_read(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(*([FN_A, FN_B] * 64))
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA, "--slots", "3")
        assert out == [_slot(0, FN_A), _slot(1, FN_B), _slot(2, FN_A)]

    def test_default_is_30_slots(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(*([FN_A, FN_B] * 64))
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA)
        assert out == [_slot(i, (FN_A, FN_B)[i % 2]) for i in range(30)]

    def test_table_stops_at_the_end_of_mapped_memory(self, tmp_path, monkeypatch, capsys):
        data = (b"\x11" * 0x1F8 + _ptrs(FN_A, FN_B))
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA + 0x1F8)
        assert out == [_slot(0, FN_A), _slot(1, FN_B)]

    def test_unmapped_slot_ends_the_table_even_if_memory_resumes_later(self, tmp_path, monkeypatch, capsys):
        # Slot 0 is the last dword of .text; slot 1 falls in the unmapped gap before .data.
        data = _ptrs(*([FN_A] * 128))
        out = _dump(tmp_path, monkeypatch, capsys, data, TEXT + 0x1FC, "--slots", "2000")
        assert out == [_slot(0, 0xCCCCCCCC)]

    def test_preview_is_the_first_three_instructions(self, tmp_path, monkeypatch, capsys):
        data = _ptrs(FN_A, 0).ljust(0x200, b"\x11")
        out = _dump(tmp_path, monkeypatch, capsys, data, DATA)
        assert out[0].endswith("  -> 0x00401000  push ebp; mov ebp, esp; sub esp, 8")

    def test_address_without_0x_prefix_is_hex(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", _text(), _ptrs(FN_B, 0).ljust(0x200, b"\x11"))
        monkeypatch.setattr(sys, "argv", ["vtable.py", str(path), "dump", f"{DATA:X}"])
        vtable.main()
        assert capsys.readouterr().out.splitlines() == [_slot(0, FN_B), _slot(1, 0)]


# call [reg+0xB0] in every ModRM form, plus near misses that must not match.
_CALL_SITES = [
    (0x00, "ff90b0000000", "eax", "dword ptr [eax + 0xb0]"),      # mod=10 disp32
    (0x06, "ff96b0000000", "esi", "dword ptr [esi + 0xb0]"),
    (0x0C, "ff9424b0000000", "esp", "dword ptr [esp + 0xb0]"),   # SIB, no index
]
_DECOYS = [
    "ff90b4000000",      # call [eax+0xb4]: other slot
    "ff94b0b0000000",    # call [eax+esi*4+0xb0]: indexed
    "ff15b0000000",      # call [0xb0]: no base register
    "ffa0b0000000",      # jmp [eax+0xb0]: not a call
    "8b80b0000000",      # mov eax, [eax+0xb0]: not a call
    "0380b0000000",      # add eax, [eax+0xb0]: not a call
    "ff5010",            # call [eax+0x10]: other slot
]


def _calls(tmp_path, monkeypatch, capsys, text: bytes, offset: str, data: bytes = b"\x11" * 0x200) -> list[str]:
    path = pe_image(tmp_path / "a.exe", text, data)
    monkeypatch.setattr(sys, "argv", ["vtable.py", str(path), "calls", offset])
    vtable.main()
    return capsys.readouterr().out.splitlines()


def _call_line(va: int, base: str, op: str) -> str:
    return f"  0x{va:08X}  {base:5s}  call {op}"


class TestCalls:
    def _text(self) -> bytes:
        code = bytearray()
        for off, hexcode, _, _ in _CALL_SITES:
            assert len(code) == off
            code += bytes.fromhex(hexcode)
        for hexcode in _DECOYS:
            code += bytes.fromhex(hexcode)
        return bytes(code)

    def test_finds_every_call_through_the_offset_and_nothing_else(self, tmp_path, monkeypatch, capsys):
        out = _calls(tmp_path, monkeypatch, capsys, self._text(), "0xB0")
        assert out == ["3 indirect calls through [reg+0xB0]", ""] + [
            _call_line(TEXT + off, base, op) for off, _, base, op in _CALL_SITES]

    def test_disp8_form(self, tmp_path, monkeypatch, capsys):
        text = bytes.fromhex("ff5010" "ff5110" "ff5014" "ff10")
        out = _calls(tmp_path, monkeypatch, capsys, text, "10")
        assert out == ["2 indirect calls through [reg+0x10]", "",
                       _call_line(TEXT, "eax", "dword ptr [eax + 0x10]"),
                       _call_line(TEXT + 3, "ecx", "dword ptr [ecx + 0x10]")]

    def test_slot_zero_is_a_call_through_the_bare_register(self, tmp_path, monkeypatch, capsys):
        text = bytes.fromhex("ff5010" "ff12")
        out = _calls(tmp_path, monkeypatch, capsys, text, "0x0")
        assert out == ["1 indirect calls through [reg+0x0]", "", _call_line(TEXT + 3, "edx", "dword ptr [edx]")]

    def test_no_hits(self, tmp_path, monkeypatch, capsys):
        out = _calls(tmp_path, monkeypatch, capsys, bytes.fromhex("ff5010"), "0x20")
        assert out == ["0 indirect calls through [reg+0x20]", ""]

    def test_only_executable_sections_are_scanned(self, tmp_path, monkeypatch, capsys):
        data = bytes.fromhex("ff5010").ljust(0x200, b"\x90")
        out = _calls(tmp_path, monkeypatch, capsys, bytes.fromhex("90ff5110"), "0x10", data)
        assert out == ["1 indirect calls through [reg+0x10]", "",
                       _call_line(TEXT + 1, "ecx", "dword ptr [ecx + 0x10]")]

    def test_scan_covers_the_whole_section(self, tmp_path, monkeypatch, capsys):
        text = (b"\x90" * 0x1FD + bytes.fromhex("ff5710"))
        out = _calls(tmp_path, monkeypatch, capsys, text, "0x10")
        assert out == ["1 indirect calls through [reg+0x10]", "",
                       _call_line(TEXT + 0x1FD, "edi", "dword ptr [edi + 0x10]")]

@pytest.mark.parametrize("command", [["dump"], ["calls"]])
def test_subcommand_argument_is_required(tmp_path, monkeypatch, command):
    path = pe_image(tmp_path / "a.exe", _text())
    monkeypatch.setattr(sys, "argv", ["vtable.py", str(path), *command])
    with pytest.raises(SystemExit):
        vtable.main()


def test_a_subcommand_is_required(tmp_path, monkeypatch):
    path = pe_image(tmp_path / "a.exe", _text())
    monkeypatch.setattr(sys, "argv", ["vtable.py", str(path)])
    with pytest.raises(SystemExit):
        vtable.main()


def test_runs_as_a_script(tmp_path):
    """The documented usage: python retools/vtable.py <binary> calls <offset>."""
    path = pe_image(tmp_path / "a.exe", bytes.fromhex("ff5010"))
    script = Path(__file__).resolve().parent.parent / "retools" / "vtable.py"
    out = subprocess.run([sys.executable, str(script), str(path), "calls", "0x10"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert out == ["1 indirect calls through [reg+0x10]", "", _call_line(TEXT, "eax", "dword ptr [eax + 0x10]")]
