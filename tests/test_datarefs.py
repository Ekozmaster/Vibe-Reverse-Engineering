"""Tests for retools/datarefs.py -- instructions that reference a global address."""

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import datarefs  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA
G = IMAGE_BASE + DATA_RVA + 0x10


def _le(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _place(code: bytearray, at: int, insn: bytes) -> None:
    code[at:at + len(insn)] = insn


def _direct_code() -> bytes:
    """One absolute reference of each kind the docstring lists, around the global G."""
    code = bytearray(b"\x90" * 0x40)
    _place(code, 0x00, b"\xA1" + _le(G))                    # mov eax, [G]          read
    _place(code, 0x05, b"\xA3" + _le(G))                    # mov [G], eax          write
    _place(code, 0x0A, b"\xFF\x05" + _le(G))                # inc dword [G]         read-write
    _place(code, 0x10, b"\xD9\x1D" + _le(G))                # fstp dword [G]        store
    _place(code, 0x16, b"\xA0" + _le(G + 3))                # mov al, [G + 3]       last byte of the range
    _place(code, 0x1B, b"\xA1" + _le(G + 4))                # mov eax, [G + 4]      past the range
    _place(code, 0x20, b"\xA1" + _le(G - 1))                # mov eax, [G - 1]      before the range
    _place(code, 0x25, b"\x8B\x80" + _le(G))                # mov eax, [eax + G]    register-based
    _place(code, 0x2B, b"\x68" + _le(G))                    # push G                immediate
    _place(code, 0x30, b"\xB9" + _le(G))                    # mov ecx, G            immediate
    _place(code, 0x35, b"\xC7\x05" + _le(G) + _le(G))       # mov dword [G], G      write + immediate
    code[0x3F] = 0xC3
    return bytes(code)


def _hits(path, addr=G, size=4, access=None, imm=False):
    return [(va - TEXT, acc) for va, _, _, acc in datarefs.scan(Binary(str(path)), addr, size, access, imm)]


@pytest.fixture
def direct(tmp_path):
    return pe_image(tmp_path / "a.exe", _direct_code())


class TestScan:
    def test_absolute_operands_classified_by_access(self, direct):
        assert _hits(direct) == [(0x00, "r"), (0x05, "w"), (0x0A, "rw"), (0x10, "w"), (0x16, "r"), (0x35, "w")]

    def test_yields_mnemonic_and_operands(self, direct):
        first = next(datarefs.scan(Binary(str(direct)), G, 4, None))
        assert first == (TEXT, "mov", f"eax, dword ptr [0x{G:x}]", "r")

    def test_range_is_start_inclusive_end_exclusive(self, direct):
        assert [va for va, _ in _hits(direct, size=1)] == [0x00, 0x05, 0x0A, 0x10, 0x35]
        assert [va for va, _ in _hits(direct, G + 3, size=1)] == [0x16]
        assert [va for va, _ in _hits(direct, size=8)] == [0x00, 0x05, 0x0A, 0x10, 0x16, 0x1B, 0x35]
        assert [va for va, _ in _hits(direct, G - 1, size=1)] == [0x20]

    def test_immediates_only_with_imm(self, direct):
        assert _hits(direct, imm=True) == [
            (0x00, "r"), (0x05, "w"), (0x0A, "rw"), (0x10, "w"), (0x16, "r"),
            (0x2B, "imm"), (0x30, "imm"), (0x35, "w")]

    def test_access_counts_any_byte_of_the_range(self, tmp_path):
        code = b"\x66\xA3" + _le(G + 2) + b"\xC3"                        # mov [G + 2], ax
        assert _hits(pe_image(tmp_path / "a.exe", code)) == [(0x00, "w")]

    def test_immediate_range_is_start_inclusive_end_exclusive(self, tmp_path):
        code = b"".join(b"\x68" + _le(v) for v in (G - 1, G + 1, G + 4, G + 8)) + b"\xC3"
        assert _hits(pe_image(tmp_path / "a.exe", code), imm=True) == [(0x05, "imm")]

    def test_only_executable_sections_are_scanned(self, tmp_path):
        data = bytearray(b"\x90" * 0x200)
        data[0x20:0x25] = b"\xA1" + _le(G)                                 # mov eax, [G] bytes in .data
        assert _hits(pe_image(tmp_path / "a.exe", b"\xC3", bytes(data))) == []

    def test_top_of_the_32_bit_address_space(self, tmp_path):
        code = b"\xA3\xF0\xFF\xFF\xFF" + b"\xA1\xF0\xFF\xFF\xFF" + b"\xC3"  # mov [0xFFFFFFF0], eax; mov eax, [...]
        path = pe_image(tmp_path / "a.exe", code)
        assert _hits(path, 0xFFFFFFF0) == [(0x00, "w"), (0x05, "r")]


# -- PE32+ ---------------------------------------------------------------------

TEXT64 = IMAGE_BASE64 + TEXT_RVA
G64 = IMAGE_BASE64 + DATA_RVA + 0x10


def _rip(at: int, size: int, target: int = G64) -> bytes:
    return struct.pack("<i", target - (TEXT64 + at + size))


class TestScan64:
    def test_rip_relative_reference_resolved(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\x8B\x05" + _rip(0x00, 6))              # mov eax, [rip + G64]
        _place(code, 0x06, b"\x8B\x05" + _rip(0x06, 6, G64 + 4))     # mov eax, [rip + G64 + 4]
        _place(code, 0x0C, b"\x48\x8D\x05" + _rip(0x0C, 7))          # lea rax, [rip + G64]
        path = pe_image(tmp_path / "a.exe", bytes(code), is_64=True)
        hits = list(datarefs.scan(Binary(str(path)), G64, 4, None))
        assert [(va - TEXT64, mn) for va, mn, _, _ in hits] == [(0x00, "mov"), (0x0C, "lea")]

    def test_rip_relative_range_is_start_inclusive_end_exclusive(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        for at, target in ((0x00, G64 - 1), (0x06, G64 + 1), (0x0C, G64 + 8)):
            _place(code, at, b"\x8B\x05" + _rip(at, 6, target))       # mov eax, [rip + target]
        path = pe_image(tmp_path / "a.exe", bytes(code), is_64=True)
        assert [va - TEXT64 for va, _, _, _ in datarefs.scan(Binary(str(path)), G64, 4, None)] == [0x06]

    def test_absolute_operand_sign_extended_to_64_bits(self, tmp_path):
        code = b"\x89\x04\x25\x10\x00\x00\x80" + b"\xC3"  # mov [0xFFFFFFFF80000010], eax
        path = pe_image(tmp_path / "a.exe", code, is_64=True)
        hits = list(datarefs.scan(Binary(str(path)), 0xFFFFFFFF80000010, 4, None))
        assert [(va - TEXT64, acc) for va, _, _, acc in hits] == [(0x00, "w")]


# -- --indirect ----------------------------------------------------------------

T = IMAGE_BASE + DATA_RVA + 0x100     # target
PTR = IMAGE_BASE + DATA_RVA + 0x40    # static pointer slot holding T - 0x80


def _indirect_image(tmp_path) -> Path:
    code = bytearray(b"\x90" * 0x60)
    _place(code, 0x00, b"\xB9" + _le(T - 0x100))                      # mov ecx, T - 0x100
    _place(code, 0x05, b"\x8B\x81" + _le(0x100))                      # mov eax, [ecx + 0x100]
    _place(code, 0x0B, b"\x89\x81" + _le(0x100))                      # mov [ecx + 0x100], eax
    _place(code, 0x11, b"\xA1" + _le(0x100))                          # mov eax, [0x100]: no register
    _place(code, 0x16, b"\xE8" + struct.pack("<i", 0x40 - 0x1B))      # call 0x40
    code[0x1B] = 0xC3
    _place(code, 0x40, b"\x8B\x15" + _le(PTR))                        # mov edx, [PTR]
    _place(code, 0x46, b"\x8B\x82" + _le(0x80))                       # mov eax, [edx + 0x80]
    code[0x4C] = 0xC3
    data = bytearray(b"\x11" * 0x200)
    data[0x40:0x44] = _le(T - 0x80)
    return pe_image(tmp_path / "a.exe", bytes(code), bytes(data))


def _defaults_image(tmp_path) -> Path:
    """Bases at the edge of the default max offset (4096), accesses at the edge of the default window (256)."""
    code = bytearray(b"\x90" * 0x120)
    _place(code, 0x00, b"\xB9" + _le(T - 4096))                           # mov ecx, T - 4096
    _place(code, 0x05, b"\xBB" + _le(T - 4097))                           # mov ebx, T - 4097: too far
    _place(code, 0x0A, b"\x8B\x83" + _le(4097))                           # mov eax, [ebx + 4097]
    _place(code, 0x10, b"\xBE" + _le(T - 4096))                           # mov esi, T - 4096
    _place(code, 0xFA, b"\x8B\x81" + _le(4096))                           # ends at 0x100: in the window of 0x00
    _place(code, 0x10B, b"\x8B\x86" + _le(4096))                          # ends at 0x111: past the window of 0x10
    return pe_image(tmp_path / "a.exe", bytes(code))


def _pairs(path, target=T, **kw):
    return [(h["base_va"] - TEXT, h["access_va"] - TEXT)
            for h in datarefs.scan_indirect(Binary(str(path)), target, **kw)]


class TestScanIndirect:
    def test_immediate_base_and_pointer_chain(self, tmp_path):
        hits = list(datarefs.scan_indirect(Binary(str(_indirect_image(tmp_path))), T))
        assert [{k: h[k] for k in ("base_va", "base_val", "offset", "source", "access_va", "access", "reg", "func")}
                for h in hits] == [
            {"base_va": TEXT, "base_val": T - 0x100, "offset": 0x100, "source": "imm",
             "access_va": TEXT + 0x05, "access": "r", "reg": "ecx", "func": None},
            {"base_va": TEXT, "base_val": T - 0x100, "offset": 0x100, "source": "imm",
             "access_va": TEXT + 0x0B, "access": "w", "reg": "ecx", "func": None},
            {"base_va": TEXT + 0x40, "base_val": T - 0x80, "offset": 0x80, "source": f"ptr@0x{PTR:X}",
             "access_va": TEXT + 0x46, "access": "r", "reg": "edx", "func": TEXT + 0x40},
        ]
        assert hits[0]["base_insn"] == f"mov ecx, 0x{T - 0x100:x}"
        assert hits[0]["access_insn"] == "mov eax, dword ptr [ecx + 0x100]"

    def test_max_offset_bounds_the_base(self, tmp_path):
        path = _indirect_image(tmp_path)
        assert _pairs(path, max_offset=0x80) == [(0x40, 0x46)]
        assert _pairs(path, max_offset=0x7F) == []

    def test_base_above_the_target_is_not_a_candidate(self, tmp_path):
        code = b"\xBB" + _le(T + 4) + b"\x8B\x43\xFC" + b"\xC3"        # mov ebx, T + 4; mov eax, [ebx - 4]
        assert _pairs(pe_image(tmp_path / "a.exe", code)) == []

    def test_window_limits_the_forward_scan(self, tmp_path):
        path = _indirect_image(tmp_path)
        assert _pairs(path, max_offset=0x100, scan_window=0x0B) == [(0x00, 0x05)]
        assert _pairs(path, max_offset=0x100, scan_window=0x11) == [(0x00, 0x05), (0x00, 0x0B), (0x40, 0x46)]

    def test_base_load_is_not_its_own_access(self, tmp_path):
        code = b"\xC7\x81" + _le(0x100) + _le(T - 0x100) + b"\xC3"    # mov dword [ecx + 0x100], T - 0x100
        assert _pairs(pe_image(tmp_path / "a.exe", code)) == []

    def test_base_equal_to_the_target(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\xB9" + _le(T))                              # mov ecx, T
        _place(code, 0x05, b"\x8B\x01")                                   # mov eax, [ecx]
        _place(code, 0x07, b"\x8B\x15" + _le(PTR))                         # mov edx, [PTR] -> T
        _place(code, 0x0D, b"\x8B\x02")                                   # mov eax, [edx]
        data = bytearray(b"\x11" * 0x200)
        data[0x40:0x44] = _le(T)
        assert {(0x00, 0x05), (0x07, 0x0D)} <= set(_pairs(pe_image(tmp_path / "a.exe", bytes(code), bytes(data))))

    def test_pointer_above_the_target_is_not_a_candidate(self, tmp_path):
        code = b"\x8B\x1D" + _le(PTR) + b"\x8B\x43\xFC" + b"\xC3"          # mov ebx, [PTR] -> T + 4; [ebx - 4]
        data = bytearray(b"\x11" * 0x200)
        data[0x40:0x44] = _le(T + 4)
        assert _pairs(pe_image(tmp_path / "a.exe", code, bytes(data))) == []

    def test_displacement_must_equal_the_offset(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\xB9" + _le(T - 0x100))                      # mov ecx, T - 0x100
        _place(code, 0x05, b"\x8B\x81" + _le(0x104))                      # mov eax, [ecx + 0x104]
        _place(code, 0x0B, b"\x8B\x81" + _le(0xFC))                       # mov eax, [ecx + 0xFC]
        assert _pairs(pe_image(tmp_path / "a.exe", bytes(code))) == []

    def test_offset_is_target_minus_base_for_a_distant_base(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\xB9" + _le(0x200000))                       # mov ecx, 0x200000
        _place(code, 0x05, b"\x8B\x81" + _le(T - 0x200000))               # mov eax, [ecx + T - 0x200000]
        hits = list(datarefs.scan_indirect(Binary(str(pe_image(tmp_path / "a.exe", bytes(code)))), T,
                                           max_offset=0x300000))
        assert [(h["access_va"] - TEXT, h["offset"]) for h in hits] == [(0x05, T - 0x200000)]

    def test_default_max_offset_and_window(self, tmp_path):
        assert _pairs(_defaults_image(tmp_path)) == [(0x00, 0xFA), (0x10, 0xFA)]

    def test_bytes_that_are_no_instruction_do_not_end_the_forward_scan(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\xB9" + _le(T - 0x100))                      # mov ecx, T - 0x100
        _place(code, 0x05, b"\x0F\x04")                                   # no instruction
        _place(code, 0x10, b"\x8B\x81" + _le(0x100))                      # mov eax, [ecx + 0x100]
        path = pe_image(tmp_path / "a.exe", bytes(code))
        b = Binary(str(path))
        assert list(b._cs.disasm(bytes(code[0x05:0x07]), 0)) == []
        assert _pairs(path) == [(0x00, 0x10)]

    def test_each_base_access_pair_reported_once(self, tmp_path):
        code = bytearray(b"\x90" * 0x20)
        _place(code, 0x00, b"\xC7\x05" + _le(PTR) + _le(T - 0x80))     # mov dword [PTR], T - 0x80
        _place(code, 0x0A, b"\x8B\x82" + _le(0x80))                    # mov eax, [edx + 0x80]
        data = bytearray(b"\x11" * 0x200)
        data[0x40:0x44] = _le(T - 0x80)
        assert _pairs(pe_image(tmp_path / "a.exe", bytes(code), bytes(data))) == [(0x00, 0x0A)]


# -- CLI -----------------------------------------------------------------------

def _run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["datarefs.py", *map(str, argv)])
    datarefs.main()
    return capsys.readouterr().out.splitlines()


class TestCli:
    def test_range_and_imm_options(self, direct, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, direct, f"{G:X}", "--range", "1", "--imm")
        assert out[0] == f"7 data refs to 0x{G:X}..0x{G:X}"
        assert out[2:] == [
            f"  0x{TEXT + 0x00:08X}  [r ]  mov      eax, dword ptr [0x{G:x}]",
            f"  0x{TEXT + 0x05:08X}  [w ]  mov      dword ptr [0x{G:x}], eax",
            f"  0x{TEXT + 0x0A:08X}  [rw]  inc      dword ptr [0x{G:x}]",
            f"  0x{TEXT + 0x10:08X}  [w ]  fstp     dword ptr [0x{G:x}]",
            f"  0x{TEXT + 0x2B:08X}  [imm]  push     0x{G:x}",
            f"  0x{TEXT + 0x30:08X}  [imm]  mov      ecx, 0x{G:x}",
            f"  0x{TEXT + 0x35:08X}  [w ]  mov      dword ptr [0x{G:x}], 0x{G:x}",
        ]

    def test_default_range_is_four_bytes(self, direct, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, direct, f"{G:X}")
        assert out[0] == f"6 data refs to 0x{G:X}..0x{G + 3:X}"

    def test_64_bit_addresses_are_16_digits(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", b"\x8B\x05" + _rip(0x00, 6) + b"\xC3", is_64=True)
        out = _run(monkeypatch, capsys, path, f"{G64:X}")
        assert out[2] == f"  0x{TEXT64:016X}  [r ]  mov      eax, dword ptr [rip + 0x{G64 - TEXT64 - 6:x}]"

    def test_indirect_listing(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, _indirect_image(tmp_path), f"{T:X}", "--indirect")
        assert out == [
            "",
            f"3 indirect refs to 0x{T:X} (max offset: 4096)",
            "",
            f"  Base 0x{T - 0x100:X} + 0x100 = 0x{T:X}",
            f"    0x{TEXT:08X}       mov ecx, 0x{T - 0x100:x}",
            f"    0x{TEXT + 0x05:08X}  [r ]  mov eax, dword ptr [ecx + 0x100]  via ecx",
            f"    0x{TEXT:08X}       mov ecx, 0x{T - 0x100:x}",
            f"    0x{TEXT + 0x0B:08X}  [w ]  mov dword ptr [ecx + 0x100], eax  via ecx",
            "",
            f"  Base 0x{T - 0x80:X} + 0x80 = 0x{T:X}",
            f"    0x{TEXT + 0x40:08X}       mov edx, dword ptr [0x{PTR:x}]  (ptr@0x{PTR:X})",
            f"    0x{TEXT + 0x46:08X}  [r ]  mov eax, dword ptr [edx + 0x80]  via edx  fn:0x{TEXT + 0x40:X}",
            "",
        ]

    def test_indirect_defaults(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, _defaults_image(tmp_path), f"{T:X}", "--indirect")
        assert out[1] == f"2 indirect refs to 0x{T:X} (max offset: 4096)"

    def test_indirect_64_bit_addresses_are_16_digits(self, tmp_path, monkeypatch, capsys):
        code = b"\x48\xB9" + struct.pack("<Q", G64 - 0x10) + b"\x8B\x41\x10" + b"\xC3"  # movabs rcx; [rcx + 0x10]
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", code, is_64=True), f"{G64:X}", "--indirect")
        assert out[4] == f"    0x{TEXT64:016X}       movabs rcx, 0x{G64 - 0x10:x}"
        assert out[5] == f"    0x{TEXT64 + 10:016X}  [r ]  mov eax, dword ptr [rcx + 0x10]  via rcx"

    def test_access_choices(self, direct, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, direct, f"{G:X}", "--access", "rw")
        assert out[0] == f"1 data refs to 0x{G:X}..0x{G + 3:X}"
        with pytest.raises(SystemExit):
            _run(monkeypatch, capsys, direct, f"{G:X}", "--access", "x")

    def test_runs_as_a_module_from_the_repo_root(self, direct):
        root = Path(__file__).resolve().parent.parent
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        out = subprocess.run([sys.executable, "-m", "retools.datarefs", str(direct), f"{G:X}"],
                             cwd=root, env=env, capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        assert out.stdout.splitlines()[0] == f"6 data refs to 0x{G:X}..0x{G + 3:X}"

    def test_indirect_options(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, _indirect_image(tmp_path), f"{T:X}", "--indirect",
                   "--max-offset", "128", "--window", "16")
        assert out[1] == f"1 indirect refs to 0x{T:X} (max offset: 128)"
        assert out[3] == f"  Base 0x{T - 0x80:X} + 0x80 = 0x{T:X}"
