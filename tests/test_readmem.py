"""Tests for retools/readmem.py -- typed little-endian reads at a VA, one output line per element."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "retools"))

import readmem  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, IMAGE_BASE64, pe_image  # noqa: E402

DATA = IMAGE_BASE + DATA_RVA
DATA64 = IMAGE_BASE64 + DATA_RVA


def _data() -> bytes:
    """Known values in .data, each at its own offset."""
    d = bytearray(0x200)
    struct.pack_into("<f", d, 0x00, 1.5)
    struct.pack_into("<f", d, 0x04, -2.25)
    struct.pack_into("<d", d, 0x08, 3.125)
    struct.pack_into("<i", d, 0x10, -2)
    struct.pack_into("<I", d, 0x14, 0x80000001)
    struct.pack_into("<h", d, 0x18, -300)
    struct.pack_into("<H", d, 0x1A, 0xFFFE)
    struct.pack_into("<b", d, 0x1C, -5)
    struct.pack_into("<B", d, 0x1D, 0xFB)
    struct.pack_into("<I", d, 0x20, 0x00401234)
    struct.pack_into("<I", d, 0x24, 0x00402000)
    struct.pack_into("<III", d, 0x30, 1, 2, 3)
    d[0x40:0x46] = bytes([0x00, 0x01, 0xAB, 0xCD, 0xEF, 0x7F])
    struct.pack_into("<I", d, 0x1FC, 7)
    return bytes(d)


@pytest.fixture
def image(tmp_path):
    return str(pe_image(tmp_path / "a.exe", b"\x90", _data()))


def _run(monkeypatch, capsys, *argv) -> list[str]:
    monkeypatch.setattr(sys, "argv", ["readmem.py", *argv])
    readmem.main()
    return capsys.readouterr().out.splitlines()


class TestIntegers:
    @pytest.mark.parametrize("type_, off, value", [
        ("int32", 0x10, -2),
        ("uint32", 0x14, 0x80000001),
        ("int16", 0x18, -300),
        ("uint16", 0x1A, 0xFFFE),
        ("int8", 0x1C, -5),
        ("uint8", 0x1D, 0xFB),
    ])
    def test_each_width_and_signedness_reads_little_endian(self, image, monkeypatch, capsys, type_, off, value):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + off:X}", type_) == [f"0x{DATA + off:08X}: {value}"]

    def test_count_reads_consecutive_elements_at_element_stride(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x30:X}", "uint32", "-n", "3") == [
            f"0x{DATA + 0x30:08X}: 1", f"0x{DATA + 0x34:08X}: 2", f"0x{DATA + 0x38:08X}: 3"]

    def test_narrow_types_step_by_their_own_size(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x18:X}", "int16", "--count", "2") == [
            f"0x{DATA + 0x18:08X}: -300", f"0x{DATA + 0x1A:08X}: -2"]
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x1C:X}", "int8", "-n", "2") == [
            f"0x{DATA + 0x1C:08X}: -5", f"0x{DATA + 0x1D:08X}: -5"]

    def test_va_is_hex_with_or_without_prefix(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"{DATA + 0x10:X}", "int32") == [f"0x{DATA + 0x10:08X}: -2"]


class TestFloats:
    def test_float_prints_value_and_raw_bits(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA:X}", "float", "-n", "2") == [
            f"0x{DATA:08X}: {1.5:14.6f}  (0x3FC00000)",
            f"0x{DATA + 4:08X}: {-2.25:14.6f}  (0xC0100000)"]

    def test_double_is_eight_bytes_with_sixteen_hex_digits(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 8:X}", "double") == [
            f"0x{DATA + 8:08X}: {3.125:14.6f}  (0x4009000000000000)"]


class TestPointers:
    def test_ptr_is_four_bytes_in_pe32(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x20:X}", "ptr", "-n", "2") == [
            f"0x{DATA + 0x20:08X}: 0x00401234", f"0x{DATA + 0x24:08X}: 0x00402000"]

    def test_ptr_is_eight_bytes_in_pe32_plus(self, tmp_path, monkeypatch, capsys):
        d = bytearray(0x200)
        struct.pack_into("<QQ", d, 0, 0x0000000140001000, 0x1122334455667788)
        path = str(pe_image(tmp_path / "b.exe", b"\x90", bytes(d), is_64=True))
        va = DATA64
        assert _run(monkeypatch, capsys, path, f"0x{va:X}", "ptr", "-n", "2") == [
            f"0x{va:08X}: 0x0000000140001000", f"0x{va + 8:08X}: 0x1122334455667788"]

    @pytest.mark.parametrize("type_, fmt, values, lines", [
        ("uint32", "<II", (5, 6), ["5", "6"]),
        ("int32", "<ii", (-5, 6), ["-5", "6"]),
        ("int16", "<hh", (-7, 8), ["-7", "8"]),
        ("float", "<ff", (1.5, 2.0), [f"{1.5:14.6f}  (0x3FC00000)", f"{2.0:14.6f}  (0x40000000)"]),
    ])
    def test_other_types_keep_their_width_in_pe32_plus(self, tmp_path, monkeypatch, capsys, type_, fmt, values, lines):
        d = bytearray(0x200)
        struct.pack_into(fmt, d, 0, *values)
        path = str(pe_image(tmp_path / "b.exe", b"\x90", bytes(d), is_64=True))
        va = DATA64
        step = struct.calcsize(fmt) // 2
        assert _run(monkeypatch, capsys, path, f"0x{va:X}", type_, "-n", "2") == [
            f"0x{va:08X}: {lines[0]}", f"0x{va + step:08X}: {lines[1]}"]


class TestBytes:
    def test_count_is_a_byte_count_on_one_line(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x40:X}", "bytes", "-n", "6") == [
            f"0x{DATA + 0x40:08X}: 00 01 AB CD EF 7F"]

    def test_default_count_is_one_byte(self, image, monkeypatch, capsys):
        assert _run(monkeypatch, capsys, image, f"0x{DATA + 0x42:X}", "bytes") == [f"0x{DATA + 0x42:08X}: AB"]


class TestArguments:
    def test_unknown_type_is_rejected(self, image, monkeypatch, capsys):
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, capsys, image, f"0x{DATA:X}", "string")
        assert e.value.code == 2

    def test_every_documented_type_reads_its_value(self, image, monkeypatch, capsys):
        expected = {                   # type -> (offset in .data, printed value)
            "float": (0x00, f"{1.5:14.6f}  (0x3FC00000)"),
            "double": (0x08, f"{3.125:14.6f}  (0x4009000000000000)"),
            "int32": (0x10, "-2"),
            "uint32": (0x14, str(0x80000001)),
            "int16": (0x18, "-300"),
            "uint16": (0x1A, str(0xFFFE)),
            "int8": (0x1C, "-5"),
            "uint8": (0x1D, str(0xFB)),
            "ptr": (0x20, "0x00401234"),
            "bytes": (0x42, "AB"),
        }
        types_line = next(line for line in readmem.__doc__.splitlines() if line.startswith("Types:"))
        documented = [t.strip() for t in types_line.removeprefix("Types:").split(",")]
        assert documented
        for type_ in documented:
            off, value = expected[type_]
            assert _run(monkeypatch, capsys, image, f"0x{DATA + off:X}", type_) == [f"0x{DATA + off:08X}: {value}"]


class TestInvocation:
    """Both documented command lines: the script path (module docstring) and ``python -m`` from the repo root."""

    @pytest.mark.parametrize("prefix", [["retools/readmem.py"], ["-m", "retools.readmem"]])
    def test_command_line_prints_the_read(self, image, prefix):
        out = subprocess.run([sys.executable, *prefix, image, f"0x{DATA + 0x10:X}", "int32"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
        assert out.splitlines() == [f"0x{DATA + 0x10:08X}: -2"]
