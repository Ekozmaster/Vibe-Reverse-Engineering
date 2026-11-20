"""Tests for retools/disasm.py -- N instructions decoded from a VA, one `0xADDRESS: [BYTES] MNEMONIC OPERANDS` line each."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "retools"))

import disasm  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA

# push ebp / mov ebp, esp / nop / ret; pe_image pads the rest of .text with int3.
PROLOGUE = bytes.fromhex("558BEC90C3")
PROLOGUE_LINES = [
    [f"0x{TEXT:08X}:", "push", "ebp"],
    [f"0x{TEXT + 1:08X}:", "mov", "ebp,", "esp"],
    [f"0x{TEXT + 3:08X}:", "nop"],
    [f"0x{TEXT + 4:08X}:", "ret"],
]


@pytest.fixture
def image(tmp_path):
    return str(pe_image(tmp_path / "a.exe", PROLOGUE))


def _run(monkeypatch, capsys, *argv) -> list[str]:
    monkeypatch.setattr(sys, "argv", ["disasm.py", *argv])
    disasm.main()
    return capsys.readouterr().out.splitlines()


def _tokens(lines: list[str]) -> list[list[str]]:
    return [line.split() for line in lines]


class TestCount:
    def test_n_decodes_exactly_that_many_instructions_from_the_va(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT:X}", "-n", "4")) == PROLOGUE_LINES

    def test_long_option_is_the_same_count(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT:X}", "--count", "2")) == PROLOGUE_LINES[:2]

    def test_default_count_is_thirty(self, image, monkeypatch, capsys):
        lines = _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT:X}"))
        assert len(lines) == 30
        assert lines[:4] == PROLOGUE_LINES
        assert lines[4:] == [[f"0x{TEXT + 5 + i:08X}:", "int3"] for i in range(26)]

    def test_va_inside_an_instruction_stream_starts_there(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT + 1:X}", "-n", "2")) == PROLOGUE_LINES[1:3]

    def test_va_is_hex_with_or_without_prefix(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"{TEXT + 3:X}", "-n", "1")) == [PROLOGUE_LINES[2]]


class TestOutputFormat:
    def test_address_is_0x_and_eight_uppercase_hex_digits(self, tmp_path, monkeypatch, capsys):
        path = str(pe_image(tmp_path / "a.exe", b"\x90" * 0x1B + b"\xC3"))
        lines = _run(monkeypatch, capsys, path, f"0x{TEXT + 0x1B:X}", "-n", "1")
        assert lines[0].startswith(f"0x{TEXT + 0x1B:08X}: ") and "0040101B" in lines[0]

    def test_mnemonic_and_operands_come_from_capstone(self, tmp_path, monkeypatch, capsys):
        # mov eax, dword ptr [ebx + 0x10] / call rel32 to TEXT+0x10
        code = bytes.fromhex("8B4310") + bytes.fromhex("E8") + struct.pack("<i", 0x10 - 8)
        path = str(pe_image(tmp_path / "a.exe", code))
        assert _tokens(_run(monkeypatch, capsys, path, f"0x{TEXT:X}", "-n", "2")) == [
            [f"0x{TEXT:08X}:", "mov", "eax,", "dword", "ptr", "[ebx", "+", "0x10]"],
            [f"0x{TEXT + 3:08X}:", "call", f"0x{TEXT + 0x10:x}"],
        ]

    def test_without_b_no_raw_bytes_are_shown(self, image, monkeypatch, capsys):
        line = _run(monkeypatch, capsys, image, f"0x{TEXT + 1:X}", "-n", "1")[0]
        assert "8B EC" not in line and "8BEC" not in line

    def test_b_shows_each_raw_byte_as_two_hex_digits_between_address_and_mnemonic(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT:X}", "-n", "3", "-b")) == [
            [f"0x{TEXT:08X}:", "55", "push", "ebp"],
            [f"0x{TEXT + 1:08X}:", "8B", "EC", "mov", "ebp,", "esp"],
            [f"0x{TEXT + 3:08X}:", "90", "nop"],
        ]

    def test_long_bytes_option(self, image, monkeypatch, capsys):
        assert _tokens(_run(monkeypatch, capsys, image, f"0x{TEXT + 1:X}", "-n", "1", "--bytes")) == [
            [f"0x{TEXT + 1:08X}:", "8B", "EC", "mov", "ebp,", "esp"],
        ]

    def test_b_keeps_a_leading_zero_byte(self, tmp_path, monkeypatch, capsys):
        # add byte ptr [eax], al
        path = str(pe_image(tmp_path / "a.exe", b"\x00\x00"))
        assert _tokens(_run(monkeypatch, capsys, path, f"0x{TEXT:X}", "-n", "1", "-b")) == [
            [f"0x{TEXT:08X}:", "00", "00", "add", "byte", "ptr", "[eax],", "al"],
        ]

    def test_stdout_holds_only_instruction_lines(self, image, monkeypatch, capsys):
        lines = _run(monkeypatch, capsys, image, f"0x{TEXT:X}", "-n", "2")
        assert len(lines) == 2 and all(line.startswith("0x") for line in lines)


class TestMode:
    def test_pe32_decodes_32_bit(self, tmp_path, monkeypatch, capsys):
        path = str(pe_image(tmp_path / "a.exe", bytes.fromhex("4889C8")))
        assert _tokens(_run(monkeypatch, capsys, path, f"0x{TEXT:X}", "-n", "2")) == [
            [f"0x{TEXT:08X}:", "dec", "eax"],
            [f"0x{TEXT + 1:08X}:", "mov", "eax,", "ecx"],
        ]

    def test_pe32_plus_decodes_64_bit_with_full_address(self, tmp_path, monkeypatch, capsys):
        path = str(pe_image(tmp_path / "b.exe", bytes.fromhex("4889C8C3"), is_64=True))
        va = IMAGE_BASE64 + 0x1000
        assert _tokens(_run(monkeypatch, capsys, path, f"0x{va:X}", "-n", "2", "-b")) == [
            [f"0x{va:08X}:", "48", "89", "C8", "mov", "rax,", "rcx"],
            [f"0x{va + 3:08X}:", "C3", "ret"],
        ]


class TestAnySection:
    def test_data_section_va_is_decoded_too(self, image, monkeypatch, capsys):
        # pe_image fills .data with 0x11: adc dword ptr [ecx], edx
        lines = _tokens(_run(monkeypatch, capsys, image, f"0x{IMAGE_BASE + DATA_RVA:X}", "-n", "1"))
        assert lines == [[f"0x{IMAGE_BASE + DATA_RVA:08X}:", "adc", "dword", "ptr", "[ecx],", "edx"]]


class TestCli:
    def test_missing_va_is_a_usage_error(self, image, monkeypatch, capsys):
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, capsys, image)
        assert e.value.code == 2

    def test_non_integer_count_is_a_usage_error(self, image, monkeypatch, capsys):
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, capsys, image, f"0x{TEXT:X}", "-n", "x")
        assert e.value.code == 2

    def test_help_documents_the_output_format_and_default(self, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            _run(monkeypatch, capsys, "-h")
        out = capsys.readouterr().out
        assert "0xADDRESS: [RAW_BYTES]  MNEMONIC  OPERANDS" in out
        assert "default: 30" in out

    @pytest.mark.parametrize("prefix", [[str(ROOT / "retools" / "disasm.py")], ["-m", "retools.disasm"]])
    def test_command_line_prints_the_instructions(self, image, prefix):
        out = subprocess.run([sys.executable, *prefix, image, f"0x{TEXT:X}", "-n", "2", "-b"],
                             cwd=ROOT, capture_output=True, text=True, check=True)
        assert _tokens(out.stdout.splitlines()) == [
            [f"0x{TEXT:08X}:", "55", "push", "ebp"],
            [f"0x{TEXT + 1:08X}:", "8B", "EC", "mov", "ebp,", "esp"],
        ]
